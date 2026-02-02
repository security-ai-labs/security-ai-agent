"""
LLM client for security analysis
"""

import json
import os
import time
import hashlib
from typing import Dict, Optional
import yaml
from dotenv import load_dotenv
from openai import OpenAI
import tiktoken

load_dotenv()


class LLMClient:
    """LLM client supporting OpenAI and Anthropic"""

    def __init__(self, config_path: str = "config/llm_config.yaml"):
        """Initialize LLM client"""
        self.config = self._load_config(config_path)
        self.client = self._initialize_client()
        self.cache = {}
        self.total_cost = 0.0
        self.encoding = tiktoken.encoding_for_model("gpt-4")

    def _load_config(self, config_path: str) -> Dict:
        """Load configuration"""
        with open(config_path, "r") as f:
            return yaml.safe_load(f)

    def _initialize_client(self) -> OpenAI:
        """Initialize OpenAI client"""
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY not found in environment variables")
        return OpenAI(api_key=api_key)

    def _count_tokens(self, text: str) -> int:
        """Count tokens in text"""
        return len(self.encoding.encode(text))

    def _calculate_cost(
        self, input_tokens: int, output_tokens: int, model: str
    ) -> float:
        """Calculate API cost"""
        config = self.config["models"][model]
        input_cost = (input_tokens / 1000) * config["cost_per_1k_input"]
        output_cost = (output_tokens / 1000) * config["cost_per_1k_output"]
        return input_cost + output_cost

    def _get_cache_key(self, code: str, prompt: str) -> str:
        """Generate cache key"""
        content = f"{code}:{prompt}"
        return hashlib.sha256(content.encode()).hexdigest()

    def _check_cache(self, cache_key: str) -> Optional[Dict]:
        """Check cache for existing result"""
        if not self.config["cache"]["enabled"]:
            return None

        if cache_key in self.cache:
            cached, timestamp = self.cache[cache_key]
            ttl = self.config["cache"]["ttl_hours"] * 3600

            if time.time() - timestamp < ttl:
                return cached

        return None

    def analyze(
        self,
        code: str,
        system_prompt: str,
        user_prompt: str,
        model: Optional[str] = None,
    ) -> Dict:
        """
        Analyze code with LLM

        Args:
            code: Source code to analyze
            system_prompt: System message for LLM
            user_prompt: User message for LLM
            model: Model to use (default from config)

        Returns:
            Analysis results dictionary
        """
        # Check cache
        cache_key = self._get_cache_key(code, user_prompt)
        cached = self._check_cache(cache_key)
        if cached:
            cached["metadata"]["from_cache"] = True
            return cached

        # Select model
        if model is None:
            model = self.config["default_model"]

        # Count tokens
        input_tokens = self._count_tokens(system_prompt + user_prompt)

        # Call LLM with robust error handling
        try:
            response = self.client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=self.config["models"][model]["temperature"],
                max_tokens=self.config["models"][model]["max_tokens"],
                response_format={"type": "json_object"},
            )

            # Parse response
            response_text = response.choices[0].message.content

            # Try to parse JSON
            try:
                result = json.loads(response_text)
            except json.JSONDecodeError as e:
                # Return a safe error structure
                return {
                    "vulnerabilities": [],
                    "summary": {
                        "total_issues": 0,
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                    },
                    "overall_assessment": f"Failed to parse LLM response: {str(e)}",
                    "metadata": {
                        "model": model,
                        "input_tokens": input_tokens,
                        "output_tokens": 0,
                        "cost_usd": 0,
                        "total_cost_usd": self.total_cost,
                        "from_cache": False,
                        "timestamp": time.time(),
                        "error": f"JSON parse error: {str(e)}",
                    },
                }

            # Ensure result is a dict
            if not isinstance(result, dict):
                return {
                    "vulnerabilities": [],
                    "summary": {
                        "total_issues": 0,
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                    },
                    "overall_assessment": "LLM returned non-dict response",
                    "metadata": {
                        "model": model,
                        "input_tokens": input_tokens,
                        "output_tokens": 0,
                        "cost_usd": 0,
                        "total_cost_usd": self.total_cost,
                        "from_cache": False,
                        "timestamp": time.time(),
                        "error": f"Result type: {type(result)}",
                    },
                }

            # Calculate cost
            output_tokens = response.usage.completion_tokens
            cost = self._calculate_cost(input_tokens, output_tokens, model)
            self.total_cost += cost

            # Ensure required fields exist
            if "vulnerabilities" not in result:
                result["vulnerabilities"] = []
            if "summary" not in result:
                result["summary"] = {
                    "total_issues": len(result["vulnerabilities"]),
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                }

            # Add metadata
            result["metadata"] = {
                "model": model,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cost_usd": round(cost, 4),
                "total_cost_usd": round(self.total_cost, 4),
                "from_cache": False,
                "timestamp": time.time(),
            }

            # Cache result
            if self.config["cache"]["enabled"]:
                self.cache[cache_key] = (result, time.time())

            return result

        except Exception as e:
            # Return safe error structure
            error_msg = str(e)
            return {
                "vulnerabilities": [],
                "summary": {
                    "total_issues": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                },
                "overall_assessment": f"Analysis failed: {error_msg}",
                "metadata": {
                    "model": model,
                    "input_tokens": input_tokens,
                    "output_tokens": 0,
                    "cost_usd": 0,
                    "total_cost_usd": self.total_cost,
                    "from_cache": False,
                    "timestamp": time.time(),
                    "error": error_msg,
                },
            }

    def get_cost_summary(self) -> Dict:
        """Get cost summary"""
        return {
            "total_cost_usd": round(self.total_cost, 4),
            "daily_limit": self.config["cost_limits"]["daily"],
            "monthly_limit": self.config["cost_limits"]["monthly"],
            "remaining_daily": round(
                self.config["cost_limits"]["daily"] - self.total_cost, 4
            ),
        }
