"""
LLM client for security analysis
Enhanced with caching, filtering, and retry logic
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
    """LLM client supporting OpenAI with enhanced features"""

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
            raise ValueError(
                "OPENAI_API_KEY not found in environment variables. Please check your .env file."
            )
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
        """Generate smart cache key using content hash"""
        # Hash the code content
        code_hash = hashlib.sha256(code.encode()).hexdigest()[:16]

        # Hash the prompt (to detect prompt changes)
        prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()[:8]

        # Combined key
        return f"{code_hash}:{prompt_hash}"

    def _check_cache(self, cache_key: str) -> Optional[Dict]:
        """Check cache with smart expiration"""
        if not self.config["cache"]["enabled"]:
            return None

        if cache_key in self.cache:
            cached_result, timestamp = self.cache[cache_key]
            ttl = self.config["cache"]["ttl_hours"] * 3600

            # Check if still valid
            if time.time() - timestamp < ttl:
                print("✨ Using cached analysis (no API cost)")
                return cached_result
            else:
                # Remove expired entry
                del self.cache[cache_key]

        return None

    def analyze(
        self,
        code: str,
        system_prompt: str,
        user_prompt: str,
        model: Optional[str] = None,
    ) -> Dict:
        """
        Analyze code with LLM - enhanced with filtering and caching

        Args:
            code: Source code to analyze
            system_prompt: System message for LLM
            user_prompt: User message for LLM
            model: Model to use (default from config)

        Returns:
            Analysis results dictionary
        """
        # Check cache first
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
                return self._create_error_result(
                    f"Failed to parse LLM response: {str(e)}", input_tokens, 0, model
                )

            # Ensure result is a dict
            if not isinstance(result, dict):
                return self._create_error_result(
                    f"LLM returned non-dict response: {type(result)}",
                    input_tokens,
                    0,
                    model,
                )

            # Ensure required fields exist
            if "vulnerabilities" not in result:
                result["vulnerabilities"] = []
            if "summary" not in result:
                result["summary"] = self._create_default_summary()

            # POST-PROCESS: Filter false positives
            original_count = len(result["vulnerabilities"])
            result["vulnerabilities"] = self._filter_false_positives(
                result["vulnerabilities"], code
            )
            filtered_count = original_count - len(result["vulnerabilities"])

            if filtered_count > 0:
                print(f"🔍 Filtered {filtered_count} low-confidence finding(s)")

            # Recalculate summary after filtering
            result["summary"] = self._recalculate_summary(result["vulnerabilities"])

            # Calculate cost
            output_tokens = response.usage.completion_tokens
            cost = self._calculate_cost(input_tokens, output_tokens, model)
            self.total_cost += cost

            # Add metadata
            result["metadata"] = {
                "model": model,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cost_usd": round(cost, 4),
                "total_cost_usd": round(self.total_cost, 4),
                "from_cache": False,
                "timestamp": time.time(),
                "original_findings": original_count,
                "filtered_findings": filtered_count,
            }

            # Cache result
            if self.config["cache"]["enabled"]:
                self.cache[cache_key] = (result, time.time())

            return result

        except Exception as e:
            # Return safe error structure
            return self._create_error_result(
                f"Analysis failed: {str(e)}", input_tokens, 0, model
            )

    def _filter_false_positives(self, vulnerabilities: list, code: str) -> list:
        """
        Filter out obvious false positives

        Rules:
        1. Skip LOW confidence findings that are not CRITICAL
        2. Skip findings marked as mitigated
        3. Skip findings in comments
        """
        filtered = []

        for vuln in vulnerabilities:
            # Rule 1: Skip LOW confidence non-critical issues
            confidence = vuln.get("confidence", "MEDIUM")
            severity = vuln.get("severity", "MEDIUM")

            if confidence == "LOW" and severity not in ["CRITICAL", "HIGH"]:
                continue

            # Rule 2: Skip if marked as mitigated
            if vuln.get("mitigated", False):
                continue

            # Rule 3: Skip if in comment
            line_num = vuln.get("line_number", 0)
            if self._is_in_comment(code, line_num):
                continue

            # Passed all filters
            filtered.append(vuln)

        return filtered

    def _is_in_comment(self, code: str, line_num: int) -> bool:
        """Check if line is in a comment"""
        if line_num <= 0:
            return False

        lines = code.split("\n")
        if line_num > len(lines):
            return False

        line = lines[line_num - 1].strip()

        # Check for comment indicators
        comment_indicators = ["//", "#", "/*", "*", '"""', "'''"]
        return any(line.startswith(indicator) for indicator in comment_indicators)

    def _recalculate_summary(self, vulnerabilities: list) -> dict:
        """Recalculate summary after filtering"""
        summary = {
            "total_issues": len(vulnerabilities),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "").lower()
            if severity in summary:
                summary[severity] += 1

        return summary

    def _create_default_summary(self) -> dict:
        """Create default summary structure"""
        return {"total_issues": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}

    def _create_error_result(
        self, error_msg: str, input_tokens: int, output_tokens: int, model: str
    ) -> dict:
        """Create error result structure"""
        cost = self._calculate_cost(input_tokens, output_tokens, model)
        self.total_cost += cost

        return {
            "vulnerabilities": [],
            "summary": self._create_default_summary(),
            "overall_assessment": f"Analysis failed: {error_msg}",
            "metadata": {
                "model": model,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cost_usd": round(cost, 4),
                "total_cost_usd": round(self.total_cost, 4),
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
