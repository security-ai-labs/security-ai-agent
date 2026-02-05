"""
Universal Security Analyzer - Supports Web2 and Web3
Enhanced with retry logic, better error handling, and caching
"""

import time
from pathlib import Path
from typing import Dict, Optional

from .language_detector import LanguageDetector
from ..llm.llm_client import LLMClient
from ..llm.prompts.base_prompts import get_system_prompt, get_analysis_prompt


class UniversalSecurityAnalyzer:
    """Universal security analyzer supporting multiple languages"""

    SUPPORTED_LANGUAGES = {
        "solidity",
        "vyper",
        "python",
        "javascript",
        "typescript",
        "rust",
        "go",
    }

    def __init__(self, config_path: str = "config/llm_config.yaml"):
        """Initialize analyzer"""
        self.llm_client = LLMClient(config_path)
        self.detector = LanguageDetector()

    def analyze_file(
        self,
        filepath: str,
        language: Optional[str] = None,
        model: Optional[str] = None,
        max_retries: int = 3,
    ) -> Dict:
        """
        Analyze a file for security vulnerabilities with retry logic

        Args:
            filepath: Path to file to analyze
            language: Force specific language (auto-detect if None)
            model: LLM model to use (default from config)
            max_retries: Maximum number of retry attempts

        Returns:
            Analysis results dictionary with vulnerabilities and metadata
        """
        start_time = time.time()

        # Read file
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                code = f.read()
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {filepath}")
        except UnicodeDecodeError:
            raise ValueError(f"Cannot decode file (binary file?): {filepath}")
        except Exception as e:
            raise Exception(f"Error reading file: {str(e)}")

        # Detect language
        if language is None:
            language = self.detector.detect(filepath, code)

        if language == "unknown":
            raise ValueError(
                f"Could not detect language for: {filepath}. "
                f"Please specify with --language flag."
            )

        if language not in self.SUPPORTED_LANGUAGES:
            raise ValueError(
                f"Unsupported language: {language}. "
                f"Supported: {', '.join(self.SUPPORTED_LANGUAGES)}"
            )

        # Get prompts
        system_prompt = get_system_prompt(language)
        user_prompt = get_analysis_prompt(code, language, filepath)

        # Analyze with retries
        last_error = None
        for attempt in range(max_retries):
            try:
                result = self.llm_client.analyze(
                    code=code,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    model=model,
                )

                # Validate result structure
                if not isinstance(result, dict):
                    raise ValueError(f"Invalid result format: {type(result)}")

                # Ensure required fields
                if "vulnerabilities" not in result:
                    result["vulnerabilities"] = []

                if "summary" not in result:
                    result["summary"] = self._create_default_summary()

                if "metadata" not in result:
                    result["metadata"] = {}

                # Add comprehensive metadata
                result["metadata"].update(
                    {
                        "language": language,
                        "filepath": filepath,
                        "category": self.detector.get_category(language),
                        "file_size_bytes": len(code),
                        "lines_of_code": code.count("\n") + 1,
                        "analysis_time_seconds": round(time.time() - start_time, 2),
                        "attempt": attempt + 1,
                    }
                )

                return result

            except Exception as e:
                last_error = str(e)
                if attempt < max_retries - 1:
                    wait_time = 2**attempt  # Exponential backoff
                    print(f"⚠️  Attempt {attempt + 1} failed: {e}")
                    print(f"   Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                else:
                    print(f"❌ All {max_retries} attempts failed")

        # All retries failed
        return self._create_error_result(
            filepath,
            f"Max retries exceeded. Last error: {last_error}",
            language,
            time.time() - start_time,
        )

    def _create_default_summary(self) -> Dict:
        """Create default summary structure"""
        return {"total_issues": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}

    def _create_error_result(
        self,
        filepath: str,
        error: str,
        language: str = "unknown",
        analysis_time: float = 0,
    ) -> Dict:
        """Create error result structure"""
        return {
            "vulnerabilities": [],
            "summary": self._create_default_summary(),
            "overall_assessment": f"Analysis failed: {error}",
            "metadata": {
                "filepath": filepath,
                "language": language,
                "error": error,
                "analysis_time_seconds": round(analysis_time, 2),
                "success": False,
            },
        }

    def get_cost_summary(self) -> Dict:
        """Get cost summary from LLM client"""
        return self.llm_client.get_cost_summary()
