"""
Universal Security Analyzer - Supports Web2 and Web3
Enhanced with multi-pass analysis for world-class detection
"""

import time
from pathlib import Path
from typing import Dict, Optional

from .language_detector import LanguageDetector
from .multipass_analyzer import MultiPassAnalyzer
from ..llm.llm_client import LLMClient
from ..llm.prompts.base_prompts import get_system_prompt, get_analysis_prompt


class UniversalSecurityAnalyzer:
    """Universal security analyzer with multi-pass analysis"""

    SUPPORTED_LANGUAGES = {
        "solidity",
        "vyper",
        "python",
        "javascript",
        "typescript",
        "rust",
        "go",
    }

    # Analysis modes
    MODE_SINGLE_PASS = "single"
    MODE_MULTI_PASS = "multi"

    def __init__(
        self,
        config_path: str = "config/llm_config.yaml",
        analysis_mode: str = MODE_MULTI_PASS,
    ):
        """
        Initialize analyzer

        Args:
            config_path: Path to LLM configuration
            analysis_mode: 'single' for fast, 'multi' for thorough (default)
        """
        self.llm_client = LLMClient(config_path)
        self.detector = LanguageDetector()
        self.analysis_mode = analysis_mode
        self.multipass = MultiPassAnalyzer(self.llm_client)

    def analyze_file(
        self,
        filepath: str,
        language: Optional[str] = None,
        model: Optional[str] = None,
        max_retries: int = 3,
        force_mode: Optional[str] = None,
    ) -> Dict:
        """
        Analyze a file for security vulnerabilities

        Args:
            filepath: Path to file to analyze
            language: Force specific language (auto-detect if None)
            model: LLM model to use (default from config)
            max_retries: Maximum number of retry attempts
            force_mode: Override analysis mode ('single' or 'multi')

        Returns:
            Analysis results dictionary with vulnerabilities and metadata
        """
        start_time = time.time()
        mode = force_mode if force_mode else self.analysis_mode

        print(f"\n🛡️  Starting {mode}-pass analysis...")

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

        # Choose analysis method
        if mode == self.MODE_MULTI_PASS:
            result = self._analyze_multipass(
                code, language, filepath, model, max_retries
            )
        else:
            result = self._analyze_singlepass(
                code, language, filepath, model, max_retries
            )

        # Add comprehensive metadata
        analysis_time = time.time() - start_time

        if "metadata" not in result:
            result["metadata"] = {}

        result["metadata"].update(
            {
                "language": language,
                "filepath": filepath,
                "category": self.detector.get_category(language),
                "file_size_bytes": len(code),
                "lines_of_code": code.count("\n") + 1,
                "analysis_time_seconds": round(analysis_time, 2),
                "analysis_mode": mode,
                "success": True,
            }
        )

        return result

    def _analyze_multipass(
        self,
        code: str,
        language: str,
        filepath: str,
        model: Optional[str],
        max_retries: int,
    ) -> Dict:
        """
        Multi-pass analysis (WORLD-CLASS mode)

        Pass 1: Static regex pattern matching
        Pass 2: Function-by-function LLM analysis
        Pass 3: Cross-function interaction analysis
        """
        last_error = None

        for attempt in range(max_retries):
            try:
                result = self.multipass.analyze(code, language, filepath)

                # Ensure required fields
                if "vulnerabilities" not in result:
                    result["vulnerabilities"] = []

                if "summary" not in result:
                    result["summary"] = self._create_default_summary()

                # Add pass statistics to metadata
                if "metadata" not in result:
                    result["metadata"] = {}

                if "pass_results" in result:
                    result["metadata"]["pass_breakdown"] = result["pass_results"]

                return result

            except Exception as e:
                last_error = str(e)
                if attempt < max_retries - 1:
                    wait_time = 2**attempt
                    print(f"⚠️  Multi-pass attempt {attempt + 1} failed: {e}")
                    print(f"   Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                else:
                    print(f"❌ All {max_retries} multi-pass attempts failed")

        # All retries failed
        return self._create_error_result(
            filepath,
            f"Multi-pass analysis failed after {max_retries} attempts. Last error: {last_error}",
            language,
            0,
        )

    def _analyze_singlepass(
        self,
        code: str,
        language: str,
        filepath: str,
        model: Optional[str],
        max_retries: int,
    ) -> Dict:
        """
        Single-pass analysis (FAST mode)

        Uses original LLM-based analysis with enhanced prompts
        """
        # Get prompts
        system_prompt = get_system_prompt(language)
        user_prompt = get_analysis_prompt(code, language, filepath)

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

                return result

            except Exception as e:
                last_error = str(e)
                if attempt < max_retries - 1:
                    wait_time = 2**attempt
                    print(f"⚠️  Attempt {attempt + 1} failed: {e}")
                    print(f"   Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                else:
                    print(f"❌ All {max_retries} attempts failed")

        # All retries failed
        return self._create_error_result(
            filepath,
            f"Single-pass analysis failed. Last error: {last_error}",
            language,
            0,
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

    def set_analysis_mode(self, mode: str):
        """
        Change analysis mode

        Args:
            mode: 'single' for fast analysis, 'multi' for thorough
        """
        if mode not in [self.MODE_SINGLE_PASS, self.MODE_MULTI_PASS]:
            raise ValueError(f"Invalid mode: {mode}. Use 'single' or 'multi'")

        self.analysis_mode = mode
        print(f"✅ Analysis mode set to: {mode}-pass")

    def get_supported_languages(self) -> list:
        """Get list of supported languages"""
        return list(self.SUPPORTED_LANGUAGES)

    def get_analysis_stats(self) -> Dict:
        """Get analysis statistics"""
        return {
            "supported_languages": list(self.SUPPORTED_LANGUAGES),
            "current_mode": self.analysis_mode,
            "cost_summary": self.get_cost_summary(),
        }
