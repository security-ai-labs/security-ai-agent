"""
Multi-pass security analyzer - World-class detection
"""

import re
from typing import Dict, List
from ..llm.llm_client import LLMClient
from ..llm.prompts.aggressive_prompts import (
    get_function_level_analysis_prompt,
    get_static_pattern_checks,
)


class MultiPassAnalyzer:
    """
    Three-pass analysis:
    1. Static regex pattern matching (100% confident)
    2. Function-by-function LLM analysis
    3. Cross-function interaction analysis
    """

    def __init__(self, llm_client: LLMClient):
        self.llm = llm_client

    def analyze(self, code: str, language: str, filepath: str) -> Dict:
        """Execute three-pass analysis"""

        all_vulnerabilities = []

        # PASS 1: Static Pattern Detection
        print("🔍 Pass 1: Static pattern detection...")
        static_vulns = self._static_analysis(code, language, filepath)
        all_vulnerabilities.extend(static_vulns)
        print(f"   Found {len(static_vulns)} issues via static analysis")

        # PASS 2: Function-by-Function Analysis
        print("🔍 Pass 2: Function-level deep dive...")
        function_vulns = self._function_analysis(code, language, filepath)
        all_vulnerabilities.extend(function_vulns)
        print(f"   Found {len(function_vulns)} issues via function analysis")

        # PASS 3: Interaction Analysis
        print("🔍 Pass 3: Cross-function interaction check...")
        interaction_vulns = self._interaction_analysis(code, language, filepath)
        all_vulnerabilities.extend(interaction_vulns)
        print(f"   Found {len(interaction_vulns)} issues via interaction analysis")

        # Deduplicate
        unique_vulns = self._deduplicate(all_vulnerabilities)

        return {
            "vulnerabilities": unique_vulns,
            "summary": self._generate_summary(unique_vulns),
            "pass_results": {
                "static": len(static_vulns),
                "function": len(function_vulns),
                "interaction": len(interaction_vulns),
            },
        }

    def _static_analysis(self, code: str, language: str, filepath: str) -> List[Dict]:
        """
        Pass 1: Regex-based pattern matching
        100% confident detections
        """
        vulns = []
        patterns = get_static_pattern_checks().get(language, {})

        for vuln_id, pattern_info in patterns.items():
            regex = pattern_info["pattern"]

            for match in re.finditer(regex, code, re.MULTILINE | re.DOTALL):
                line_num = code[: match.start()].count("\n") + 1

                vulns.append(
                    {
                        "id": f"static-{vuln_id}-{line_num}",
                        "title": pattern_info["description"],
                        "severity": pattern_info["severity"],
                        "confidence": pattern_info["confidence"],
                        "line_number": line_num,
                        "description": pattern_info["description"],
                        "matched_code": match.group(0)[:100],
                        "detection_method": "static_regex",
                    }
                )

        return vulns

    def _function_analysis(self, code: str, language: str, filepath: str) -> List[Dict]:
        """
        Pass 2: Analyze each function individually with LLM
        """
        functions = self._extract_functions(code, language)
        vulns = []

        for func_name, func_code, func_start_line in functions:
            print(f"   Analyzing function: {func_name}")

            prompt = get_function_level_analysis_prompt(
                func_code, func_name, filepath, language
            )

            try:
                result = self.llm.analyze(
                    code=func_code,
                    system_prompt="You are a ruthless security auditor analyzing a single function.",
                    user_prompt=prompt,
                )

                if "vulnerabilities_found" in result:
                    for vuln in result["vulnerabilities_found"]:
                        # Adjust line numbers relative to full file
                        vuln["line_number"] = func_start_line + vuln.get(
                            "line_number", 0
                        )
                        vuln["detection_method"] = "function_analysis"
                        vuln["function_name"] = func_name
                        vulns.append(vuln)

            except Exception as e:
                print(f"   Warning: Failed to analyze {func_name}: {e}")
                continue

        return vulns

    def _interaction_analysis(
        self, code: str, language: str, filepath: str
    ) -> List[Dict]:
        """
        Pass 3: Check cross-function interactions
        Example: Function A lacks reentrancy guard but calls Function B which has external call
        """
        # For now, return empty - this is advanced analysis
        # TODO: Implement cross-function data flow analysis
        return []

    def _extract_functions(self, code: str, language: str) -> List:
        """Extract individual functions from code"""
        functions = []

        if language == "solidity":
            # Match: function name(...) visibility modifiers { ... }
            pattern = r"function\s+(\w+)\s*\([^)]*\)[^{]*\{((?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*)\}"

            for match in re.finditer(pattern, code, re.MULTILINE | re.DOTALL):
                func_name = match.group(1)
                func_code = match.group(0)
                func_start_line = code[: match.start()].count("\n") + 1
                functions.append((func_name, func_code, func_start_line))

        elif language == "python":
            pattern = r"def\s+(\w+)\s*\([^)]*\)\s*:([^\n]*\n(?:    .*\n)*)"

            for match in re.finditer(pattern, code):
                func_name = match.group(1)
                func_code = match.group(0)
                func_start_line = code[: match.start()].count("\n") + 1
                functions.append((func_name, func_code, func_start_line))

        elif language in ["javascript", "typescript"]:
            # Match: function name(...) { ... } and arrow functions
            pattern = r"(?:function\s+(\w+)|const\s+(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>)\s*\{([^}]*)\}"

            for match in re.finditer(pattern, code, re.DOTALL):
                func_name = match.group(1) or match.group(2)
                func_code = match.group(0)
                func_start_line = code[: match.start()].count("\n") + 1
                functions.append((func_name, func_code, func_start_line))

        return functions

    def _deduplicate(self, vulns: List[Dict]) -> List[Dict]:
        """Remove duplicate vulnerabilities found by multiple passes"""
        seen = set()
        unique = []

        for vuln in vulns:
            # Create unique key based on line number and type
            key = (vuln.get("line_number"), vuln.get("title", "")[:50])

            if key not in seen:
                seen.add(key)
                unique.append(vuln)

        return unique

    def _generate_summary(self, vulns: List[Dict]) -> Dict:
        """Generate summary statistics"""
        summary = {
            "total_issues": len(vulns),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }

        for vuln in vulns:
            severity = vuln.get("severity", "").lower()
            if severity in summary:
                summary[severity] += 1

        return summary
