"""
Language detector for security analyzer
Enhanced with more language support and content-based detection
"""

from pathlib import Path
from typing import Tuple


class LanguageDetector:
    """Detect programming language from file extension and content"""

    # Extended file type mappings
    EXTENSIONS = {
        # Blockchain/Web3
        ".sol": "solidity",
        ".vy": "vyper",
        ".rs": "rust",
        ".move": "move",
        ".cairo": "cairo",
        # Web2 - Backend
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".jsx": "javascript",
        ".tsx": "typescript",
        ".go": "go",
        ".java": "java",
        ".kt": "kotlin",
        ".rb": "ruby",
        ".php": "php",
        ".cs": "csharp",
        ".swift": "swift",
    }

    # Category mappings
    WEB3_LANGUAGES = {"solidity", "vyper", "rust", "move", "cairo"}

    def detect(self, filepath: str, content: str = "") -> str:
        """
        Detect language from file path and content

        Args:
            filepath: Path to the file
            content: File content (optional, for content-based detection)

        Returns:
            Language name or 'unknown'
        """
        # Try extension-based detection first
        ext = Path(filepath).suffix.lower()
        if ext in self.EXTENSIONS:
            return self.EXTENSIONS[ext]

        # Fallback: content-based detection
        if content:
            detected = self._detect_from_content(content)
            if detected != "unknown":
                return detected

        return "unknown"

    def _detect_from_content(self, content: str) -> str:
        """
        Detect language from file content

        Args:
            content: File content

        Returns:
            Language name or 'unknown'
        """
        # Check shebang (first line)
        if content.startswith("#!"):
            first_line = content.split("\n")[0].lower()
            if "python" in first_line:
                return "python"
            if "node" in first_line or "javascript" in first_line:
                return "javascript"
            if "ruby" in first_line:
                return "ruby"
            if "php" in first_line:
                return "php"

        # Check pragma (Solidity/Vyper)
        if "pragma solidity" in content:
            return "solidity"
        if "pragma vyper" in content or "@version" in content[:200]:
            return "vyper"

        # Check imports (Python)
        if any(
            marker in content
            for marker in [
                "from flask import",
                "from django",
                "import django",
                "from fastapi import",
                "import asyncio",
            ]
        ):
            return "python"

        # Check imports (JavaScript/TypeScript)
        if any(
            marker in content
            for marker in [
                "const express = require",
                "import express from",
                "import React from",
                "const React = require",
                "module.exports",
                "export default",
            ]
        ):
            # Check for TypeScript-specific syntax
            if any(
                ts_marker in content
                for ts_marker in [
                    ": string",
                    ": number",
                    ": boolean",
                    "interface ",
                    "type ",
                ]
            ):
                return "typescript"
            return "javascript"

        # Check for Go
        if "package main" in content or "func main()" in content:
            return "go"

        # Check for Rust
        if "fn main()" in content or "use std::" in content:
            return "rust"

        # Check for Java
        if "public class" in content or "public static void main" in content:
            return "java"

        # Check for PHP
        if "<?php" in content:
            return "php"

        return "unknown"

    def get_category(self, language: str) -> str:
        """
        Get security category for language

        Args:
            language: Programming language

        Returns:
            'web3' or 'web2'
        """
        return "web3" if language in self.WEB3_LANGUAGES else "web2"

    def is_supported(self, language: str) -> bool:
        """
        Check if language is supported for analysis

        Args:
            language: Programming language

        Returns:
            True if supported
        """
        supported = {
            "solidity",
            "vyper",
            "python",
            "javascript",
            "typescript",
            "rust",
            "go",
        }
        return language in supported
