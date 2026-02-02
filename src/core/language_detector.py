"""
Automatic language detection for security analysis
"""

import re
from pathlib import Path
from typing import Optional


class LanguageDetector:
    """Detect programming language from file extension and content"""
    
    EXTENSIONS = {
        '.sol': 'solidity',
        '.py': 'python',
        '.js': 'javascript',
        '.ts': 'typescript',
        '.jsx': 'javascript',
        '.tsx': 'typescript',
        '.rs': 'rust',
        '.go': 'go',
    }
    
    PATTERNS = {
        'solidity': [
            r'pragma solidity',
            r'contract\s+\w+',
            r'function\s+\w+.*\s+public',
        ],
        'python': [
            r'def\s+\w+\(',
            r'import\s+\w+',
            r'from\s+\w+\s+import',
        ],
        'javascript': [
            r'function\s+\w+\(',
            r'const\s+\w+\s*=',
            r'require\([\'"]',
        ],
        'typescript': [
            r'interface\s+\w+',
            r'type\s+\w+\s*=',
        ],
        'rust': [
            r'fn\s+\w+\(',
            r'use\s+\w+',
        ],
    }
    
    @classmethod
    def detect(cls, filepath: str, content: Optional[str] = None) -> str:
        """Detect language from file path and content"""
        ext = Path(filepath).suffix.lower()
        if ext in cls.EXTENSIONS:
            return cls.EXTENSIONS[ext]
        
        if content is None:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
        
        return cls._detect_by_content(content)
    
    @classmethod
    def _detect_by_content(cls, content: str) -> str:
        """Detect language by analyzing content patterns"""
        scores = {}
        
        for lang, patterns in cls.PATTERNS.items():
            scores[lang] = sum(
                1 for pattern in patterns 
                if re.search(pattern, content, re.MULTILINE)
            )
        
        if not scores or max(scores.values()) == 0:
            return 'unknown'
        
        return max(scores, key=scores.get)
    
    @classmethod
    def get_category(cls, language: str) -> str:
        """Get category: web3 or web2"""
        web3_langs = {'solidity', 'rust'}
        return 'web3' if language in web3_langs else 'web2'