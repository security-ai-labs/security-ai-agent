"""
Universal Security Analyzer - Supports Web2 and Web3
"""

from pathlib import Path
from typing import Dict, Optional

from .language_detector import LanguageDetector
from ..llm.llm_client import LLMClient
from ..llm.prompts.base_prompts import get_system_prompt, get_analysis_prompt


class UniversalSecurityAnalyzer:
    """Universal security analyzer supporting multiple languages"""
    
    SUPPORTED_LANGUAGES = {
        'solidity', 'python', 'javascript', 'typescript', 'rust', 'go'
    }
    
    def __init__(self, config_path: str = "config/llm_config.yaml"):
        """Initialize analyzer"""
        self.llm_client = LLMClient(config_path)
        self.detector = LanguageDetector()
    
    def analyze_file(self, filepath: str, 
                    language: Optional[str] = None,
                    model: Optional[str] = None) -> Dict:
        """
        Analyze a file for security vulnerabilities
        
        Args:
            filepath: Path to file to analyze
            language: Force specific language (auto-detect if None)
            model: LLM model to use (default from config)
            
        Returns:
            Analysis results dictionary with vulnerabilities and metadata
        """
        # Read file
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                code = f.read()
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {filepath}")
        except Exception as e:
            raise Exception(f"Error reading file: {str(e)}")
        
        # Detect language
        if language is None:
            language = self.detector.detect(filepath, code)
        
        if language == 'unknown':
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
        
        # Analyze with LLM
        result = self.llm_client.analyze(
            code=code,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            model=model
        )
        
        # Add metadata
        result['metadata']['language'] = language
        result['metadata']['filepath'] = filepath
        result['metadata']['category'] = self.detector.get_category(language)
        result['metadata']['file_size_bytes'] = len(code)
        result['metadata']['lines_of_code'] = code.count('\n') + 1
        
        return result
    
    def get_cost_summary(self) -> Dict:
        """Get cost summary from LLM client"""
        return self.llm_client.get_cost_summary()