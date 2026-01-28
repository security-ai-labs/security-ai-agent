"""
Pytest configuration and shared fixtures for security analyzer tests
"""
import pytest
import sys
import os
from typing import List, Dict

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from analyzer import SecurityAnalyzer
from pattern_matcher import PatternMatcher


@pytest.fixture
def analyzer():
    """Create SecurityAnalyzer instance with test rules"""
    rules_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'vulnerability_rules.json')
    return SecurityAnalyzer(rules_path)


@pytest.fixture
def pattern_matcher():
    """Create PatternMatcher instance with test rules"""
    rules_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'vulnerability_rules.json')
    return PatternMatcher(rules_path)


def analyze_code(pattern_matcher: PatternMatcher, code: str, chain: str) -> List[Dict]:
    """
    Helper function to analyze code snippet
    
    Args:
        pattern_matcher: PatternMatcher instance
        code: Code to analyze
        chain: Blockchain/platform ('ethereum', 'solana', 'web2', 'defi')
    
    Returns:
        List of found vulnerabilities
    """
    return pattern_matcher.find_vulnerabilities('test_file', code, chain)


@pytest.fixture
def analyze_ethereum(pattern_matcher):
    """Helper to analyze Ethereum code"""
    def _analyze(code: str) -> List[Dict]:
        return analyze_code(pattern_matcher, code, 'ethereum')
    return _analyze


@pytest.fixture
def analyze_solana(pattern_matcher):
    """Helper to analyze Solana code"""
    def _analyze(code: str) -> List[Dict]:
        return analyze_code(pattern_matcher, code, 'solana')
    return _analyze


@pytest.fixture
def analyze_web2(pattern_matcher):
    """Helper to analyze Web2 code"""
    def _analyze(code: str) -> List[Dict]:
        return analyze_code(pattern_matcher, code, 'web2')
    return _analyze


@pytest.fixture
def analyze_defi(pattern_matcher):
    """Helper to analyze DeFi code"""
    def _analyze(code: str) -> List[Dict]:
        return analyze_code(pattern_matcher, code, 'defi')
    return _analyze
