import re
from typing import List

class SecurityRules:
    """Security vulnerability detection rules"""
    
    # Web2 vulnerability patterns
    SQL_INJECTION_PATTERNS = [
        r"execute\s*\(\s*['\"].*\+",
        r"query\s*\(\s*['\"].*\+",
        r"f['\"].*SELECT.*WHERE.*\{",
    ]
    
    XSS_PATTERNS = [
        r"innerHTML\s*=",
        r"\.html\s*\(",
        r"dangerouslySetInnerHTML",
    ]
    
    CSRF_PATTERNS = [
        r"POST|PUT|DELETE(?!.*csrf|!.*token)",
    ]
    
    # Web3 vulnerability patterns
    REENTRANCY_PATTERNS = [
        r"\.transfer\s*\(",
        r"\.call\s*\{.*value.*\}",
    ]
    
    OVERFLOW_PATTERNS = [
        r"\+\s*\w+|solidity\s*\<\s*0\.8",
    ]
    
    UNCHECKED_CALL_PATTERNS = [
        r"\.call\s*\(\s*\)(?!\s*require)",
    ]
    
    def _check_patterns(self, content: str, patterns: List[str]) -> bool:
        """Check if content matches any patterns"""
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False
    
    def has_sql_injection_risk(self, content: str) -> bool:
        return self._check_patterns(content, self.SQL_INJECTION_PATTERNS)
    
    def has_xss_risk(self, content: str) -> bool:
        return self._check_patterns(content, self.XSS_PATTERNS)
    
    def has_csrf_risk(self, content: str) -> bool:
        return self._check_patterns(content, self.CSRF_PATTERNS)
    
    def has_reentrancy_risk(self, content: str) -> bool:
        return self._check_patterns(content, self.REENTRANCY_PATTERNS)
    
    def has_overflow_risk(self, content: str) -> bool:
        return self._check_patterns(content, self.OVERFLOW_PATTERNS)
    
    def has_unchecked_calls(self, content: str) -> bool:
        return self._check_patterns(content, self.UNCHECKED_CALL_PATTERNS)