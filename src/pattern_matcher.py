import json
from typing import Dict, List

class PatternMatcher:
    """Matches code patterns against vulnerability rules"""
    
    def __init__(self, rules_file: str):
        """Load vulnerability rules from JSON file"""
        with open(rules_file, 'r') as f:
            self.rules = json.load(f)
    
    def find_vulnerabilities(self, filepath: str, content: str, chain: str) -> List[Dict]:
        """Find all vulnerabilities in code for given chain
        
        Args:
            filepath: Path to file being analyzed
            content: File contents
            chain: Blockchain/platform ('ethereum', 'solana', 'web2', etc)
        
        Returns:
            List of found vulnerabilities with details
        """
        vulnerabilities = []
        
        # Get rules for this chain
        if chain not in self.rules:
            return vulnerabilities
        
        chain_rules = self.rules[chain]
        
        # Check each vulnerability rule
        for vuln_id, rule in chain_rules.items():
            if self._matches(content, rule.get('patterns', [])):
                # Find the line number where it appears
                line_num = self._find_line(content, rule.get('patterns', []))
                
                vulnerabilities.append({
                    'id': vuln_id,
                    'name': rule.get('name', vuln_id),
                    'severity': rule.get('severity', 'MEDIUM'),
                    'description': rule.get('description', ''),
                    'remediation': rule.get('remediation', ''),
                    'examples': rule.get('examples', []),
                    'references': rule.get('references', []),
                    'line': line_num
                })
        
        return vulnerabilities
    
    @staticmethod
    def _matches(content: str, patterns: List[str]) -> bool:
        """Check if any pattern exists in content
        
        Uses simple substring matching for precision
        (avoids false positives from complex regex)
        """
        for pattern in patterns:
            if pattern in content:
                return True
        return False
    
    @staticmethod
    def _find_line(content: str, patterns: List[str]) -> int:
        """Find line number where first pattern appears"""
        lines = content.split('\n')
        
        for pattern in patterns:
            for line_num, line in enumerate(lines, 1):
                if pattern in line:
                    return line_num
        
        return 1