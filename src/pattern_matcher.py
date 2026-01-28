import json
import re
from typing import Dict, List

class PatternMatcher:
    """Matches code patterns against vulnerability rules with advanced filtering"""
    
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
            if self._matches_with_context(content, rule):
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
                    'line': line_num,
                    'filepath': filepath
                })
        
        return vulnerabilities
    
    def _matches_with_context(self, content: str, rule: Dict) -> bool:
        """Enhanced pattern matching with context awareness
        
        Args:
            content: File contents
            rule: Vulnerability rule dictionary
        
        Returns:
            True if pattern matches and passes all filters
        """
        patterns = rule.get('patterns', [])
        exclude_patterns = rule.get('exclude_patterns', [])
        required_context = rule.get('required_context', [])
        context_window = rule.get('context_window', 5)
        
        # Step 1: Check if any pattern matches
        matched_lines = set()  # Use set to avoid duplicates
        for pattern in patterns:
            if pattern.startswith('regex:'):
                # Regex pattern
                regex_pattern = pattern[6:]  # Remove 'regex:' prefix
                try:
                    if re.search(regex_pattern, content):
                        matched_lines.update(self._find_regex_lines(content, regex_pattern))
                except re.error:
                    # Invalid regex pattern, skip it
                    continue
            else:
                # Literal string pattern
                if pattern in content:
                    matched_lines.update(self._find_pattern_lines(content, pattern))
        
        if not matched_lines:
            return False
        
        # Step 2: Check exclude patterns
        if exclude_patterns:
            for line_num in matched_lines:
                context = self._extract_context(content, line_num, context_window)
                
                # If any exclude pattern is in context, skip this match (case-insensitive)
                if any(excl.lower() in context.lower() for excl in exclude_patterns):
                    continue
                
                # Step 3: Check required context (if specified)
                if required_context:
                    if not any(ctx.lower() in context.lower() for ctx in required_context):
                        continue
                
                # This match passed all filters
                return True
            
            # All matches were filtered out
            return False
        
        # Step 3: Check required context (no exclude patterns)
        if required_context:
            for line_num in matched_lines:
                context = self._extract_context(content, line_num, context_window)
                if any(ctx.lower() in context.lower() for ctx in required_context):
                    return True
            return False
        
        # Pattern matched and no filters applied
        return True
    
    def _extract_context(self, content: str, line_num: int, window_size: int) -> str:
        """Extract context window around a line
        
        Args:
            content: File contents
            line_num: Line number (1-indexed)
            window_size: Number of lines to include before and after
        
        Returns:
            String containing the context window
        """
        lines = content.split('\n')
        start = max(0, line_num - window_size - 1)
        end = min(len(lines), line_num + window_size)
        return '\n'.join(lines[start:end])
    
    def _find_pattern_lines(self, content: str, pattern: str) -> List[int]:
        """Find all line numbers where pattern appears
        
        Args:
            content: File contents
            pattern: Literal string pattern to find
        
        Returns:
            List of line numbers (1-indexed)
        """
        lines = content.split('\n')
        return [i + 1 for i, line in enumerate(lines) if pattern in line]
    
    def _find_regex_lines(self, content: str, regex_pattern: str) -> List[int]:
        """Find all line numbers where regex matches
        
        Args:
            content: File contents
            regex_pattern: Regular expression pattern
        
        Returns:
            List of line numbers (1-indexed)
        """
        lines = content.split('\n')
        line_nums = []
        try:
            for i, line in enumerate(lines):
                if re.search(regex_pattern, line):
                    line_nums.append(i + 1)
        except re.error:
            # Invalid regex pattern, return empty list
            pass
        return line_nums
    
    @staticmethod
    def _matches(content: str, patterns: List[str]) -> bool:
        """Check if any pattern exists in content (legacy method for backward compatibility)
        
        Uses simple substring matching for precision
        (avoids false positives from complex regex)
        """
        for pattern in patterns:
            if pattern in content:
                return True
        return False
    
    @staticmethod
    def _find_line(content: str, patterns: List[str]) -> int:
        """Find line number where first pattern appears
        
        Args:
            content: File contents
            patterns: List of patterns (strings or regex patterns)
        
        Returns:
            Line number (1-indexed) where first pattern appears
        """
        lines = content.split('\n')
        
        for pattern in patterns:
            # Handle regex patterns
            if pattern.startswith('regex:'):
                regex_pattern = pattern[6:]
                try:
                    for line_num, line in enumerate(lines, 1):
                        if re.search(regex_pattern, line):
                            return line_num
                except re.error:
                    # Invalid regex pattern, skip it
                    continue
            else:
                # Literal pattern
                for line_num, line in enumerate(lines, 1):
                    if pattern in line:
                        return line_num
        
        return 1