"""
Confidence scoring for vulnerability findings
Calculates likelihood that a finding is a true positive
"""

class ConfidenceScorer:
    """Calculate confidence scores for vulnerability findings"""
    
    # Confidence thresholds
    CONFIDENCE_HIGH = 0.75
    CONFIDENCE_MEDIUM = 0.50
    CONFIDENCE_LOW = 0.25
    
    @staticmethod
    def calculate_confidence(vuln: dict, content: str, context_window: str = None) -> dict:
        """Calculate confidence score for a vulnerability finding
        
        Args:
            vuln: Vulnerability dict from pattern matcher
            content: Full file content
            context_window: Context around the finding (optional)
        
        Returns:
            Updated vuln dict with confidence and confidence_label
        """
        confidence = 1.0  # Start with maximum confidence
        
        # Extract context if not provided
        if context_window is None:
            context_window = ConfidenceScorer._extract_context(content, vuln.get('line', 1))
        
        # Factor 1: Check if in comment
        if ConfidenceScorer._is_in_comment(context_window):
            confidence *= 0.1  # Very low confidence for comments
        
        # Factor 2: Check if in documentation
        if ConfidenceScorer._is_in_documentation(context_window):
            confidence *= 0.2
        
        # Factor 3: Check if in test file
        if ConfidenceScorer._is_in_test_file(vuln.get('filepath', '')):
            confidence *= 0.5  # Lower confidence for test files
        
        # Factor 4: Check severity (critical issues need less context)
        if vuln.get('severity') == 'CRITICAL':
            confidence *= 1.2  # Boost critical findings
        elif vuln.get('severity') == 'LOW':
            confidence *= 0.8  # Reduce low severity confidence
        
        # Factor 5: Check if in state-changing function
        if ConfidenceScorer._is_in_state_changing_function(context_window):
            confidence *= 1.3  # Boost if in risky function
        
        # Factor 6: Check for security keywords nearby
        security_keywords = ['owner', 'admin', 'auth', 'require', 'modifier', 
                           'onlyOwner', 'onlyAdmin', 'access', 'permission']
        if any(keyword in context_window.lower() for keyword in security_keywords):
            confidence *= 1.1  # Slight boost for security context
        
        # Factor 7: Check for mitigation patterns
        mitigation_patterns = ['ReentrancyGuard', 'nonReentrant', 'Ownable', 
                              'AccessControl', 'SafeMath', 'checked']
        if any(pattern in context_window for pattern in mitigation_patterns):
            confidence *= 0.7  # Lower confidence if mitigations present
        
        # Normalize confidence to [0, 1]
        confidence = max(0.0, min(1.0, confidence))
        
        # Add confidence label
        if confidence >= ConfidenceScorer.CONFIDENCE_HIGH:
            confidence_label = 'HIGH'
        elif confidence >= ConfidenceScorer.CONFIDENCE_MEDIUM:
            confidence_label = 'MEDIUM'
        else:
            confidence_label = 'LOW'
        
        # Update vulnerability dict
        vuln['confidence'] = round(confidence, 2)
        vuln['confidence_label'] = confidence_label
        
        return vuln
    
    @staticmethod
    def _extract_context(content: str, line_num: int, window_size: int = 10) -> str:
        """Extract context window around a line number"""
        lines = content.split('\n')
        start = max(0, line_num - window_size - 1)
        end = min(len(lines), line_num + window_size)
        return '\n'.join(lines[start:end])
    
    @staticmethod
    def _is_in_comment(context: str) -> bool:
        """Check if finding is in a comment"""
        # Check for single-line comments
        if '//' in context or '#' in context:
            return True
        
        # Check for multi-line comments
        if '/*' in context or '"""' in context or "'''" in context:
            return True
        
        return False
    
    @staticmethod
    def _is_in_documentation(context: str) -> bool:
        """Check if finding is in documentation"""
        doc_markers = ['@dev', '@notice', '@param', '@return', '/**', 'docstring']
        return any(marker in context.lower() for marker in doc_markers)
    
    @staticmethod
    def _is_in_test_file(filepath: str) -> bool:
        """Check if file is a test file"""
        test_indicators = ['test', 'spec', 'mock', '__tests__', '.test.', '.spec.']
        return any(indicator in filepath.lower() for indicator in test_indicators)
    
    @staticmethod
    def _is_in_state_changing_function(context: str) -> bool:
        """Check if finding is in a state-changing function"""
        state_changing_keywords = [
            'withdraw', 'deposit', 'transfer', 'mint', 'burn', 
            'approve', 'setOwner', 'updateBalance', 'delete', 'insert'
        ]
        return any(keyword in context.lower() for keyword in state_changing_keywords)
