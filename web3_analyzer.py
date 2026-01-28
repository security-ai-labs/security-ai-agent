from typing import Dict, List, Tuple
from security_rules import SecurityRules

class Web3Analyzer:
    """
    Comprehensive Web3 security analyzer with file and line tracking
    Analyzes all vulnerability types across chains and code styles
    """
    
    def __init__(self):
        self.rules = SecurityRules()
    
    def analyze_code(self, code: str, file_name: str = "code") -> Dict:
        """Comprehensive code analysis with file name tracking"""
        findings, chain, code_type = self.rules.run_all_checks(code)
        summary = self.rules.get_findings_summary(findings)
        
        return {
            'file_name': file_name,
            'detected_chain': chain,
            'detected_code_type': code_type,
            'total_vulnerabilities': summary['total'],
            'by_severity': summary['by_severity'],
            'by_category': summary['by_category'],
            'findings': self._format_findings(findings),
            'risk_score': self._calculate_risk_score(summary),
            'recommendations': self._generate_recommendations(findings),
        }
    
    def _format_findings(self, findings: List[Dict]) -> List[Dict]:
        """Format findings for output"""
        formatted = []
        for finding in findings:
            severity = finding.get('severity')
            if hasattr(severity, 'value'):
                severity_str = severity.value
            else:
                severity_str = str(severity)
            
            category = finding.get('category')
            if hasattr(category, 'value'):
                category_str = category.value
            else:
                category_str = str(category)
            
            formatted.append({
                'name': finding.get('name'),
                'type': finding.get('type'),
                'severity': severity_str,
                'category': category_str,
                'description': finding.get('description'),
                'remediation': finding.get('remediation'),
            })
        
        return formatted
    
    def _calculate_risk_score(self, summary: Dict) -> float:
        """Calculate overall risk score (0-100)"""
        critical = summary['by_severity'].get('CRITICAL', 0)
        high = summary['by_severity'].get('HIGH', 0)
        medium = summary['by_severity'].get('MEDIUM', 0)
        
        score = (critical * 25) + (high * 10) + (medium * 5)
        return min(score, 100.0)
    
    def _generate_recommendations(self, findings: List[Dict]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        remediation_set = set()
        
        for finding in findings:
            remediation = finding.get('remediation')
            if remediation and remediation not in remediation_set:
                remediation_set.add(remediation)
                recommendations.append(remediation)
        
        return recommendations
    
    def analyze_for_code_generation_issues(self, code: str) -> Dict:
        """Specifically check for code generation and AI-related issues"""
        findings, _, _ = self.rules.run_all_checks(code)
        
        code_gen_issues = [f for f in findings if 'code_generation' in str(f.get('category'))]
        
        return {
            'ai_generated_code_detected': len(code_gen_issues) > 0,
            'issues': code_gen_issues,
            'recommendations': [
                'Always manually review AI-generated code',
                'Implement comprehensive test coverage',
                'Use static analysis and linting tools',
                'Conduct security audit before deployment',
            ]
        }