import os
import json
from typing import Dict, List

class SecurityAIAgent:
    """
    AI Agent for analyzing PRs for security vulnerabilities in Web2 and Web3
    """
    
    def __init__(self):
        self.findings = []
        
    def analyze_pr(self, pr_files: List[str], pr_content: str) -> Dict:
        """
        Analyze PR for security vulnerabilities
        """
        web2_issues = self.check_web2_vulnerabilities(pr_files, pr_content)
        web3_issues = self.check_web3_vulnerabilities(pr_files, pr_content)
        
        report = {
            "web2_issues": web2_issues,
            "web3_issues": web3_issues,
            "severity_summary": self.get_severity_summary(web2_issues + web3_issues),
            "recommendation": self.generate_recommendation(web2_issues + web3_issues)
        }
        
        return report
    
    def check_web2_vulnerabilities(self, files: List[str], content: str) -> List[Dict]:
        """Check for Web2 security vulnerabilities"""
        issues = []
        
        if "execute" in content and "+" in content:
            issues.append({
                "type": "SQL Injection",
                "severity": "HIGH",
                "description": "Potential SQL injection vulnerability detected",
                "recommendation": "Use parameterized queries"
            })
        
        if "innerHTML" in content or "dangerouslySetInnerHTML" in content:
            issues.append({
                "type": "Cross-Site Scripting (XSS)",
                "severity": "HIGH",
                "description": "Potential XSS vulnerability detected",
                "recommendation": "Sanitize and encode inputs"
            })
        
        return issues
    
    def check_web3_vulnerabilities(self, files: List[str], content: str) -> List[Dict]:
        """Check for Web3 security vulnerabilities"""
        issues = []
        
        if ".transfer(" in content or ".call{" in content:
            issues.append({
                "type": "Reentrancy Attack",
                "severity": "CRITICAL",
                "description": "Potential reentrancy vulnerability",
                "recommendation": "Use checks-effects-interactions pattern"
            })
        
        if "pragma solidity" in content and "0.8" not in content:
            issues.append({
                "type": "Integer Overflow/Underflow",
                "severity": "HIGH",
                "description": "Potential overflow/underflow detected",
                "recommendation": "Use Solidity 0.8+ or SafeMath"
            })
        
        return issues
    
    def get_severity_summary(self, issues: List[Dict]) -> Dict:
        """Generate severity summary"""
        summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for issue in issues:
            severity = issue.get("severity", "LOW")
            summary[severity] += 1
        return summary
    
    def generate_recommendation(self, issues: List[Dict]) -> str:
        """Generate overall recommendation"""
        if not issues:
            return "✅ No security issues detected. PR appears safe to merge."
        
        critical = sum(1 for i in issues if i.get("severity") == "CRITICAL")
        high = sum(1 for i in issues if i.get("severity") == "HIGH")
        
        if critical > 0:
            return "🚨 CRITICAL issues found. DO NOT merge until resolved."
        elif high > 0:
            return "⚠️ HIGH severity issues found. Review before merging."
        else:
            return "ℹ️ Minor issues found. Review recommendations before merging."

if __name__ == "__main__":
    agent = SecurityAIAgent()
    print("Security AI Agent initialized successfully!")