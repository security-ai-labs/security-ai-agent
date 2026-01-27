import os
import json
from typing import Dict, List
from github_pr_commenter import GitHubPRCommenter

class SecurityAIAgent:
    """
    AI Agent for analyzing PRs for security vulnerabilities in Web2 and Web3
    """
    
    def __init__(self):
        self.findings = []
        self.pr_commenter = None
        
        # Initialize PR commenter if running in GitHub Actions
        if os.getenv('GITHUB_TOKEN') and os.getenv('PR_NUMBER'):
            try:
                self.pr_commenter = GitHubPRCommenter()
            except ValueError as e:
                print(f"⚠️ PR commenter disabled: {e}")
    
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
        
        # SQL Injection detection
        if "execute" in content and "+" in content:
            issues.append({
                "type": "SQL Injection",
                "severity": "HIGH",
                "description": "Potential SQL injection vulnerability detected - user input concatenated to SQL query",
                "recommendation": "Use parameterized queries and prepared statements instead of string concatenation"
            })
        
        # XSS detection
        if "innerHTML" in content or "dangerouslySetInnerHTML" in content:
            issues.append({
                "type": "Cross-Site Scripting (XSS)",
                "severity": "HIGH",
                "description": "Potential XSS vulnerability detected - innerHTML or dangerouslySetInnerHTML usage",
                "recommendation": "Sanitize and encode all user inputs before rendering. Use textContent instead of innerHTML"
            })
        
        # CSRF detection
        if "POST" in content or "PUT" in content:
            if "csrf" not in content.lower() and "token" not in content.lower():
                issues.append({
                    "type": "Missing CSRF Protection",
                    "severity": "MEDIUM",
                    "description": "Potential CSRF vulnerability - state-changing request without CSRF token",
                    "recommendation": "Implement CSRF tokens for all POST/PUT/DELETE requests"
                })
        
        return issues
    
    def check_web3_vulnerabilities(self, files: List[str], content: str) -> List[Dict]:
        """Check for Web3 security vulnerabilities"""
        issues = []
        
        # Reentrancy detection
        if ".transfer(" in content or ".call{" in content:
            issues.append({
                "type": "Reentrancy Attack",
                "severity": "CRITICAL",
                "description": "Potential reentrancy vulnerability in smart contract - external call before state update",
                "recommendation": "Use checks-effects-interactions pattern or ReentrancyGuard from OpenZeppelin"
            })
        
        # Integer overflow detection
        if "pragma solidity" in content and "0.8" not in content:
            issues.append({
                "type": "Integer Overflow/Underflow",
                "severity": "HIGH",
                "description": "Potential integer overflow/underflow detected - using Solidity < 0.8",
                "recommendation": "Use SafeMath library or upgrade to Solidity 0.8+ with automatic overflow checks"
            })
        
        # Unchecked external calls
        if ".call(" in content and "require(" not in content:
            issues.append({
                "type": "Unchecked Low-Level Call",
                "severity": "HIGH",
                "description": "Low-level call without proper error handling",
                "recommendation": "Check return value of call() or use high-level functions with require()"
            })
        
        # Front-running vulnerability
        if "tx.gasprice" in content or "block.timestamp" in content:
            issues.append({
                "type": "Potential Front-Running Vulnerability",
                "severity": "MEDIUM",
                "description": "Use of blockchain-dependent variables that can be manipulated",
                "recommendation": "Avoid relying on tx.gasprice or block.timestamp for critical logic"
            })
        
        return issues
    
    def get_severity_summary(self, issues: List[Dict]) -> Dict:
        """Generate severity summary"""
        summary = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }
        
        for issue in issues:
            severity = issue.get("severity", "LOW")
            summary[severity] += 1
        
        return summary
    
    def generate_recommendation(self, issues: List[Dict]) -> str:
        """Generate overall recommendation based on findings"""
        if not issues:
            return "✅ No security issues detected. PR appears safe to merge."
        
        critical = sum(1 for i in issues if i.get("severity") == "CRITICAL")
        high = sum(1 for i in issues if i.get("severity") == "HIGH")
        
        if critical > 0:
            return "🚨 **CRITICAL issues found. DO NOT MERGE** until all critical issues are resolved."
        elif high > 0:
            return "⚠️ **HIGH severity issues found.** Review and address these issues before merging."
        else:
            return "ℹ️ **Minor issues found.** Review the recommendations below before merging."
    
    def post_findings_to_pr(self, findings: Dict) -> bool:
        """Post security findings as a PR comment"""
        if not self.pr_commenter:
            print("⚠️ PR commenter not initialized - skipping PR comment")
            return False
        
        return self.pr_commenter.post_security_findings(findings)
    
    def handle_findings(self, findings: Dict) -> None:
        """Handle security findings (post comment and optionally request changes)"""
        # Post findings as PR comment
        self.post_findings_to_pr(findings)
        
        # Request changes if critical issues found
        severity_summary = findings.get('severity_summary', {})
        if severity_summary.get('CRITICAL', 0) > 0:
            if self.pr_commenter:
                self.pr_commenter.request_changes(
                    reason="🚨 Critical security vulnerabilities detected - changes requested for resolution"
                )
        
        # Approve if no issues found
        elif not findings.get('web2_issues') and not findings.get('web3_issues'):
            if self.pr_commenter:
                self.pr_commenter.approve_pr(
                    reason="✅ Security analysis passed - no vulnerabilities detected"
                )

def main():
    """Main entry point"""
    agent = SecurityAIAgent()
    
    # Sample PR content for testing
    test_pr_content = """
    def query_user(user_id):
        query = "SELECT * FROM users WHERE id = " + str(user_id)
        return execute(query)
    """
    
    # Analyze
    findings = agent.analyze_pr([], test_pr_content)
    
    # Post findings
    agent.handle_findings(findings)
    
    # Print report
    print("\n" + "="*60)
    print("SECURITY ANALYSIS REPORT")
    print("="*60)
    print(json.dumps(findings, indent=2))
    print("="*60)

if __name__ == "__main__":
    main()