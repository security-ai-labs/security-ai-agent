import os
import json
from typing import Dict, List
from github_pr_commenter import GitHubPRCommenter
from web3_analyzer import Web3Analyzer
from security_rules import SecurityRules

class SecurityAIAgent:
    """
    AI Agent for analyzing PRs for security vulnerabilities in Web2 and Web3
    Supports: Ethereum, Solana, Polygon, DeFi, NFTs
    """
    
    def __init__(self):
        self.findings = []
        self.pr_commenter = None
        self.web3_analyzer = Web3Analyzer()
        self.security_rules = SecurityRules()
        
        # Initialize PR commenter if running in GitHub Actions
        if os.getenv('GITHUB_TOKEN') and os.getenv('PR_NUMBER'):
            try:
                self.pr_commenter = GitHubPRCommenter()
            except ValueError as e:
                print(f"⚠️ PR commenter disabled: {e}")
    
    def analyze_pr(self, pr_files: List[str], pr_content: str) -> Dict:
        """
        Analyze PR for security vulnerabilities using enhanced rules
        """
        # Auto-detect chain type
        chain_type = self.security_rules.detect_chain_type(pr_content)
        
        # Run appropriate analyzer
        if "solidity" in pr_content.lower() or "pragma" in pr_content.lower():
            web3_findings = self.web3_analyzer.analyze_ethereum_contract(pr_content)
        elif "solana" in pr_content.lower() or "anchor" in pr_content.lower():
            web3_findings = self.web3_analyzer.analyze_solana_program(pr_content)
        else:
            web3_findings = self.web3_analyzer.auto_detect_and_analyze(pr_content)
        
        # Run all checks
        all_vulnerabilities = self.security_rules.run_all_checks(pr_content)
        
        # Categorize findings
        web2_issues = [v for v in all_vulnerabilities if v['type'] in [
            'SQL Injection',
            'Cross-Site Scripting (XSS)',
            'Missing CSRF Protection',
            'Insecure Deserialization',
            'Hardcoded Secrets',
            'Broken Authentication',
        ]]
        
        web3_issues = [v for v in all_vulnerabilities if v['type'] in [
            'Reentrancy Attack',
            'Integer Overflow/Underflow',
            'Unchecked Low-Level Call',
            'Delegatecall Injection',
            'Timestamp Dependency',
            'Front-Running Vulnerability',
            'Missing Zero Address Check',
            'Missing Access Control',
            'Flash Loan Attack',
            'Missing Signer Check (Solana)',
            'Missing Owner Check (Solana)',
            'Missing Account Validation (Solana)',
            'Unchecked Arithmetic (Solana)',
            'Price Oracle Manipulation',
            'Missing Slippage Protection',
            'Arbitrary Token Transfer',
            'NFT Reentrancy (Minting)',
            'Unauthorized NFT Burn',
            'Centralized Metadata',
        ]]
        
        report = {
            "chain_detected": chain_type.value,
            "web2_issues": self._format_issues(web2_issues),
            "web3_issues": self._format_issues(web3_issues),
            "severity_summary": self.get_severity_summary(web2_issues + web3_issues),
            "recommendation": self.generate_recommendation(web2_issues + web3_issues),
            "remediation_guidance": self._get_remediation_for_all(all_vulnerabilities),
        }
        
        return report
    
    def _format_issues(self, issues: List[Dict]) -> List[Dict]:
        """Format issues with severity and recommendations"""
        formatted = []
        for issue in issues:
            formatted.append({
                "type": issue.get('type'),
                "severity": issue.get('severity').value if hasattr(issue.get('severity'), 'value') else issue.get('severity'),
                "description": issue.get('description'),
                "recommendation": self.web3_analyzer.get_remediation_guidance(issue)
            })
        return formatted
    
    def _get_remediation_for_all(self, issues: List[Dict]) -> List[Dict]:
        """Get remediation guidance for all issues"""
        return [
            {
                "type": issue.get('type'),
                "guidance": self.web3_analyzer.get_remediation_guidance(issue)
            }
            for issue in issues
        ]
    
    def get_severity_summary(self, issues: List[Dict]) -> Dict:
        """Generate severity summary"""
        summary = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }
        
        for issue in issues:
            severity = issue.get('severity')
            if hasattr(severity, 'value'):
                severity = severity.value
            summary[severity] = summary.get(severity, 0) + 1
        
        return summary
    
    def generate_recommendation(self, issues: List[Dict]) -> str:
        """Generate overall recommendation based on findings"""
        if not issues:
            return "✅ No security issues detected. PR appears safe to merge."
        
        critical = sum(1 for i in issues if (i.get('severity').value if hasattr(i.get('severity'), 'value') else i.get('severity')) == "CRITICAL")
        high = sum(1 for i in issues if (i.get('severity').value if hasattr(i.get('severity'), 'value') else i.get('severity')) == "HIGH")
        
        if critical > 0:
            return "🚨 **CRITICAL issues found. DO NOT MERGE** until all critical issues are resolved. This code poses significant security risks."
        elif high > 0:
            return "⚠️ **HIGH severity issues found.** Review and address these issues before merging. Consider security audit."
        else:
            return "ℹ️ **Minor issues found.** Review the recommendations below before merging."
    
    def post_findings_to_pr(self, findings: Dict) -> bool:
        """Post security findings as a PR comment"""
        if not self.pr_commenter:
            print("⚠️ PR commenter not initialized - skipping PR comment")
            return False
        
        # Format the findings for the commenter
        formatted_findings = {
            "web2_issues": findings.get('web2_issues', []),
            "web3_issues": findings.get('web3_issues', []),
            "severity_summary": findings.get('severity_summary', {}),
            "recommendation": findings.get('recommendation', ''),
        }
        
        return self.pr_commenter.post_security_findings(formatted_findings)
    
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
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.7.0;
    
    contract VulnerableContract {
        mapping(address => uint) balances;
        
        function withdraw(uint amount) public {
            msg.sender.call{value: amount}("");
            balances[msg.sender] -= amount;
        }
        
        function transfer(address recipient, uint amount) public {
            require(balances[msg.sender] >= amount);
            balances[msg.sender] -= amount;
            balances[recipient] += amount;
        }
    }
    """
    
    # Analyze
    findings = agent.analyze_pr([], test_pr_content)
    
    # Post findings
    agent.handle_findings(findings)
    
    # Print report
    print("\n" + "="*80)
    print("SECURITY ANALYSIS REPORT - ENHANCED WEB3")
    print("="*80)
    print(json.dumps(findings, indent=2, default=str))
    print("="*80)

if __name__ == "__main__":
    main()