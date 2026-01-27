import os
import json
from typing import Dict, List
from github_pr_commenter import GitHubPRCommenter
from web3_analyzer import Web3Analyzer

class SecurityAIAgent:
    """
    Comprehensive security AI Agent
    Analyzes Web2, Web3, and hybrid code for ALL possible vulnerabilities
    Supports: Ethereum, Solana, Polygon, DeFi, NFTs, Cross-Chain, Code Generation Issues
    """
    
    def __init__(self):
        self.findings = []
        self.pr_commenter = None
        self.analyzer = Web3Analyzer()
        
        if os.getenv('GITHUB_TOKEN') and os.getenv('PR_NUMBER'):
            try:
                self.pr_commenter = GitHubPRCommenter()
            except ValueError as e:
                print(f"⚠️ PR commenter disabled: {e}")
    
    def analyze_pr(self, pr_files: List[str], pr_content: str) -> Dict:
        """Comprehensive PR analysis"""
        
        # Run comprehensive analysis
        analysis_result = self.analyzer.analyze_code(pr_content)
        
        # Format report
        report = {
            "detected_chain": analysis_result['detected_chain'],
            "detected_code_type": analysis_result['detected_code_type'],
            "total_vulnerabilities": analysis_result['total_vulnerabilities'],
            "risk_score": analysis_result['risk_score'],
            "severity_summary": analysis_result['by_severity'],
            "category_summary": analysis_result['by_category'],
            "findings": analysis_result['findings'],
            "recommendations": analysis_result['recommendations'],
            "overall_recommendation": self._generate_overall_recommendation(analysis_result),
        }
        
        return report
    
    def _generate_overall_recommendation(self, analysis: Dict) -> str:
        """Generate overall recommendation based on analysis"""
        risk_score = analysis['risk_score']
        critical_count = analysis['by_severity'].get('CRITICAL', 0)
        
        if critical_count > 0:
            return "🚨 **DO NOT MERGE** - Critical vulnerabilities must be fixed before deployment"
        elif risk_score > 70:
            return "⚠️ **SECURITY AUDIT REQUIRED** - High-risk code needs expert review"
        elif risk_score > 40:
            return "⚡ **ISSUES FOUND** - Address medium/high severity vulnerabilities"
        elif analysis['total_vulnerabilities'] > 0:
            return "ℹ️ **MINOR ISSUES** - Low severity findings to review"
        else:
            return "✅ **NO ISSUES** - Code appears secure"
    
    def post_findings_to_pr(self, findings: Dict) -> bool:
        """Post comprehensive findings to PR"""
        if not self.pr_commenter:
            return False
        
        comment = self._format_comprehensive_comment(findings)
        return self.pr_commenter.post_comment(comment)
    
    def _format_comprehensive_comment(self, findings: Dict) -> str:
        """Format findings into detailed markdown comment"""
        
        comment = f"""## 🔍 Comprehensive Security Analysis

### 📊 Overview
- **Detected Chain:** {findings['detected_chain']}
- **Code Type:** {findings['detected_code_type']}
- **Risk Score:** {findings['risk_score']:.1f}/100
- **Total Vulnerabilities:** {findings['total_vulnerabilities']}

### 📈 Severity Breakdown
"""
        
        for severity, count in findings['severity_summary'].items():
            emoji = {'CRITICAL': '🚨', 'HIGH': '⚠️', 'MEDIUM': '⚡', 'LOW': 'ℹ️', 'INFO': '💡'}.get(severity, '•')
            comment += f"- {emoji} **{severity}:** {count}\n"
        
        comment += "\n### 🏷️ Category Breakdown\n"
        for category, count in sorted(findings['category_summary'].items(), key=lambda x: x[1], reverse=True):
            comment += f"- {category}: {count}\n"
        
        comment += "\n### 🔴 Detailed Findings\n"
        
        if findings['findings']:
            for finding in findings['findings']:
                emoji = {'CRITICAL': '🚨', 'HIGH': '⚠️', 'MEDIUM': '⚡', 'LOW': 'ℹ️', 'INFO': '💡'}.get(finding['severity'], '•')
                comment += f"\n{emoji} **{finding['type']}** [{finding['severity']}]\n"
                comment += f"- **Category:** {finding['category']}\n"
                comment += f"- **Description:** {finding['description']}\n"
                comment += f"- **Remediation:** {finding['remediation']}\n"
        else:
            comment += "\n✅ No vulnerabilities detected!\n"
        
        comment += f"\n### 💡 Recommendations\n"
        if findings['recommendations']:
            for i, rec in enumerate(findings['recommendations'], 1):
                comment += f"{i}. {rec}\n"
        
        comment += f"\n### 📋 Overall Assessment\n{findings['overall_recommendation']}\n\n"
        comment += "---\n*Powered by Comprehensive Web3 Security Agent* 🛡️\n"
        
        return comment
    
    def handle_findings(self, findings: Dict) -> None:
        """Handle findings and take actions"""
        self.post_findings_to_pr(findings)
        
        if findings['risk_score'] >= 70:
            if self.pr_commenter:
                self.pr_commenter.request_changes(
                    "🚨 High-risk code detected - changes required"
                )
        elif findings['total_vulnerabilities'] == 0:
            if self.pr_commenter:
                self.pr_commenter.approve_pr(
                    "✅ No security issues found"
                )

def main():
    """Main entry point"""
    agent = SecurityAIAgent()
    
    # Test code
    test_code = """
    pragma solidity ^0.7.0;
    
    contract Test {
        mapping(address => uint) balances;
        
        function withdraw(uint amount) public {
            msg.sender.call{value: amount}("");
            balances[msg.sender] -= amount;
        }
    }
    """
    
    findings = agent.analyze_pr([], test_code)
    agent.handle_findings(findings)
    
    print("\n" + "="*80)
    print("COMPREHENSIVE SECURITY ANALYSIS REPORT")
    print("="*80)
    print(json.dumps(findings, indent=2, default=str))
    print("="*80)

if __name__ == "__main__":
    main()