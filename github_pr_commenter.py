import os
import requests
import json
from typing import Dict, List

class GitHubPRCommenter:
    """Posts security analysis findings as PR comments on GitHub"""
    
    def __init__(self):
        self.github_token = os.getenv('GITHUB_TOKEN')
        self.repo_name = os.getenv('REPO_NAME')
        self.pr_number = os.getenv('PR_NUMBER')
        self.github_api_url = "https://api.github.com"
        
        if not self.github_token:
            raise ValueError("GITHUB_TOKEN environment variable not set")
        if not self.repo_name:
            raise ValueError("REPO_NAME environment variable not set")
        if not self.pr_number:
            raise ValueError("PR_NUMBER environment variable not set")
    
    def post_comment(self, comment_body: str) -> bool:
        """Post a comment on the PR"""
        try:
            url = f"{self.github_api_url}/repos/{self.repo_name}/issues/{self.pr_number}/comments"
            
            headers = {
                "Authorization": f"token {self.github_token}",
                "Accept": "application/vnd.github.v3+json",
                "Content-Type": "application/json"
            }
            
            data = {
                "body": comment_body
            }
            
            response = requests.post(url, json=data, headers=headers, timeout=30)
            
            if response.status_code == 201:
                print(f"✅ Comment posted successfully on PR #{self.pr_number}")
                return True
            else:
                print(f"❌ Failed to post comment: {response.status_code}")
                print(f"Response: {response.text}")
                return False
        
        except Exception as e:
            print(f"❌ Error posting comment: {str(e)}")
            return False
    
    def format_security_report(self, findings: Dict) -> str:
        """Format security findings into a markdown comment"""
        
        web2_issues = findings.get('web2_issues', [])
        web3_issues = findings.get('web3_issues', [])
        severity_summary = findings.get('severity_summary', {})
        recommendation = findings.get('recommendation', '')
        
        # Build the comment
        comment = "## 🔒 Security Analysis Report\n\n"
        
        # Summary section
        comment += "### Summary\n"
        comment += f"- **CRITICAL:** {severity_summary.get('CRITICAL', 0)}\n"
        comment += f"- **HIGH:** {severity_summary.get('HIGH', 0)}\n"
        comment += f"- **MEDIUM:** {severity_summary.get('MEDIUM', 0)}\n"
        comment += f"- **LOW:** {severity_summary.get('LOW', 0)}\n\n"
        
        # Recommendation
        comment += f"### Recommendation\n{recommendation}\n\n"
        
        # Web2 Issues
        if web2_issues:
            comment += "### 🌐 Web2 Vulnerabilities\n"
            for issue in web2_issues:
                severity_emoji = self._get_severity_emoji(issue.get('severity'))
                comment += f"\n**{severity_emoji} {issue.get('type')}** [{issue.get('severity')}]\n"
                comment += f"- Description: {issue.get('description')}\n"
                comment += f"- Recommendation: {issue.get('recommendation')}\n"
            comment += "\n"
        
        # Web3 Issues
        if web3_issues:
            comment += "### ⛓️ Web3 Vulnerabilities\n"
            for issue in web3_issues:
                severity_emoji = self._get_severity_emoji(issue.get('severity'))
                comment += f"\n**{severity_emoji} {issue.get('type')}** [{issue.get('severity')}]\n"
                comment += f"- Description: {issue.get('description')}\n"
                comment += f"- Recommendation: {issue.get('recommendation')}\n"
            comment += "\n"
        
        # No issues
        if not web2_issues and not web3_issues:
            comment += "### ✅ Status\nNo security vulnerabilities detected!\n\n"
        
        # Footer
        comment += "---\n"
        comment += "*Security analysis powered by AI Security Agent* 🤖\n"
        
        return comment
    
    def _get_severity_emoji(self, severity: str) -> str:
        """Get emoji for severity level"""
        emojis = {
            'CRITICAL': '🚨',
            'HIGH': '⚠️',
            'MEDIUM': '⚡',
            'LOW': 'ℹ️'
        }
        return emojis.get(severity, 'ℹ️')
    
    def post_security_findings(self, findings: Dict) -> bool:
        """Format and post security findings as a PR comment"""
        comment_body = self.format_security_report(findings)
        return self.post_comment(comment_body)
    
    def request_changes(self, reason: str = "Security vulnerabilities detected") -> bool:
        """Request changes on the PR (requires write permissions)"""
        try:
            url = f"{self.github_api_url}/repos/{self.repo_name}/pulls/{self.pr_number}/reviews"
            
            headers = {
                "Authorization": f"token {self.github_token}",
                "Accept": "application/vnd.github.v3+json",
                "Content-Type": "application/json"
            }
            
            data = {
                "body": reason,
                "event": "REQUEST_CHANGES"
            }
            
            response = requests.post(url, json=data, headers=headers, timeout=30)
            
            if response.status_code == 200:
                print(f"✅ Changes requested on PR #{self.pr_number}")
                return True
            else:
                print(f"⚠️ Could not request changes: {response.status_code}")
                return False
        
        except Exception as e:
            print(f"⚠️ Error requesting changes: {str(e)}")
            return False
    
    def approve_pr(self, reason: str = "Security analysis passed") -> bool:
        """Approve the PR if security checks pass"""
        try:
            url = f"{self.github_api_url}/repos/{self.repo_name}/pulls/{self.pr_number}/reviews"
            
            headers = {
                "Authorization": f"token {self.github_token}",
                "Accept": "application/vnd.github.v3+json",
                "Content-Type": "application/json"
            }
            
            data = {
                "body": reason,
                "event": "APPROVE"
            }
            
            response = requests.post(url, json=data, headers=headers, timeout=30)
            
            if response.status_code == 200:
                print(f"✅ PR #{self.pr_number} approved by security bot")
                return True
            else:
                print(f"⚠️ Could not approve PR: {response.status_code}")
                return False
        
        except Exception as e:
            print(f"⚠️ Error approving PR: {str(e)}")
            return False