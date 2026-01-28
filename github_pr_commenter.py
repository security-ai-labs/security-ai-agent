import os
import requests
import json
from typing import Dict, List

class GitHubPRCommenter:
    """Posts security analysis findings as PR comments on GitHub with file/line info"""
    
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
    
    def post_review_comment(self, file_path: str, line_number: int, comment_body: str) -> bool:
        """Post a review comment on a specific line of a file"""
        try:
            url = f"{self.github_api_url}/repos/{self.repo_name}/pulls/{self.pr_number}/comments"
            
            headers = {
                "Authorization": f"token {self.github_token}",
                "Accept": "application/vnd.github.v3+json",
                "Content-Type": "application/json"
            }
            
            data = {
                "body": comment_body,
                "commit_id": self._get_head_commit(),
                "path": file_path,
                "line": line_number,
                "side": "RIGHT"
            }
            
            response = requests.post(url, json=data, headers=headers, timeout=30)
            
            if response.status_code == 201:
                print(f"✅ Review comment posted on {file_path}:{line_number}")
                return True
            else:
                print(f"⚠️ Could not post review comment: {response.status_code}")
                return False
        
        except Exception as e:
            print(f"⚠️ Error posting review comment: {str(e)}")
            return False
    
    def _get_head_commit(self) -> str:
        """Get the head commit SHA of the PR"""
        try:
            url = f"{self.github_api_url}/repos/{self.repo_name}/pulls/{self.pr_number}"
            headers = {
                "Authorization": f"token {self.github_token}",
                "Accept": "application/vnd.github.v3+json",
            }
            
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                pr_data = response.json()
                return pr_data['head']['sha']
        except:
            pass
        
        return ""
    
    def format_security_report(self, findings: Dict) -> str:
        """Format security findings into a markdown comment"""
        
        file_name = findings.get('file_name', 'code')
        
        comment = f"""## 🔍 Comprehensive Security Analysis

### 📄 File Information
- **File:** `{file_name}`
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
            # Group findings by line number
            findings_by_line = {}
            for finding in findings['findings']:
                line_num = finding.get('line_number', 'unknown')
                if line_num not in findings_by_line:
                    findings_by_line[line_num] = []
                findings_by_line[line_num].append(finding)
            
            # Sort by line number
            for line_num in sorted(findings_by_line.keys(), key=lambda x: x if isinstance(x, int) else 999):
                findings_list = findings_by_line[line_num]
                comment += f"\n#### 📍 Line {line_num} in `{file_name}`\n"
                
                for finding in findings_list:
                    emoji = {'CRITICAL': '🚨', 'HIGH': '⚠️', 'MEDIUM': '⚡', 'LOW': 'ℹ️', 'INFO': '💡'}.get(finding['severity'], '•')
                    comment += f"\n{emoji} **{finding['type']}** `[{finding['severity']}]`\n"
                    comment += f"- **Category:** `{finding['category']}`\n"
                    comment += f"- **Location:** `{file_name}:{line_num}`\n"
                    comment += f"- **Description:** {finding['description']}\n"
                    comment += f"- **Remediation:** {finding['remediation']}\n"
        else:
            comment += "\n✅ No vulnerabilities detected!\n"
        
        comment += f"\n### 💡 Remediation Summary\n"
        if findings['recommendations']:
            for i, rec in enumerate(findings['recommendations'], 1):
                comment += f"{i}. {rec}\n"
        
        comment += f"\n### 📋 Overall Assessment\n"
        comment += f"{findings['overall_recommendation']}\n\n"
        comment += f"**File:** `{file_name}` | **Issues:** {findings['total_vulnerabilities']} | **Risk:** {findings['risk_score']:.1f}/100\n\n"
        comment += "---\n*Powered by Comprehensive Web3 Security Agent* 🛡️\n"
        
        return comment
    
    def post_security_findings(self, findings: Dict) -> bool:
        """Format and post security findings as a PR comment"""
        comment_body = self.format_security_report(findings)
        return self.post_comment(comment_body)
    
    def post_line_specific_comments(self, findings: Dict, file_path: str) -> bool:
        """Post individual review comments for each vulnerability at specific lines"""
        file_name = findings.get('file_name', '')
        success_count = 0
        
        for finding in findings.get('findings', []):
            line_num = finding.get('line_number', 0)
            if line_num and line_num > 0:
                comment_text = f"🔴 **{finding['type']}** [{finding['severity']}]\n\n"
                comment_text += f"{finding['description']}\n\n"
                comment_text += f"**Fix:** {finding['remediation']}"
                
                if self.post_review_comment(file_path, line_num, comment_text):
                    success_count += 1
        
        return success_count > 0
    
    def request_changes(self, reason: str = "Security vulnerabilities detected") -> bool:
        """Request changes on the PR"""
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