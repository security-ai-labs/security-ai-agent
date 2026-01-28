import os
import json
import re
from typing import Dict, List
from github_pr_commenter import GitHubPRCommenter
from web3_analyzer import Web3Analyzer

class SecurityAIAgent:
    """
    Comprehensive security AI Agent
    Analyzes Web2, Web3, and hybrid code for ALL possible vulnerabilities
    Scans security-relevant files in the repository
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
    
    def analyze_pr(self, pr_files: List[str], pr_content: str, file_name: str = "code") -> Dict:
        """Comprehensive PR analysis with file location tracking"""
        
        # Run comprehensive analysis
        analysis_result = self.analyzer.analyze_code(pr_content, file_name)
        
        # Enrich findings with line numbers
        enriched_findings = self._add_line_numbers(pr_content, analysis_result['findings'], file_name)
        
        # Format report
        report = {
            "file_name": file_name,
            "detected_chain": analysis_result['detected_chain'],
            "detected_code_type": analysis_result['detected_code_type'],
            "total_vulnerabilities": analysis_result['total_vulnerabilities'],
            "risk_score": analysis_result['risk_score'],
            "severity_summary": analysis_result['by_severity'],
            "category_summary": analysis_result['by_category'],
            "findings": enriched_findings,
            "recommendations": analysis_result['recommendations'],
            "overall_recommendation": self._generate_overall_recommendation(analysis_result),
        }
        
        return report
    
    def _add_line_numbers(self, content: str, findings: List[Dict], file_name: str) -> List[Dict]:
        """Add line numbers to findings based on pattern matching"""
        lines = content.split('\n')
        enriched_findings = []
        
        for finding in findings:
            finding_copy = finding.copy()
            finding_copy['file_name'] = file_name
            
            # Try to find the line number based on vulnerability type
            line_number = self._find_line_for_vulnerability(content, lines, finding)
            finding_copy['line_number'] = line_number
            
            enriched_findings.append(finding_copy)
        
        return enriched_findings
    
    def _find_line_for_vulnerability(self, content: str, lines: List[str], finding: Dict) -> int:
        """Find the approximate line number for a vulnerability"""
        vuln_type = finding.get('name', '').lower()
        
        # Map vulnerability types to search patterns
        search_patterns = {
            'hardcoded_secrets': [r'password\s*=|api[_-]?key|secret[_-]?key|private[_-]?key|credentials|PRIVATE_KEY|ADMIN\s*='],
            'sql_injection': [r'execute\s*\(|query\s*\(|SELECT.*WHERE.*\+'],
            'xss': [r'innerHTML|dangerouslySetInnerHTML|eval\s*\(|document\.write'],
            'reentrancy': [r'\.call\{.*value|\.transfer\s*\(|\.send\s*\('],
            'integer_overflow': [r'pragma solidity\s+\^?0\.[0-7]|\+=\s*\w+|\-=\s*\w+'],
            'unchecked_call': [r'\.call\s*\(\s*\)(?!.*require)|\.delegatecall'],
            'delegatecall_to_untrusted': [r'delegatecall\s*\('],
            'missing_zero_address_check': [r'transfer.*to|_to\s*=|address\(0\)'],
            'missing_access_control': [r'function\s+\w+.*public|function\s+\w+.*external(?!.*onlyOwner)'],
            'flash_loan': [r'flashLoan|receiveFlashLoan'],
            'timestamp_manipulation': [r'block\.timestamp|now\s*[><=]'],
            'missing_signer_check': [r'is_signer.*false|is_signed.*false'],
            'missing_owner_check': [r'owner.*check|assert_owned_by'],
            'unchecked_account': [r'UncheckedAccount'],
            'arithmetic_overflow': [r'\+=\s*\w+|\-=\s*\w+(?!.*checked)|\*\s*\w+(?!.*checked)'],
            'oracle_manipulation': [r'getPrice|price.*feed|pricePerShare'],
            'missing_slippage_protection': [r'swap.*\(|addLiquidity|getAmountsOut'],
            'command_injection': [r'exec\s*\(|os\.system|subprocess|shell_exec'],
            'path_traversal': [r'\.\./|open\s*\(|readFile\s*\('],
            'weak_hash': [r'md5|sha1(?!_)|CRC32'],
            'weak_rng': [r'Math\.random|random\.random|rand.*seed.*time'],
        }
        
        # Get patterns for this vulnerability
        patterns = search_patterns.get(vuln_type, [])
        
        # Search for the pattern in the code
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    return i
        
        # If no specific pattern found, return a default
        return 1
    
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
        """Format findings into detailed markdown comment with file and line info"""
        
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
            # Group findings by line number for better organization
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
                    comment += f"- **File:** `{file_name}`\n"
                    comment += f"- **Line:** `{line_num}`\n"
                    comment += f"- **Description:** {finding['description']}\n"
                    comment += f"- **Remediation:** {finding['remediation']}\n"
        else:
            comment += "\n✅ No vulnerabilities detected!\n"
        
        comment += f"\n### 💡 Remediation Summary\n"
        if findings['recommendations']:
            for i, rec in enumerate(findings['recommendations'], 1):
                comment += f"{i}. {rec}\n"
        
        comment += f"\n### 📋 Overall Assessment\n{findings['overall_recommendation']}\n\n"
        comment += f"**File:** `{file_name}` | **Issues:** {findings['total_vulnerabilities']} | **Risk:** {findings['risk_score']:.1f}/100\n\n"
        comment += "---\n*Powered by Comprehensive Web3 Security Agent* 🛡️\n"
        
        return comment
    
    def handle_findings(self, findings: Dict) -> None:
        """Handle findings and take actions"""
        self.post_findings_to_pr(findings)
        
        if findings['risk_score'] >= 70:
            if self.pr_commenter:
                self.pr_commenter.request_changes(
                    f"🚨 High-risk code detected in {findings.get('file_name', 'code')} - changes required"
                )
        elif findings['total_vulnerabilities'] == 0:
            if self.pr_commenter:
                self.pr_commenter.approve_pr(
                    f"✅ No security issues found in {findings.get('file_name', 'code')}"
                )

def is_security_agent_file(filepath: str) -> bool:
    """Check if the file is part of the security agent itself"""
    agent_files = {
        'main.py',
        'web3_analyzer.py',
        'github_pr_commenter.py',
        'security_rules.py',
        'requirements.txt',
    }
    
    filename = os.path.basename(filepath)
    return filename in agent_files

def get_security_relevant_files(directory='.', exclude_dirs=None):
    """
    Get all security-relevant files from the repository
    Includes: .sol, .rs, .js, .ts, .py, .go, .java, .yml, .yaml
    Excludes: Security agent files and temporary files
    """
    if exclude_dirs is None:
        exclude_dirs = {'.git', '__pycache__', 'node_modules', '.venv', 'venv', 'env', 
                       'temp-agent', 'artifacts', 'dist', 'build', '.idea', '.vscode', 
                       '.github', '.pytest_cache', 'htmlcov'}
    
    security_extensions = {
        '.sol',   # Solidity
        '.rs',    # Rust (Solana)
        '.js',    # JavaScript
        '.ts',    # TypeScript
        '.py',    # Python (but not security agent files)
        '.go',    # Go
        '.java',  # Java
        '.yml',   # YAML
        '.yaml',  # YAML
    }
    
    security_files = []
    
    for root, dirs, files in os.walk(directory):
        # Remove excluded directories from traversal
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        
        for file in files:
            # Check if file has security-relevant extension
            if any(file.endswith(ext) for ext in security_extensions):
                filepath = os.path.join(root, file)
                
                # Skip security agent files
                if is_security_agent_file(filepath):
                    print(f"⏭️  Skipping (security agent file): {filepath}")
                    continue
                
                # Skip temporary files
                if file.startswith('temp-') or file.startswith('.'):
                    continue
                
                security_files.append(filepath)
    
    return sorted(security_files)

def main():
    """Main entry point - analyzes all security-relevant files"""
    agent = SecurityAIAgent()
    
    # Get all security-relevant files (excluding agent files)
    security_files = get_security_relevant_files('.')
    
    print(f"\n🔍 Security Analysis Starting\n")
    print(f"📁 Found {len(security_files)} security-relevant file(s)\n")
    
    if not security_files:
        print("ℹ️ No security-relevant code files found in this PR")
        return
    
    all_findings = {
        'total_vulnerabilities': 0,
        'files_analyzed': [],
        'severity_summary': {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0,
        },
        'category_summary': {},
        'findings_by_file': {},
    }
    
    # Analyze each file
    for filepath in security_files:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Skip empty files
            if not content.strip():
                print(f"⏭️  Skipping (empty): {filepath}\n")
                continue
            
            print(f"🔍 Analyzing: {filepath}")
            
            # Analyze the file
            findings = agent.analyze_pr([], content, filepath)
            
            # Store findings
            all_findings['files_analyzed'].append(filepath)
            all_findings['findings_by_file'][filepath] = findings
            
            # Aggregate summary
            all_findings['total_vulnerabilities'] += findings['total_vulnerabilities']
            
            for severity, count in findings['severity_summary'].items():
                all_findings['severity_summary'][severity] += count
            
            for category, count in findings['category_summary'].items():
                all_findings['category_summary'][category] = all_findings['category_summary'].get(category, 0) + count
            
            print(f"   ✅ Found {findings['total_vulnerabilities']} issue(s)\n")
        
        except Exception as e:
            print(f"   ❌ Error analyzing: {str(e)}\n")
            continue
    
    # Post findings to PR
    if agent.pr_commenter and all_findings['files_analyzed']:
        print("📤 Posting security findings to PR...\n")
        
        for filepath, findings in all_findings['findings_by_file'].items():
            if findings['total_vulnerabilities'] > 0:
                agent.post_findings_to_pr(findings)
                print(f"   ✅ Posted comment for {filepath}")
        
        print("\n✅ All findings posted to PR!")
    else:
        # Print for local testing
        print("\n" + "="*80)
        print("ANALYSIS RESULTS")
        print("="*80)
        if all_findings['files_analyzed']:
            for filepath, findings in all_findings['findings_by_file'].items():
                print(f"\n📄 {filepath}")
                print(f"   Total Vulnerabilities: {findings['total_vulnerabilities']}")
                print(f"   Risk Score: {findings['risk_score']:.1f}/100")
                print(f"   Chain: {findings['detected_chain']}")
        else:
            print("No security-relevant files found")
        print("="*80)

if __name__ == "__main__":
    main()