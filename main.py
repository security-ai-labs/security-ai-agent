#!/usr/bin/env python3
"""
Web3 Security Agent - Main Entry Point
Analyzes code repositories for Web2 and Web3 vulnerabilities
"""

import os
import sys

# Add src to path
sys.path.insert(0, 'src')

from analyzer import SecurityAnalyzer

def post_to_github(results: dict):
    """Post findings to GitHub PR if in Actions"""
    if not os.getenv('GITHUB_TOKEN'):
        return
    
    try:
        from github_pr_commenter import GitHubPRCommenter
        
        commenter = GitHubPRCommenter()
        
        # Post each comment
        for comment in results['comments']:
            commenter.post_comment(comment)
            print("✅ Posted to PR")
        
        # Post summary if multiple files
        if len(results['files_analyzed']) > 1:
            summary = _generate_summary(results)
            commenter.post_comment(summary)
    
    except Exception as e:
        print(f"⚠️  Could not post to GitHub: {str(e)}")

def _generate_summary(results: dict) -> str:
    """Generate summary comment"""
    critical = results['severity_counts'].get('CRITICAL', 0)
    high = results['severity_counts'].get('HIGH', 0)
    
    comment = f"""## 📊 Security Analysis Complete

**Summary:**
- Files Analyzed: {results['total_files']}
- Files with Issues: {results['files_with_issues']}
- Total Vulnerabilities: {results['total_vulnerabilities']}

**Breakdown:**
- 🚨 CRITICAL: {critical}
- ⚠️ HIGH: {high}
- ⚡ MEDIUM: {results['severity_counts'].get('MEDIUM', 0)}
- ℹ️ LOW: {results['severity_counts'].get('LOW', 0)}

"""
    
    if critical > 0:
        comment += "🚨 **CRITICAL issues found** - Please review before merging\n"
    elif results['total_vulnerabilities'] > 0:
        comment += "⚠️ **Issues found** - Review the comments above\n"
    else:
        comment += "✅ **No vulnerabilities detected** - Code looks good!\n"
    
    return comment

def main():
    """Main entry point"""
    
    print("\n" + "="*60)
    print("  🛡️  Web3 Security Agent")
    print("="*60 + "\n")
    
    # Initialize analyzer
    analyzer = SecurityAnalyzer('config/vulnerability_rules.json')
    
    # Analyze repository
    results = analyzer.analyze_repository('.')
    
    # Print summary
    print(f"\n{'='*60}")
    print("  📊 Analysis Summary")
    print(f"{'='*60}\n")
    
    print(f"Total Files: {results['total_files']}")
    print(f"Files with Issues: {results['files_with_issues']}")
    print(f"Total Vulnerabilities: {results['total_vulnerabilities']}\n")
    
    print("Severity Breakdown:")
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = results['severity_counts'].get(severity, 0)
        print(f"  {severity:10}: {count}")
    
    print(f"\n{'='*60}\n")
    
    # Post to GitHub if in Actions
    if results['comments']:
        post_to_github(results)
    
    # Return exit code based on findings
    if results['severity_counts'].get('CRITICAL', 0) > 0:
        print("🚨 CRITICAL issues found - Failing check")
        return 1
    elif results['total_vulnerabilities'] > 0:
        print("⚠️ Issues found - Review required")
        return 0
    else:
        print("✅ No issues found")
        return 0

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)