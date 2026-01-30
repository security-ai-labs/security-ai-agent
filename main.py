#!/usr/bin/env python3
"""
Web3 Security Agent - Main Entry Point
Analyzes code repositories for Web2 and Web3 vulnerabilities
"""

import os
import sys
import argparse
import json

# Add src to path - use absolute path relative to script location
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(script_dir, 'src'))

from analyzer import SecurityAnalyzer

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Web3 Security Analyzer - Scan code for vulnerabilities'
    )
    parser.add_argument(
        '--target',
        type=str,
        default='.',
        help='Target directory to analyze (default: current directory)'
    )
    parser.add_argument(
        '--rules',
        type=str,
        default='config/vulnerability_rules.json',
        help='Path to vulnerability rules JSON file (default: config/vulnerability_rules.json)'
    )
    parser.add_argument(
        '--output',
        type=str,
        help='Output file for analysis results (JSON format)'
    )
    parser.add_argument(
        '--strict',
        action='store_true',
        help='Exit with error code if CRITICAL issues found (default: False)'
    )
    return parser.parse_args()

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
    args = parse_args()
    
    # Convert to absolute path
    target_dir = os.path.abspath(args.target)
    
    if not os.path.exists(target_dir):
        print(f"❌ Error: Target directory does not exist: {target_dir}")
        return 1
    
    if not os.path.isdir(target_dir):
        print(f"❌ Error: Target path is not a directory: {target_dir}")
        return 1
    
    print("\n" + "="*60)
    print("  🛡️  Web3 Security Agent")
    print("="*60)
    print(f"  Target: {target_dir}")
    print("="*60 + "\n")
    
    # Initialize analyzer with rules file path
    # If rules path is relative, make it relative to script location
    rules_path = args.rules
    if not os.path.isabs(rules_path):
        rules_path = os.path.join(script_dir, rules_path)
    
    if not os.path.exists(rules_path):
        print(f"❌ Error: Rules file not found: {rules_path}")
        return 1
    
    if not os.path.isfile(rules_path):
        print(f"❌ Error: Rules path is not a file: {rules_path}")
        return 1
    
    analyzer = SecurityAnalyzer(rules_path)
    
    # Analyze repository
    results = analyzer.analyze_repository(target_dir)
    
    # Print summary
    print(f"\n{'='*60}")
    print("  📊 Analysis Summary")
    print(f"{'='*60}\n")
    
    print(f"Target Directory: {target_dir}")
    print(f"Total Files: {results['total_files']}")
    print(f"Files with Issues: {results['files_with_issues']}")
    print(f"Total Vulnerabilities: {results['total_vulnerabilities']}\n")
    
    print("Severity Breakdown:")
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = results['severity_counts'].get(severity, 0)
        print(f"  {severity:10}: {count}")
    
    print(f"\n{'='*60}\n")
    
    # Save output if requested
    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"📝 Results saved to: {args.output}\n")
        except (IOError, OSError) as e:
            print(f"⚠️  Error saving results to {args.output}: {str(e)}\n")
    
    # Post to GitHub if in Actions
    if results['comments']:
        post_to_github(results)
    
    # Return exit code based on findings and strict mode
    if args.strict:
        if results['severity_counts'].get('CRITICAL', 0) > 0:
            print("🚨 CRITICAL issues found - Failing check (strict mode)")
            return 1
        elif results['total_vulnerabilities'] > 0:
            print("⚠️ Issues found - Passing with warnings")
            return 0
    
    # Default: always succeed, just report
    if results['severity_counts'].get('CRITICAL', 0) > 0:
        print("🚨 CRITICAL issues found - Review recommended")
    elif results['total_vulnerabilities'] > 0:
        print("⚠️ Issues found - Review recommended")
    else:
        print("✅ No issues found")
    
    return 0  # Always succeed by default

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)