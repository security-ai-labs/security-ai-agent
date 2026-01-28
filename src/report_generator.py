from typing import Dict, List

class ReportGenerator:
    """Generates markdown security reports"""
    
    SEVERITY_EMOJI = {
        'CRITICAL': '🚨',
        'HIGH': '⚠️',
        'MEDIUM': '⚡',
        'LOW': 'ℹ️',
        'INFO': '💡'
    }
    
    @staticmethod
    def generate_comment(filepath: str, vulnerabilities: List[Dict]) -> str:
        """Generate PR comment for a file with vulnerabilities
        
        Args:
            filepath: Path to analyzed file
            vulnerabilities: List of found vulnerabilities
        
        Returns:
            Formatted markdown comment
        """
        
        if not vulnerabilities:
            return f"✅ **No vulnerabilities found** in `{filepath}`"
        
        # Count by severity
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Build comment
        comment = f"""## 🔍 Security Analysis: `{filepath}`

**Total Issues Found:** {len(vulnerabilities)}
"""
        
        # Add severity breakdown
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                emoji = ReportGenerator.SEVERITY_EMOJI.get(severity, '•')
                comment += f"- {emoji} **{severity}:** {count}\n"
        
        comment += "\n### Vulnerabilities\n"
        
        # Add each vulnerability
        for vuln in vulnerabilities:
            emoji = ReportGenerator.SEVERITY_EMOJI.get(vuln['severity'], '•')
            
            comment += f"""
{emoji} **{vuln['name']}** (Line {vuln['line']})
- **Severity:** `{vuln['severity']}`
- **Issue:** {vuln['description']}
- **Solution:** {vuln['remediation']}
"""
            
            # Add examples if available
            if vuln.get('examples'):
                comment += "\n**Examples:**\n"
                for example in vuln['examples'][:2]:  # Show max 2 examples
                    comment += f"  - `{example}`\n"
        
        comment += "\n---\n*Powered by Web3 Security Agent* 🛡️\n"
        
        return comment
    
    @staticmethod
    def generate_summary(results: Dict) -> str:
        """Generate summary report for all files"""
        
        comment = """## 📊 Security Analysis Summary

"""
        
        # Overall stats
        comment += f"""**Files Analyzed:** {results['total_files']}
**Files with Issues:** {results['files_with_issues']}
**Total Vulnerabilities:** {results['total_vulnerabilities']}

"""
        
        # Severity breakdown
        comment += "### Severity Breakdown\n"
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = results['severity_counts'].get(severity, 0)
            if count > 0:
                emoji = ReportGenerator.SEVERITY_EMOJI.get(severity, '•')
                comment += f"- {emoji} **{severity}:** {count}\n"
        
        # Risk assessment
        critical = results['severity_counts'].get('CRITICAL', 0)
        if critical > 0:
            comment += f"\n🚨 **{critical} CRITICAL issues found** - DO NOT MERGE\n"
        elif results['total_vulnerabilities'] > 5:
            comment += f"\n⚠️ **High risk code** - Review and fix before merging\n"
        elif results['total_vulnerabilities'] > 0:
            comment += f"\n⚡ **Minor issues** - Consider fixing\n"
        else:
            comment += f"\n✅ **No vulnerabilities found** - Code looks good!\n"
        
        return comment