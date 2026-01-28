import os
from typing import List, Dict, Tuple
from file_detector import FileDetector
from pattern_matcher import PatternMatcher
from report_generator import ReportGenerator

class SecurityAnalyzer:
    """Main security analyzer - orchestrates file detection, pattern matching, and reporting"""
    
    def __init__(self, rules_file: str = 'config/vulnerability_rules.json'):
        """Initialize analyzer with rules"""
        self.matcher = PatternMatcher(rules_file)
        self.reporter = ReportGenerator()
    
    def analyze_repository(self, directory: str = '.') -> Dict:
        """Analyze all files in repository
        
        Returns:
            Dictionary with analysis results
        """
        
        # Find all security-relevant files
        files_to_analyze = FileDetector.find_files(directory)
        
        print(f"\n🛡️  Web3 Security Analyzer")
        print(f"📁 Found {len(files_to_analyze)} security-relevant files\n")
        
        if not files_to_analyze:
            print("ℹ️  No security-relevant files found")
            return self._empty_results()
        
        # Initialize results
        results = {
            'total_files': len(files_to_analyze),
            'files_with_issues': 0,
            'total_vulnerabilities': 0,
            'severity_counts': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
            'files_analyzed': [],
            'comments': [],
            'details': []
        }
        
        # Analyze each file
        for filepath, chain, language in files_to_analyze:
            result = self._analyze_file(filepath, chain, language)
            
            if result['vulnerabilities']:
                results['files_with_issues'] += 1
                results['total_vulnerabilities'] += len(result['vulnerabilities'])
                
                # Update severity counts
                for vuln in result['vulnerabilities']:
                    severity = vuln['severity']
                    if severity in results['severity_counts']:
                        results['severity_counts'][severity] += 1
                
                # Generate comment
                comment = self.reporter.generate_comment(filepath, result['vulnerabilities'])
                results['comments'].append(comment)
                results['details'].append(result)
            
            results['files_analyzed'].append({
                'filepath': filepath,
                'chain': chain,
                'language': language,
                'vulnerabilities': len(result['vulnerabilities'])
            })
        
        return results
    
    def _analyze_file(self, filepath: str, chain: str, language: str) -> Dict:
        """Analyze single file"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            print(f"📄 Analyzing: {filepath:40} ({language:10})", end='')
            
            # Find vulnerabilities
            vulnerabilities = self.matcher.find_vulnerabilities(filepath, content, chain)
            
            if vulnerabilities:
                print(f" ⚠️  {len(vulnerabilities)} issue(s)")
            else:
                print(f" ✅")
            
            return {
                'filepath': filepath,
                'chain': chain,
                'language': language,
                'vulnerabilities': vulnerabilities
            }
        
        except Exception as e:
            print(f" ❌ Error: {str(e)}")
            return {
                'filepath': filepath,
                'chain': chain,
                'language': language,
                'vulnerabilities': [],
                'error': str(e)
            }
    
    @staticmethod
    def _empty_results() -> Dict:
        """Return empty results dict"""
        return {
            'total_files': 0,
            'files_with_issues': 0,
            'total_vulnerabilities': 0,
            'severity_counts': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
            'files_analyzed': [],
            'comments': [],
            'details': []
        }