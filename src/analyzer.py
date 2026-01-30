import os
from typing import List, Dict, Tuple
from file_detector import FileDetector
from pattern_matcher import PatternMatcher
from report_generator import ReportGenerator
from confidence_scorer import ConfidenceScorer

class SecurityAnalyzer:
    """Main security analyzer - orchestrates file detection, pattern matching, and reporting"""
    
    def __init__(self, rules_file: str = 'config/vulnerability_rules.json'):
        """Initialize analyzer with rules"""
        self.matcher = PatternMatcher(rules_file)
        self.reporter = ReportGenerator()
        self.scorer = ConfidenceScorer()
    
    def analyze_repository(self, directory: str = '.') -> Dict:
        """Analyze all files in repository
        
        Returns:
            Dictionary with analysis results
        """
        
        # Convert to absolute path for traversal
        abs_directory = os.path.abspath(directory)
        
        # Find all security-relevant files
        files_to_analyze = FileDetector.find_files(abs_directory)
        
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
            # Calculate relative path from target directory
            try:
                relative_path = os.path.relpath(filepath, abs_directory)
            except ValueError:
                # If relpath fails (different drives on Windows), use basename
                relative_path = os.path.basename(filepath)
            
            result = self._analyze_file(filepath, chain, language, relative_path)
            
            if result['vulnerabilities']:
                results['files_with_issues'] += 1
                results['total_vulnerabilities'] += len(result['vulnerabilities'])
                
                # Update severity counts
                for vuln in result['vulnerabilities']:
                    severity = vuln['severity']
                    if severity in results['severity_counts']:
                        results['severity_counts'][severity] += 1
                
                # Generate comment with relative path
                comment = self.reporter.generate_comment(relative_path, result['vulnerabilities'])
                results['comments'].append(comment)
                results['details'].append(result)
            
            results['files_analyzed'].append({
                'filepath': relative_path,  # Use relative path
                'chain': chain,
                'language': language,
                'vulnerabilities': len(result['vulnerabilities'])
            })
        
        return results
    
    def _analyze_file(self, filepath: str, chain: str, language: str, display_path: str = None) -> Dict:
        """Analyze single file with confidence scoring
        
        Args:
            filepath: Absolute path to file
            chain: Blockchain/platform
            language: Programming language
            display_path: Relative path for display (optional)
        """
        if display_path is None:
            display_path = filepath
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            print(f"📄 Analyzing: {display_path:40} ({language:10})", end='')
            
            # Find vulnerabilities
            vulnerabilities = self.matcher.find_vulnerabilities(display_path, content, chain)
            
            # Add confidence scores to each vulnerability
            for vuln in vulnerabilities:
                vuln['filepath'] = display_path  # Use relative path
                self.scorer.calculate_confidence(vuln, content)
            
            # Filter out very low confidence findings (optional)
            # vulnerabilities = [v for v in vulnerabilities if v['confidence'] >= 0.3]
            
            if vulnerabilities:
                print(f" ⚠️  {len(vulnerabilities)} issue(s)")
            else:
                print(f" ✅")
            
            return {
                'filepath': display_path,  # Use relative path
                'chain': chain,
                'language': language,
                'vulnerabilities': vulnerabilities
            }
        
        except Exception as e:
            print(f" ❌ Error: {str(e)}")
            return {
                'filepath': display_path,  # Use relative path
                'chain': chain,
                'language': language,
                'vulnerabilities': [],
                'error': str(e)
            }
    
    def _analyze_file_content(self, content: str, chain: str, language: str) -> List[Dict]:
        """Analyze code content directly (for testing)
        
        Args:
            content: Code to analyze
            chain: Blockchain/platform (e.g., 'ethereum', 'solana', 'web2', 'defi')
            language: Programming language (e.g., 'solidity', 'rust', 'python', 'javascript')
        
        Returns:
            List of vulnerabilities found
        """
        return self.matcher.find_vulnerabilities('test_file', content, chain)
    
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