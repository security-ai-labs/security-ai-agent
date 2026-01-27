from ai_analyzer import VulnerabilityAnalyzer
import os

class SecurityAIAgent:
    def __init__(self):
        api_key = os.getenv('OPENAI_API_KEY')
        self.analyzer = VulnerabilityAnalyzer(api_key)
        self.findings = []
    
    def analyze_pr(self, pr_files, pr_content):
        """Analyze PR using AI"""
        try:
            # Use AI analyzer for smart detection
            ai_report = self.analyzer.analyze_code(pr_content)
            return {
                "ai_analysis": ai_report,
                "web2_issues": self.extract_web2_issues(ai_report),
                "web3_issues": self.extract_web3_issues(ai_report),
                "recommendation": self.generate_recommendation(ai_report)
            }
        except Exception as e:
            # Fallback to pattern matching
            print(f"AI analysis failed: {e}, using pattern matching")
            return self.analyze_with_patterns(pr_files, pr_content)
    
    def extract_web2_issues(self, ai_report):
        # Parse AI response for Web2 issues
        return []
    
    def extract_web3_issues(self, ai_report):
        # Parse AI response for Web3 issues
        return []
    
    def generate_recommendation(self, ai_report):
        # Generate final recommendation
        return "Review AI analysis above"
    
    def analyze_with_patterns(self, files, content):
        # Fallback to pattern matching
        return {"status": "pattern_fallback"}