import openai

class VulnerabilityAnalyzer:
    def __init__(self, api_key: str):
        openai.api_key = api_key
    
    def analyze_code(self, code_snippet: str) -> str:
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {"role": "user", "content": f"Analyze the following code for security vulnerabilities:\n{code_snippet}"}
            ]
        )
        return response['choices'][0]['message']['content']

if __name__ == "__main__":
    # Sample usage
    api_key = "Your-OpenAI-API-Key"  # Replace with actual API key
    analyzer = VulnerabilityAnalyzer(api_key)
    code = """
    def vulnerable_function():
        user_input = input("Enter your name: ")
        print("Hello, " + user_input)
    """
    print(analyzer.analyze_code(code))
