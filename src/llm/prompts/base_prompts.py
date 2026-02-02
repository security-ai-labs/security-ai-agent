"""
Base security analysis prompts - All languages
"""

# ============================================================================
# SYSTEM PROMPTS - Language-specific expertise
# ============================================================================

LANGUAGE_EXPERTISE = {
    "solidity": """
- Solidity and EVM internals
- Smart contract vulnerabilities (reentrancy, access control, oracle manipulation)
- DeFi protocol security and MEV attacks
- Gas optimization and best practices
""",
    "python": """
- Python security best practices
- Web framework vulnerabilities (Flask, Django, FastAPI)
- SQL injection, XSS, CSRF, command injection
- Authentication and authorization flaws
- API security and dependency vulnerabilities
""",
    "javascript": """
- JavaScript/Node.js security
- Express.js and React vulnerabilities
- XSS, CSRF, prototype pollution
- NoSQL injection and JWT vulnerabilities
- npm dependency security
""",
    "typescript": """
- TypeScript security patterns
- React security (XSS in JSX, dangerous props)
- API security and type safety issues
- Authentication flaws
""",
    "rust": """
- Rust memory safety
- Smart contract security (Solana, Near)
- Integer overflow/underflow
- Logic bugs in blockchain programs
""",
    "go": """
- Go security best practices
- Concurrency vulnerabilities
- SQL injection and authentication bypass
- Insecure crypto usage
""",
}

# ============================================================================
# COMMON VULNERABILITIES BY CATEGORY
# ============================================================================

WEB2_VULNERABILITIES = [
    "SQL Injection",
    "Cross-Site Scripting (XSS)",
    "Cross-Site Request Forgery (CSRF)",
    "Authentication bypass",
    "Authorization flaws",
    "Command Injection",
    "Path Traversal",
    "Server-Side Request Forgery (SSRF)",
    "Insecure Deserialization",
    "Security Misconfiguration",
    "Sensitive Data Exposure",
    "API vulnerabilities",
]

WEB3_VULNERABILITIES = [
    "Reentrancy attacks",
    "Access control issues",
    "Oracle manipulation / Flash loan attacks",
    "Integer overflow/underflow",
    "Unchecked external calls",
    "Front-running / MEV vulnerabilities",
    "Denial of Service",
    "Logic bugs in business logic",
    "Signature replay attacks",
]

# ============================================================================
# LANGUAGE-SPECIFIC VULNERABILITY EXAMPLES
# ============================================================================

SOLIDITY_EXAMPLES = """
Common Solidity Vulnerabilities:

1. Reentrancy:
   VULNERABLE: External call before state update
   SECURE: State update before external call

2. Access Control:
   VULNERABLE: No modifier on privileged functions
   SECURE: Use onlyOwner or role-based modifiers

3. Unchecked External Calls:
   VULNERABLE: Ignoring return values
   SECURE: Check success and handle failures
"""

PYTHON_EXAMPLES = """
Common Python Vulnerabilities:

1. SQL Injection:
   VULNERABLE: String concatenation in queries
   SECURE: Use parameterized queries

2. Command Injection:
   VULNERABLE: os.system() with user input
   SECURE: Use subprocess with list arguments

3. Path Traversal:
   VULNERABLE: Direct file access with user input
   SECURE: Validate and sanitize file paths
"""

JAVASCRIPT_EXAMPLES = """
Common JavaScript Vulnerabilities:

1. XSS:
   VULNERABLE: innerHTML with user input
   SECURE: Use textContent or sanitize HTML

2. Prototype Pollution:
   VULNERABLE: Unvalidated object key assignment
   SECURE: Check for __proto__ and hasOwnProperty

3. NoSQL Injection:
   VULNERABLE: Direct object in MongoDB queries
   SECURE: Sanitize and validate input types
"""

LANGUAGE_EXAMPLES = {
    "solidity": SOLIDITY_EXAMPLES,
    "python": PYTHON_EXAMPLES,
    "javascript": JAVASCRIPT_EXAMPLES,
    "typescript": JAVASCRIPT_EXAMPLES,
    "rust": "Focus on memory safety and integer overflow issues.",
    "go": "Focus on concurrency, SQL injection, and authentication flaws.",
}

# ============================================================================
# MAIN PROMPT FUNCTIONS
# ============================================================================


def get_system_prompt(language: str) -> str:
    """Get system prompt for specific language"""
    expertise = LANGUAGE_EXPERTISE.get(language, "various security domains")

    return f"""You are an expert security auditor with deep knowledge of:
    {expertise}

    Your task is to analyze code for security vulnerabilities and provide:
    1. Clear identification of vulnerabilities
    2. Severity assessment (CRITICAL, HIGH, MEDIUM, LOW)
    3. Explanation of the exploit path
    4. Recommended fixes with code examples

    Be thorough but concise. Focus on exploitable vulnerabilities, not code style issues.
    Only report REAL vulnerabilities that have security impact."""


def get_analysis_prompt(code: str, language: str, filepath: str) -> str:
    """Get analysis prompt for code"""
    # Determine category
    category = "web3" if language in ["solidity", "rust"] else "web2"
    vulns = WEB3_VULNERABILITIES if category == "web3" else WEB2_VULNERABILITIES

    # Get language-specific examples
    examples = LANGUAGE_EXAMPLES.get(language, "")

    # Build vulnerability list
    vuln_list = "\n".join(f"- {v}" for v in vulns)

    prompt = f"""Analyze the following {language.upper()} code for security vulnerabilities.

    FILE: {filepath}

    CODE:
    {code}

    Provide your analysis in the following JSON format:
    {{
    "vulnerabilities": [
        {{
        "id": "unique-id",
        "title": "Brief title (e.g., 'SQL Injection in login endpoint')",
        "severity": "CRITICAL|HIGH|MEDIUM|LOW",
        "line_number": 42,
        "description": "Detailed explanation of the vulnerability",
        "exploit_scenario": "Step-by-step: how an attacker could exploit this",
        "recommendation": "Specific fix with code example",
        "cwe": "CWE-XXX",
        "references": ["URL1", "URL2"]
        }}
    ],
    "summary": {{
        "total_issues": 5,
        "critical": 1,
        "high": 2,
        "medium": 1,
        "low": 1
    }},
    "overall_assessment": "Brief overall security assessment (2-3 sentences)",
    "secure_patterns": ["List any good security practices found"]
    }}

    Focus on detecting:
    {vuln_list}

    {examples}

    Important Guidelines:
    - Report ONLY real, exploitable vulnerabilities
    - Avoid false positives and style issues
    - Provide specific line numbers when possible
    - Include concrete exploit scenarios
    - Suggest actionable fixes with code examples
    - Consider the context (test files, comments, etc.)"""

    return prompt


def get_fix_prompt(vulnerability: dict, vulnerable_code: str) -> str:
    """Get fix generation prompt"""

    title = vulnerability.get("title", "Unknown")
    severity = vulnerability.get("severity", "UNKNOWN")
    line = vulnerability.get("line_number", "?")
    desc = vulnerability.get("description", "No description")

    prompt = f"""Generate a secure fix for this vulnerability:

    VULNERABILITY:
    - Title: {title}
    - Severity: {severity}
    - Line: {line}
    - Description: {desc}

    VULNERABLE CODE:
    {vulnerable_code}

    Provide a fix in JSON format:
    {{
    "fixed_code": "Complete secure code snippet",
    "explanation": "Explain what was changed and why it's now secure",
    "additional_notes": "Any other security considerations",
    "diff": "Unified diff format showing the changes"
    }}

    Make sure the fix:
    1. Actually resolves the security issue
    2. Doesn't break existing functionality
    3. Follows best practices
    4. Is production-ready"""

    return prompt
