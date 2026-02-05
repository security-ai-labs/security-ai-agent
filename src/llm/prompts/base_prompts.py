"""
Base security analysis prompts - All languages
Enhanced with pattern detection and false positive reduction
"""

import re
from typing import List

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
# SECURITY PATTERN DETECTION
# ============================================================================


def detect_security_patterns(code: str, language: str) -> List[str]:
    """
    Detect existing security patterns in code
    This helps reduce false positives by identifying mitigations already in place
    """
    patterns = []

    if language == "solidity":
        # Reentrancy protection
        if re.search(
            r"import.*ReentrancyGuard|is\s+ReentrancyGuard|nonReentrant", code
        ):
            patterns.append("ReentrancyGuard - protects against reentrancy attacks")

        # Version check for overflow protection
        if re.search(
            r"pragma\s+solidity\s+\^0\.[8-9]|pragma\s+solidity\s+\^[1-9]", code
        ):
            patterns.append(
                "Solidity 0.8+ - built-in integer overflow/underflow protection"
            )

        # Access control
        if re.search(r"import.*AccessControl|import.*Ownable", code):
            patterns.append(
                "OpenZeppelin AccessControl/Ownable - role-based access control"
            )
        if re.search(r"onlyOwner|onlyRole|hasRole", code):
            patterns.append("Access control modifiers present")

        # Safe transfers
        if re.search(r"import.*SafeERC20|using\s+SafeERC20", code):
            patterns.append("SafeERC20 - safe token transfer operations")
        if re.search(r"safeTransfer|safeTransferFrom", code):
            patterns.append("Using safe transfer methods")

        # Pausable
        if re.search(r"import.*Pausable|is\s+Pausable|whenNotPaused", code):
            patterns.append("Pausable - emergency pause functionality")

    elif language == "python":
        # SQL injection protection
        if re.search(r'execute\([^,]*,\s*\(|execute\([^"\']*[\?\%]s', code):
            patterns.append("Parameterized SQL queries - prevents SQL injection")
        if re.search(r"from\s+sqlalchemy|import\s+sqlalchemy", code):
            patterns.append("SQLAlchemy ORM - safe query handling")

        # Rate limiting
        if re.search(r"from\s+flask_limiter|import.*Limiter|@limiter\.limit", code):
            patterns.append("Rate limiting implemented")

        # Secure comparison
        if re.search(r"hmac\.compare_digest|constant_time_compare", code):
            patterns.append("Timing-safe comparison - prevents timing attacks")

        # Input validation
        if re.search(
            r"from\s+.*\s+import\s+.*[Vv]alidator|@.*validate|validationResult", code
        ):
            patterns.append("Input validation framework")

    elif language in ["javascript", "typescript"]:
        # CSRF protection
        if re.search(r'require\([\'"]csurf|import.*csurf|csrfProtection', code):
            patterns.append("CSRF protection enabled")

        # Input sanitization
        if re.search(r"DOMPurify\.sanitize|validator\.escape|sanitize\(", code):
            patterns.append("Input sanitization implemented")

        # Security headers
        if re.search(r'require\([\'"]helmet|import.*helmet|app\.use\(helmet', code):
            patterns.append("Helmet security headers configured")

        # Rate limiting
        if re.search(r"express-rate-limit|rateLimit\(", code):
            patterns.append("Rate limiting configured")

        # JWT algorithm specification
        if re.search(r"jwt\.verify\([^,]+,\s*[^,]+,\s*\{\s*algorithms", code):
            patterns.append(
                "JWT algorithm specification - prevents algorithm confusion"
            )

    return patterns


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
3. Confidence level (HIGH, MEDIUM, LOW)
4. Explanation of the exploit path
5. Recommended fixes with code examples

CRITICAL RULES:
- Be thorough but concise
- Focus on EXPLOITABLE vulnerabilities only
- Do NOT report issues that are already mitigated by security patterns
- Avoid false positives and style issues
- Include confidence levels for each finding
- Only report REAL vulnerabilities with security impact"""


def get_analysis_prompt(code: str, language: str, filepath: str) -> str:
    """Get enhanced analysis prompt with context awareness"""

    # Detect security patterns FIRST
    security_patterns = detect_security_patterns(code, language)

    # Build context section
    context_section = ""
    if security_patterns:
        patterns_text = "\n".join(f"- {pattern}" for pattern in security_patterns)
        context_section = f"""
## DETECTED SECURITY MEASURES:

The code already implements these security patterns:
{patterns_text}

IMPORTANT INSTRUCTIONS:
- Do NOT flag vulnerabilities that are already mitigated by these patterns
- For example:
  * If ReentrancyGuard is present, do NOT flag reentrancy unless incorrectly used
  * If parameterized queries are used, do NOT flag SQL injection
  * If Solidity 0.8+, do NOT flag integer overflow (built-in protection)
  * If SafeERC20 is used, do NOT flag unchecked transfers
  * If CSRF protection exists, do NOT flag CSRF unless misconfigured
- Only report if mitigation is INCORRECTLY implemented or MISSING

"""

    # Determine category
    category = "web3" if language in ["solidity", "rust"] else "web2"
    vulns = WEB3_VULNERABILITIES if category == "web3" else WEB2_VULNERABILITIES

    # Get language-specific examples
    examples = LANGUAGE_EXAMPLES.get(language, "")

    # Build vulnerability list
    vuln_list = "\n".join(f"- {v}" for v in vulns)

    # Build the prompt WITHOUT code blocks (causing the issue)
    prompt = f"""Analyze the following {language.upper()} code for security vulnerabilities.

FILE: {filepath}

{context_section}

CODE:
{code}

Provide your analysis in the following JSON format:
{{
  "vulnerabilities": [
    {{
      "id": "unique-id",
      "title": "Brief descriptive title",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "confidence": "HIGH|MEDIUM|LOW",
      "line_number": 42,
      "description": "Detailed explanation of the vulnerability",
      "exploit_scenario": "Step-by-step: how an attacker could exploit this",
      "recommendation": "Specific fix with code example",
      "cwe": "CWE-XXX",
      "references": [],
      "mitigated": false
    }}
  ],
  "summary": {{
    "total_issues": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0
  }},
  "overall_assessment": "Brief overall security assessment",
  "secure_patterns": []
}}

Focus on detecting:
{vuln_list}

{examples}

CRITICAL ANALYSIS GUIDELINES:

1. Confidence Levels:
   - HIGH: Definite vulnerability with clear exploit path
   - MEDIUM: Likely vulnerability but needs specific conditions
   - LOW: Potential issue but uncertain or depends on context

2. False Positive Prevention:
   - Check if vulnerability is already MITIGATED before reporting
   - Verify the security pattern is correctly implemented
   - Consider the full context (not just isolated lines)
   - Do not report issues in comments, documentation, or test files

3. Severity Assessment:
   - CRITICAL: Direct exploit leading to fund loss, data breach, or system compromise
   - HIGH: Exploitable with significant impact but requires conditions
   - MEDIUM: Security weakness that could lead to exploitation
   - LOW: Minor issue or security improvement

4. Required for Each Finding:
   - Specific line number (not approximate)
   - Concrete exploit scenario (not theoretical)
   - Actionable fix with code example
   - Proper confidence level

5. Do NOT Report:
   - Style issues or code quality
   - Theoretical vulnerabilities without exploit path
   - Issues already mitigated by detected security patterns
   - Generic security advice without specific vulnerability

Be precise, be confident, and avoid false positives!"""

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
  "explanation": "Explain what was changed and why it is now secure",
  "additional_notes": "Any other security considerations",
  "diff": "Unified diff format showing the changes"
}}

Make sure the fix:
1. Actually resolves the security issue
2. Does not break existing functionality
3. Follows best practices
4. Is production-ready"""

    return prompt
