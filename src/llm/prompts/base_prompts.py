"""
Base security analysis prompts - All languages
Enhanced with intelligent pattern detection and context-aware analysis
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
   SECURE: State update before external call + nonReentrant modifier

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
# INTELLIGENT SECURITY PATTERN DETECTION
# ============================================================================


def detect_security_patterns(code: str, language: str) -> List[str]:
    """
    Intelligently detect security patterns and their actual usage
    Returns both properly implemented patterns AND misconfigurations
    """
    patterns = []

    if language == "solidity":
        # ===== ReentrancyGuard Analysis =====
        has_reentrancy_import = re.search(r"import.*ReentrancyGuard", code)
        is_reentrancy_inherited = re.search(
            r"is\s+ReentrancyGuard|is\s+\w+,\s*ReentrancyGuard|is\s+ReentrancyGuard\s*,",
            code,
        )
        nonreentrant_uses = len(re.findall(r"\bnonReentrant\b", code))

        if has_reentrancy_import or is_reentrancy_inherited:
            if is_reentrancy_inherited and nonreentrant_uses > 0:
                patterns.append(
                    f"ReentrancyGuard: Inherited and applied to {nonreentrant_uses} function(s). Verify ALL state-changing functions use it."
                )
            elif is_reentrancy_inherited and nonreentrant_uses == 0:
                patterns.append(
                    "WARNING: ReentrancyGuard inherited but NEVER USED in any function - likely missing protection!"
                )
            elif has_reentrancy_import and not is_reentrancy_inherited:
                patterns.append(
                    "WARNING: ReentrancyGuard imported but contract does NOT inherit it - protection not active!"
                )

        # ===== Solidity Version Analysis =====
        version_match = re.search(r"pragma\s+solidity\s+[\^>=<]*(\d+)\.(\d+)", code)
        if version_match:
            major, minor = int(version_match.group(1)), int(version_match.group(2))
            if (major == 0 and minor >= 8) or major > 0:
                patterns.append(
                    f"Solidity {major}.{minor}+ detected - Built-in overflow/underflow protection active"
                )
                # Check for unnecessary SafeMath
                if re.search(r"using\s+SafeMath", code):
                    patterns.append(
                        "NOTE: SafeMath used with Solidity 0.8+ - unnecessary but not harmful"
                    )

        # ===== AccessControl Analysis =====
        has_access_import = re.search(r"import.*AccessControl", code)
        is_access_inherited = re.search(
            r"is\s+AccessControl|is\s+\w+,\s*AccessControl|is\s+AccessControl\s*,", code
        )
        role_checks = re.findall(r"\bonlyRole\b|\bhasRole\b|\b_grantRole\b", code)

        if has_access_import or is_access_inherited:
            if is_access_inherited and len(role_checks) > 0:
                patterns.append(
                    f"AccessControl: Inherited with {len(role_checks)} role check(s) found. Verify ALL admin functions protected."
                )
            elif is_access_inherited and len(role_checks) == 0:
                patterns.append(
                    "WARNING: AccessControl inherited but NO role checks found - protection not applied!"
                )
            elif has_access_import and not is_access_inherited:
                patterns.append(
                    "WARNING: AccessControl imported but NOT inherited - protection not active!"
                )

        # ===== Ownable Analysis =====
        has_ownable_import = re.search(r"import.*Ownable", code)
        is_ownable_inherited = re.search(
            r"is\s+Ownable|is\s+\w+,\s*Ownable|is\s+Ownable\s*,", code
        )
        onlyowner_uses = len(re.findall(r"\bonlyOwner\b", code))

        if has_ownable_import or is_ownable_inherited:
            if is_ownable_inherited and onlyowner_uses > 0:
                patterns.append(
                    f"Ownable: Inherited with {onlyowner_uses} onlyOwner modifier(s) applied"
                )
            elif is_ownable_inherited and onlyowner_uses == 0:
                patterns.append(
                    "WARNING: Ownable inherited but onlyOwner NEVER used - missing access control!"
                )

        # ===== SafeERC20 Analysis =====
        has_safeerc20_import = re.search(r"import.*SafeERC20", code)
        has_safeerc20_using = re.search(r"using\s+SafeERC20\s+for\s+IERC20", code)
        safetransfer_uses = len(
            re.findall(r"\bsafeTransfer\b|\bsafeTransferFrom\b", code)
        )
        unsafe_transfer_uses = len(
            re.findall(r"\.transfer\((?!.*safe)|\.transferFrom\((?!.*safe)", code)
        )

        if has_safeerc20_import or has_safeerc20_using:
            if has_safeerc20_using and safetransfer_uses > 0:
                patterns.append(
                    f"SafeERC20: Active with {safetransfer_uses} safe transfer(s)"
                )
                if unsafe_transfer_uses > 0:
                    patterns.append(
                        f"WARNING: Found {unsafe_transfer_uses} UNSAFE transfer(s) alongside SafeERC20 - inconsistent protection!"
                    )
            elif has_safeerc20_import and not has_safeerc20_using:
                patterns.append(
                    "WARNING: SafeERC20 imported but NOT declared with 'using' - protection not active!"
                )

        # ===== Pausable Analysis =====
        has_pausable_import = re.search(r"import.*Pausable", code)
        is_pausable_inherited = re.search(
            r"is\s+Pausable|is\s+\w+,\s*Pausable|is\s+Pausable\s*,", code
        )
        pausable_modifiers = len(re.findall(r"\bwhenNotPaused\b|\bwhenPaused\b", code))

        if has_pausable_import or is_pausable_inherited:
            if is_pausable_inherited and pausable_modifiers > 0:
                patterns.append(
                    f"Pausable: Inherited with {pausable_modifiers} pause modifier(s) applied"
                )
            elif is_pausable_inherited and pausable_modifiers == 0:
                patterns.append(
                    "WARNING: Pausable inherited but whenNotPaused NEVER used - pause won't work!"
                )

    elif language == "python":
        # ===== SQL Injection Protection =====
        parameterized_queries = len(
            re.findall(r'execute\([^,]*,\s*\(|execute\([^"\']*[\?\%]s', code)
        )
        concat_queries = len(
            re.findall(r'execute\([\'"].*\+.*[\'"]|execute\(f[\'"]', code)
        )

        if parameterized_queries > 0:
            patterns.append(
                f"Parameterized SQL queries: {parameterized_queries} safe query/queries found"
            )
            if concat_queries > 0:
                patterns.append(
                    f"WARNING: Found {concat_queries} string-concatenated query/queries - SQL injection risk!"
                )

        # ===== ORM Usage =====
        if re.search(r"from\s+sqlalchemy|import\s+sqlalchemy", code):
            patterns.append(
                "SQLAlchemy ORM detected - generally safe from SQL injection"
            )

        # ===== Rate Limiting =====
        has_limiter_import = re.search(r"from\s+flask_limiter|import.*Limiter", code)
        limiter_decorators = len(re.findall(r"@limiter\.limit|@.*limit\(", code))

        if has_limiter_import:
            if limiter_decorators > 0:
                patterns.append(
                    f"Rate limiting: Active on {limiter_decorators} endpoint(s)"
                )
            else:
                patterns.append(
                    "WARNING: Flask-Limiter imported but NO @limiter.limit decorators found!"
                )

        # ===== Secure Comparison =====
        if re.search(r"hmac\.compare_digest|constant_time_compare", code):
            patterns.append("Timing-safe comparison: Using hmac.compare_digest")

        # ===== Input Validation =====
        has_validator = re.search(
            r"from\s+.*\s+import\s+.*[Vv]alidator|@.*validate", code
        )
        if has_validator:
            patterns.append("Input validation framework detected")

        # ===== CORS Configuration =====
        if re.search(r"from\s+flask_cors\s+import\s+CORS", code):
            if re.search(r"CORS\(app\)(?!\s*,)", code):
                patterns.append(
                    "WARNING: CORS enabled for ALL origins - security risk!"
                )
            else:
                patterns.append("CORS: Configured (verify origin restrictions)")

    elif language in ["javascript", "typescript"]:
        # ===== CSRF Protection =====
        has_csrf_import = re.search(r'require\([\'"]csurf|import.*csurf', code)
        csrf_middleware = re.search(r"csrfProtection|csurf\(\)", code)
        csrf_usage = len(re.findall(r"csrfProtection|csrfToken", code))

        if has_csrf_import:
            if csrf_middleware and csrf_usage > 1:
                patterns.append(f"CSRF protection: Active with {csrf_usage} usage(s)")
            elif has_csrf_import and not csrf_middleware:
                patterns.append(
                    "WARNING: csurf imported but NOT configured as middleware!"
                )

        # ===== Input Sanitization =====
        has_dompurify = re.search(
            r"DOMPurify|require.*dompurify|import.*dompurify", code
        )
        sanitize_calls = len(re.findall(r"\.sanitize\(|sanitize\(", code))

        if has_dompurify:
            if sanitize_calls > 0:
                patterns.append(
                    f"Input sanitization: DOMPurify used {sanitize_calls} time(s)"
                )
            else:
                patterns.append(
                    "WARNING: DOMPurify imported but .sanitize() NEVER called!"
                )

        # ===== Helmet Security Headers =====
        has_helmet = re.search(r'require\([\'"]helmet|import.*helmet', code)
        helmet_usage = re.search(r"app\.use\(helmet", code)

        if has_helmet:
            if helmet_usage:
                patterns.append("Helmet: Security headers configured")
            else:
                patterns.append("WARNING: Helmet imported but NOT used with app.use()!")

        # ===== Rate Limiting =====
        has_rate_limit = re.search(r"express-rate-limit|rateLimit", code)
        if has_rate_limit:
            patterns.append("Rate limiting: Configured")

        # ===== JWT Algorithm Specification =====
        jwt_verify_secure = re.search(
            r"jwt\.verify\([^,]+,\s*[^,]+,\s*\{\s*algorithms", code
        )
        jwt_verify_insecure = re.search(
            r"jwt\.verify\([^,]+,\s*[^,]+\)(?!\s*,\s*\{)", code
        )

        if jwt_verify_secure:
            patterns.append("JWT: Algorithm specified in verification")
        if jwt_verify_insecure:
            patterns.append(
                "WARNING: JWT verification WITHOUT algorithm specification - security risk!"
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
- Security imports/inheritance do NOT guarantee protection
- Verify that security measures are ACTUALLY APPLIED to vulnerable functions
- Include confidence levels for each finding
- Report REAL vulnerabilities with concrete exploit scenarios"""


def get_analysis_prompt(code: str, language: str, filepath: str) -> str:
    """Get enhanced analysis prompt with intelligent context awareness"""

    # Detect security patterns FIRST
    security_patterns = detect_security_patterns(code, language)

    # Build context section
    context_section = ""
    if security_patterns:
        patterns_text = "\n".join(f"- {pattern}" for pattern in security_patterns)
        context_section = f"""
## DETECTED SECURITY PATTERNS AND CONFIGURATIONS:

{patterns_text}

CRITICAL ANALYSIS INSTRUCTIONS:

1. These patterns show what's IMPORTED/INHERITED, not necessarily what's USED correctly
2. You MUST verify that security measures are ACTUALLY APPLIED:
   - If ReentrancyGuard is inherited, check EACH state-changing function has nonReentrant
   - If AccessControl is inherited, check EACH admin function has proper role modifiers
   - If SafeERC20 is declared, check ALL token transfers use safe methods
   
3. REPORT vulnerabilities when:
   - Security library is imported but NOT inherited
   - Security library is inherited but modifiers are MISSING on vulnerable functions
   - Security library is used INCONSISTENTLY (some functions protected, others not)
   - Security measure is applied INCORRECTLY

4. EXAMPLES of what to flag:
   - Contract inherits ReentrancyGuard but deposit() lacks nonReentrant modifier
   - Contract has AccessControl but updateOracle() has NO access control
   - Contract uses SafeERC20 in some places but plain transfer() in others
   - JWT verification without algorithm specification despite importing jwt library

DO NOT ASSUME PROTECTION EXISTS JUST BECAUSE A LIBRARY IS IMPORTED!
Verify actual usage on EVERY potentially vulnerable function!

"""

    # Determine category
    category = "web3" if language in ["solidity", "rust"] else "web2"
    vulns = WEB3_VULNERABILITIES if category == "web3" else WEB2_VULNERABILITIES

    # Get language-specific examples
    examples = LANGUAGE_EXAMPLES.get(language, "")

    # Build vulnerability list
    vuln_list = "\n".join(f"- {v}" for v in vulns)

    # Build the prompt
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

2. Verification Checklist:
   - Check if imported security libraries are actually INHERITED
   - Check if inherited security features are actually USED
   - Check if security modifiers are applied to ALL relevant functions
   - Check for inconsistent security patterns (protected in some places, not others)

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
   - Style issues or code quality concerns
   - Theoretical vulnerabilities without concrete exploit path
   - Issues that are ACTUALLY properly mitigated (verify the mitigation exists and is correct)
   - Generic security advice without specific vulnerability

Be precise, verify security measures are ACTUALLY APPLIED, and report REAL vulnerabilities!"""

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
