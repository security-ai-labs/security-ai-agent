"""
Aggressive security analysis prompts - Zero tolerance for vulnerabilities
"""


def get_function_level_analysis_prompt(
    function_code: str, function_name: str, contract_context: str, language: str
) -> str:
    """
    Hyper-focused analysis on a SINGLE function
    Forces LLM to check every line
    """

    checklist = ""
    if language == "solidity":
        checklist = """
## MANDATORY CHECKS FOR THIS FUNCTION:

1. REENTRANCY:
   - Does it make external calls? (transfer, call, send)
   - Are state variables updated BEFORE external calls?
   - Does it have 'nonReentrant' modifier?
   - VERDICT: VULNERABLE / SAFE

2. ACCESS CONTROL:
   - Does it modify contract state?
   - Does it have access control modifier? (onlyOwner, onlyRole, etc)
   - Can anyone call it?
   - VERDICT: VULNERABLE / SAFE

3. UNCHECKED EXTERNAL CALLS:
   - Does it call external contracts?
   - Are return values checked with 'require'?
   - Uses SafeERC20 or raw transfer()?
   - VERDICT: VULNERABLE / SAFE

4. INTEGER OVERFLOW/UNDERFLOW:
   - Math operations present?
   - Using SafeMath or Solidity 0.8+?
   - Any unchecked blocks?
   - VERDICT: VULNERABLE / SAFE

5. INPUT VALIDATION:
   - Takes user input?
   - All inputs validated with require()?
   - Zero-address checks?
   - VERDICT: VULNERABLE / SAFE
"""
    elif language == "python":
        checklist = """
## MANDATORY CHECKS FOR THIS FUNCTION:

1. SQL INJECTION:
   - Executes SQL queries?
   - Uses parameterized queries or string concatenation?
   - VERDICT: VULNERABLE / SAFE

2. COMMAND INJECTION:
   - Executes system commands?
   - Uses user input in commands?
   - VERDICT: VULNERABLE / SAFE

3. PATH TRAVERSAL:
   - File operations?
   - Input sanitization?
   - VERDICT: VULNERABLE / SAFE

4. AUTHENTICATION/AUTHORIZATION:
   - Requires authentication?
   - Has decorators like @require_auth?
   - VERDICT: VULNERABLE / SAFE
"""
    elif language in ["javascript", "typescript"]:
        checklist = """
## MANDATORY CHECKS FOR THIS FUNCTION:

1. XSS:
   - Renders user input?
   - Uses innerHTML or dangerouslySetInnerHTML?
   - Input sanitized?
   - VERDICT: VULNERABLE / SAFE

2. CSRF:
   - State-changing operation?
   - CSRF protection enforced?
   - VERDICT: VULNERABLE / SAFE

3. AUTHORIZATION:
   - Protected endpoint?
   - Authentication checked?
   - VERDICT: VULNERABLE / SAFE
"""

    return f"""You are a ruthless security auditor. Analyze THIS SPECIFIC FUNCTION ONLY.

LANGUAGE: {language}
FUNCTION NAME: {function_name}
CONTRACT/FILE CONTEXT: {contract_context}

FUNCTION CODE:
{function_code}

{checklist}

CRITICAL INSTRUCTIONS:
1. Go through EVERY line of this function
2. Answer EVERY check in the checklist above
3. If you find even ONE vulnerability, report it
4. Don't assume anything is safe - verify it
5. If a security measure is missing, it's VULNERABLE

Output in JSON:
{{
  "function_name": "{function_name}",
  "vulnerabilities_found": [
    {{
      "type": "Reentrancy|Access Control|SQL Injection|etc",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "confidence": "HIGH",
      "line_number": 123,
      "specific_code": "exact line of vulnerable code",
      "why_vulnerable": "concrete reason",
      "how_to_exploit": "step by step attack",
      "fix": "exact code fix"
    }}
  ],
  "checklist_results": {{
    "reentrancy": "SAFE|VULNERABLE",
    "access_control": "SAFE|VULNERABLE",
    ...
  }}
}}

BE RUTHLESS. IF IT'S NOT EXPLICITLY PROTECTED, IT'S VULNERABLE!
"""


def get_static_pattern_checks() -> dict:
    """
    Returns regex patterns for KNOWN vulnerabilities
    These are 100% confident detections
    """
    return {
        "solidity": {
            "missing_nonreentrant_on_deposit": {
                "pattern": r"function\s+deposit\s*\([^)]*\)[^{]*\{(?:(?!nonReentrant).)*?\.transfer",
                "severity": "CRITICAL",
                "description": "deposit() function makes external call without nonReentrant modifier",
                "confidence": "HIGH",
            },
            "missing_access_control": {
                "pattern": r"function\s+(update|set|change|modify)\w*\s*\([^)]*\)\s+external[^{]*\{(?!.*onlyRole)(?!.*onlyOwner)",
                "severity": "HIGH",
                "description": "Admin function lacks access control modifier",
                "confidence": "HIGH",
            },
            "unchecked_transfer": {
                "pattern": r'IERC20\([^)]+\)\.transfer\([^)]+\)(?!\s*,\s*["\'])',
                "severity": "HIGH",
                "description": "ERC20 transfer without checking return value",
                "confidence": "MEDIUM",
            },
        },
        "python": {
            "sql_injection": {
                "pattern": r'execute\s*\(\s*[f"\'].*\+.*[f"\']|execute\s*\(\s*f["\']',
                "severity": "CRITICAL",
                "description": "SQL query uses string concatenation",
                "confidence": "HIGH",
            },
            "command_injection": {
                "pattern": r"os\.system\s*\(.*\+|subprocess.*shell\s*=\s*True",
                "severity": "CRITICAL",
                "description": "Command injection via os.system or shell=True",
                "confidence": "HIGH",
            },
        },
        "javascript": {
            "xss": {
                "pattern": r"\.innerHTML\s*=(?!.*sanitize)|dangerouslySetInnerHTML",
                "severity": "HIGH",
                "description": "Potential XSS via innerHTML without sanitization",
                "confidence": "MEDIUM",
            },
        },
    }
