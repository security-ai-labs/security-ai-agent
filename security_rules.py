import re
from typing import List, Dict
from enum import Enum

class ChainType(Enum):
    """Supported blockchain chains"""
    ETHEREUM = "ethereum"
    SOLANA = "solana"
    POLYGON = "polygon"
    BINANCE = "binance"
    AVALANCHE = "avalanche"
    WEB2 = "web2"

class VulnerabilitySeverity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class SecurityRules:
    """Enhanced security vulnerability detection rules for Web2 & Web3"""
    
    # ==================== WEB2 PATTERNS ====================
    
    SQL_INJECTION_PATTERNS = [
        r"execute\s*\(\s*['\"].*\+",
        r"query\s*\(\s*['\"].*\+",
        r"f['\"].*SELECT.*WHERE.*\{",
        r"SQL.*\+.*user|input.*\+.*query",
        r"db\..*\(\s*['\"].*\+",
    ]
    
    XSS_PATTERNS = [
        r"innerHTML\s*=",
        r"\.html\s*\(",
        r"dangerouslySetInnerHTML",
        r"eval\s*\(",
        r"Function\s*\(\s*['\"].*code",
        r"document\.write",
        r"innerHTML\s*\+=",
    ]
    
    CSRF_PATTERNS = [
        r"POST|PUT|DELETE(?!.*csrf|!.*token)",
        r"fetch\s*\(.*POST.*(?!.*csrf)",
        r"axios\s*\.post\s*\(.*(?!.*csrf)",
    ]
    
    INSECURE_DESERIALIZATION = [
        r"pickle\.loads|yaml\.load(?!_safe)|json\.loads.*user",
        r"unserialize\s*\(",
        r"ObjectInputStream",
    ]
    
    HARDCODED_SECRETS = [
        r"password\s*=\s*['\"][^'\"]+['\"]",
        r"api[_-]?key\s*=\s*['\"][a-zA-Z0-9_\-]{20,}['\"]",
        r"secret[_-]?key\s*=\s*['\"][^'\"]+['\"]",
        r"private[_-]?key\s*=\s*['\"][a-f0-9]{64}['\"]",
    ]
    
    BROKEN_AUTH = [
        r"if\s*\(.*password\s*==|if\s*\(.*auth.*==\s*true",
        r"md5\s*\(.*password|sha1\s*\(.*password",
        r"jwt.*decode.*verify\s*=\s*false",
    ]
    
    # ==================== ETHEREUM/EVM PATTERNS ====================
    
    REENTRANCY_PATTERNS = [
        r"\.transfer\s*\(\s*\)|\.send\s*\(\s*\)",
        r"\.call\s*\{.*value.*\}\s*\(\s*\)",
        r"msg\.sender\.call|recipient\.call",
        r"balances?\[.*\]\s*\+=.*call|balances?\[.*\]\s*-=.*call",
    ]
    
    INTEGER_OVERFLOW_PATTERNS = [
        r"pragma solidity\s+\^?0\.[0-7]",  # Solidity < 0.8
        r"SafeMath.*not imported|SafeMath.*not used",
        r"\+=\s*\w+|\-=\s*\w+(?!.*SafeMath)",
        r"uint\d+.*\+\s*\w+(?!.*require|!.*SafeMath)",
    ]
    
    UNCHECKED_CALL_PATTERNS = [
        r"\.call\s*\(\s*\)(?!\s*require|!.*assert)",
        r"\.delegatecall\s*\(\s*\)(?!\s*require)",
        r"address\s*\(.*\)\.call(?!.*require)",
    ]
    
    DELEGATECALL_INJECTION = [
        r"delegatecall\s*\(.*address\s*\(\s*.*\(\s*\)\)",
        r"delegatecall.*user|delegatecall.*input",
    ]
    
    TIMESTAMP_DEPENDENCY = [
        r"block\.timestamp|now(?=\s*[><=!])",
        r"if\s*\(\s*block\.timestamp.*\)",
        r"block\.number.*[><=!]",
    ]
    
    FRONT_RUNNING = [
        r"tx\.gasprice|block\.basefee",
        r"mempool|pending.*transaction",
        r"nonce.*manipulation|ordering.*attack",
    ]
    
    ZERO_ADDRESS_CHECK = [
        r"require\s*\(\s*_\w+\s*!=\s*address\s*\(0\)\s*\)(?!.*true)",
        r"msg\.sender\s*=\s*address|_to\s*=\s*address\s*\(0\)(?!.*require)",
    ]
    
    LACK_OF_ACCESS_CONTROL = [
        r"function\s+\w+\s*\(.*\)\s*(?:public|external|payable)(?!.*onlyOwner|!.*require.*msg\.sender)",
        r"transfer\s*\(.*\)(?!.*onlyOwner|!.*require)",
        r"withdraw\s*\(.*\)(?!.*onlyOwner|!.*require)",
    ]
    
    FLASHLOAN_ATTACK = [
        r"flashLoan\s*\(|receiveFlashLoan\s*\(",
        r"balance.*before|balance.*after(?!.*assert|!.*require)",
    ]
    
    # ==================== SOLANA PATTERNS ====================
    
    SOLANA_SIGNER_CHECK = [
        r"is_signer.*false|is_signer.*=.*false",
        r"is_signed.*=.*false|signed.*=.*false",
    ]
    
    SOLANA_OWNER_CHECK = [
        r"owner.*check(?!.*true|!.*assert)|assert_owned_by(?!.*)",
        r"if.*owner.*!=(?!.*panic|!.*err)",
    ]
    
    SOLANA_ACCOUNT_VALIDATION = [
        r"account.*validation(?!.*implemented|!.*true)",
        r"UncheckedAccount|Unchecked\s*<\s*Account",
    ]
    
    SOLANA_ARITHMETIC = [
        r"\+=\s*\w+|\-=\s*\w+(?!.*checked_|!.*saturating_)",
        r"multiply\s*\(.*\)(?!.*checked)",
    ]
    
    SOLANA_LAMPORT_CHECKS = [
        r"lamports.*transfer(?!.*rent_exempt|!.*assert)",
        r"rent_exempt.*check(?!.*true|!.*require)",
    ]
    
    # ==================== POLYGON/LAYER2 PATTERNS ====================
    
    POLYGON_BRIDGE_ISSUES = [
        r"bridge.*transfer(?!.*verify|!.*validate)",
        r"cross.*chain.*transfer(?!.*check)",
    ]
    
    POLYGON_SEQUENCER_DEPENDENCY = [
        r"block\.timestamp(?!.*sequencer|!.*validated)",
    ]
    
    # ==================== DEFI SPECIFIC ====================
    
    PRICE_ORACLE_RISK = [
        r"getPrice\s*\(|price\s*\)(?!.*chainlink|!.*aggregator)",
        r"oracle\.price|price.*feed(?!.*verified)",
        r"uniswap.*getAmountsOut(?!.*slippage|!.*minAmountOut)",
    ]
    
    SLIPPAGE_PROTECTION = [
        r"swap.*\(.*\)(?!.*minAmountOut|!.*slippage|!.*deadline)",
        r"addLiquidity\s*\(.*\)(?!.*minAmountA|!.*minAmountB)",
    ]
    
    ARBITRARY_TRANSFER = [
        r"transferFrom\s*\(.*msg\.sender.*\)(?!.*require.*allowance)",
        r"burn\s*\(.*\)(?!.*onlyOwner|!.*require)",
    ]
    
    # ==================== NFT SPECIFIC ====================
    
    NFT_REENTRANCY_MINT = [
        r"safeMint\s*\(.*\)(?!.*nonReentrant|!.*mutex)",
        r"_mint\s*\(.*\)(?!.*checked|!.*safe)",
    ]
    
    NFT_UNAUTHORIZED_BURN = [
        r"burn\s*\(.*\)(?!.*onlyOwner|!.*require.*msg\.sender)",
    ]
    
    NFT_METADATA_CENTRALIZATION = [
        r"baseURI.*http|metadata.*centralized",
    ]
    
    def __init__(self):
        """Initialize security rules"""
        self.chain_type = ChainType.WEB2
    
    def detect_chain_type(self, content: str) -> ChainType:
        """Detect which blockchain chain the code is for"""
        content_lower = content.lower()
        
        if "contract " in content_lower or "pragma solidity" in content_lower:
            if "interface" in content_lower or "event" in content_lower or "emit" in content_lower:
                return ChainType.ETHEREUM
        
        if "@program" in content or "use anchor_lang" in content:
            return ChainType.SOLANA
        
        if "polygon" in content_lower or "matic" in content_lower:
            return ChainType.POLYGON
        
        if "bsc" in content_lower or "binance" in content_lower:
            return ChainType.BINANCE
        
        if "avalanche" in content_lower or "avax" in content_lower:
            return ChainType.AVALANCHE
        
        return ChainType.WEB2
    
    def _check_patterns(self, content: str, patterns: List[str]) -> bool:
        """Check if content matches any patterns"""
        for pattern in patterns:
            try:
                if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                    return True
            except re.error:
                # Skip invalid regex patterns
                continue
        return False
    
    # ==================== WEB2 CHECKS ====================
    
    def has_sql_injection_risk(self, content: str) -> Dict:
        return {
            "found": self._check_patterns(content, self.SQL_INJECTION_PATTERNS),
            "severity": VulnerabilitySeverity.HIGH,
            "type": "SQL Injection",
            "description": "User input directly concatenated to SQL queries"
        }
    
    def has_xss_risk(self, content: str) -> Dict:
        return {
            "found": self._check_patterns(content, self.XSS_PATTERNS),
            "severity": VulnerabilitySeverity.HIGH,
            "type": "Cross-Site Scripting (XSS)",
            "description": "Unsafe DOM manipulation or script injection"
        }
    
    def has_csrf_risk(self, content: str) -> Dict:
        return {
            "found": self._check_patterns(content, self.CSRF_PATTERNS),
            "severity": VulnerabilitySeverity.MEDIUM,
            "type": "Missing CSRF Protection",
            "description": "State-changing requests without CSRF tokens"
        }
    
    def has_insecure_deserialization(self, content: str) -> Dict:
        return {
            "found": self._check_patterns(content, self.INSECURE_DESERIALIZATION),
            "severity": VulnerabilitySeverity.CRITICAL,
            "type": "Insecure Deserialization",
            "description": "Unsafe deserialization of untrusted data"
        }
    
    def has_hardcoded_secrets(self, content: str) -> Dict:
        return {
            "found": self._check_patterns(content, self.HARDCODED_SECRETS),
            "severity": VulnerabilitySeverity.CRITICAL,
            "type": "Hardcoded Secrets",
            "description": "API keys, passwords, or private keys in source code"
        }
    
    def has_broken_authentication(self, content: str) -> Dict:
        return {
            "found": self._check_patterns(content, self.BROKEN_AUTH),
            "severity": VulnerabilitySeverity.CRITICAL,
            "type": "Broken Authentication",
            "description": "Weak or bypassed authentication mechanisms"
        }
    
    # ==================== ETHEREUM/EVM CHECKS ====================
    
    def has_reentrancy_risk(self, content: str) -> Dict:
        return {
            "found": self._check_patterns(content, self.REENTRANCY_PATTERNS),
            "severity": VulnerabilitySeverity.CRITICAL,
            "type": "Reentrancy Attack",
            "description": "External call before state update - vulnerable to reentrancy"
        }
    
    def has_integer_overflow_risk(self, content: str) -> Dict:
        return {
            "found": self._check_patterns(content, self.INTEGER_OVERFLOW_PATTERNS),
            "severity": VulnerabilitySeverity.CRITICAL,
            "type": "Integer Overflow/Underflow",
            "description": "Arithmetic operations without SafeMath or Solidity < 0.8"
        }
    
    def has_unchecked_call_risk(self, content: str) -> Dict:
        return {
            "found": self._check_patterns(content, self.UNCHECKED_CALL_PATTERNS),
            "severity": VulnerabilitySeverity.HIGH,
            "type": "Unchecked Low-Level Call",
            "description": "Call without checking return value"
        }
    
    def has_delegatecall_injection(self, content: str) -> Dict:
        return {
            "found": self._check_patterns(content, self.DELEGATECALL_INJECTION),
            "severity": VulnerabilitySeverity.CRITICAL,
            "type": "Delegatecall Injection",
            "description": "Dynamic delegatecall to user-controlled address"
        }
    
    def has_timestamp_dependency(self, content: str) -> Dict:
        return {
            "found": self._check_patterns(content, self.TIMESTAMP_DEPENDENCY),
            "severity": VulnerabilitySeverity.MEDIUM,
            "type": "Timestamp Dependency",
            "description": "Logic depends on block.timestamp which can be manipulated"
        }
    
    def has_front_running_risk(self, content: str) -> Dict:
        return {
            "found": self._check_patterns(content, self.FRONT_RUNNING),
            "severity": VulnerabilitySeverity.HIGH,
            "type": "Front-Running Vulnerability",
            "description": "Vulnerable to transaction ordering manipulation"
        }
    
    def has_zero_address_check(self, content: str) -> Dict:
        return {
            "found": self._check_patterns(content, self.ZERO_ADDRESS_CHECK),
            "severity": VulnerabilitySeverity.MEDIUM,
            "type": "Missing Zero Address Check",
            "description": "No validation for zero address (0x0)"
        }
    
    def has_access_control_issue(self, content: str) -> Dict:
        return {
            "found": self._check_patterns(content, self.LACK_OF_ACCESS_CONTROL),
            "severity": VulnerabilitySeverity.HIGH,
            "type": "Missing Access Control",
            "description": "Critical functions missing access control modifiers"
        }
    
    def has_flashloan_risk(self, content: str) -> Dict:
        return {
            "found": self._check_patterns(content, self.FLASHLOAN_ATTACK),
            "severity": VulnerabilitySeverity.CRITICAL,
            "type": "Flash Loan Attack",
            "description": "Vulnerable to flash loan attacks - unsafe balance checks"
        }
    
    # ==================== SOLANA CHECKS ====================
    
    def has_solana_signer_issue(self, content: str) -> Dict:
        return {
            "found": self._check_patterns(content, self.SOLANA_SIGNER_CHECK),
            "severity": VulnerabilitySeverity.CRITICAL,
            "type": "Missing Signer Check (Solana)",
            "description": "Account not verified as signer - signature forging possible"
        }
    
    def has_solana_owner_issue(self, content: str) -> Dict:
        return {
            "found": self._check_patterns(content, self.SOLANA_OWNER_CHECK),
            "severity": VulnerabilitySeverity.CRITICAL,
            "type": "Missing Owner Check (Solana)",
            "description": "Owner validation missing or incomplete"
        }
    
    def has_solana_account_validation_issue(self, content: str) -> Dict:
        return {
            "found": self._check_patterns(content, self.SOLANA_ACCOUNT_VALIDATION),
            "severity": VulnerabilitySeverity.HIGH,
            "type": "Missing Account Validation (Solana)",
            "description": "Accounts not properly validated - arbitrary account injection"
        }
    
    def has_solana_arithmetic_issue(self, content: str) -> Dict:
        return {
            "found": self._check_patterns(content, self.SOLANA_ARITHMETIC),
            "severity": VulnerabilitySeverity.HIGH,
            "type": "Unchecked Arithmetic (Solana)",
            "description": "Arithmetic operations without overflow checks"
        }
    
    def has_solana_rent_exempt_issue(self, content: str) -> Dict:
        return {
            "found": self._check_patterns(content, self.SOLANA_LAMPORT_CHECKS),
            "severity": VulnerabilitySeverity.MEDIUM,
            "type": "Rent Exempt Check Missing (Solana)",
            "description": "Lamport transfers may violate rent exemption requirements"
        }
    
    # ==================== DEFI CHECKS ====================
    
    def has_oracle_risk(self, content: str) -> Dict:
        return {
            "found": self._check_patterns(content, self.PRICE_ORACLE_RISK),
            "severity": VulnerabilitySeverity.CRITICAL,
            "type": "Price Oracle Manipulation",
            "description": "Reliance on unverified or manipulable price feeds"
        }
    
    def has_slippage_risk(self, content: str) -> Dict:
        return {
            "found": self._check_patterns(content, self.SLIPPAGE_PROTECTION),
            "severity": VulnerabilitySeverity.MEDIUM,
            "type": "Missing Slippage Protection",
            "description": "Swaps without slippage limits - vulnerable to sandwich attacks"
        }
    
    def has_arbitrary_token_transfer(self, content: str) -> Dict:
        return {
            "found": self._check_patterns(content, self.ARBITRARY_TRANSFER),
            "severity": VulnerabilitySeverity.HIGH,
            "type": "Arbitrary Token Transfer",
            "description": "Token transfers not properly validated"
        }
    
    # ==================== NFT CHECKS ====================
    
    def has_nft_reentrancy_issue(self, content: str) -> Dict:
        return {
            "found": self._check_patterns(content, self.NFT_REENTRANCY_MINT),
            "severity": VulnerabilitySeverity.CRITICAL,
            "type": "NFT Reentrancy (Minting)",
            "description": "Mint function vulnerable to reentrancy attacks"
        }
    
    def has_nft_burn_issue(self, content: str) -> Dict:
        return {
            "found": self._check_patterns(content, self.NFT_UNAUTHORIZED_BURN),
            "severity": VulnerabilitySeverity.HIGH,
            "type": "Unauthorized NFT Burn",
            "description": "Burn function missing access control"
        }
    
    def has_nft_metadata_issue(self, content: str) -> Dict:
        return {
            "found": self._check_patterns(content, self.NFT_METADATA_CENTRALIZATION),
            "severity": VulnerabilitySeverity.MEDIUM,
            "type": "Centralized Metadata",
            "description": "NFT metadata hosted centrally - single point of failure"
        }
    
    def run_all_checks(self, content: str) -> List[Dict]:
        """Run all vulnerability checks and return findings"""
        checks = [
            # Web2
            self.has_sql_injection_risk(content),
            self.has_xss_risk(content),
            self.has_csrf_risk(content),
            self.has_insecure_deserialization(content),
            self.has_hardcoded_secrets(content),
            self.has_broken_authentication(content),
            # Ethereum/EVM
            self.has_reentrancy_risk(content),
            self.has_integer_overflow_risk(content),
            self.has_unchecked_call_risk(content),
            self.has_delegatecall_injection(content),
            self.has_timestamp_dependency(content),
            self.has_front_running_risk(content),
            self.has_zero_address_check(content),
            self.has_access_control_issue(content),
            self.has_flashloan_risk(content),
            # Solana
            self.has_solana_signer_issue(content),
            self.has_solana_owner_issue(content),
            self.has_solana_account_validation_issue(content),
            self.has_solana_arithmetic_issue(content),
            self.has_solana_rent_exempt_issue(content),
            # DeFi
            self.has_oracle_risk(content),
            self.has_slippage_risk(content),
            self.has_arbitrary_token_transfer(content),
            # NFT
            self.has_nft_reentrancy_issue(content),
            self.has_nft_burn_issue(content),
            self.has_nft_metadata_issue(content),
        ]
        
        # Filter only found vulnerabilities
        return [check for check in checks if check.get('found')]