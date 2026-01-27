import re
from typing import List, Dict, Tuple
from enum import Enum

class ChainType(Enum):
    """Supported blockchain chains"""
    ETHEREUM = "ethereum"
    SOLANA = "solana"
    POLYGON = "polygon"
    BINANCE = "binance"
    AVALANCHE = "avalanche"
    ARBITRUM = "arbitrum"
    OPTIMISM = "optimism"
    BASE = "base"
    WEB2 = "web2"
    UNKNOWN = "unknown"

class VulnerabilitySeverity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class VulnerabilityCategory(Enum):
    """Vulnerability categories"""
    WEB2 = "web2"
    WEB3_CORE = "web3_core"
    WEB3_ETHEREUM = "web3_ethereum"
    WEB3_SOLANA = "web3_solana"
    WEB3_DEFI = "web3_defi"
    WEB3_NFT = "web3_nft"
    CROSS_CHAIN = "cross_chain"
    CODE_GENERATION = "code_generation"
    CRYPTOGRAPHY = "cryptography"
    ARCHITECTURE = "architecture"

class SecurityRules:
    """
    Comprehensive security vulnerability detection rules
    Covers Web2, Web3, and hybrid code generation issues
    """
    
    def __init__(self):
        self.rules_db = {}
        self._initialize_all_rules()
    
    def _initialize_all_rules(self):
        """Initialize all rule databases"""
        self.rules_db = {
            'web2': self._get_web2_rules(),
            'web3_core': self._get_web3_core_rules(),
            'web3_ethereum': self._get_ethereum_rules(),
            'web3_solana': self._get_solana_rules(),
            'web3_defi': self._get_defi_rules(),
            'web3_nft': self._get_nft_rules(),
            'web3_privacy': self._get_privacy_rules(),
            'cross_chain': self._get_cross_chain_rules(),
            'code_generation': self._get_code_generation_rules(),
            'cryptography': self._get_cryptography_rules(),
            'architecture': self._get_architecture_rules(),
        }
    
    # ==================== WEB2 RULES ====================
    
    def _get_web2_rules(self) -> Dict:
        """All Web2 security rules"""
        return {
            'sql_injection': {
                'patterns': [
                    r"execute\s*\(\s*['\"].*\+",
                    r"query\s*\(\s*['\"].*\+",
                    r"f['\"].*SELECT.*WHERE.*\{",
                    r"db\..*\(\s*['\"].*\+",
                    r"SQL.*\+.*user|input.*\+.*query",
                    r"\.execute\s*\(['\"].*\+",
                    r"PreparedStatement.*\+",
                    r"cursor\.execute\s*\(['\"].*\+",
                ],
                'severity': VulnerabilitySeverity.CRITICAL,
                'category': VulnerabilityCategory.WEB2,
                'description': 'User input directly concatenated to SQL queries',
                'remediation': 'Use parameterized queries and prepared statements',
            },
            'xss': {
                'patterns': [
                    r"innerHTML\s*=",
                    r"\.html\s*\(",
                    r"dangerouslySetInnerHTML",
                    r"eval\s*\(",
                    r"Function\s*\(\s*['\"].*code",
                    r"document\.write",
                    r"innerHTML\s*\+=",
                    r"insertAdjacentHTML",
                    r"outerHTML\s*=",
                ],
                'severity': VulnerabilitySeverity.HIGH,
                'category': VulnerabilityCategory.WEB2,
                'description': 'Unsafe DOM manipulation or script injection',
                'remediation': 'Sanitize inputs and use textContent instead of innerHTML',
            },
            'csrf': {
                'patterns': [
                    r"POST|PUT|DELETE(?!.*csrf|!.*token)",
                    r"fetch\s*\(.*POST.*(?!.*csrf)",
                    r"axios\s*\.post\s*\(.*(?!.*csrf)",
                    r"\.post\s*\(.*(?!.*token|!.*nonce)",
                ],
                'severity': VulnerabilitySeverity.MEDIUM,
                'category': VulnerabilityCategory.WEB2,
                'description': 'State-changing requests without CSRF tokens',
                'remediation': 'Implement CSRF tokens for all POST/PUT/DELETE requests',
            },
            'insecure_deserialization': {
                'patterns': [
                    r"pickle\.loads",
                    r"yaml\.load(?!_safe)",
                    r"json\.loads.*user",
                    r"unserialize\s*\(",
                    r"ObjectInputStream",
                    r"Marshal\.load",
                ],
                'severity': VulnerabilitySeverity.CRITICAL,
                'category': VulnerabilityCategory.WEB2,
                'description': 'Unsafe deserialization of untrusted data',
                'remediation': 'Use safe deserialization methods (pickle_safe, yaml.safe_load)',
            },
            'hardcoded_secrets': {
                'patterns': [
                    r"password\s*=\s*['\"][^'\"]{5,}['\"]",
                    r"api[_-]?key\s*=\s*['\"][a-zA-Z0-9_\-]{10,}['\"]",
                    r"secret[_-]?key\s*=\s*['\"][^'\"]+['\"]",
                    r"private[_-]?key\s*=\s*['\"][a-f0-9]{64}['\"]",
                    r"token\s*=\s*['\"][a-zA-Z0-9_\-]{20,}['\"]",
                    r"auth.*=\s*['\"][^'\"]{10,}['\"]",
                    r"credentials\s*=\s*{.*password",
                ],
                'severity': VulnerabilitySeverity.CRITICAL,
                'category': VulnerabilityCategory.WEB2,
                'description': 'API keys, passwords, or secrets in source code',
                'remediation': 'Use environment variables or secret management systems',
            },
            'broken_authentication': {
                'patterns': [
                    r"if\s*\(.*password\s*==\s*.*\)",
                    r"if\s*\(.*auth.*==\s*true\)",
                    r"md5\s*\(.*password",
                    r"sha1\s*\(.*password",
                    r"jwt.*decode.*verify\s*=\s*false",
                    r"bypass.*auth|skip.*auth",
                ],
                'severity': VulnerabilitySeverity.CRITICAL,
                'category': VulnerabilityCategory.WEB2,
                'description': 'Weak or bypassed authentication mechanisms',
                'remediation': 'Use strong hashing (bcrypt, Argon2) and proper JWT verification',
            },
            'path_traversal': {
                'patterns': [
                    r"\.\.\/|\.\.\\",
                    r"open\s*\(\s*.*user.*\)",
                    r"readFile\s*\(\s*.*user.*\)",
                    r"__file__.*user|__dir__.*user",
                ],
                'severity': VulnerabilitySeverity.HIGH,
                'category': VulnerabilityCategory.WEB2,
                'description': 'Path traversal vulnerability allowing file access',
                'remediation': 'Validate and sanitize file paths, use allowlists',
            },
            'command_injection': {
                'patterns': [
                    r"exec\s*\(.*\+",
                    r"os\.system\s*\(.*\+",
                    r"subprocess\s*\..*\(.*shell\s*=\s*True",
                    r"shell_exec|system\s*\(.*user",
                ],
                'severity': VulnerabilitySeverity.CRITICAL,
                'category': VulnerabilityCategory.WEB2,
                'description': 'Command injection vulnerability',
                'remediation': 'Use parameterized system calls, avoid shell=True',
            },
            'ssrf': {
                'patterns': [
                    r"requests\.get\s*\(\s*.*user",
                    r"curl\s*\(.*\$.*\)",
                    r"http\.get\s*\(.*user",
                    r"fetch\s*\(.*user.*url",
                ],
                'severity': VulnerabilitySeverity.HIGH,
                'category': VulnerabilityCategory.WEB2,
                'description': 'Server-Side Request Forgery vulnerability',
                'remediation': 'Validate and sanitize URLs, use URL allowlists',
            },
        }
    
    # ==================== WEB3 CORE RULES ====================
    
    def _get_web3_core_rules(self) -> Dict:
        """Core Web3 security rules"""
        return {
            'private_key_exposure': {
                'patterns': [
                    r"0x[a-f0-9]{64}(?=\s*[,;)\n])",
                    r"privateKey.*=.*0x[a-f0-9]{64}",
                    r"PRIVATE_KEY.*0x[a-f0-9]{64}",
                    r"from_key\s*=\s*0x",
                ],
                'severity': VulnerabilitySeverity.CRITICAL,
                'category': VulnerabilityCategory.WEB3_CORE,
                'description': 'Private key exposed in source code',
                'remediation': 'Use hardware wallets or key management systems',
            },
            'mnemonic_exposure': {
                'patterns': [
                    r"mnemonic\s*=\s*['\"][^'\"]+['\"]",
                    r"seed\s*=\s*['\"][^'\"]{50,}['\"]",
                    r"bip39.*=\s*['\"]",
                ],
                'severity': VulnerabilitySeverity.CRITICAL,
                'category': VulnerabilityCategory.WEB3_CORE,
                'description': 'Seed phrase or mnemonic exposed',
                'remediation': 'Never hardcode mnemonics, use secure key derivation',
            },
            'signature_verification_missing': {
                'patterns': [
                    r"recover\s*\(.*\)(?!.*verify)",
                    r"ecrecover(?!.*require)",
                    r"verify.*signature(?!.*require|!.*assert)",
                ],
                'severity': VulnerabilitySeverity.CRITICAL,
                'category': VulnerabilityCategory.WEB3_CORE,
                'description': 'Missing or incomplete signature verification',
                'remediation': 'Always verify signatures before processing transactions',
            },
            'nonce_reuse': {
                'patterns': [
                    r"nonce.*static|nonce.*=\s*0",
                    r"replay.*protection(?!.*implemented)",
                ],
                'severity': VulnerabilitySeverity.CRITICAL,
                'category': VulnerabilityCategory.WEB3_CORE,
                'description': 'Nonce reuse or missing replay attack protection',
                'remediation': 'Implement proper nonce management and EIP-712 domain separation',
            },
        }
    
    # ==================== ETHEREUM RULES ====================
    
    def _get_ethereum_rules(self) -> Dict:
        """Ethereum-specific vulnerability rules"""
        return {
            'reentrancy': {
                'patterns': [
                    r"\.transfer\s*\(\s*\)|\.send\s*\(\s*\)",
                    r"\.call\s*\{.*value.*\}\s*\(\s*\)",
                    r"msg\.sender\.call|recipient\.call",
                    r"balances?\[.*\]\s*\+=.*call|balances?\[.*\]\s*-=.*call",
                    r"transfer\s*\(.*\)(?!.*require.*balances)",
                ],
                'severity': VulnerabilitySeverity.CRITICAL,
                'category': VulnerabilityCategory.WEB3_ETHEREUM,
                'description': 'Reentrancy vulnerability - external call before state update',
                'remediation': 'Use OpenZeppelin ReentrancyGuard or checks-effects-interactions pattern',
            },
            'integer_overflow': {
                'patterns': [
                    r"pragma solidity\s+\^?0\.[0-7]",
                    r"\+=\s*\w+|\-=\s*\w+(?!.*SafeMath|!.*checked)",
                    r"uint\d+.*\+\s*\w+(?!.*require|!.*SafeMath)",
                ],
                'severity': VulnerabilitySeverity.CRITICAL,
                'category': VulnerabilityCategory.WEB3_ETHEREUM,
                'description': 'Integer overflow in Solidity < 0.8',
                'remediation': 'Use Solidity 0.8+ or OpenZeppelin SafeMath',
            },
            'unchecked_call': {
                'patterns': [
                    r"\.call\s*\(\s*\)(?!\s*require|!.*assert)",
                    r"\.delegatecall\s*\(\s*\)(?!\s*require)",
                    r"address\s*\(.*\)\.call(?!.*require)",
                ],
                'severity': VulnerabilitySeverity.HIGH,
                'category': VulnerabilityCategory.WEB3_ETHEREUM,
                'description': 'Unchecked low-level call return value',
                'remediation': 'Always check return value or use high-level functions',
            },
            'delegatecall_to_untrusted': {
                'patterns': [
                    r"delegatecall\s*\(.*address\s*\(\s*.*\(\s*\)\)",
                    r"delegatecall.*user|delegatecall.*input",
                    r"delegatecall\s*\(.*msg\.data\)",
                ],
                'severity': VulnerabilitySeverity.CRITICAL,
                'category': VulnerabilityCategory.WEB3_ETHEREUM,
                'description': 'Delegatecall to user-controlled or untrusted address',
                'remediation': 'Use whitelisting and avoid dynamic delegatecalls',
            },
            'timestamp_manipulation': {
                'patterns': [
                    r"block\.timestamp(?=[><=!])",
                    r"now(?=\s*[><=!])",
                    r"if\s*\(\s*block\.timestamp",
                ],
                'severity': VulnerabilitySeverity.MEDIUM,
                'category': VulnerabilityCategory.WEB3_ETHEREUM,
                'description': 'Logic depends on block.timestamp (miners can manipulate)',
                'remediation': 'Use block.number instead or accept small variance',
            },
            'front_running': {
                'patterns': [
                    r"tx\.gasprice|block\.basefee",
                    r"mempool|pending.*transaction",
                    r"ordering.*attack",
                ],
                'severity': VulnerabilitySeverity.HIGH,
                'category': VulnerabilityCategory.WEB3_ETHEREUM,
                'description': 'Vulnerable to transaction ordering manipulation',
                'remediation': 'Use commit-reveal schemes or MEV protection services',
            },
            'missing_zero_address_check': {
                'patterns': [
                    r"require\s*\(\s*_\w+\s*!=\s*address\s*\(0\)\s*\)(?!.*true)",
                    r"transfer.*to(?!.*require.*zero)",
                    r"_to\s*=\s*address\s*\(0\)(?!.*require)",
                ],
                'severity': VulnerabilitySeverity.MEDIUM,
                'category': VulnerabilityCategory.WEB3_ETHEREUM,
                'description': 'Missing zero address (0x0) validation',
                'remediation': 'Add require(address != address(0)) checks',
            },
            'missing_access_control': {
                'patterns': [
                    r"function\s+\w+.*\(.*\)\s*(?:public|external|payable)(?!.*onlyOwner|!.*require.*msg\.sender|!.*auth)",
                    r"transfer\s*\(.*\)(?!.*onlyOwner|!.*require)",
                    r"burn\s*\(.*\)(?!.*onlyOwner|!.*require)",
                    r"mint\s*\(.*\)(?!.*onlyMinter|!.*require)",
                ],
                'severity': VulnerabilitySeverity.HIGH,
                'category': VulnerabilityCategory.WEB3_ETHEREUM,
                'description': 'Critical functions missing access control',
                'remediation': 'Add onlyOwner or role-based access control modifiers',
            },
            'flash_loan': {
                'patterns': [
                    r"flashLoan\s*\(|receiveFlashLoan\s*\(",
                    r"balance.*before|balance.*after(?!.*assert|!.*require)",
                    r"balance.*==.*balance",
                ],
                'severity': VulnerabilitySeverity.CRITICAL,
                'category': VulnerabilityCategory.WEB3_ETHEREUM,
                'description': 'Vulnerable to flash loan attacks',
                'remediation': 'Verify prices from multiple sources, implement balance checks',
            },
            'selfdestruct': {
                'patterns': [
                    r"selfdestruct\s*\(|suicide\s*\(",
                ],
                'severity': VulnerabilitySeverity.HIGH,
                'category': VulnerabilityCategory.WEB3_ETHEREUM,
                'description': 'Selfdestruct usage (deprecated in Cancun)',
                'remediation': 'Avoid selfdestruct, use proper contract upgrades',
            },
        }
    
    # ==================== SOLANA RULES ====================
    
    def _get_solana_rules(self) -> Dict:
        """Solana-specific vulnerability rules"""
        return {
            'missing_signer_check': {
                'patterns': [
                    r"is_signer.*false|is_signer.*=.*false",
                    r"is_signed.*=.*false|signed.*=.*false",
                    r"\.is_signer(?!.*true|!.*require)",
                ],
                'severity': VulnerabilitySeverity.CRITICAL,
                'category': VulnerabilityCategory.WEB3_SOLANA,
                'description': 'Missing signer validation - signature forging possible',
                'remediation': 'Verify is_signer = true for all required signers',
            },
            'missing_owner_check': {
                'patterns': [
                    r"owner.*check(?!.*true|!.*assert)",
                    r"assert_owned_by(?!.*)",
                    r"if.*owner.*!=(?!.*panic|!.*err)",
                ],
                'severity': VulnerabilitySeverity.CRITICAL,
                'category': VulnerabilityCategory.WEB3_SOLANA,
                'description': 'Missing owner validation',
                'remediation': 'Always verify ctx.accounts.owner.key() matches expected owner',
            },
            'unchecked_account': {
                'patterns': [
                    r"UncheckedAccount|Unchecked\s*<\s*Account",
                    r"account.*validation(?!.*implemented|!.*true)",
                ],
                'severity': VulnerabilitySeverity.CRITICAL,
                'category': VulnerabilityCategory.WEB3_SOLANA,
                'description': 'Unchecked account - arbitrary account injection possible',
                'remediation': 'Use proper account constraints and validation',
            },
            'arithmetic_overflow': {
                'patterns': [
                    r"\+=\s*\w+|\-=\s*\w+(?!.*checked_|!.*saturating_)",
                    r"multiply\s*\(.*\)(?!.*checked)",
                    r"\*\s*\w+(?!.*checked)",
                ],
                'severity': VulnerabilitySeverity.HIGH,
                'category': VulnerabilityCategory.WEB3_SOLANA,
                'description': 'Arithmetic overflow in Rust',
                'remediation': 'Use checked_add, checked_mul, or saturating operations',
            },
            'rent_exempt_violation': {
                'patterns': [
                    r"lamports.*transfer(?!.*rent_exempt|!.*assert)",
                    r"rent_exempt.*check(?!.*true|!.*require)",
                ],
                'severity': VulnerabilitySeverity.MEDIUM,
                'category': VulnerabilityCategory.WEB3_SOLANA,
                'description': 'Lamport transfers may violate rent exemption',
                'remediation': 'Ensure accounts remain rent-exempt after transfers',
            },
        }
    
    # ==================== DEFI RULES ====================
    
    def _get_defi_rules(self) -> Dict:
        """DeFi-specific vulnerability rules"""
        return {
            'oracle_manipulation': {
                'patterns': [
                    r"getPrice\s*\(|price\s*\)(?!.*chainlink|!.*aggregator)",
                    r"oracle\.price|price.*feed(?!.*verified)",
                    r"pricePerShare(?!.*cached|!.*verified)",
                ],
                'severity': VulnerabilitySeverity.CRITICAL,
                'category': VulnerabilityCategory.WEB3_DEFI,
                'description': 'Reliance on unverified or manipulable price feeds',
                'remediation': 'Use Chainlink oracles or decentralized aggregators',
            },
            'missing_slippage_protection': {
                'patterns': [
                    r"swap.*\(.*\)(?!.*minAmountOut|!.*slippage|!.*deadline)",
                    r"addLiquidity\s*\(.*\)(?!.*minAmountA|!.*minAmountB)",
                    r"getAmountsOut(?!.*minAmount)",
                ],
                'severity': VulnerabilitySeverity.MEDIUM,
                'category': VulnerabilityCategory.WEB3_DEFI,
                'description': 'Missing slippage protection - vulnerable to sandwich attacks',
                'remediation': 'Add minAmountOut parameter and deadline checks',
            },
            'arbitrary_token_transfer': {
                'patterns': [
                    r"transferFrom\s*\(.*msg\.sender.*\)(?!.*require.*allowance)",
                    r"burn\s*\(.*\)(?!.*onlyOwner|!.*require)",
                ],
                'severity': VulnerabilitySeverity.HIGH,
                'category': VulnerabilityCategory.WEB3_DEFI,
                'description': 'Arbitrary token transfers without proper validation',
                'remediation': 'Validate token transfers and allowances',
            },
            'liquidity_pool_attack': {
                'patterns': [
                    r"reserve.*balance|balance.*reserve(?!.*external)",
                    r"k\s*=\s*reserve.*\*.*reserve",
                ],
                'severity': VulnerabilitySeverity.HIGH,
                'category': VulnerabilityCategory.WEB3_DEFI,
                'description': 'Potential liquidity pool manipulation',
                'remediation': 'Implement proper price calculations and guards',
            },
            'lending_under_collateralized': {
                'patterns': [
                    r"loan.*amount(?!.*collateral|!.*ratio)",
                    r"borrow\s*\(.*\)(?!.*check|!.*validate)",
                ],
                'severity': VulnerabilitySeverity.HIGH,
                'category': VulnerabilityCategory.WEB3_DEFI,
                'description': 'Under-collateralized loans possible',
                'remediation': 'Implement collateralization ratio checks',
            },
        }
    
    # ==================== NFT RULES ====================
    
    def _get_nft_rules(self) -> Dict:
        """NFT-specific vulnerability rules"""
        return {
            'reentrancy_in_mint': {
                'patterns': [
                    r"safeMint\s*\(.*\)(?!.*nonReentrant|!.*mutex)",
                    r"_safeMint\s*\(.*\)(?!.*checked|!.*safe)",
                ],
                'severity': VulnerabilitySeverity.CRITICAL,
                'category': VulnerabilityCategory.WEB3_NFT,
                'description': 'Mint function vulnerable to reentrancy',
                'remediation': 'Add nonReentrant modifier or checks-effects-interactions',
            },
            'unauthorized_burn': {
                'patterns': [
                    r"burn\s*\(.*\)(?!.*onlyOwner|!.*require.*msg\.sender)",
                ],
                'severity': VulnerabilitySeverity.HIGH,
                'category': VulnerabilityCategory.WEB3_NFT,
                'description': 'Burn function missing access control',
                'remediation': 'Add onlyOwner or require(msg.sender == ownerOf(tokenId))',
            },
            'centralized_metadata': {
                'patterns': [
                    r"baseURI.*http|metadata.*centralized",
                    r"ipfs.*off.*chain|metadata.*server",
                ],
                'severity': VulnerabilitySeverity.MEDIUM,
                'category': VulnerabilityCategory.WEB3_NFT,
                'description': 'Centralized metadata hosting',
                'remediation': 'Use IPFS or decentralized storage for metadata',
            },
            'forced_transfer': {
                'patterns': [
                    r"safeTransferFrom(?!.*from.*==.*msg\.sender|!.*require)",
                    r"transferFrom\s*\(.*\)(?!.*approve|!.*require)",
                ],
                'severity': VulnerabilitySeverity.HIGH,
                'category': VulnerabilityCategory.WEB3_NFT,
                'description': 'Forced NFT transfers without approval',
                'remediation': 'Implement proper approval checks',
            },
        }
    
    # ==================== PRIVACY RULES ====================
    
    def _get_privacy_rules(self) -> Dict:
        """Privacy and anonymity vulnerability rules"""
        return {
            'privacy_leak_transaction': {
                'patterns': [
                    r"msg\.sender|tx\.origin",
                    r"address\s*\(\s*msg\.sender\s*\)",
                ],
                'severity': VulnerabilitySeverity.MEDIUM,
                'category': VulnerabilityCategory.WEB3_CORE,
                'description': 'Transaction sender may leak user identity',
                'remediation': 'Use privacy protocols like Tornado Cash or zk-SNARKs',
            },
            'weak_randomness': {
                'patterns': [
                    r"block\.number|block\.timestamp|block\.hash",
                    r"randomness.*=.*block",
                    r"random.*timestamp",
                ],
                'severity': VulnerabilitySeverity.HIGH,
                'category': VulnerabilityCategory.WEB3_CORE,
                'description': 'Weak randomness source',
                'remediation': 'Use Chainlink VRF or other cryptographic randomness',
            },
        }
    
    # ==================== CROSS-CHAIN RULES ====================
    
    def _get_cross_chain_rules(self) -> Dict:
        """Cross-chain and bridge vulnerability rules"""
        return {
            'bridge_validation': {
                'patterns': [
                    r"bridge.*transfer(?!.*verify|!.*validate)",
                    r"cross.*chain.*transfer(?!.*check)",
                    r"wrapped.*token(?!.*mint.*check)",
                ],
                'severity': VulnerabilitySeverity.CRITICAL,
                'category': VulnerabilityCategory.CROSS_CHAIN,
                'description': 'Missing bridge validation',
                'remediation': 'Implement multi-signature validation for bridge transfers',
            },
            'sequencer_dependency': {
                'patterns': [
                    r"block\.timestamp(?!.*sequencer|!.*validated)",
                    r"sequencer.*offline",
                ],
                'severity': VulnerabilitySeverity.MEDIUM,
                'category': VulnerabilityCategory.CROSS_CHAIN,
                'description': 'Dependency on sequencer for critical logic',
                'remediation': 'Implement fallback mechanisms for sequencer failure',
            },
            'wrapped_token_risk': {
                'patterns': [
                    r"wrapped.*=.*balance|pegged.*=.*token",
                ],
                'severity': VulnerabilitySeverity.HIGH,
                'category': VulnerabilityCategory.CROSS_CHAIN,
                'description': 'Wrapped token peg risk',
                'remediation': 'Monitor peg stability and implement circuit breakers',
            },
        }
    
    # ==================== CODE GENERATION RULES ====================
    
    def _get_code_generation_rules(self) -> Dict:
        """Code generation and integration vulnerability rules"""
        return {
            'ai_generated_unverified': {
                'patterns': [
                    r"#\s*auto[_-]?generated|generated by AI",
                    r"TODO.*verify|FIXME.*check",
                    r"this was generated|AI generated",
                ],
                'severity': VulnerabilitySeverity.HIGH,
                'category': VulnerabilityCategory.CODE_GENERATION,
                'description': 'AI-generated code without verification',
                'remediation': 'Manually review and test all AI-generated code',
            },
            'incomplete_error_handling': {
                'patterns': [
                    r"try.*pass|except.*pass",
                    r"\.unwrap\s*\(\)|\.expect\s*\(",
                    r"TODO.*error|panic!.*\(\)",
                ],
                'severity': VulnerabilitySeverity.MEDIUM,
                'category': VulnerabilityCategory.CODE_GENERATION,
                'description': 'Incomplete error handling in generated code',
                'remediation': 'Implement comprehensive error handling',
            },
            'type_mismatch': {
                'patterns': [
                    r"type.*mismatch|casting.*unsafe",
                    r"any\s*\(|interface\s*\{\}",
                ],
                'severity': VulnerabilitySeverity.MEDIUM,
                'category': VulnerabilityCategory.CODE_GENERATION,
                'description': 'Type mismatches in generated code',
                'remediation': 'Use static type checking and type assertions',
            },
            'missing_validation': {
                'patterns': [
                    r"user.*input(?!.*validate|!.*check|!.*sanitize)",
                    r"TODO.*validate|FIXME.*check.*input",
                ],
                'severity': VulnerabilitySeverity.HIGH,
                'category': VulnerabilityCategory.CODE_GENERATION,
                'description': 'Missing input validation in generated code',
                'remediation': 'Add comprehensive input validation',
            },
            'untested_code_path': {
                'patterns': [
                    r"test.*TODO|skip.*test",
                    r"x\.it\s*\(|it\.skip\s*\(",
                ],
                'severity': VulnerabilitySeverity.MEDIUM,
                'category': VulnerabilityCategory.CODE_GENERATION,
                'description': 'Code paths without test coverage',
                'remediation': 'Add tests for all generated code paths',
            },
        }
    
    # ==================== CRYPTOGRAPHY RULES ====================
    
    def _get_cryptography_rules(self) -> Dict:
        """Cryptography vulnerability rules"""
        return {
            'weak_hash': {
                'patterns': [
                    r"md5|sha1(?!_)|CRC32",
                    r"hashlib\.md5|hashlib\.sha1",
                ],
                'severity': VulnerabilitySeverity.HIGH,
                'category': VulnerabilityCategory.CRYPTOGRAPHY,
                'description': 'Weak cryptographic hash function',
                'remediation': 'Use SHA-256 or stronger hash functions',
            },
            'weak_rng': {
                'patterns': [
                    r"random\.random|Math\.random",
                    r"rand.*seed.*time",
                ],
                'severity': VulnerabilitySeverity.CRITICAL,
                'category': VulnerabilityCategory.CRYPTOGRAPHY,
                'description': 'Weak random number generator',
                'remediation': 'Use cryptographically secure RNG (os.urandom, secrets)',
            },
            'ecb_mode': {
                'patterns': [
                    r"AES.*ECB|MODE_ECB",
                ],
                'severity': VulnerabilitySeverity.CRITICAL,
                'category': VulnerabilityCategory.CRYPTOGRAPHY,
                'description': 'ECB mode encryption (deterministic)',
                'remediation': 'Use CBC, GCM, or CTR mode with random IV',
            },
            'custom_crypto': {
                'patterns': [
                    r"def.*encrypt|def.*decrypt|class.*Cipher",
                    r"custom.*encryption|homemade.*crypto",
                ],
                'severity': VulnerabilitySeverity.CRITICAL,
                'category': VulnerabilityCategory.CRYPTOGRAPHY,
                'description': 'Custom cryptographic implementation',
                'remediation': 'Use well-tested cryptographic libraries',
            },
        }
    
    # ==================== ARCHITECTURE RULES ====================
    
    def _get_architecture_rules(self) -> Dict:
        """Architecture and design vulnerability rules"""
        return {
            'single_point_failure': {
                'patterns': [
                    r"owner.*only|ownerOnly",
                    r"single.*validator|one.*signer",
                ],
                'severity': VulnerabilitySeverity.MEDIUM,
                'category': VulnerabilityCategory.ARCHITECTURE,
                'description': 'Single point of failure in governance',
                'remediation': 'Implement multi-signature and distributed governance',
            },
            'centralized_upgrade': {
                'patterns': [
                    r"upgrade\s*\(.*\)(?!.*timelock|!.*multisig)",
                    r"proxy.*admin(?!.*multisig)",
                ],
                'severity': VulnerabilitySeverity.HIGH,
                'category': VulnerabilityCategory.ARCHITECTURE,
                'description': 'Centralized upgrade mechanism',
                'remediation': 'Implement timelock and multi-signature upgrades',
            },
            'missing_event_logging': {
                'patterns': [
                    r"transfer(?!.*emit)|burn(?!.*emit)",
                    r"approve(?!.*emit)",
                ],
                'severity': VulnerabilitySeverity.LOW,
                'category': VulnerabilityCategory.ARCHITECTURE,
                'description': 'Critical operations without event logging',
                'remediation': 'Emit events for all state changes',
            },
        }
    
    # ==================== DETECTION METHODS ====================
    
    def detect_chain_type(self, content: str) -> ChainType:
        """Detect blockchain chain type from code"""
        content_lower = content.lower()
        
        if "pragma solidity" in content_lower or "@pragma" in content_lower:
            return ChainType.ETHEREUM
        if "use anchor_lang" in content_lower or "#[program]" in content_lower:
            return ChainType.SOLANA
        if "polygon" in content_lower or "matic" in content_lower:
            return ChainType.POLYGON
        if "bsc" in content_lower or "binance" in content_lower:
            return ChainType.BINANCE
        if "arbitrum" in content_lower:
            return ChainType.ARBITRUM
        if "optimism" in content_lower or "op_" in content_lower:
            return ChainType.OPTIMISM
        if "avalanche" in content_lower or "avax" in content_lower:
            return ChainType.AVALANCHE
        if "base" in content_lower and "blockchain" in content_lower:
            return ChainType.BASE
        
        return ChainType.WEB2
    
    def detect_code_type(self, content: str) -> str:
        """Detect type of code (contract, program, library, etc.)"""
        content_lower = content.lower()
        
        if "contract " in content_lower:
            return "smart_contract"
        if "#[program]" in content_lower:
            return "solana_program"
        if "erc721" in content_lower or "erc1155" in content_lower:
            return "nft_contract"
        if "uniswap" in content_lower or "swap" in content_lower or "dex" in content_lower:
            return "defi_contract"
        if "lending" in content_lower or "borrow" in content_lower:
            return "lending_protocol"
        if "def " in content_lower or "function " in content_lower:
            return "library"
        if "class " in content_lower:
            return "class_library"
        
        return "unknown"
    
    def _check_patterns(self, content: str, patterns: List[str]) -> bool:
        """Check if content matches any patterns"""
        for pattern in patterns:
            try:
                if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                    return True
            except re.error:
                continue
        return False
    
    def run_category_checks(self, content: str, category: str) -> List[Dict]:
        """Run checks for a specific vulnerability category"""
        if category not in self.rules_db:
            return []
        
        category_rules = self.rules_db[category]
        findings = []
        
        for vuln_name, vuln_rule in category_rules.items():
            if self._check_patterns(content, vuln_rule.get('patterns', [])):
                findings.append({
                    'name': vuln_name,
                    'type': vuln_name.replace('_', ' ').title(),
                    'severity': vuln_rule.get('severity'),
                    'category': vuln_rule.get('category'),
                    'description': vuln_rule.get('description'),
                    'remediation': vuln_rule.get('remediation'),
                })
        
        return findings
    
    def run_all_checks(self, content: str) -> Tuple[List[Dict], str, str]:
        """
        Run all vulnerability checks
        Returns: (findings, detected_chain, detected_code_type)
        """
        detected_chain = self.detect_chain_type(content)
        detected_code_type = self.detect_code_type(content)
        
        all_findings = []
        
        # Run all category checks
        for category in self.rules_db.keys():
            findings = self.run_category_checks(content, category)
            all_findings.extend(findings)
        
        # Sort by severity
        severity_order = {
            VulnerabilitySeverity.CRITICAL: 0,
            VulnerabilitySeverity.HIGH: 1,
            VulnerabilitySeverity.MEDIUM: 2,
            VulnerabilitySeverity.LOW: 3,
            VulnerabilitySeverity.INFO: 4,
        }
        
        all_findings.sort(key=lambda x: severity_order.get(x.get('severity'), 999))
        
        return all_findings, detected_chain.value, detected_code_type
    
    def get_findings_summary(self, findings: List[Dict]) -> Dict:
        """Get summary statistics of findings"""
        summary = {
            'total': len(findings),
            'by_severity': {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0,
                'INFO': 0,
            },
            'by_category': {},
        }
        
        for finding in findings:
            severity = finding.get('severity')
            if hasattr(severity, 'value'):
                severity = severity.value
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            
            category = finding.get('category')
            if hasattr(category, 'value'):
                category = category.value
            summary['by_category'][category] = summary['by_category'].get(category, 0) + 1
        
        return summary