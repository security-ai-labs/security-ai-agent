from typing import Dict, List
from security_rules import SecurityRules, ChainType

class Web3Analyzer:
    """Specialized analyzer for Web3/Blockchain vulnerabilities"""
    
    def __init__(self):
        self.rules = SecurityRules()
        self.findings = []
    
    def analyze_ethereum_contract(self, contract_code: str) -> Dict:
        """Analyze Ethereum/EVM smart contracts"""
        vulnerabilities = self.rules.run_all_checks(contract_code)
        
        # Filter for Ethereum-specific issues
        ethereum_issues = [v for v in vulnerabilities if v['type'] in [
            'Reentrancy Attack',
            'Integer Overflow/Underflow',
            'Unchecked Low-Level Call',
            'Delegatecall Injection',
            'Timestamp Dependency',
            'Front-Running Vulnerability',
            'Missing Zero Address Check',
            'Missing Access Control',
            'Flash Loan Attack',
        ]]
        
        return {
            "chain": "Ethereum",
            "vulnerabilities": ethereum_issues,
            "total": len(ethereum_issues),
            "critical": sum(1 for v in ethereum_issues if v['severity'].value == 'CRITICAL'),
            "high": sum(1 for v in ethereum_issues if v['severity'].value == 'HIGH'),
        }
    
    def analyze_solana_program(self, program_code: str) -> Dict:
        """Analyze Solana programs (Rust/Anchor)"""
        vulnerabilities = self.rules.run_all_checks(program_code)
        
        # Filter for Solana-specific issues
        solana_issues = [v for v in vulnerabilities if v['type'] in [
            'Missing Signer Check (Solana)',
            'Missing Owner Check (Solana)',
            'Missing Account Validation (Solana)',
            'Unchecked Arithmetic (Solana)',
            'Rent Exempt Check Missing (Solana)',
        ]]
        
        return {
            "chain": "Solana",
            "vulnerabilities": solana_issues,
            "total": len(solana_issues),
            "critical": sum(1 for v in solana_issues if v['severity'].value == 'CRITICAL'),
            "high": sum(1 for v in solana_issues if v['severity'].value == 'HIGH'),
        }
    
    def analyze_defi_protocol(self, contract_code: str) -> Dict:
        """Analyze DeFi protocol contracts"""
        vulnerabilities = self.rules.run_all_checks(contract_code)
        
        # Filter for DeFi-specific issues
        defi_issues = [v for v in vulnerabilities if v['type'] in [
            'Price Oracle Manipulation',
            'Missing Slippage Protection',
            'Arbitrary Token Transfer',
            'Flash Loan Attack',
            'Reentrancy Attack',
        ]]
        
        return {
            "protocol_type": "DeFi",
            "vulnerabilities": defi_issues,
            "total": len(defi_issues),
            "critical": sum(1 for v in defi_issues if v['severity'].value == 'CRITICAL'),
            "high": sum(1 for v in defi_issues if v['severity'].value == 'HIGH'),
        }
    
    def analyze_nft_contract(self, contract_code: str) -> Dict:
        """Analyze NFT contracts"""
        vulnerabilities = self.rules.run_all_checks(contract_code)
        
        # Filter for NFT-specific issues
        nft_issues = [v for v in vulnerabilities if v['type'] in [
            'NFT Reentrancy (Minting)',
            'Unauthorized NFT Burn',
            'Centralized Metadata',
            'Missing Access Control',
        ]]
        
        return {
            "contract_type": "NFT",
            "vulnerabilities": nft_issues,
            "total": len(nft_issues),
            "critical": sum(1 for v in nft_issues if v['severity'].value == 'CRITICAL'),
            "high": sum(1 for v in nft_issues if v['severity'].value == 'HIGH'),
        }
    
    def auto_detect_and_analyze(self, code: str) -> Dict:
        """Auto-detect chain/contract type and analyze"""
        chain = self.rules.detect_chain_type(code)
        
        if chain == ChainType.ETHEREUM:
            return self.analyze_ethereum_contract(code)
        elif chain == ChainType.SOLANA:
            return self.analyze_solana_program(code)
        elif "uniswap" in code.lower() or "swap" in code.lower():
            return self.analyze_defi_protocol(code)
        elif "erc721" in code.lower() or "erc1155" in code.lower():
            return self.analyze_nft_contract(code)
        else:
            # Default analysis
            vulnerabilities = self.rules.run_all_checks(code)
            return {
                "chain": chain.value,
                "vulnerabilities": vulnerabilities,
                "total": len(vulnerabilities),
            }
    
    def get_remediation_guidance(self, vulnerability: Dict) -> str:
        """Get remediation guidance for a vulnerability"""
        
        guidance_map = {
            'Reentrancy Attack': 'Use OpenZeppelin ReentrancyGuard or implement checks-effects-interactions pattern',
            'Integer Overflow/Underflow': 'Use Solidity 0.8+ with built-in overflow checks or OpenZeppelin SafeMath',
            'Unchecked Low-Level Call': 'Always check return value of .call() or use high-level functions with require()',
            'Delegatecall Injection': 'Never allow user-controlled addresses in delegatecall. Use whitelisting',
            'Timestamp Dependency': 'Use block.number instead of timestamp for critical logic or accept small variance',
            'Front-Running Vulnerability': 'Implement commit-reveal schemes or use private mempools (MEV protection)',
            'Missing Zero Address Check': 'Add require(address != address(0)) checks for critical addresses',
            'Missing Access Control': 'Add onlyOwner or onlyRole modifiers to critical functions',
            'Flash Loan Attack': 'Verify prices from multiple sources and implement balances checks',
            'Price Oracle Manipulation': 'Use Chainlink oracles or decentralized price feeds with aggregation',
            'Missing Slippage Protection': 'Add minAmountOut parameter and deadline to swap functions',
            'Missing Signer Check (Solana)': 'Use require!(ctx.accounts.signer.is_signer) in Anchor programs',
            'Missing Owner Check (Solana)': 'Verify owner with require!(ctx.accounts.owner.key() == expected_owner)',
            'Missing Account Validation (Solana)': 'Use anchor_lang constraints or manual validation for all accounts',
            'SQL Injection': 'Use parameterized queries and prepared statements',
            'Cross-Site Scripting (XSS)': 'Sanitize inputs and use textContent instead of innerHTML',
            'Hardcoded Secrets': 'Move secrets to environment variables or use secret management systems',
        }
        
        vuln_type = vulnerability.get('type', 'Unknown')
        return guidance_map.get(vuln_type, 'Please review this vulnerability with security experts')