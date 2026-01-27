// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;  // ❌ CRITICAL: Old Solidity version (< 0.8) - Integer Overflow Risk

/**
 * VulnerableToken - Intentionally Vulnerable ERC20-like Contract for Testing
 * DO NOT USE IN PRODUCTION
 */

contract VulnerableToken {
    
    // ❌ CRITICAL: Hardcoded private key exposure
    bytes32 private constant PRIVATE_KEY = 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef;
    
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowance;
    
    // ❌ CRITICAL: No access control on mint function
    function mint(address to, uint256 amount) public {
        balances[to] += amount;  // ❌ INTEGER OVERFLOW - No SafeMath in Solidity 0.7
    }
    
    // ❌ CRITICAL: Reentrancy vulnerability
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // ❌ REENTRANCY: External call BEFORE state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        // State update AFTER call - vulnerable to reentrancy!
        balances[msg.sender] -= amount;
    }
    
    // ❌ HIGH: Unchecked low-level call
    function unsafeWithdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        
        // ❌ No require on call return value
        msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }
    
    // ❌ HIGH: Missing zero address check
    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // ❌ No check if 'to' is address(0)
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
    
    // ❌ HIGH: No access control - anyone can burn
    function burn(address account, uint256 amount) public {
        balances[account] -= amount;  // ❌ No onlyOwner check
    }
    
    // ❌ MEDIUM: Timestamp dependency
    function claimReward() public {
        // ❌ Miners can manipulate block.timestamp
        if (block.timestamp > 1234567890) {
            balances[msg.sender] += 1000;
        }
    }
    
    // ❌ HIGH: Delegatecall to user-controlled address
    function delegateCall(address target, bytes memory data) public {
        // ❌ CRITICAL: User can call any contract
        (bool success, ) = target.delegatecall(data);
        require(success);
    }
    
    // ❌ CRITICAL: Flash loan vulnerability
    function flashLoan(uint256 amount) public {
        uint256 balanceBefore = address(this).balance;
        
        // Send loan
        msg.sender.call{value: amount}("");
        
        // ❌ UNSAFE: Balance check can be manipulated
        require(address(this).balance >= balanceBefore, "Loan not repaid");
    }
}

// ❌ CRITICAL: Proxy contract with delegatecall injection
contract VulnerableProxy {
    address public implementation;
    
    // ❌ No access control - anyone can set implementation
    function setImplementation(address newImpl) public {
        implementation = newImpl;
    }
    
    fallback() external payable {
        // ❌ Delegatecall to user-controlled address
        (bool success, ) = implementation.delegatecall(msg.data);
        require(success);
    }
}