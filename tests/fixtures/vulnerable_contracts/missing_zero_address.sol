// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Vulnerable contract missing zero address checks
 * DO NOT USE IN PRODUCTION
 */
contract VulnerableToken {
    mapping(address => uint256) public balances;
    
    // VULNERABLE: No zero address check for recipient
    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
    
    // VULNERABLE: No zero address check for both from and to
    function transferFrom(address from, address to, uint256 amount) public {
        balances[from] -= amount;
        balances[to] += amount;
    }
}
