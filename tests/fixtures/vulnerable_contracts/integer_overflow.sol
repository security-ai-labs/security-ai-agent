// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

/**
 * Vulnerable contract with integer overflow (pre-0.8.0)
 * DO NOT USE IN PRODUCTION
 */
contract VulnerableToken {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    
    // VULNERABLE: No overflow protection in Solidity 0.7
    function transfer(address to, uint256 amount) public {
        balances[msg.sender] -= amount;  // Can underflow
        balances[to] += amount;           // Can overflow
    }
    
    function mint(address to, uint256 amount) public {
        totalSupply += amount;  // Can overflow
        balances[to] += amount;
    }
}
