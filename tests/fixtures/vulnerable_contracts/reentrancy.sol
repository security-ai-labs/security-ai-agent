// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Vulnerable contract with reentrancy issue
 * DO NOT USE IN PRODUCTION
 */
contract VulnerableBank {
    mapping(address => uint) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    // VULNERABLE: External call before state update
    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Call external contract before updating state
        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        // State updated after external call - reentrancy risk!
        balances[msg.sender] -= amount;
    }
}
