// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * Safe contract with reentrancy protection
 * Follows checks-effects-interactions pattern
 */
contract SafeBank is ReentrancyGuard {
    mapping(address => uint) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    // SAFE: State updated before external call
    function withdraw(uint amount) public nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Update state first (checks-effects-interactions)
        balances[msg.sender] -= amount;
        
        // External call after state update
        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}
