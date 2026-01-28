// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Vulnerable contract using tx.origin for authorization
 * DO NOT USE IN PRODUCTION
 */
contract VulnerableWallet {
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    // VULNERABLE: Using tx.origin instead of msg.sender
    function transfer(address payable to, uint amount) public {
        require(tx.origin == owner, "Not authorized");
        to.transfer(amount);
    }
    
    receive() external payable {}
}
