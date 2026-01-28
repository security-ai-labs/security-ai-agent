// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Safe contract using msg.sender for authorization
 */
contract SafeWallet {
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    // SAFE: Using msg.sender instead of tx.origin
    function transfer(address payable to, uint amount) public {
        require(msg.sender == owner, "Not authorized");
        to.transfer(amount);
    }
    
    receive() external payable {}
}
