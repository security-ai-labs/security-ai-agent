// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Safe contract with event logging using tx.origin
 * This is a FALSE POSITIVE test - tx.origin for logging is safe
 */
contract SafeEventLogger {
    event UserAction(address indexed origin, address indexed sender, string action);
    event TransactionOrigin(address indexed txOrigin);
    
    // SAFE: Using tx.origin only for logging/analytics, not authorization
    function logAction(string memory action) public {
        emit UserAction(tx.origin, msg.sender, action);
    }
    
    // SAFE: Just emitting tx.origin in an event
    function trackOrigin() public {
        emit TransactionOrigin(tx.origin);
    }
    
    // SAFE: Authorization uses msg.sender, not tx.origin
    address public owner;
    
    function privilegedAction() public {
        require(msg.sender == owner, "Not authorized");
        // This is safe - using msg.sender for authorization
    }
}
