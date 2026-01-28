// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Vulnerable contract with delegatecall injection
 * DO NOT USE IN PRODUCTION
 */
contract VulnerableProxy {
    address public implementation;
    
    // VULNERABLE: Delegatecall to user-controlled address
    function execute(address target, bytes memory data) public returns (bytes memory) {
        // Anyone can call this with arbitrary target address
        (bool success, bytes memory result) = target.delegatecall(data);
        require(success, "Delegatecall failed");
        return result;
    }
    
    // VULNERABLE: Delegatecall with msg.data
    function forward(address impl) public {
        impl.delegatecall(msg.data);
    }
}
