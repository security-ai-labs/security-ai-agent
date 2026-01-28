// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Vulnerable contract with timestamp dependency
 * DO NOT USE IN PRODUCTION
 */
contract VulnerableLottery {
    uint256 public deadline;
    address public winner;
    
    // VULNERABLE: Using block.timestamp for randomness
    function draw() public {
        require(block.timestamp > deadline, "Too early");
        
        // Miners can manipulate block.timestamp
        uint256 random = uint256(keccak256(abi.encode(block.timestamp, msg.sender))) % 100;
        
        if (random > 50) {
            winner = msg.sender;
        }
    }
    
    // VULNERABLE: Time-based logic with block.timestamp
    function isExpired() public view returns (bool) {
        return block.timestamp > deadline;
    }
}
