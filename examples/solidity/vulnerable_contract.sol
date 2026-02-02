// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableBank
 * @dev Intentionally vulnerable contract for testing
 * Contains multiple security vulnerabilities
 */
contract VulnerableBank {
    mapping(address => uint256) public balances;
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    // VULNERABILITY 1: Missing access control
    function setOwner(address newOwner) public {
        owner = newOwner;
    }
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    // VULNERABILITY 2: Reentrancy attack
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // External call BEFORE state update (vulnerable!)
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        // State update AFTER external call (reentrancy risk!)
        balances[msg.sender] -= amount;
    }
    
    // VULNERABILITY 3: tx.origin for authentication
    function emergencyWithdraw() public {
        require(tx.origin == owner, "Not owner");
        payable(owner).transfer(address(this).balance);
    }
    
    // VULNERABILITY 4: Unchecked external call
    function unsafeTransfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        balances[msg.sender] -= amount;
        balances[to] += amount;
        
        // Return value not checked!
        to.call{value: amount}("");
    }
    
    // VULNERABILITY 5: Timestamp dependence
    function randomNumber() public view returns (uint256) {
        // Predictable randomness
        return uint256(keccak256(abi.encodePacked(block.timestamp)));
    }
}