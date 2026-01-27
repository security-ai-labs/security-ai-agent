// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;  // ❌ VULNERABILITY: Old Solidity version (< 0.8)

contract VulnerableDefiContract {
    
    // ❌ VULNERABILITY: Hardcoded admin address (Hardcoded Secrets)
    address admin = 0x1234567890123456789012345678901234567890;
    
    mapping(address => uint256) public balances;
    mapping(address => uint256) public userDeposits;
    
    // ❌ VULNERABILITY: No zero address check
    function deposit(address recipient, uint256 amount) public {
        userDeposits[recipient] += amount;  // Missing zero address check
    }
    
    // ❌ VULNERABILITY: Reentrancy - external call before state update
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        
        // ❌ CRITICAL: Call before state update
        msg.sender.call{value: amount}("");
        
        // State update AFTER external call - REENTRANCY RISK!
        balances[msg.sender] -= amount;
    }
    
    // ❌ VULNERABILITY: Unchecked call return value
    function withdrawUnsafe(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        
        // ❌ No require check on return value
        msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }
    
    // ❌ VULNERABILITY: No access control on critical function
    function adminTransfer(address from, address to, uint256 amount) public {
        // Missing onlyAdmin check!
        balances[from] -= amount;
        balances[to] += amount;
    }
    
    // ❌ VULNERABILITY: Integer arithmetic without SafeMath
    function addFunds(uint256 amount) public {
        balances[msg.sender] += amount;  // Overflow possible in Solidity < 0.8
    }
    
    // ❌ VULNERABILITY: Timestamp dependency
    function claimReward() public {
        if (block.timestamp > 1234567890) {  // ❌ Miners can manipulate this
            balances[msg.sender] += 100;
        }
    }
    
    // ❌ VULNERABILITY: Missing slippage protection in swap
    function swapTokens(uint256 amountIn) public returns (uint256) {
        // ❌ No minAmountOut parameter - vulnerable to sandwich attacks
        uint256 amountOut = calculateSwap(amountIn);
        return amountOut;
    }
    
    // ❌ VULNERABILITY: Flash loan vulnerability
    function flashLoanCallback(uint256 amount) public {
        uint256 balanceBefore = address(this).balance;
        
        // Do something with loan...
        doSomething();
        
        // ❌ VULNERABILITY: Unsafe balance check (can be manipulated)
        require(address(this).balance >= balanceBefore);
    }
    
    function calculateSwap(uint256 amount) internal view returns (uint256) {
        return amount * 95 / 100;
    }
    
    function doSomething() internal {}
}

// ❌ VULNERABILITY: Delegatecall to user-controlled address
contract ProxyContract {
    address public implementation;
    
    function setImplementation(address _impl) public {
        implementation = _impl;  // No access control!
    }
    
    fallback() external payable {
        // ❌ CRITICAL: Delegatecall to user-controlled address
        (bool success, ) = implementation.delegatecall(msg.data);
        require(success);
    }
}

// ❌ VULNERABILITY: NFT with reentrancy in mint
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

contract VulnerableNFT is ERC721 {
    
    function mintWithCallback(address to) public {
        // ❌ VULNERABILITY: No reentrancy guard
        _safeMint(to, nextTokenId++);
        
        // ❌ Potential reentrancy here during _safeMint
        ICallback(to).onERC721Received(address(this), address(0), nextTokenId, "");
    }
    
    uint256 nextTokenId = 1;
}

interface ICallback {
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data) external returns (bytes4);
}