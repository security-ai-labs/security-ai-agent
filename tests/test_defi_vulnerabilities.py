"""
Tests for DeFi-specific vulnerability detection
"""
import pytest


class TestOracleManipulation:
    """Tests for price oracle manipulation"""
    
    def test_detects_get_price_usage(self, analyze_defi):
        """Test that agent detects getPrice pattern"""
        vulnerable_code = """
        pragma solidity ^0.8.0;
        
        contract LendingProtocol {
            function collateralValue(address token) public view returns (uint) {
                uint price = priceOracle.getPrice(token);
                return balanceOf[token] * price;
            }
        }
        """
        result = analyze_defi(vulnerable_code)
        assert any(v['id'] == 'oracle_manipulation' for v in result)
        vuln = next(v for v in result if v['id'] == 'oracle_manipulation')
        assert vuln['severity'] == 'CRITICAL'
    
    def test_detects_balance_of_price(self, analyze_defi):
        """Test that agent detects balanceOf usage for pricing"""
        vulnerable_code = """
        contract Vulnerable {
            function getTokenPrice() public view returns (uint) {
                uint lpBalance = token.balanceOf(address(pool));
                return lpBalance / totalSupply;
            }
        }
        """
        result = analyze_defi(vulnerable_code)
        assert any(v['id'] == 'oracle_manipulation' for v in result)
    
    def test_detects_get_amounts_out(self, analyze_defi):
        """Test that agent detects getAmountsOut pattern"""
        vulnerable_code = """
        function calculateValue(uint amount) external view returns (uint) {
            address[] memory path = new address[](2);
            path[0] = tokenA;
            path[1] = tokenB;
            uint[] memory amounts = router.getAmountsOut(amount, path);
            return amounts[1];
        }
        """
        result = analyze_defi(vulnerable_code)
        assert any(v['id'] == 'oracle_manipulation' for v in result)
    
    def test_detects_price_feed_reference(self, analyze_defi):
        """Test that agent detects price.feed pattern"""
        vulnerable_code = """
        IPriceFeed public price.feed;
        
        function getValue() returns (uint) {
            return amount * price;
        }
        """
        result = analyze_defi(vulnerable_code)
        assert any(v['id'] == 'oracle_manipulation' for v in result)


class TestSlippageProtection:
    """Tests for missing slippage protection"""
    
    def test_detects_swap_with_zero_min(self, analyze_defi):
        """Test that agent detects swap with 0 minimum"""
        vulnerable_code = """
        pragma solidity ^0.8.0;
        
        contract Trader {
            function trade(uint amountIn) external {
                router.swapExactTokensForTokens(
                    amountIn,
                    0,  // No slippage protection!
                    path,
                    msg.sender,
                    block.timestamp
                );
            }
        }
        """
        result = analyze_defi(vulnerable_code)
        assert any(v['id'] == 'slippage' for v in result)
        vuln = next(v for v in result if v['id'] == 'slippage')
        assert vuln['severity'] == 'MEDIUM'
    
    def test_detects_add_liquidity(self, analyze_defi):
        """Test that agent detects addLiquidity pattern"""
        vulnerable_code = """
        function provideLiquidity(uint amount) external {
            pair.addLiquidity(tokenA, tokenB, amount, amount, 0, 0, msg.sender, deadline);
        }
        """
        result = analyze_defi(vulnerable_code)
        assert any(v['id'] == 'slippage' for v in result)
    
    def test_detects_swap_function(self, analyze_defi):
        """Test that agent detects swap pattern"""
        vulnerable_code = """
        contract DEX {
            function swap(address tokenIn, address tokenOut, uint amountIn) external {
                // Execute swap without checking minAmount
            }
        }
        """
        result = analyze_defi(vulnerable_code)
        assert any(v['id'] == 'slippage' for v in result)
    
    def test_detects_min_amount_reference(self, analyze_defi):
        """Test that agent flags code mentioning minAmount"""
        code_with_min = """
        function swapTokens(uint amountIn, uint minAmount) external {
            // Should validate minAmount
        }
        """
        result = analyze_defi(code_with_min)
        assert any(v['id'] == 'slippage' for v in result)
