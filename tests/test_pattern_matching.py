"""
Tests for enhanced pattern matching features
"""
import sys
import os
import json
import tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from pattern_matcher import PatternMatcher


class TestExcludePatterns:
    """Tests for exclude patterns (negative matching)"""
    
    def test_exclude_patterns_prevent_false_positives(self):
        """Test that exclude patterns filter out false positives"""
        # Create temporary rules with exclude patterns
        rules = {
            "ethereum": {
                "tx_origin_test": {
                    "name": "tx.origin Test",
                    "patterns": ["tx.origin"],
                    "exclude_patterns": ["event", "emit"],
                    "severity": "CRITICAL"
                }
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(rules, f)
            rules_file = f.name
        
        try:
            matcher = PatternMatcher(rules_file)
            
            # Should flag this (no exclude pattern present)
            vulnerable_code = "require(tx.origin == owner);"
            vulns = matcher.find_vulnerabilities('test.sol', vulnerable_code, 'ethereum')
            assert len(vulns) > 0, "Should detect tx.origin in authorization"
            
            # Should NOT flag this (emit is an exclude pattern)
            safe_code = "emit UserAction(tx.origin);"
            vulns = matcher.find_vulnerabilities('test.sol', safe_code, 'ethereum')
            assert len(vulns) == 0, "Should NOT flag tx.origin in event emission"
            
            # Should NOT flag this (event is an exclude pattern)
            safe_code2 = "event UserAction(address indexed origin); // tx.origin"
            vulns = matcher.find_vulnerabilities('test.sol', safe_code2, 'ethereum')
            assert len(vulns) == 0, "Should NOT flag tx.origin in event definition"
        
        finally:
            os.unlink(rules_file)
    
    def test_exclude_patterns_with_context_window(self):
        """Test that exclude patterns work within context window"""
        rules = {
            "ethereum": {
                "call_test": {
                    "name": "Call Test",
                    "patterns": [".call{value:"],
                    "exclude_patterns": ["ReentrancyGuard", "nonReentrant"],
                    "context_window": 3,
                    "severity": "CRITICAL"
                }
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(rules, f)
            rules_file = f.name
        
        try:
            matcher = PatternMatcher(rules_file)
            
            # Should flag this (no protection)
            vulnerable = """
            function withdraw() public {
                msg.sender.call{value: amount}("");
                balance = 0;
            }
            """
            vulns = matcher.find_vulnerabilities('test.sol', vulnerable, 'ethereum')
            assert len(vulns) > 0, "Should detect unprotected call"
            
            # Should NOT flag this (ReentrancyGuard within context window)
            protected = """
            function withdraw() public nonReentrant {
                require(balance > 0);
                msg.sender.call{value: amount}("");
                balance = 0;
            }
            """
            vulns = matcher.find_vulnerabilities('test.sol', protected, 'ethereum')
            assert len(vulns) == 0, "Should NOT flag protected call with nonReentrant"
        
        finally:
            os.unlink(rules_file)
    
    def test_multiple_exclude_patterns(self):
        """Test that any exclude pattern filters the match"""
        rules = {
            "web2": {
                "secret_test": {
                    "name": "Secret Test",
                    "patterns": ["API_KEY ="],
                    "exclude_patterns": ["os.getenv", "process.env", "# example"],
                    "severity": "CRITICAL"
                }
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(rules, f)
            rules_file = f.name
        
        try:
            matcher = PatternMatcher(rules_file)
            
            # Should flag this
            vulnerable = 'API_KEY = "abc123"'
            vulns = matcher.find_vulnerabilities('config.py', vulnerable, 'web2')
            assert len(vulns) > 0, "Should detect hardcoded API key"
            
            # Should NOT flag (os.getenv)
            safe1 = 'API_KEY = os.getenv("API_KEY")'
            vulns = matcher.find_vulnerabilities('config.py', safe1, 'web2')
            assert len(vulns) == 0, "Should NOT flag env var usage"
            
            # Should NOT flag (process.env)
            safe2 = 'API_KEY = process.env.API_KEY'
            vulns = matcher.find_vulnerabilities('config.js', safe2, 'web2')
            assert len(vulns) == 0, "Should NOT flag process.env usage"
            
            # Should NOT flag (example comment)
            safe3 = '# example: API_KEY = "your-key-here"'
            vulns = matcher.find_vulnerabilities('readme.md', safe3, 'web2')
            assert len(vulns) == 0, "Should NOT flag example in documentation"
        
        finally:
            os.unlink(rules_file)


class TestRequiredContext:
    """Tests for required context filtering"""
    
    def test_required_context_filtering(self):
        """Test that required_context filters matches"""
        rules = {
            "ethereum": {
                "context_test": {
                    "name": "Context Test",
                    "patterns": ["delegatecall("],
                    "required_context": ["user", "input"],
                    "context_window": 2,
                    "severity": "CRITICAL"
                }
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(rules, f)
            rules_file = f.name
        
        try:
            matcher = PatternMatcher(rules_file)
            
            # Should flag (has "user" in context)
            vulnerable = """
            function execute(address user) public {
                user.delegatecall(msg.data);
            }
            """
            vulns = matcher.find_vulnerabilities('test.sol', vulnerable, 'ethereum')
            assert len(vulns) > 0, "Should detect delegatecall with user input"
            
            # Should NOT flag (no required context)
            safe = """
            function execute() internal {
                trustedContract.delegatecall(msg.data);
            }
            """
            vulns = matcher.find_vulnerabilities('test.sol', safe, 'ethereum')
            assert len(vulns) == 0, "Should NOT flag delegatecall without user context"
        
        finally:
            os.unlink(rules_file)
    
    def test_required_context_case_insensitive(self):
        """Test that required_context matching is case-insensitive"""
        rules = {
            "web2": {
                "sql_test": {
                    "name": "SQL Test",
                    "patterns": ["execute("],
                    "required_context": ["SELECT", "insert"],  # Mixed case
                    "context_window": 2,
                    "severity": "CRITICAL"
                }
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(rules, f)
            rules_file = f.name
        
        try:
            matcher = PatternMatcher(rules_file)
            
            # Should flag (SELECT in uppercase, context item also uppercase)
            vulnerable = """
            query = "SELECT * FROM users"
            execute(query)
            """
            vulns = matcher.find_vulnerabilities('app.py', vulnerable, 'web2')
            assert len(vulns) > 0, "Should detect with uppercase SELECT matching uppercase context"
            
            # Should flag (select in lowercase, context item in uppercase)
            vulnerable2 = """
            query = "select * from users"
            execute(query)
            """
            vulns = matcher.find_vulnerabilities('app.py', vulnerable2, 'web2')
            assert len(vulns) > 0, "Should detect with lowercase select matching uppercase context"
            
            # Should flag (INSERT in uppercase, context item in lowercase)
            vulnerable3 = """
            query = "INSERT INTO users VALUES"
            execute(query)
            """
            vulns = matcher.find_vulnerabilities('app.py', vulnerable3, 'web2')
            assert len(vulns) > 0, "Should detect with uppercase INSERT matching lowercase context"
            
            # Should NOT flag (no SQL keywords)
            safe = """
            result = calculate_total()
            execute(result)
            """
            vulns = matcher.find_vulnerabilities('app.py', safe, 'web2')
            assert len(vulns) == 0, "Should NOT flag non-SQL execute"
        
        finally:
            os.unlink(rules_file)
    
    def test_multiple_required_context_any_match(self):
        """Test that ANY required context word triggers detection"""
        rules = {
            "ethereum": {
                "auth_test": {
                    "name": "Auth Test",
                    "patterns": ["tx.origin =="],
                    "required_context": ["owner", "admin", "auth"],
                    "context_window": 3,
                    "severity": "CRITICAL"
                }
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(rules, f)
            rules_file = f.name
        
        try:
            matcher = PatternMatcher(rules_file)
            
            # Should flag (has "owner")
            vulnerable1 = """
            require(tx.origin == owner);
            """
            vulns = matcher.find_vulnerabilities('test.sol', vulnerable1, 'ethereum')
            assert len(vulns) > 0, "Should detect with owner context"
            
            # Should flag (has "admin")
            vulnerable2 = """
            if (tx.origin == admin) {
                doSomething();
            }
            """
            vulns = matcher.find_vulnerabilities('test.sol', vulnerable2, 'ethereum')
            assert len(vulns) > 0, "Should detect with admin context"
            
            # Should NOT flag (has tx.origin but no auth context)
            safe = """
            emit Event(tx.origin);
            """
            vulns = matcher.find_vulnerabilities('test.sol', safe, 'ethereum')
            assert len(vulns) == 0, "Should NOT flag without auth context"
        
        finally:
            os.unlink(rules_file)


class TestExcludeAndRequiredContext:
    """Tests for combined exclude patterns and required context"""
    
    def test_both_filters_work_together(self):
        """Test that both exclude patterns and required context are applied"""
        rules = {
            "ethereum": {
                "combined_test": {
                    "name": "Combined Test",
                    "patterns": ["tx.origin"],
                    "exclude_patterns": ["emit", "event"],
                    "required_context": ["require", "owner"],
                    "context_window": 3,
                    "severity": "CRITICAL"
                }
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(rules, f)
            rules_file = f.name
        
        try:
            matcher = PatternMatcher(rules_file)
            
            # Should flag (has required context, no exclude pattern)
            vulnerable = """
            require(tx.origin == owner);
            """
            vulns = matcher.find_vulnerabilities('test.sol', vulnerable, 'ethereum')
            assert len(vulns) > 0, "Should detect when both filters pass"
            
            # Should NOT flag (has exclude pattern)
            excluded = """
            emit Action(tx.origin, owner);
            """
            vulns = matcher.find_vulnerabilities('test.sol', excluded, 'ethereum')
            assert len(vulns) == 0, "Should NOT flag when exclude pattern present"
            
            # Should NOT flag (missing required context)
            no_context = """
            console.log(tx.origin);
            """
            vulns = matcher.find_vulnerabilities('test.sol', no_context, 'ethereum')
            assert len(vulns) == 0, "Should NOT flag when required context missing"
        
        finally:
            os.unlink(rules_file)


class TestRegexPatterns:
    """Tests for regex pattern support"""
    
    def test_regex_pattern_matching(self):
        """Test that regex: prefix enables regex matching"""
        rules = {
            "ethereum": {
                "regex_test": {
                    "name": "Regex Test",
                    "patterns": [r"regex:tx\.origin\s*==\s*\w+"],
                    "severity": "CRITICAL"
                }
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(rules, f)
            rules_file = f.name
        
        try:
            matcher = PatternMatcher(rules_file)
            
            # Should flag (matches regex with spaces)
            vulnerable1 = "tx.origin == owner"
            vulns = matcher.find_vulnerabilities('test.sol', vulnerable1, 'ethereum')
            assert len(vulns) > 0, "Should match with spaces"
            
            # Should flag (matches regex without spaces)
            vulnerable2 = "tx.origin==owner"
            vulns = matcher.find_vulnerabilities('test.sol', vulnerable2, 'ethereum')
            assert len(vulns) > 0, "Should match without spaces"
            
            # Should flag (matches with multiple spaces)
            vulnerable3 = "tx.origin   ==   myOwner"
            vulns = matcher.find_vulnerabilities('test.sol', vulnerable3, 'ethereum')
            assert len(vulns) > 0, "Should match with multiple spaces"
            
            # Should NOT flag (different pattern)
            safe = "msg.sender == owner"
            vulns = matcher.find_vulnerabilities('test.sol', safe, 'ethereum')
            assert len(vulns) == 0, "Should NOT match different pattern"
        
        finally:
            os.unlink(rules_file)
    
    def test_regex_with_exclude_patterns(self):
        """Test that regex patterns work with exclude patterns"""
        rules = {
            "ethereum": {
                "regex_exclude_test": {
                    "name": "Regex Exclude Test",
                    "patterns": [r"regex:\.call\{value:\s*\w+\}"],
                    "exclude_patterns": ["nonReentrant"],
                    "context_window": 2,
                    "severity": "CRITICAL"
                }
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(rules, f)
            rules_file = f.name
        
        try:
            matcher = PatternMatcher(rules_file)
            
            # Should flag
            vulnerable = """
            function withdraw() public {
                msg.sender.call{value: amount}("");
            }
            """
            vulns = matcher.find_vulnerabilities('test.sol', vulnerable, 'ethereum')
            assert len(vulns) > 0, "Should detect unprotected call"
            
            # Should NOT flag (has nonReentrant)
            safe = """
            function withdraw() public nonReentrant {
                msg.sender.call{value: amount}("");
            }
            """
            vulns = matcher.find_vulnerabilities('test.sol', safe, 'ethereum')
            assert len(vulns) == 0, "Should NOT flag with nonReentrant"
        
        finally:
            os.unlink(rules_file)


class TestBackwardCompatibility:
    """Tests to ensure backward compatibility"""
    
    def test_rules_without_filters_still_work(self):
        """Test that rules without exclude_patterns or required_context still work"""
        rules = {
            "ethereum": {
                "simple_test": {
                    "name": "Simple Test",
                    "patterns": ["pragma solidity"],
                    "severity": "INFO"
                }
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(rules, f)
            rules_file = f.name
        
        try:
            matcher = PatternMatcher(rules_file)
            
            # Should flag (simple pattern matching)
            code = "pragma solidity ^0.8.0;"
            vulns = matcher.find_vulnerabilities('test.sol', code, 'ethereum')
            assert len(vulns) > 0, "Should detect with simple pattern"
            assert vulns[0]['name'] == "Simple Test"
        
        finally:
            os.unlink(rules_file)
    
    def test_literal_patterns_still_work(self):
        """Test that literal string patterns (not regex) still work"""
        rules = {
            "ethereum": {
                "literal_test": {
                    "name": "Literal Test",
                    "patterns": ["tx.origin ==", "msg.sender =="],
                    "severity": "MEDIUM"
                }
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(rules, f)
            rules_file = f.name
        
        try:
            matcher = PatternMatcher(rules_file)
            
            # Should flag (literal match)
            code1 = "require(tx.origin == owner);"
            vulns = matcher.find_vulnerabilities('test.sol', code1, 'ethereum')
            assert len(vulns) > 0, "Should detect tx.origin =="
            
            # Should flag (literal match)
            code2 = "require(msg.sender == owner);"
            vulns = matcher.find_vulnerabilities('test.sol', code2, 'ethereum')
            assert len(vulns) > 0, "Should detect msg.sender =="
        
        finally:
            os.unlink(rules_file)


class TestRealWorldScenarios:
    """Tests with real-world vulnerability scenarios"""
    
    def test_tx_origin_event_logging_not_flagged(self, pattern_matcher):
        """Test that tx.origin in event logging is not flagged as CRITICAL"""
        safe_code = """
        pragma solidity ^0.8.0;
        
        contract SafeLogger {
            event Action(address indexed origin, address indexed sender);
            
            function doAction() public {
                // Safe - just logging tx.origin for analytics
                emit Action(tx.origin, msg.sender);
            }
        }
        """
        
        vulns = pattern_matcher.find_vulnerabilities('SafeLogger.sol', safe_code, 'ethereum')
        
        # Should not detect tx_origin_authorization because "emit" is in exclude_patterns
        tx_origin_vulns = [v for v in vulns if v['id'] == 'tx_origin_authorization']
        assert len(tx_origin_vulns) == 0, "Should NOT flag tx.origin in event emission"
    
    def test_tx_origin_authorization_is_flagged(self, pattern_matcher):
        """Test that real tx.origin authorization is still flagged"""
        vulnerable_code = """
        pragma solidity ^0.8.0;
        
        contract Vulnerable {
            address owner;
            
            function sensitiveOperation() public {
                require(tx.origin == owner, "Not authorized");
                // Dangerous!
            }
        }
        """
        
        vulns = pattern_matcher.find_vulnerabilities('Vulnerable.sol', vulnerable_code, 'ethereum')
        
        # Should detect because it has "require" and "owner" in context
        tx_origin_vulns = [v for v in vulns if v['id'] == 'tx_origin_authorization']
        assert len(tx_origin_vulns) > 0, "Should flag tx.origin in authorization"
        assert tx_origin_vulns[0]['severity'] == 'CRITICAL'
    
    def test_reentrancy_with_guard_not_flagged(self, pattern_matcher):
        """Test that reentrancy with ReentrancyGuard is not flagged"""
        safe_code = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
        
        contract SafeWithdraw is ReentrancyGuard {
            function withdraw(uint amount) public nonReentrant {
                (bool success,) = msg.sender.call{value: amount}("");
                require(success);
                balances[msg.sender] -= amount;
            }
        }
        """
        
        vulns = pattern_matcher.find_vulnerabilities('SafeWithdraw.sol', safe_code, 'ethereum')
        
        # Should not detect reentrancy because "nonReentrant" is in exclude_patterns
        reentrancy_vulns = [v for v in vulns if v['id'] == 'reentrancy']
        assert len(reentrancy_vulns) == 0, "Should NOT flag with ReentrancyGuard"
    
    def test_hardcoded_secret_with_env_not_flagged(self, pattern_matcher):
        """Test that secrets from environment are not flagged"""
        safe_code = """
        import os
        
        # Good practice - load from environment
        API_KEY = os.getenv('API_KEY')
        SECRET_TOKEN = os.getenv('SECRET_TOKEN', 'default')
        """
        
        vulns = pattern_matcher.find_vulnerabilities('config.py', safe_code, 'web2')
        
        # Should not detect because "os.getenv" is in exclude_patterns
        secret_vulns = [v for v in vulns if v['id'] == 'hardcoded_secrets']
        assert len(secret_vulns) == 0, "Should NOT flag environment variables"
    
    def test_hardcoded_secret_literal_is_flagged(self, pattern_matcher):
        """Test that actual hardcoded secrets are still flagged"""
        vulnerable_code = """
        # Bad practice - hardcoded secret
        API_KEY = "sk_live_abc123xyz789"
        SECRET_TOKEN = "my-secret-token-12345"
        """
        
        vulns = pattern_matcher.find_vulnerabilities('config.py', vulnerable_code, 'web2')
        
        # Should detect because no exclude patterns present
        secret_vulns = [v for v in vulns if v['id'] == 'hardcoded_secrets']
        assert len(secret_vulns) > 0, "Should flag hardcoded secrets"
