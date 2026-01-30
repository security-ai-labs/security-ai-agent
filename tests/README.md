# Test Suite Documentation

## Overview

This directory contains comprehensive tests for the Security AI Agent that validates vulnerability detection across all supported chains and vulnerability types.

## Directory Structure

```
tests/
├── __init__.py                      # Package initialization
├── conftest.py                      # Pytest configuration and fixtures
├── test_ethereum_vulnerabilities.py # Ethereum/Solidity tests
├── test_solana_vulnerabilities.py   # Solana/Rust tests
├── test_web2_vulnerabilities.py     # Web2 vulnerability tests
├── test_defi_vulnerabilities.py     # DeFi-specific tests
├── fixtures/                        # Sample code for testing
│   ├── vulnerable_contracts/        # Contracts with vulnerabilities
│   ├── safe_contracts/              # Properly secured contracts
│   └── web2_samples/                # Web2 code samples
└── README.md                        # This file
```

## Running Tests

### Run All Tests
```bash
pytest tests/
```

### Run Specific Test File
```bash
pytest tests/test_ethereum_vulnerabilities.py
pytest tests/test_solana_vulnerabilities.py
pytest tests/test_web2_vulnerabilities.py
pytest tests/test_defi_vulnerabilities.py
```

### Run Specific Test Class
```bash
pytest tests/test_ethereum_vulnerabilities.py::TestReentrancy
pytest tests/test_web2_vulnerabilities.py::TestSQLInjection
```

### Run Specific Test
```bash
pytest tests/test_ethereum_vulnerabilities.py::TestReentrancy::test_detects_reentrancy_with_call_value
```

### Run with Verbose Output
```bash
pytest tests/ -v
```

### Run with Coverage Report
```bash
pytest tests/ --cov=src --cov-report=html --cov-report=term
```

The HTML coverage report will be available in `htmlcov/index.html`

### Run Tests in Parallel (faster)
```bash
pip install pytest-xdist
pytest tests/ -n auto
```

## Running Tests with Target Directory

### Test with Sample Vulnerable Code

```bash
# Test with sample vulnerable code
python main.py --target tests/fixtures/vulnerable_contracts/
```

## Test Coverage

### Ethereum/Solidity (8 vulnerability types)
- ✅ **Reentrancy** - External calls before state updates
- ✅ **tx.origin Authorization** - Using tx.origin for access control
- ✅ **Unchecked Call Returns** - Not checking call/delegatecall return values
- ✅ **Integer Overflow/Underflow** - Pre-0.8.0 Solidity arithmetic
- ✅ **Missing Zero Address Check** - Transfers without address validation
- ✅ **Missing Access Control** - Public functions without authorization
- ✅ **Delegatecall Injection** - Delegatecall to untrusted addresses
- ✅ **Timestamp Dependency** - Relying on block.timestamp

### Solana/Rust (4 vulnerability types)
- ✅ **Missing Signer Check** - is_signer validation
- ✅ **Missing Owner Check** - Account ownership validation
- ✅ **Unchecked Account** - UncheckedAccount usage
- ✅ **Arithmetic Overflow** - Unchecked arithmetic operations

### Web2 (6 vulnerability types)
- ✅ **SQL Injection** - Unparameterized queries
- ✅ **XSS** - innerHTML and eval usage
- ✅ **Command Injection** - os.system and shell=True
- ✅ **Hardcoded Secrets** - API keys and passwords in code
- ✅ **Weak Hash** - MD5/SHA1 usage
- ✅ **Path Traversal** - Unsafe file path handling

### DeFi (2 vulnerability types)
- ✅ **Oracle Manipulation** - Unverified price sources
- ✅ **Slippage Protection** - Missing minimum amount checks

## Test Structure

Each test follows this pattern:

### Positive Tests (Detect Vulnerabilities)
```python
def test_detects_vulnerability_name(self, analyze_ethereum):
    """Test that agent detects [vulnerability] in vulnerable code"""
    vulnerable_code = """
    // Code with vulnerability
    """
    result = analyze_ethereum(vulnerable_code)
    assert any(v['id'] == 'vulnerability_id' for v in result)
    vuln = next(v for v in result if v['id'] == 'vulnerability_id')
    assert vuln['severity'] == 'CRITICAL'
```

### Negative Tests (Don't Flag Safe Code)
```python
def test_ignores_safe_pattern(self, analyze_ethereum):
    """Test that agent doesn't flag safe usage"""
    safe_code = """
    // Safe code
    """
    result = analyze_ethereum(safe_code)
    assert not any(v['id'] == 'vulnerability_id' for v in result)
```

## Adding New Tests

### 1. Choose the Appropriate Test File
- Ethereum/Solidity → `test_ethereum_vulnerabilities.py`
- Solana/Rust → `test_solana_vulnerabilities.py`
- Web2 → `test_web2_vulnerabilities.py`
- DeFi → `test_defi_vulnerabilities.py`

### 2. Create a Test Class
```python
class TestNewVulnerability:
    """Tests for new vulnerability detection"""
    
    def test_detects_vulnerability(self, analyze_ethereum):
        """Test description"""
        vulnerable_code = """
        // vulnerable code
        """
        result = analyze_ethereum(vulnerable_code)
        assert any(v['id'] == 'new_vulnerability' for v in result)
```

### 3. Add Corresponding Rule
Make sure the vulnerability rule exists in `config/vulnerability_rules.json`:

```json
{
  "ethereum": {
    "new_vulnerability": {
      "name": "New Vulnerability Name",
      "patterns": ["pattern1", "pattern2"],
      "severity": "CRITICAL",
      "description": "Description of the vulnerability",
      "remediation": "How to fix it",
      "examples": ["Example 1", "Example 2"],
      "references": ["Reference URL"]
    }
  }
}
```

### 4. Run the New Tests
```bash
pytest tests/test_ethereum_vulnerabilities.py::TestNewVulnerability -v
```

## Fixtures and Helpers

### Available Fixtures (from conftest.py)
- `analyzer` - Full SecurityAnalyzer instance
- `pattern_matcher` - PatternMatcher instance
- `analyze_ethereum(code)` - Helper for Ethereum code
- `analyze_solana(code)` - Helper for Solana code
- `analyze_web2(code)` - Helper for Web2 code
- `analyze_defi(code)` - Helper for DeFi code

### Sample Fixtures
Sample vulnerable and safe code is available in `tests/fixtures/`:
- `vulnerable_contracts/` - Known vulnerable contracts
- `safe_contracts/` - Properly secured contracts
- `web2_samples/` - Web2 code samples

## CI/CD Integration

Tests run automatically on:
- Every push to `main` or `develop` branches
- Every pull request to `main` or `develop` branches

The CI workflow (`.github/workflows/test.yml`):
1. Runs tests on Python 3.9, 3.10, 3.11, and 3.12
2. Generates coverage reports
3. Uploads coverage artifacts
4. Fails the build if tests fail

## Continuous Improvement

### When to Update Tests
- ✅ Adding new vulnerability detection rules
- ✅ Fixing false positives
- ✅ Improving detection accuracy
- ✅ Supporting new languages or frameworks

### Best Practices
1. **Write tests first** when adding new vulnerability detection
2. **Test both positive and negative cases** (detect vulnerabilities AND don't flag safe code)
3. **Keep tests focused** - one vulnerability per test
4. **Use descriptive names** - test names should explain what they test
5. **Document edge cases** - add comments for non-obvious behavior
6. **Keep fixtures realistic** - use real-world code patterns

## Troubleshooting

### Tests Failing Locally
```bash
# Clear pytest cache
pytest --cache-clear tests/

# Run with more verbose output
pytest tests/ -vv

# Run a single test to isolate the issue
pytest tests/test_ethereum_vulnerabilities.py::TestReentrancy::test_detects_reentrancy_with_call_value -vv
```

### Coverage Issues
```bash
# Generate detailed coverage report
pytest tests/ --cov=src --cov-report=html
# Open htmlcov/index.html in browser

# Show missing lines
pytest tests/ --cov=src --cov-report=term-missing
```

### Import Errors
Make sure you're in the project root and dependencies are installed:
```bash
cd /path/to/security-ai-agent
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

## Contact

For questions or issues with tests:
1. Check existing test examples
2. Review `conftest.py` for available fixtures
3. Consult `config/vulnerability_rules.json` for rule definitions
4. Open an issue on GitHub with test failure details
