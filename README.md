# Security AI Agent

A comprehensive security analysis tool for Web3 and Web2 applications that detects vulnerabilities across Ethereum/Solidity, Solana/Rust, DeFi protocols, and traditional web applications.

## Features

✅ **Multi-Chain Support**: Ethereum, Solana, and general Web2 applications
✅ **60+ Vulnerability Rules**: Comprehensive detection patterns
✅ **GitHub Integration**: Automated PR comments with security findings
✅ **Test-Driven**: 68+ tests validating detection accuracy
✅ **Low False Positives**: Carefully tuned patterns to minimize noise

## Supported Vulnerabilities

### Ethereum/Solidity (8 types)
- Reentrancy attacks
- tx.origin authorization
- Unchecked call returns
- Integer overflow/underflow
- Missing zero address checks
- Missing access control
- Delegatecall injection
- Timestamp dependency

### Solana/Rust (4 types)
- Missing signer checks
- Missing owner checks
- Unchecked account injection
- Arithmetic overflow

### Web2 (6 types)
- SQL injection
- Cross-Site Scripting (XSS)
- Command injection
- Hardcoded secrets
- Weak cryptographic hashing
- Path traversal

### DeFi (2 types)
- Oracle manipulation
- Missing slippage protection

## Installation

```bash
# Clone the repository
git clone https://github.com/security-ai-labs/security-ai-agent.git
cd security-ai-agent

# Install dependencies
pip install -r requirements.txt

# For development (includes test dependencies)
pip install -r requirements-dev.txt
```

## Usage

### Analyze a Repository

```bash
python main.py
```

This will:
1. Scan all security-relevant files in the current directory
2. Detect vulnerabilities using pattern matching
3. Generate a security report with findings

### GitHub PR Integration

```bash
python github_pr_commenter.py
```

Automatically comments on pull requests with security findings.

## Testing

The project includes a comprehensive test suite to validate vulnerability detection accuracy and minimize false positives.

### Run All Tests

```bash
pytest tests/
```

Expected output:
```
```

### Run Specific Test Files

```bash
# Ethereum/Solidity tests
pytest tests/test_ethereum_vulnerabilities.py -v

# Solana/Rust tests
pytest tests/test_solana_vulnerabilities.py -v

# Web2 tests
pytest tests/test_web2_vulnerabilities.py -v

# DeFi tests
pytest tests/test_defi_vulnerabilities.py -v
```

### Run Specific Test Classes

```bash
pytest tests/test_ethereum_vulnerabilities.py::TestReentrancy -v
pytest tests/test_web2_vulnerabilities.py::TestSQLInjection -v
```

### Run with Coverage

```bash
pytest tests/ --cov=src --cov-report=html --cov-report=term
```

View the HTML report: `htmlcov/index.html`

### Test Structure

The test suite includes:
- **68+ tests** covering all vulnerability types
- **Positive tests**: Verify vulnerabilities ARE detected
- **Negative tests**: Verify safe code is NOT flagged (false positive prevention)
- **Real-world patterns**: Tests use authentic vulnerable code patterns

See [tests/README.md](tests/README.md) for detailed testing documentation.

## Project Structure

```
security-ai-agent/
├── src/                           # Source code
│   ├── analyzer.py                # Main security analyzer
│   ├── pattern_matcher.py         # Pattern matching logic
│   ├── file_detector.py           # File detection
│   └── report_generator.py        # Report generation
├── config/                        # Configuration
│   └── vulnerability_rules.json   # Vulnerability definitions
├── tests/                         # Test suite
│   ├── test_ethereum_vulnerabilities.py
│   ├── test_solana_vulnerabilities.py
│   ├── test_web2_vulnerabilities.py
│   ├── test_defi_vulnerabilities.py
│   ├── conftest.py                # Test fixtures
│   └── fixtures/                  # Sample code
│       ├── vulnerable_contracts/  # Vulnerable examples
│       ├── safe_contracts/        # Safe examples
│       └── web2_samples/          # Web2 examples
├── main.py                        # CLI entry point
├── github_pr_commenter.py         # GitHub integration
├── pytest.ini                     # Pytest configuration
├── requirements.txt               # Dependencies
└── requirements-dev.txt           # Dev dependencies
```

## Development

### Adding New Vulnerability Rules

1. Add rule definition to `config/vulnerability_rules.json`
2. Create tests in appropriate test file (e.g., `tests/test_ethereum_vulnerabilities.py`)
3. Run tests to verify detection: `pytest tests/ -v`
4. Document the vulnerability in this README

### Running Linters

```bash
# Install dev dependencies if not already done
pip install -r requirements-dev.txt

# Run linters (if configured)
# flake8 src/
# black --check src/
```

## CI/CD

Tests run automatically on:
- Every push to `main` branch
- Every pull request

The CI pipeline:
1. Installs dependencies
2. Runs full test suite
3. Generates coverage reports
4. Fails if any tests fail

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-detection`)
3. Write tests for your changes
4. Implement the feature
5. Ensure all tests pass (`pytest tests/`)
6. Submit a pull request

## Security

If you discover a security vulnerability in this tool, please email [security@example.com](mailto:security@example.com).

## License

[Add license information]

## Contact

- **GitHub**: [security-ai-labs/security-ai-agent](https://github.com/security-ai-labs/security-ai-agent)
- **Issues**: [Report bugs or request features](https://github.com/security-ai-labs/security-ai-agent/issues)

## Acknowledgments

This tool is designed to help developers catch common security vulnerabilities early in the development process. It complements, but does not replace, professional security audits.
# Security Agent Development Progress

## Completed
✅ Clean architecture (src/, config/)
✅ Comprehensive vulnerability rules (60+ rules)
✅ File detection and pattern matching
✅ GitHub PR integration
✅ Web2 and Web3 vulnerability coverage
✅ Confidence scoring for vulnerability findings

## In Progress
- Improving Solidity-specific detection
- Adding more DeFi vulnerability rules
- Testing with vulnerable contracts

## Next Steps
- Enhance tx.origin detection
- Add more assembly-based vulnerabilities
- Improve false positive filtering

## Key Files
- config/vulnerability_rules.json - Main rules database
- src/pattern_matcher.py - Pattern detection logic
- src/analyzer.py - Main orchestrator
- src/confidence_scorer.py - Confidence scoring logic

## Confidence Scoring

Each vulnerability finding includes a confidence score (0-1) indicating the likelihood it's a true positive.

### Confidence Levels
- **HIGH (≥0.75):** 🔴 Very likely a real vulnerability
- **MEDIUM (0.5-0.75):** 🟡 Likely a vulnerability, review carefully
- **LOW (<0.5):** ⚪ Possible false positive, verify manually

### Factors Affecting Confidence
- ✅ In state-changing function → Higher confidence
- ❌ In comments or documentation → Lower confidence  
- ❌ In test files → Lower confidence
- ✅ CRITICAL severity → Confidence boost
- ✅ Security keywords nearby → Confidence boost
- ❌ Mitigation patterns present → Lower confidence

### Filtering Low Confidence
Configure minimum confidence threshold in `config.yaml`:
```yaml
confidence:
  min_confidence: 0.3
  show_low_confidence: true
  boost_critical: 1.2
```

### Example Output
Vulnerability findings now include confidence information:
```markdown
🚨 **Reentrancy Attack** (Line 42) 🔴 Confidence: HIGH (85%)
- **Severity:** `CRITICAL`
- **Issue:** External call before state update
- **Solution:** Update state before making external calls
```
