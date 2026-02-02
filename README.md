# 🛡️ Universal AI Security Agent

An AI-powered security analyzer for Web2 and Web3 applications. Detects vulnerabilities in smart contracts and traditional web applications using advanced LLM analysis.

## 🚀 Features

- ✅ **Multi-Language Support** - Solidity, Python, JavaScript, TypeScript, Rust, Go
- 🤖 **AI-Powered Analysis** - Uses GPT-4 for semantic vulnerability detection
- 🌐 **Web2 + Web3** - Covers both traditional and blockchain security
- 💰 **Cost Tracking** - Monitor API costs with smart caching
- 📊 **Beautiful Reports** - Rich terminal output and JSON exports
- ⚡ **Fast & Accurate** - Smart caching avoids redundant analysis

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/security-ai-labs/security-ai-agent.git
cd security-ai-agent

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY

# Analyze a Python file
python cli.py examples/python/vulnerable_api.py

# Analyze a Solidity contract
python cli.py examples/solidity/vulnerable_contract.sol

# Analyze JavaScript with detailed output
python cli.py examples/javascript/vulnerable_app.js --detailed

# Use GPT-4 instead of GPT-4o-mini
python cli.py myfile.py --model gpt-4o