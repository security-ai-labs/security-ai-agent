"""
Vulnerable Python code with hardcoded secrets
DO NOT USE IN PRODUCTION
"""

# VULNERABLE: Hardcoded API key
API_KEY = "sk_live_1234567890abcdef"

# VULNERABLE: Hardcoded private key
PRIVATE_KEY = "0x1234567890abcdef1234567890abcdef"

# VULNERABLE: Hardcoded password
DATABASE_CONFIG = {
    'host': 'localhost',
    'user': 'admin',
    'password = 'super_secret_password_123'
}

# VULNERABLE: Hardcoded JWT secret
JWT_SECRET = "my-super-secret-jwt-key"

def connect_to_api():
    """Connect using hardcoded credentials"""
    return requests.get(
        'https://api.example.com/data',
        headers={'Authorization': f'Bearer {API_KEY}'}
    )
