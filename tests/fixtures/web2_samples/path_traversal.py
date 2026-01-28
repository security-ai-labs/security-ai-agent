"""
Vulnerable Python code with path traversal
DO NOT USE IN PRODUCTION
"""

def read_user_file(filename):
    """VULNERABLE: Path traversal with ../ pattern"""
    # User can access files outside intended directory
    path = f"../uploads/{filename}"
    with open(path, 'r') as f:
        return f.read()

def load_config(config_name):
    """VULNERABLE: open() with user input"""
    # No path sanitization
    with open(config_name) as f:
        return f.read()

def access_file(file_path):
    """VULNERABLE: Backslash traversal (Windows)"""
    base_dir = "C:\\Users\\Public\\"
    full_path = base_dir + file_path  # Can be ..\\..\\system\\config
    return open(full_path).read()
