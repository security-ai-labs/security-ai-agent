"""
Vulnerable Python code with command injection
DO NOT USE IN PRODUCTION
"""
import os
import subprocess

def delete_file(filename):
    """VULNERABLE: os.system with user input"""
    # Shell injection risk!
    os.system(f'rm {filename}')

def run_command(cmd):
    """VULNERABLE: subprocess with shell=True"""
    # Shell injection risk!
    subprocess.run(cmd, shell=True)

def execute_python_code(code):
    """VULNERABLE: exec with user input"""
    # Code execution risk!
    exec(code)

def backup_files(directory):
    """VULNERABLE: os.system with concatenation"""
    os.system('tar -czf backup.tar.gz ' + directory)
