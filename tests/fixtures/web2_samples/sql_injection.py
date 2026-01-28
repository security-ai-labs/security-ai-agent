"""
Vulnerable Python code with SQL injection
DO NOT USE IN PRODUCTION
"""
import sqlite3

def get_user_by_id(user_id):
    """VULNERABLE: SQL injection via string concatenation"""
    conn = sqlite3.connect('users.db')
    # Direct string concatenation - SQL injection risk!
    query = 'SELECT * FROM users WHERE id = ' + user_id
    result = conn.execute(query)
    return result.fetchall()

def search_users(username):
    """VULNERABLE: f-string in SQL query"""
    conn = sqlite3.connect('users.db')
    # f-string with user input - SQL injection risk!
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
