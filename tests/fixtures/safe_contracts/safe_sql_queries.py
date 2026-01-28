"""
Safe Python code - parameterized queries
This should NOT be flagged as SQL injection
"""
import sqlite3
import psycopg2

def get_user_safe(user_id):
    """SAFE: Using parameterized query with ?"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", [user_id])
    return cursor.fetchall()

def search_users_safe(username):
    """SAFE: Using named parameters"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = :username", {"username": username})
    return cursor.fetchall()

def get_products_postgres(category):
    """SAFE: Using PostgreSQL parameterized query"""
    conn = psycopg2.connect("dbname=shop")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE category = %s", (category,))
    return cursor.fetchall()

# SAFE: Even if query mentions 'SELECT', using parameters is safe
def complex_query_safe(user_id, status):
    """SAFE: Multiple parameters"""
    conn = sqlite3.connect('db.sqlite')
    query = "SELECT * FROM orders WHERE user_id = ? AND status = ?"
    cursor = conn.cursor()
    cursor.execute(query, (user_id, status))
    return cursor.fetchall()
