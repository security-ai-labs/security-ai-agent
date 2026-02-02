"""
Vulnerable Flask API - For Testing Only
DO NOT USE IN PRODUCTION
"""

from flask import Flask, request, render_template_string
import sqlite3
import os

app = Flask(__name__)

# VULNERABILITY 1: Hardcoded secret key
app.secret_key = "super_secret_key_123"

# VULNERABILITY 2: SQL Injection
@app.route('/user/<user_id>')
def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Vulnerable: String formatting in SQL query
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    
    user = cursor.fetchone()
    return {'user': user}

# VULNERABILITY 3: Cross-Site Scripting (XSS)
@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    # Vulnerable: Unescaped user input in HTML
    html = f"<h1>Search results for: {query}</h1>"
    return render_template_string(html)

# VULNERABILITY 4: Command Injection
@app.route('/ping')
def ping():
    host = request.args.get('host', 'localhost')
    
    # Vulnerable: User input directly in system command
    result = os.system(f"ping -c 1 {host}")
    
    return {'result': result}

# VULNERABILITY 5: Missing Authentication
@app.route('/admin/delete_user/<user_id>', methods=['POST'])
def delete_user(user_id):
    # No authentication or authorization check!
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM users WHERE id = {user_id}")
    conn.commit()
    return {'deleted': user_id}

# VULNERABILITY 6: Path Traversal
@app.route('/download/<filename>')
def download_file(filename):
    # Vulnerable: No path validation
    with open(f"/uploads/{filename}", 'rb') as f:
        return f.read()

if __name__ == '__main__':
    # VULNERABILITY 7: Debug mode in production
    app.run(debug=True, host='0.0.0.0')