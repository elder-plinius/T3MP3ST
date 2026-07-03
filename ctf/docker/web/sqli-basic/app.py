#!/usr/bin/env python3
"""
Vulnerable Login Application - SQL Injection Challenge
DO NOT USE IN PRODUCTION - Intentionally vulnerable for CTF training
"""

import os
import sqlite3
from flask import Flask, request, render_template_string

app = Flask(__name__)

# Get flag from environment
FLAG = os.environ.get('CTF_FLAG', 'T3MP3ST{test_flag}')

# Initialize database
def init_db():
    conn = sqlite3.connect(':memory:')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Create users table
    c.execute('''CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        password TEXT,
        role TEXT
    )''')

    # Create secrets table with flag
    c.execute('''CREATE TABLE secrets (
        id INTEGER PRIMARY KEY,
        name TEXT,
        value TEXT
    )''')

    # Insert test users
    c.execute("INSERT INTO users VALUES (1, 'admin', 'sup3rs3cr3t_p4ssw0rd!', 'admin')")
    c.execute("INSERT INTO users VALUES (2, 'guest', 'guest123', 'user')")

    # Insert flag
    c.execute("INSERT INTO secrets VALUES (1, 'flag', ?)", (FLAG,))

    conn.commit()
    return conn

# Global connection (for simplicity - in real app would use connection pool)
db = init_db()

LOGIN_PAGE = '''
<!DOCTYPE html>
<html>
<head>
    <title>KORP Terminal - Login</title>
    <style>
        body {
            background: #0a0a0a;
            color: #00ff00;
            font-family: monospace;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .container {
            background: #111;
            padding: 40px;
            border: 1px solid #00ff00;
            border-radius: 5px;
        }
        h1 { text-align: center; }
        input {
            width: 100%;
            padding: 10px;
            margin: 10px 0;
            background: #0a0a0a;
            border: 1px solid #00ff00;
            color: #00ff00;
            font-family: monospace;
        }
        button {
            width: 100%;
            padding: 12px;
            background: #00ff00;
            color: #0a0a0a;
            border: none;
            cursor: pointer;
            font-family: monospace;
            font-weight: bold;
        }
        .error { color: #ff0000; margin-top: 10px; }
        .success { color: #00ff00; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>KORP Terminal</h1>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">ACCESS TERMINAL</button>
        </form>
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        {% if success %}
        <div class="success">{{ success }}</div>
        {% endif %}
    </div>
</body>
</html>
'''

ADMIN_PAGE = '''
<!DOCTYPE html>
<html>
<head>
    <title>KORP Terminal - Admin Panel</title>
    <style>
        body {
            background: #0a0a0a;
            color: #00ff00;
            font-family: monospace;
            padding: 40px;
        }
        .flag {
            background: #001100;
            padding: 20px;
            border: 2px solid #00ff00;
            margin: 20px 0;
            font-size: 18px;
        }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #00ff00; padding: 10px; text-align: left; }
    </style>
</head>
<body>
    <h1>Welcome, Admin!</h1>
    <div class="flag">
        <strong>SECRET FLAG:</strong> {{ flag }}
    </div>
    <h2>User Database</h2>
    <table>
        <tr><th>ID</th><th>Username</th><th>Password</th><th>Role</th></tr>
        {% for user in users %}
        <tr><td>{{ user.id }}</td><td>{{ user.username }}</td><td>{{ user.password }}</td><td>{{ user.role }}</td></tr>
        {% endfor %}
    </table>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(LOGIN_PAGE)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    # VULNERABLE: Direct string concatenation in SQL query
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

    try:
        cursor = db.cursor()
        cursor.execute(query)
        user = cursor.fetchone()

        if user:
            if user['role'] == 'admin':
                # Get all users for admin panel
                cursor.execute("SELECT * FROM users")
                users = cursor.fetchall()

                # Get flag
                cursor.execute("SELECT value FROM secrets WHERE name='flag'")
                flag_row = cursor.fetchone()
                flag = flag_row['value'] if flag_row else 'FLAG_NOT_FOUND'

                return render_template_string(ADMIN_PAGE, users=users, flag=flag)
            else:
                return render_template_string(LOGIN_PAGE, success=f"Welcome, {user['username']}! But you're not admin...")
        else:
            return render_template_string(LOGIN_PAGE, error="Invalid credentials")

    except sqlite3.Error as e:
        # VULNERABLE: Exposes SQL errors
        return render_template_string(LOGIN_PAGE, error=f"Database error: {str(e)}")

@app.route('/health')
def health():
    return 'OK', 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
