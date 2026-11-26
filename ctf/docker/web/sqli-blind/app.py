#!/usr/bin/env python3
"""
Vulnerable Username Checker - Blind SQL Injection Challenge
DO NOT USE IN PRODUCTION - Intentionally vulnerable for CTF training

The flag lives in the vault table. It is never rendered by any endpoint;
it can only be extracted one character at a time via blind injection
(boolean via exists field, time-based via randomblob delay).
"""

import os
import sqlite3
import threading
import time
from flask import Flask, jsonify, request

app = Flask(__name__)

FLAG = os.environ.get('CTF_FLAG', 'T3MP3ST{bl1nd_sql1_t1m3_b4s3d}')


def init_db():
    # check_same_thread=False: Flask serves requests on worker threads;
    # QUERY_LOCK serializes access instead.
    conn = sqlite3.connect(':memory:', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute('''CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        password TEXT,
        role TEXT
    )''')

    # The flag sits in a vault table no page ever renders
    c.execute('''CREATE TABLE vault (
        id INTEGER PRIMARY KEY,
        site TEXT,
        secret TEXT
    )''')

    c.execute("INSERT INTO users VALUES (1, 'admin', 'N0tTh3Fl4g', 'admin')")
    c.execute("INSERT INTO users VALUES (2, 'guest', 'guest123', 'user')")
    c.execute("INSERT INTO users VALUES (3, 'auditor', 'Audit_2024!', 'auditor')")

    c.execute("INSERT INTO vault VALUES (1, 'legacy-ssi-portal', ?)", (FLAG,))
    c.execute("INSERT INTO vault VALUES (2, 'wiki', 'hunter2')")

    conn.commit()
    return conn


db = init_db()
QUERY_LOCK = threading.Lock()

INDEX_PAGE = '''
<!DOCTYPE html>
<html>
<head>
    <title>T3MP3ST Corp - Account Lookup</title>
    <style>
        body { background:#0a0a0a; color:#00ff00; font-family:monospace;
               display:flex; justify-content:center; padding-top:10vh; }
        .container { background:#111; border:1px solid #00ff00;
                     border-radius:5px; padding:40px; width:480px; }
        input { width:100%; padding:10px; margin:8px 0; background:#0a0a0a;
                border:1px solid #00ff00; color:#00ff00; font-family:monospace; }
        button { width:100%; padding:12px; background:#00ff00; color:#0a0a0a;
                 border:none; cursor:pointer; font-weight:bold;
                 font-family:monospace; }
        #result { margin-top:12px; white-space:pre-wrap; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Account Lookup</h1>
        <p>Check whether a username exists in the corporate directory.</p>
        <p><em>Note: the old SSI portal is offline. Its secrets were moved
        to the vault. There is no page that displays vault contents.</em></p>
        <input type="text" id="u" placeholder="username" value="guest">
        <button onclick="check()">CHECK</button>
        <div id="result"></div>
    </div>
    <script>
        function check() {
            fetch('/api/v1/username-check?u=' + encodeURIComponent(document.getElementById('u').value))
                .then(r => r.json())
                .then(d => document.getElementById('result').textContent =
                    'exists: ' + d.exists + '  (query time: ' + d.elapsed_ms + ' ms)');
        }
    </script>
</body>
</html>
'''


@app.route('/')
def index():
    return INDEX_PAGE


@app.route('/api/v1/username-check')
def username_check():
    username = request.args.get('u', '')

    # VULNERABLE: direct string concatenation inside the WHERE clause.
    # The exists boolean leaks the query result; randomblob enables
    # time-based extraction of the vault flag.
    query = ("SELECT COUNT(*) AS n FROM users WHERE username='%s'" % username)

    try:
        start = time.time()
        with QUERY_LOCK:
            cursor = db.cursor()
            cursor.execute(query)
            n = cursor.fetchone()['n']
        elapsed_ms = int((time.time() - start) * 1000)
        return jsonify(exists=(n > 0), elapsed_ms=elapsed_ms)

    except sqlite3.Error as e:
        return jsonify(exists=False, error=str(e)), 200


@app.route('/health')
def health():
    return 'OK', 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, threaded=True)
