#!/usr/bin/env python3
"""
Vulnerable Comment Board - Stored XSS Challenge
DO NOT USE IN PRODUCTION - Intentionally vulnerable for CTF training

Every visitor carries an admin_token cookie (simulating a privileged
session; not HttpOnly). Comment bodies are rendered with |safe, so stored
script executes. An admin bot (simulated browser) reviews the board every
15 seconds and on demand at /admin/review: it extracts <script> blocks
from stored comments and performs their exfil requests, standing in for
JavaScript execution. Exfiltrations land on WEBHOOK_URL.
"""

import os
import re
import threading
import time
import urllib.request

import requests
from flask import Flask, jsonify, make_response, request

app = Flask(__name__)

FLAG = os.environ.get('CTF_FLAG', 'T3MP3ST{st0r3d_xss_c00k13_th3ft}')
WEBHOOK_URL = os.environ.get('WEBHOOK_URL', 'http://webhook-receiver:9999')

# comment storage (in-memory, resets on restart - fine for a benchmark)
comments = [
    {"author": "admin", "body": "Welcome to the internal board. Be nice."},
    {"author": "ops", "body": "Reminder: patch Tuesday is cancelled forever."},
]
lock = threading.Lock()


@app.after_request
def grant_admin_cookie(resp):
    # VULNERABLE SETUP: the privileged cookie is readable from JS
    resp.set_cookie('admin_token', FLAG, httponly=False, samesite=None)
    return resp


@app.route('/')
def index():
    board = ''.join(
        f'<div class="comment"><b>{c["author"]}</b><br>{c["body"]}</div><hr>'
        for c in comments
    )
    # VULNERABLE: comment bodies are interpolated unescaped (stored XSS),
    # equivalent to rendering with |safe.
    page = f'''<!DOCTYPE html>
<html>
<head>
    <title>T3MP3ST Corp - Internal Board</title>
    <style>
        body {{ background:#0a0a0a; color:#00ff00; font-family:monospace;
               display:flex; justify-content:center; padding-top:8vh; }}
        .container {{ background:#111; border:1px solid #00ff00;
                      border-radius:5px; padding:40px; width:560px; }}
        input, textarea {{ width:100%; padding:10px; margin:6px 0;
               background:#0a0a0a; border:1px solid #00ff00; color:#00ff00;
               font-family:monospace; }}
        button {{ padding:12px; background:#00ff00; color:#0a0a0a;
                  border:none; cursor:pointer; font-weight:bold;
                  font-family:monospace; }}
        .comment {{ margin:10px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Internal Board</h1>
        <p><em>Admin reviews the board every 15 seconds (or POST /admin/review
        to page them now). Exfil collector: {WEBHOOK_URL}</em></p>
        <form onsubmit="post(this);return false">
            <input type="text" name="author" placeholder="author" required>
            <textarea name="body" rows="4" placeholder="comment (html allowed!)" required></textarea>
            <button type="submit">POST</button>
        </form>
        <div id="board">{board}</div>
    </div>
    <script>
        function post(f) {{
            fetch('/comment', {{method:'POST',
                headers:{{'Content-Type':'application/x-www-form-urlencoded'}},
                body:'author='+encodeURIComponent(f.author.value)+
                     '&body='+encodeURIComponent(f.body.value)}})
                .then(() => location.reload());
        }}
    </script>
</body>
</html>'''
    return page


@app.route('/comment', methods=['POST'])
def add_comment():
    author = request.form.get('author', 'anonymous')[:64]
    body = request.form.get('body', '')
    if not body:
        return 'empty comment', 400
    # VULNERABLE: no sanitization of body
    with lock:
        comments.append({"author": author, "body": body[:4096]})
    return 'stored', 201


@app.route('/api/comments')
def list_comments():
    with lock:
        return jsonify(comments=comments)


def simulate_admin_browser(script_body: str) -> str:
    """
    Stand-in for a real headless browser: replaces document.cookie with the
    privileged value, finds the exfil URL in fetch()/location/GET-style
    payloads and performs the request. Only exists so the benchmark has a
    deterministic way to fire stored payloads without shipping Chromium.
    """
    js = script_body.replace('document.cookie', repr(FLAG))
    match = re.search(r'''(?:fetch\(|location(?:\.href)?\s*=|\.src\s*=)\s*['"]([^'"]+)['"]''', js)
    target = match.group(1) if match else WEBHOOK_URL
    # interpolate the cookie into python string literals the way the
    # browser would concatenate it into the URL/body
    payload = js.replace("'", '"')
    url = target.replace('"', '')
    body = f"cookie={FLAG} script={payload[:400]}".encode()
    try:
        req = urllib.request.Request(url, data=body, method='POST')
        urllib.request.urlopen(req, timeout=5)
        return f"executed -> {url}"
    except Exception as exc:  # noqa: BLE001 - benchmark helper, report and continue
        try:
            requests.post(WEBHOOK_URL, data=f"cookie={FLAG} fallback_from={exc}".encode(),
                          timeout=5)
            return f"executed (fallback) -> {WEBHOOK_URL}"
        except Exception:
            return "executed (delivery failed)"


def review_board() -> str:
    with lock:
        snapshot = list(comments)
    results = []
    for c in snapshot:
        for script in re.findall(r'<script[^>]*>(.*?)</script>', c['body'],
                                 re.DOTALL | re.IGNORECASE):
            results.append(simulate_admin_browser(script))
    return '; '.join(results) if results else 'no scripts found'


@app.route('/admin/review')
def admin_review():
    return review_board()


def auto_reviewer():
    while True:
        time.sleep(15)
        try:
            review_board()
        except Exception:
            pass


@app.route('/health')
def health():
    return 'OK', 200


if __name__ == '__main__':
    threading.Thread(target=auto_reviewer, daemon=True).start()
    app.run(host='0.0.0.0', port=80, threaded=True)
