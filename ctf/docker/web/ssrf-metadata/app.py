#!/usr/bin/env python3
"""
Vulnerable URL Preview Service - SSRF Challenge
DO NOT USE IN PRODUCTION - Intentionally vulnerable for CTF training

The preview endpoint performs server-side requests with no scheme or host
validation. The internal network hosts a mock cloud metadata service at
169.254.169.254 (reachable only via ctf-internal, not exposed to the host).
"""

import os

import requests
from flask import Flask, request

app = Flask(__name__)

FLAG = os.environ.get('CTF_FLAG', 'T3MP3ST{ssrf_t0_cl0ud_m3t4d4t4}')

INDEX_PAGE = '''<!DOCTYPE html>
<html>
<head>
    <title>T3MP3ST Cloud - URL Previewer</title>
    <style>
        body { background:#0a0a0a; color:#00ff00; font-family:monospace;
               display:flex; justify-content:center; padding-top:8vh; }
        .container { background:#111; border:1px solid #00ff00;
                     border-radius:5px; padding:40px; width:640px; }
        input { width:100%%; padding:10px; margin:8px 0; background:#0a0a0a;
                border:1px solid #00ff00; color:#00ff00; font-family:monospace; }
        button { width:100%%; padding:12px; background:#00ff00; color:#0a0a0a;
                 border:none; cursor:pointer; font-weight:bold;
                 font-family:monospace; }
        pre { background:#001100; padding:16px; overflow-x:auto;
              white-space:pre-wrap; word-break:break-all; }
        .err { color:#ff4757; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Link Preview Service</h1>
        <p>Generates rich previews for internal dashboards. Submit any URL.</p>
        <input type="text" id="url" placeholder="http://intranet.corp.local/dashboard">
        <button onclick="preview()">PREVIEW</button>
        <div id="out"></div>
    </div>
    <script>
        function preview() {
            fetch('/fetch', {method:'POST',
                headers:{'Content-Type':'application/x-www-form-urlencoded'},
                body:'url='+encodeURIComponent(document.getElementById('url').value)})
                .then(r => r.text())
                .then(t => {
                    document.getElementById('out').innerHTML =
                        '<pre>' + t.replace(/</g,'&lt;') + '</pre>';
                });
        }
    </script>
</body>
</html>'''


@app.route('/')
def index():
    return INDEX_PAGE


@app.route('/fetch', methods=['POST'])
def fetch_url():
    url = request.form.get('url', '').strip()
    if not url:
        return 'missing url parameter', 400

    # VULNERABLE: server-side request with zero validation. The instance
    # role credentials live on the metadata service inside ctf-internal.
    try:
        resp = requests.get(url, timeout=5, allow_redirects=False)
        body = resp.text[:4000]
        return f'status: {resp.status_code}\ncontent-type: {resp.headers.get("content-type", "-")}\n\n{body}'
    except requests.exceptions.RequestException as exc:
        return f'status: error\n\n{type(exc).__name__}: {exc}', 200


@app.route('/health')
def health():
    return 'OK', 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, threaded=True)
