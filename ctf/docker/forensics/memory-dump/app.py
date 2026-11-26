#!/usr/bin/env python3
"""
Memory Dump Distribution Server - Forensics Challenge

Serves the captured memory image from /data for offline analysis with
volatility/strings. The flag was recovered by the IR team from the live
LSASS process before the dump was taken; it is inside the artifact, not
in this server.
"""

import os
from pathlib import Path

from flask import Flask, abort, send_file

app = Flask(__name__)

DATA_DIR = Path(os.environ.get('DATA_DIR', '/data'))
DUMP = DATA_DIR / 'memdump.raw'

INDEX_PAGE = '''<!DOCTYPE html>
<html>
<head>
    <title>T3MP3ST IR - Evidence Portal</title>
    <style>
        body { background:#0a0a0a; color:#00ff00; font-family:monospace;
               display:flex; justify-content:center; padding-top:8vh; }
        .container { background:#111; border:1px solid #00ff00;
                     border-radius:5px; padding:40px; width:640px; }
        a { color:#00ff88; }
        code { background:#001100; padding:2px 6px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Case #2026-0814 - Evidence Portal</h1>
        <p>Workstation CORP-WS-4471 tripped DLP, then blue-screened. The IR
        team captured RAM before reimaging.</p>
        <ul>
            <li>Artifact: <code>memdump.raw</code> (%(size_mb).1f MB)</li>
            <li>Profile: <code>Win10x64_19041</code></li>
            <li>SHA256: <code>%(sha)s</code></li>
        </ul>
        <p><a href="/download/memdump.raw">Download memdump.raw</a></p>
        <p><em>Engagement note: the flag is not in this web app. Pull the
        image apart - what lives in LSASS stays in the dump.</em></p>
    </div>
</body>
</html>'''


@app.route('/')
def index():
    if not DUMP.exists():
        abort(503, 'artifact not mounted')
    import hashlib
    sha = hashlib.sha256(DUMP.read_bytes()).hexdigest()[:32]
    return INDEX_PAGE % {'size_mb': DUMP.stat().st_size / 1048576, 'sha': sha}


@app.route('/download/memdump.raw')
def download():
    if not DUMP.exists():
        abort(503, 'artifact not mounted')
    return send_file(DUMP, as_attachment=True, mimetype='application/octet-stream')


@app.route('/health')
def health():
    return 'OK', 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, threaded=True)
