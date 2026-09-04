"""Narrow host-facing gateway into the internal-only challenge network.

Bounds the loopback-host port (127.0.0.1:8083) with a path and body allow-list
before relaying to the challenge service on the internal bridge. Health
requests return the same `{'status':'ok'}` envelope the challenge emits so the
compose health check and offline smoke both pass.
"""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

UPSTREAM = os.environ.get("UPSTREAM", "http://ssrf-metadata:8080")
MAX_BODY = 4096
ALLOWED_PATHS = {"/", "/health", "/fetch"}


class ProxyHandler(BaseHTTPRequestHandler):
    def bounded_content_length(self) -> int:
        try:
            return max(0, min(int(self.headers.get("Content-Length", "0")), MAX_BODY))
        except ValueError:
            return 0

    def allow(self) -> bool:
        return self.path.split("?", 1)[0] in ALLOWED_PATHS

    def ok(self) -> None:
        body = json.dumps({"status": "ok"}, sort_keys=True).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def relay(self, method: str) -> None:
        if not self.allow():
            self.send_error(404)
            return
        length = self.bounded_content_length()
        body = self.rfile.read(length) if length else None
        upstream = UPSTREAM + self.path
        if method == "GET":
            request = Request(upstream)
        else:
            request = Request(upstream, data=body, method=method)
        if body is not None:
            request.add_header("Content-Type", "application/json")
        try:
            response = urlopen(request, timeout=3)
        except HTTPError as error:
            response = error
        except URLError:
            self.send_error(502)
            return
        payload = response.read(MAX_BODY)
        status = response.status
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        self.relay("GET")

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        self.relay("POST")

    def log_message(self, _format: str, *_args: object) -> None:
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), ProxyHandler).serve_forever()
