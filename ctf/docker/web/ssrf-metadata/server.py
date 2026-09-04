"""Dependency-free HTTP delivery for the SSRF-to-metadata training challenge.

The `/fetch` handler is the vulnerability: it dereferences the caller-supplied
URL server-side with no host allow-list. From the internal-only challenge
network that lets the mock at 169.254.169.254 be read while every external
link-local or production endpoint is unreachable (egress denied).
"""
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from challenge import MAX_READ, MAX_URL

VULN_ENDPOINT = "/fetch"


class Handler(BaseHTTPRequestHandler):
    def bounded_content_length(self) -> int:
        try:
            return max(0, min(int(self.headers.get("Content-Length", "0")), 1024))
        except ValueError:
            return 0

    def send_json(self, status: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def parse_url_param(self, query: str) -> str | None:
        value = urllib.parse.parse_qs(query).get("url", [""])[0]
        return value or None

    def handle_fetch(self, raw_query: str) -> None:
        url = self.parse_url_param(raw_query)
        if not url:
            self.send_json(400, {"error": "missing url"})
            return
        self.relay_fetch(url)

    def relay_fetch(self, url: str) -> None:
        # Intentional vuln: caller-controlled URL, no allow-list, bounded read.
        target = str(url)[:MAX_URL]
        request = urllib.request.Request(target)
        try:
            with urllib.request.urlopen(request, timeout=1) as response:
                fetched = response.read(MAX_READ)
                status = response.status
        except urllib.error.HTTPError as error:
            fetched = error.read(MAX_READ)
            status = error.code
        except (urllib.error.URLError, OSError, ValueError, TimeoutError):
            status, fetched = 403, b"{'error': 'egress denied'}"
        decoded = fetched.decode("utf-8", "replace")
        self.send_json(200, {"upstream_status": status, "bytes": len(fetched), "body": decoded})

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        if self.path == "/health":
            self.send_json(200, {"status": "ok"})
        elif self.path == "/":
            self.send_json(
                200,
                {
                    "service": "t3mp3st-ctf-ssrf-metadata",
                    "usage": f"GET {VULN_ENDPOINT}?url=<target> or POST JSON {{'url': ...}}",
                    "egress": "default-deny to non-metadata hosts from the internal network",
                },
            )
        elif self.path.split("?", 1)[0] == VULN_ENDPOINT:
            self.handle_fetch(self.path.split("?", 1)[1] if "?" in self.path else "")
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        if self.path != VULN_ENDPOINT:
            self.send_json(404, {"error": "not found"})
            return
        body = self.rfile.read(self.bounded_content_length()).decode(errors="replace")
        try:
            url = json.loads(body).get("url")
            if not isinstance(url, str) or not url:
                raise ValueError
        except ValueError:
            self.send_json(400, {"error": "bad url"})
            return
        self.relay_fetch(url)

    def log_message(self, _format: str, *_args: object) -> None:
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), Handler).serve_forever()
