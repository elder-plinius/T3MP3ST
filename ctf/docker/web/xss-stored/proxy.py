"""Narrow host-facing gateway into the internal-only stored-XSS lab.

Owns the loopback-only host port and relays only the allow-listed challenge
paths to the internal service. The exfiltration leg is same-origin too: the
board's ``ctfCollect()`` posts the reader's cookie body to this gateway
(``/cb``) and it forwards it to the internal callback service, which echoes
the body back; so exfil traffic never reaches the host directly.
"""
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

UPSTREAM = os.environ.get("UPSTREAM", "http://xss-stored:8080")
CALLBACK = os.environ.get("CALLBACK", "http://xss-callback:9999")
CHALLENGE_PATHS = {"", "/", "/health", "/notes", "/login", "/admin"}
CB_PATH = "/cb"


def _forward(method: str, url: str, body: bytes | None, content_type: str) -> tuple[int, bytes, str, list[str]]:
    request = Request(url, data=body, method=method)
    request.add_header("Content-Type", content_type)
    try:
        response = urlopen(request, timeout=3)
    except HTTPError as error:
        return error.code, error.read(), "application/json; charset=utf-8", []
    except URLError:
        return 502, b"{}", "application/json; charset=utf-8", []
    return (
        response.status,
        response.read(8192),
        response.headers.get("Content-Type", content_type) or content_type,
        response.headers.get_all("Set-Cookie", []),
    )


class ProxyHandler(BaseHTTPRequestHandler):
    def bounded_content_length(self) -> int:
        try:
            return max(0, min(int(self.headers.get("Content-Length", "0")), 8192))
        except ValueError:
            return 0

    def relay(self, method: str) -> None:
        length = self.bounded_content_length()
        body = self.rfile.read(length) if length else None
        path, _, _ = self.path.partition("?")
        if path == CB_PATH:
            status, payload, ctype, set_cookie = _forward("POST", CALLBACK + "/x", body or b"", "text/plain; charset=utf-8")
        elif self.path in CHALLENGE_PATHS:
            status, payload, ctype, set_cookie = _forward(method, UPSTREAM + self.path, body, "application/x-www-form-urlencoded")
        else:
            self.send_error(404)
            return
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        for cookie in set_cookie:
            self.send_header("Set-Cookie", cookie)
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
