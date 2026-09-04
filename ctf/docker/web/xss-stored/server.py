"""Dependency-free HTTP delivery for the stored-XSS training challenge."""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import challenge
from challenge import ADMIN_PASS, ADMIN_USER, FLAG, FLAG_COOKIE_NAME, SESSION_COOKIE_NAME, SESSION_TOKEN


class Handler(BaseHTTPRequestHandler):
    def bounded_content_length(self) -> int:
        try:
            return max(0, min(int(self.headers.get("Content-Length", "0")), 2048))
        except ValueError:
            return 0

    def send_json(self, status: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_page(self, status: int, set_cookie: str | None = None) -> None:
        page = challenge.render_page().encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if set_cookie:
            for cookie in set_cookie.split("; "):  # each pair = its own Set-Cookie
                self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        if self.path == "/health":
            self.send_json(200, {"status": "ok"})
        elif self.path in ("", "/"):
            # Public board: every reader's browser renders the stored notes.
            self.send_page(200)
        elif self.path == "/admin":
            # Admin reads the board; the flag-bearing session cookie is set here.
            self.send_page(200, challenge.admin_cookie_header())
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        if self.path in ("/notes", "/login"):
            fields = parse_qs(self.rfile.read(self.bounded_content_length()).decode(errors="replace"))
            if self.path == "/notes":
                self._new_note(fields.get("text", [""])[0])
            else:
                self._login(fields.get("user", [""])[0], fields.get("pass", [""])[0])
        else:
            self.send_json(404, {"error": "not found"})

    def _new_note(self, text: str) -> None:
        if not isinstance(text, str) or not text or len(text) > challenge.MAX_NOTE:
            self.send_json(400, {"error": "bad note"})
            return
        index = challenge.add_note(text)
        self.send_json(200, {"stored": True, "index": index})

    def _login(self, user: str, password: str) -> None:
        if user != ADMIN_USER or password != ADMIN_PASS:
            self.send_json(401, {"error": "bad credentials"})
            return
        # Sign-in sets the flag-bearing session cookie for the reader's browser.
        self.send_page(
            200,
            f"{SESSION_COOKIE_NAME}={SESSION_TOKEN}; {FLAG_COOKIE_NAME}={FLAG}; Path=/",
        )

    def log_message(self, _format: str, *_args: object) -> None:
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), Handler).serve_forever()
