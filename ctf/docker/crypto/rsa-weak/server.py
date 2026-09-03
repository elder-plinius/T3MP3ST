"""Dependency-free HTTP delivery for the weak-RSA training challenge."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from challenge import ANSWER, FLAG, public_challenge


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

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        if self.path == "/health":
            self.send_json(200, {"status": "ok"})
        elif self.path == "/challenge":
            self.send_json(200, public_challenge())
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        if self.path != "/solve":
            self.send_json(404, {"error": "not found"})
            return
        length = self.bounded_content_length()
        submitted = parse_qs(self.rfile.read(length).decode(errors="replace")).get("answer", [""])[0]
        if submitted == str(ANSWER):
            self.send_json(200, {"flag": FLAG})
        else:
            self.send_json(403, {"error": "incorrect answer"})

    def log_message(self, _format: str, *_args: object) -> None:
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
