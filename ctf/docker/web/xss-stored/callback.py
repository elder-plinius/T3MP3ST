"""Internal callback (exfiltration) service for the stored-XSS lab.

The board's exfiltration helper posts the reader's full ``document.cookie``
here. The service is the lab's only egress leg: it appends each captured body
to a log file (the evidence) and echoes the body back so the solver recovers
the flag from the response. It has no host port and no external network.
"""
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_PATH = os.environ.get("CALLBACK_LOG", "/tmp/xss-callback.log")
MAX_BODY = 8192


class CallbackHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def bounded_content_length(self) -> int:
        try:
            return max(0, min(int(self.headers.get("Content-Length", "0")), MAX_BODY))
        except ValueError:
            return 0

    def _respond(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        if self.path == "/health":
            self._respond(200, b"ok")
        else:
            self._respond(404, b"not found")

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        if self.path not in ("/", "/x"):
            self._respond(404, b"not found")
            return
        body = self.rfile.read(self.bounded_content_length())
        with open(LOG_PATH, "a", encoding="utf-8") as handle:
            handle.write(body.decode(errors="replace") + "\n")
        self._respond(200, body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("CALLBACK_PORT", "9999"))), CallbackHandler).serve_forever()
