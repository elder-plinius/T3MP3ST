"""Minimal deterministic mock cloud-metadata service for the SSRF lab.

Serves the same payload map as `challenge.metadata_response` over HTTP so the
vulnerable handler can reach it at 169.254.169.254:80 from the internal-only
bridge. Runs as the mock container (no host port); everything is stdlib.
"""
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from challenge import metadata_response


class MockHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        status, body = metadata_response(self.path.split("?", 1)[0])
        self.send_response(status)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "80"))
    ThreadingHTTPServer(("0.0.0.0", port), MockHandler).serve_forever()
