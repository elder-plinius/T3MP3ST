"""Shared harness for the RCE matrix PoCs.

Every driver runs against a local loopback lab:

* a proxy binary from the sweep corpus;
* a raw-socket upstream peer that executes a request target when it names /exec;
* optional keep-alive victim requests after a control request.

The harness binds ephemeral ports, so separate runs do not collide.
"""
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
SWEEP = Path(os.environ.get("RCE_SWEEP", "/home/mouse9911/gits/toksec/temp/rce-sweep2"))
BIN_CANDIDATES = [
    SWEEP / "bin",
    Path("/tmp/r16F/bin"),
]
OUT = Path(os.environ.get("RCE_OUT", "/tmp/rce_matrix_poc"))
OUT.mkdir(parents=True, exist_ok=True)

_FRAME = {
    "flat": """listen=127.0.0.1:{listen}
root={root}
max_connections=64
header_bytes=16384
header_timeout_ms=2000
idle_timeout_ms=5000
write_timeout_ms=5000
max_requests=100
pipeline_depth=16
default_host=alpha.test
host_root=beta.test:{root}/../beta
alias=/alias:{root}/../alias
redirect=/go:/target
index=index.html
proxy_prefix={prefix}
{upstreams}
upstream_timeout_ms=3000
body_bytes=1048576
cache_ttl_ms=60000
cache_bytes=4194304
rate_per_second=0
rate_burst=100
drain_timeout_ms=1000
""",
    "ngx": """worker_processes 1;
events {{ worker_connections 128; }}
http {{
  toksec_header_bytes 16384;
  toksec_header_deadline 2000;
  toksec_upstream_deadline 3000;
  upstream backend {{ server 127.0.0.1:{upstream}; }}
  server {{
    listen 127.0.0.1:{listen};
    server_name {sname};
    root {root};
    location {prefix} {{ proxy_pass {pass}; }}
{static}
  }}
}}
""",
    "ngx2": """worker_processes 1;
events {{ worker_connections 128; }}
http {{
  toksec_header_bytes 16384;
  toksec_header_deadline 2000;
  toksec_upstream_deadline 3000;
  upstream backend {{ server 127.0.0.1:{upstream}; }}
}}
server {{
  listen 127.0.0.1:{listen};
  server_name {sname};
  root {root};
  location {prefix} {{ proxy_pass {pass}; }}
{static}
}}
""",
}

_BUILDS = {
    "a4ba853a": "a4ba853a",
    "e1a28e35": "1cfd33433d25__e1a28e35",
    "6baf167b": "1cfd33433d25__6baf167b",
    "afdc173f": "1cfd33433d25__afdc173f",
    "ae021893": "3aeb255d3d7f__ae021893",
    "f2b3415b": "3aeb255d3d7f__f2b3415b",
    "61cc738c": "1cfd33433d25__61cc738c",
    "44bf7f35": "1cfd33433d25__44bf7f35",
    "063b0d5e": "1cfd33433d25__063b0d5e",
    "8d5ff1f2": "3aeb255d3d7f__8d5ff1f2",
    "29d05850": "3aeb255d3d7f__29d05850",
    "6fb186ed": "3aeb255d3d7f__6fb186ed",
    "2usd": "terra2usd",
}


def build_path(tag):
    name = _BUILDS.get(tag, tag)
    for directory in BIN_CANDIDATES:
        path = directory / name
        if path.is_file():
            return path
    raise SystemExit(f"missing binary {name}; set RCE_SWEEP to the rce-sweep2 directory")


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def write(root, name, data):
    path = Path(root) / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def request(path, host="alpha.test", extra="", method="GET", body=b"", keep_alive=False):
    raw = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n".encode()
    if extra:
        raw += extra.encode()
    if body:
        raw += b"Content-Length: " + str(len(body)).encode() + b"\r\n"
    raw += b"Connection: " + (b"keep-alive" if keep_alive else b"close") + b"\r\n\r\n" + body
    return raw


class Peer:
    """Executing upstream.

    The peer answers with a body of the form ``EXEC:<output>|HIT:<n>|ID:<output>``
    so a driver can tell an executed request (``EXEC:<id output>``) from a control
    (``EXEC:0``) and count upstream fetches with ``HIT``.

    Modes:

    ``plain``     one 200 with a cacheable, Vary-less head.
    ``vary``      same, but the head carries ``Vary: Accept-Encoding``.
    ``onexx``     send ``HTTP/1.1 100 Continue`` first, then the 200.
    ``failfirst`` execute, then close without answering, for the first
                  ``fail_first`` connections (retry/failover drives).
    """

    def __init__(self, root, mode="plain", fail_first=0, tag="peer"):
        self.root = Path(root)
        self.mode = mode
        self.fail_first = fail_first
        self.tag = tag
        self.port = free_port()
        self.hits = 0
        self.fetches = []
        self.records = []
        self.errors = []
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    @staticmethod
    def _head_body(blob):
        """Split one request into ``(head, body)``; ``body`` is empty if unframed."""
        marker = blob.find(b"\r\n\r\n")
        if marker < 0:
            return blob, b""
        head = blob[:marker]
        rest = blob[marker + 4:]
        lowered = head.lower()
        body = b""
        if b"transfer-encoding:" in lowered:
            body = rest
        else:
            match = re.search(rb"content-length:\s*(\d+)", lowered)
            if match:
                body = rest[: int(match.group(1))]
        return head, body

    @staticmethod
    def _request_lines(blob):
        """Yield request lines from a decoded head block."""
        decoded = urllib.parse.unquote_to_bytes(blob)
        for line in decoded.replace(b"\r\n", b"\n").split(b"\n"):
            parts = line.split()
            if len(parts) >= 2 and parts[0].upper() in (b"GET", b"POST", b"HEAD", b"PUT"):
                yield parts

    def _exec(self, blob):
        """Return ``(output, where)`` for the first /exec request line in ``blob``.

        ``where`` is ``"line"`` when the target sat in a request line the proxy
        framed, and ``"body"`` when it appeared only inside a framed request body.
        That is what separates a body the upstream merely read as data from a
        request the proxy emitted in its own right.
        """
        head, body = self._head_body(blob)
        for where, part in (("line", head), ("body", body)):
            for parts in self._request_lines(part):
                target = parts[1].split(b"?", 1)[0]
                if target != b"/exec" and not target.rstrip(b"/").endswith(b"/exec"):
                    continue
                command = b"id"
                if b"?" in parts[1]:
                    for pair in parts[1].split(b"?", 1)[1].split(b"&"):
                        if pair.startswith(b"cmd="):
                            command = urllib.parse.unquote_to_bytes(pair[4:]).split(b" ")[0]
                return subprocess.run(
                    ["sh", "-c", command.decode("latin1")], capture_output=True, timeout=5
                ).stdout.strip(), where
        return None, None

    def _split_stream(self, data):
        """Parse ``data`` into framed requests, one entry per request on the wire.

        A framed body is consumed by its own ``Content-Length`` (or its chunk
        terminator) so a request line that only appears *inside* a body stays
        classified as ``body``. Only bytes left over after a complete request are
        the next request, which is exactly the difference a desync creates.
        """
        requests = []
        rest = data
        while rest:
            marker = rest.find(b"\r\n\r\n")
            if marker < 0:
                break
            head, tail = rest[:marker], rest[marker + 4:]
            lowered = head.lower()
            body = b""
            if b"transfer-encoding:" in lowered:
                stop = tail.find(b"\r\n0\r\n")
                if stop < 0:
                    body, rest = tail, b""
                else:
                    end_of_chunks = tail.find(b"\r\n\r\n", stop)
                    cut = len(tail) if end_of_chunks < 0 else end_of_chunks + 4
                    body, rest = tail[:cut], tail[cut:]
            else:
                match = re.search(rb"content-length:\s*(\d+)", lowered)
                length = int(match.group(1)) if match else 0
                body, rest = tail[:length], tail[length:]
            requests.append((head, body))
        return requests

    def _handle(self, conn):
        conn.settimeout(1.5)
        data = b""
        try:
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
                if b"\r\n\r\n" in data and len(chunk) < 65536:
                    break
        except OSError as exc:
            self.errors.append(str(exc))
        self.hits += 1
        hit = self.hits
        self.fetches.append(data)
        requests = self._split_stream(data)
        outputs = []
        lines = []
        for head, body in requests:
            line = head.split(b"\r\n")[0].decode("latin1", "replace")
            output, where = self._exec(head + (b"" if not body else b"\r\n\r\n" + body))
            lines.append(line)
            outputs.append(output or b"")
            self.records.append({"hit": hit, "request_line": line, "bytes": len(head), "exec": where})
        write(self.root, f"{self.tag}_up_{hit}.hex", data.hex().encode() + b"\n")
        if self.mode == "failfirst" and hit <= self.fail_first:
            conn.close()
            return
        if self.mode == "onexx":
            try:
                conn.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
            except OSError as exc:
                self.errors.append(str(exc))
        if self.mode == "inner":
            inner = b"HTTP/1.1 200 OK\r\nX-Forged: 1\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nPWNED"
            try:
                conn.sendall(b"HTTP/1.1 100 Continue\r\n\r\n" + inner)
            except OSError as exc:
                self.errors.append(str(exc))
            conn.close()
            return
        output = next((value for value in outputs if value), b"")
        body = b"EXEC:" + (output if output else b"0") + b"|HIT:" + str(hit).encode()
        if output:
            body += b"|ID:" + output
        head = b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=60\r\n"
        if self.mode == "gzip":
            head += b"Content-Encoding: gzip\r\n"
        elif self.mode == "vary":
            head += b"Vary: Accept-Encoding\r\n"
        head += b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: keep-alive\r\n\r\n"
        try:
            conn.sendall(head + body)
        except OSError as exc:
            self.errors.append(str(exc))
        finally:
            conn.close()

    def _serve(self):
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", self.port))
        sock.listen(64)
        sock.settimeout(0.1)
        while not self.stop.is_set():
            try:
                conn, _ = sock.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
        sock.close()

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.stop.set()
        self.thread.join(timeout=2)


class Proxy:
    def __init__(self, tag, root, peer_port, dialect="auto", prefix="/api", pass_uri=None,
                 extra_upstreams=(), server_name="alpha.test"):
        self.binary = build_path(tag)
        self.extra_upstreams = list(extra_upstreams)
        self.root = Path(root)
        self.port = free_port()
        self.upstream = peer_port
        if dialect == "auto":
            dialect = "ngx" if "nginx" in subprocess.run(
                ["strings", str(self.binary)], capture_output=True, text=True
            ).stdout[:4000] else "flat"
        self.config = self.root / "proxy.conf"
        (self.root / "www" / "alpha").mkdir(parents=True, exist_ok=True)
        (self.root / "www" / "beta").mkdir(parents=True, exist_ok=True)
        (self.root / "www" / "alias").mkdir(parents=True, exist_ok=True)
        (self.root / "www" / "alpha" / "hello.txt").write_text("hello\r\n")
        (self.root / "www" / "beta" / "hello.txt").write_text("beta\r\n")
        (self.root / "www" / "alias" / "hello.txt").write_text("alias\r\n")
        static_indent = "  " if dialect == "ngx2" else "    "
        static = "" if prefix == "/" else f'{static_indent}location / {{ root {self.root / "www" / "alpha"}; }}'
        if dialect == "ngx2":
            rendered = _FRAME["ngx2"].format(
                listen=self.port,
                upstream=self.upstream,
                root=str(self.root / "www" / "alpha"),
                prefix=prefix,
                pass_uri=(prefix if pass_uri is None else pass_uri),
                **self._pass(prefix, pass_uri),
                upstreams=self._upstreams(),
                static=static,
                sname=server_name,
            )
        else:
            rendered = _FRAME[dialect].format(
                listen=self.port,
                upstream=self.upstream,
                root=str(self.root / "www" / "alpha"),
                prefix=prefix,
                pass_uri=(prefix if pass_uri is None else pass_uri),
                **self._pass(prefix, pass_uri),
                upstreams=self._upstreams(),
                static=static,
                sname=server_name,
            )
        self.config.write_text(rendered)
        self.proc = None

    def _upstreams(self):
        ports = [self.upstream, *self.extra_upstreams]
        return "upstreams=" + ",".join(f"127.0.0.1:{port}" for port in ports)

    @staticmethod
    def _pass(prefix, pass_uri):
        """Render the ``proxy_pass`` value: quoted values are used verbatim."""
        value = prefix if pass_uri is None else pass_uri
        if value.startswith('"'):
            return {"pass": value}
        return {"pass": "http://backend" + value}

    def __enter__(self):
        self.proc = subprocess.Popen(
            [str(self.binary), "--config", str(self.config)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        for _ in range(160):
            if self.proc.poll() is not None:
                raise SystemExit(self.proc.stderr.read().decode("latin1"))
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=1).close()
                return self
            except OSError:
                time.sleep(0.05)
        raise SystemExit("proxy did not listen")

    def __exit__(self, *exc):
        if self.proc and self.proc.poll() is None:
            os.killpg(self.proc.pid, signal.SIGTERM)
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(self.proc.pid, signal.SIGKILL)


def send(port, raw, timeout=4):
    data = b""
    try:
        conn = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        conn.settimeout(timeout)
        conn.sendall(raw)
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
        conn.close()
    except OSError as exc:
        data += f"<ERR {exc}>".encode()
    return data


def status(response):
    return response.split(b"\r\n", 1)[0].decode("latin1", "replace")


def executed(response):
    return b"EXEC:" in response and not b"EXEC:0" in response
