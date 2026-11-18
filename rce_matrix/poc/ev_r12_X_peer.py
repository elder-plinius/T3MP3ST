# Raw-socket upstream peer for lane X. Logs EVERY connection's verbatim request
# bytes before deciding to fail. Strict exec rule: a request-line or body token
# must be exactly "/exec". Stateful across connections via --fail-first N.
import socket, subprocess, threading, sys, time, os

PORT = int(sys.argv[1]); FAIL = int(sys.argv[2]); MODE = sys.argv[3]
LOG = sys.argv[4]; NAME = sys.argv[5]
lock = threading.Lock(); conn = 0

def logrec(n, raw, toks, execs, substr, bexec):
    with lock:
        f = open(LOG, "a")
        f.write("CONN %d t=%.6f name=%s tokens=%d execs=%d bexec=%d lesubstr=%d len=%d\n" % (n, time.time(), NAME, toks, execs, bexec, substr, len(raw)))
        f.write("HEX " + raw.hex() + "\n")
        if execs:
            f.write("EXEC %d\n" % execs)
        f.flush(); os.fsync(f.fileno()); f.close()

def readreq(c):
    c.settimeout(1.0); d = b""
    while b"\r\n\r\n" not in d:
        x = c.recv(16384)
        if not x: break
        d += x
    if b"\r\n\r\n" in d:
        head, _, rest = d.partition(b"\r\n\r\n")
        cl = 0
        for line in head.split(b"\r\n")[1:]:
            k, _, v = line.partition(b":")
            if k.strip().lower() == b"content-length":
                try: cl = int(v.strip())
                except: cl = 0
        while len(rest) < cl:
            x = c.recv(16384)
            if not x: break
            rest += x; d += x
    return d

def handle(c, n):
    try: raw = readreq(c)
    except Exception: raw = b""
    lines = raw.split(b"\r\n")
    rl = lines[0].split(b" ") if lines else [b""]
    toks = len(rl)
    # STRICT: a 3-token line whose target is exactly /exec, or a 4-token line
    # whose 2nd token is exactly //exec and 3rd starts with ?cmd= .
    execs = 1 if (toks == 3 and rl[1] == b"/exec") or \
                  (toks == 4 and rl[1] == b"//exec" and rl[2].startswith(b"?cmd=")) else 0
    substr = raw.count(b"/exec")
    bexec = 1 if b"\r\n\r\nBODY //exec ?cmd=id\n" in raw else 0
    logrec(n, raw, toks, execs, substr, bexec)
    cmd0 = "id"
    for t in rl[1:]:
        if t.startswith(b"?cmd="): cmd0 = t.split(b"cmd=", 1)[1].decode("latin1")
    if MODE == "execfail" and n <= FAIL:
        # execute on THIS host, then die before any response byte (app crash)
        e = subprocess.run(["sh", "-c", cmd0], capture_output=True).stdout if toks == 4 else b""
        with lock:
            f = open(LOG, "a"); f.write("RAN %d treexecs=%d\n" % (n, 1 if toks == 4 else 0)); f.close()
        try: c.close()
        except Exception: pass
        return
    if MODE == "bodytrunc" and n <= FAIL:
        try: c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\nPARTIAL")
        except Exception: pass
        try: c.close()
        except Exception: pass
        return
    if MODE == "bodytrunc" and n > FAIL:
        pass
    if n <= FAIL:
        if MODE == "head":
            try: c.sendall(b"HTTP/1.1 200 OK\r\n")
            except Exception: pass
        if MODE == "hang":
            time.sleep(6.0)
        try: c.close()
        except Exception: pass
        return
    cmd = "id"
    for t in rl[1:]:
        if t.startswith(b"?cmd="): cmd = t.split(b"cmd=", 1)[1].decode("latin1")
    out = subprocess.run(["sh", "-c", cmd], capture_output=True).stdout if execs else b""
    body = b"PEER=%s CONN=%d TOKENS=%d EXECS=%d LINE=%s\nOUT:" % (NAME.encode(), n, toks, execs, rl[1] if len(rl) > 1 else b"") + out
    try:
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
    except Exception: pass
    try: c.close()
    except Exception: pass

s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", PORT)); s.listen(64); s.settimeout(120)
t0 = time.time()
while time.time() - t0 < 120:
    try: c, _ = s.accept()
    except socket.timeout: break
    except OSError: break
    conn += 1
    threading.Thread(target=handle, args=(c, conn), daemon=True).start()
