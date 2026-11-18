import socket,sys,subprocess,time,os,hashlib
BIN=sys.argv[1]; ROOT=sys.argv[2]
def fp():
    s=socket.socket(); s.bind(("127.0.0.1",0)); p=s.getsockname()[1]; s.close(); return p
P=fp(); cf=f"/tmp/ev_r6_A_fr_{os.getpid()}_{P}.conf"
open(cf,"w").write(f"listen=127.0.0.1:{P}\nroot={ROOT}\nmax_connections=64\nheader_bytes=8192\nheader_timeout_ms=3000\nidle_timeout_ms=1500\nwrite_timeout_ms=5000\nmax_requests=64\npipeline_depth=4\n")
srv=subprocess.Popen([BIN,"--config",cf],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
for _ in range(200):
    time.sleep(0.05)
    if srv.poll() is not None: break
    if f":{P} " in subprocess.run(["ss","-ltnp"],capture_output=True,text=True).stdout: break
else: print("PREFLIGHT FAIL"); sys.exit(1)
print(f"PREFLIGHT ok port={P}")
def raw(b,tmo=6.0):
    c=socket.create_connection(("127.0.0.1",P),timeout=tmo); c.settimeout(tmo)
    try: c.sendall(b)
    except Exception: pass
    o=b""
    try:
        while True:
            x=c.recv(262144)
            if not x: break
            o+=x
    except socket.timeout: pass
    except ConnectionResetError: pass
    c.close(); return o
def count_resp(b): return b.count(b"HTTP/1.1 ")
# 1) large file integrity
b=raw(b"GET /big.txt HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
h,_,body=b.partition(b"\r\n\r\n")
cl=[x.split(b":",1)[1].strip() for x in h.split(b"\r\n") if x.lower().startswith(b"content-length")][0]
print(f"BIG cl={cl.decode()} served={len(body)} exact={len(body)==int(cl)} sha_ok={hashlib.sha256(body).hexdigest()[:12]}")
# 2) pipeline two requests in one write
b=raw(b"GET /ten.txt HTTP/1.1\r\nHost: a\r\n\r\nGET /hello.txt HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
print(f"PIPE responses={count_resp(b)} ten={b.find(bytes([48,49,50,51,52,53,54,55,56,57]))>=0} hello={b.find(bytes([104,101,108,108,111]))>=0}")
# 3) POST with a body advertised as Content-Length: 0 (body must be re-parsed or ignored)
b=raw(b"GET /ten.txt HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\nGET /hello.txt HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
print(f"CLZERO responses={count_resp(b)} hello={b.find(bytes([104,101,108,108,111]))>=0}")
# 4) POST with CL 0 and 5 body bytes
b=raw(b"POST /ten.txt HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\nConnection: close\r\n\r\nabcde")
print(f"POSTCL0 {b.split(bytes([13,10]))[0]!r} served={len(b.partition(bytes([13,10,13,10]))[2])}")
# 5) HEAD
b=raw(b"HEAD /ten.txt HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
print(f"HEAD {b.split(bytes([13,10]))[0]!r} totalbytes={len(b)} bodyserved={len(b.partition(bytes([13,10,13,10]))[2])}")
# 6) two GETs without CL/pipelining marker, same write, no keepalive close on first
srv.terminate()
try: srv.wait(2)
except Exception: srv.kill()
