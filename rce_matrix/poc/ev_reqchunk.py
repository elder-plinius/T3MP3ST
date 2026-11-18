import socket,subprocess,threading,sys,time
def fp():
    s=socket.socket(); s.bind(("127.0.0.1",0)); p=s.getsockname()[1]; s.close(); return p
SEEN=[]
def handle(c):
    try:
        c.settimeout(0.6); d=b""
        while True:
            try: x=c.recv(16384)
            except socket.timeout: break
            if not x: break
            d+=x
        SEEN.append(d)
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
    except Exception: pass
    finally:
        try: c.close()
        except Exception: pass
def up(port,stop):
    s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind(("127.0.0.1",port)); s.listen(32); s.settimeout(0.1)
    while not stop.is_set():
        try: c,_=s.accept()
        except (socket.timeout,OSError): continue
        threading.Thread(target=handle,args=(c,),daemon=True).start()
    s.close()
binp=sys.argv[1]; label=sys.argv[2]
P="/home/mouse9911/gits/toksec/temp/rce-sweep2/www"; l=fp(); u=fp(); cf=f"/tmp/evrc_{l}.conf"
open(cf,"w").write(f"events {{ }}\nhttp {{\n upstream b {{ server 127.0.0.1:{u}; }}\n server {{\n  listen 127.0.0.1:{l};\n  server_name alpha.test;\n  root {P}/alpha;\n  location / {{ proxy_pass http://b/api/; }}\n }}\n}}\n")
stop=threading.Event(); threading.Thread(target=up,args=(u,stop),daemon=True).start(); time.sleep(0.2)
p=subprocess.Popen([binp,"--config",cf],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
ok=False
for _ in range(100):
    time.sleep(0.05)
    try: socket.create_connection(("127.0.0.1",l),timeout=1).close(); ok=True; break
    except: pass
if not ok: print(f"{label}: NO LISTEN"); sys.exit(0)
CASES={
 "CL 5 body":"POST /api/x HTTP/1.1\r\nHost: alpha.test\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
 "TE chunked":"POST /api/x HTTP/1.1\r\nHost: alpha.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
 "TE chunked + CL":"POST /api/x HTTP/1.1\r\nHost: alpha.test\r\nTransfer-Encoding: chunked\r\nContent-Length: 7\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
 "CL 5, 2 requests in body":"POST /api/x HTTP/1.1\r\nHost: alpha.test\r\nContent-Length: 38\r\nConnection: close\r\n\r\nGET /api/exec?cmd=id HTTP/1.1\r\nHost: a\r\n\r\n",
}
print(f"##### {label}")
for k,v in CASES.items():
    SEEN.clear()
    c=socket.create_connection(("127.0.0.1",l),timeout=3); c.settimeout(1.2); c.sendall(v.encode()); b=b""
    try:
        while True:
            x=c.recv(8192)
            if not x: break
            b+=x
    except: pass
    c.close()
    print(f"--- {k}")
    print("  status:", b.split(b"\r\n")[0].decode("latin1"), "| upstream conns:", len(SEEN))
    if SEEN: print("  upstream sent:", repr(SEEN[0][SEEN[0].find(b'\r\n\r\n')+4:][:60]))
p.terminate()
try: p.wait(timeout=2)
except: p.kill()
stop.set()
