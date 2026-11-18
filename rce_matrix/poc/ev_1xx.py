# Upstream emits an interim response (100 Continue / 103 Early Hints) before the final one,
# exactly as real app servers and CDNs do. Records what the client receives.
import socket,subprocess,threading,sys,time
def fp():
    s=socket.socket(); s.bind(("127.0.0.1",0)); p=s.getsockname()[1]; s.close(); return p
MODE=sys.argv[3]; RAW=[]
def handle(c):
    try:
        c.settimeout(0.6); d=b""
        while True:
            try: x=c.recv(16384)
            except socket.timeout: break
            if not x: break
            d+=x
            if b"\r\n\r\n" in d: break
        RAW.append(d)
        if MODE=="100": c.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
        elif MODE=="103": c.sendall(b"HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n")
        elif MODE=="two100": c.sendall(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 100 Continue\r\n\r\n")
        elif MODE=="101": c.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\n\r\n")
        time.sleep(0.05)
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nHELLO")
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
binp=sys.argv[1]; P="/home/mouse9911/gits/toksec/temp/rce-sweep2/www"
l=fp(); u=fp(); cf=f"/tmp/ev1xx_{l}.conf"
open(cf,"w").write(f"events {{ }}\nhttp {{\n upstream b {{ server 127.0.0.1:{u}; }}\n server {{\n  listen 127.0.0.1:{l};\n  server_name alpha.test;\n  root {P}/alpha;\n  location / {{ proxy_pass http://b/api/; }}\n }}\n}}\n")
stop=threading.Event(); threading.Thread(target=up,args=(u,stop),daemon=True).start(); time.sleep(0.2)
p=subprocess.Popen([binp,"--config",cf],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
for _ in range(100):
    time.sleep(0.05)
    try: socket.create_connection(("127.0.0.1",l),timeout=1).close(); break
    except: pass
req=b"GET /api/x HTTP/1.1\r\nHost: alpha.test\r\nConnection: close\r\n\r\n"
c=socket.create_connection(("127.0.0.1",l),timeout=3); c.settimeout(2.0); c.sendall(req); b=b""
try:
    while True:
        x=c.recv(8192)
        if not x: break
        b+=x
except: pass
c.close()
print()  # noop
print("upstream sent: "+MODE)
print("client got  : "+repr(b[:300]))
print("has 200     : "+str(b" 200 " in b))
print("has HELLO   : "+str(b"HELLO" in b))
p.terminate()
try: p.wait(timeout=2)
except: p.kill()
stop.set()
