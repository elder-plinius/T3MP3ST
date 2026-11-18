import socket,subprocess,threading,sys,time,os,urllib.parse
P=os.path.abspath("www")
def fp():
    s=socket.socket(); s.bind(("127.0.0.1",0)); p=s.getsockname()[1]; s.close(); return p
RAW=[]
def run(c): return subprocess.run(["sh","-c",c],capture_output=True,timeout=5).stdout
def h(c):
    d=b"";c.settimeout(1.0)
    try:
        while b"\r\n\r\n" not in d:
            x=c.recv(8192)
            if not x: break
            d+=x
    except: pass
    line=d.split(b"\r\n")[0]; RAW.append(line)
    toks=line.split(b" ")
    body=b"PLAIN"
    if len(toks)>1:
        t=urllib.parse.unquote(toks[1].decode("latin1"))
        if "/exec" in t:
            k=t.find("cmd=")
            body=run((urllib.parse.unquote(t[k+4:].split("&")[0]).split() or ["id"])[0]) if k>=0 else run("id")
    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: "+str(len(body)).encode()+b"\r\nConnection: close\r\n\r\n"+body)
    try: c.close()
    except: pass
def serve(port,stop):
    s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind(("127.0.0.1",port)); s.listen(16); s.settimeout(0.1)
    while not stop.is_set():
        try: c,_=s.accept()
        except (socket.timeout,OSError): continue
        threading.Thread(target=h,args=(c,),daemon=True).start()
b,loc,pp=sys.argv[1],sys.argv[2],sys.argv[3]
l=fp(); u=fp(); cf=f"cfgs/cs_{l}.conf"
open(cf,"w").write(f"""worker_processes 1;
events {{ worker_connections 128; }}
http {{
  upstream backend {{ server 127.0.0.1:{u}; }}
  server {{
    listen 127.0.0.1:{l};
    server_name alpha.test;
    root {P}/alpha;
    location {loc} {{ proxy_pass {pp}; }}
    location / {{ root {P}/alpha; }}
  }}
}}
""")
stop=threading.Event(); threading.Thread(target=serve,args=(u,stop),daemon=True).start(); time.sleep(0.2)
p=subprocess.Popen(["./bin/"+b,"--config",cf],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
for _ in range(80):
    time.sleep(0.05)
    try: socket.create_connection(("127.0.0.1",l),timeout=1).close(); break
    except: pass
for tag,path in (("bare","/api"),("with q","/api%3fcmd=whoami")):
    RAW.clear()
    try:
        c=socket.create_connection(("127.0.0.1",l),timeout=2); c.settimeout(1.5)
        c.sendall(f"GET {path} HTTP/1.1\r\nHost: alpha.test\r\nConnection: close\r\n\r\n".encode())
        buf=b""
        while True:
            x=c.recv(4096)
            if not x: break
            buf+=x
        c.close()
    except: buf=b""
    print("%-8s %-16s toks=%d EXEC=%-5s body=%r up=%r" % (tag,path,len(RAW[0].split(b" ")) if RAW else 0, b"uid=" in buf or b"mouse" in buf, buf.split(b"\r\n\r\n")[-1][:20], RAW[0] if RAW else b""))
p.terminate()
try: p.wait(timeout=2)
except: p.kill()
stop.set()
