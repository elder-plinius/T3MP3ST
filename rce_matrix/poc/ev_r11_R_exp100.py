import socket,subprocess,sys,time,os
BIN=sys.argv[1]; LP=int(sys.argv[2]); UP=int(sys.argv[3]); TAG=sys.argv[4]
W="/tmp/r11_www_R"; os.makedirs("cfgs",exist_ok=True); CFG=f"cfgs/R_{LP}_e100.conf"
if sys.argv[5]=="flat":
    open(CFG,"w").write(f"""listen=127.0.0.1:{LP}
root={W}/alpha
max_connections=64
header_bytes=16384
header_timeout_ms=2000
idle_timeout_ms=5000
write_timeout_ms=5000
max_requests=100
pipeline_depth=16
default_host=alpha.test
host_root=beta.test:{W}/beta
alias=/alias:{W}/alias
redirect=/go:/target
index=index.html
proxy_prefix=/api
upstreams=127.0.0.1:{UP}
upstream_timeout_ms=3000
body_bytes=1048576
cache_ttl_ms=1000
cache_bytes=1024
rate_per_second=0
rate_burst=100
drain_timeout_ms=1000
""")
else:
    open(CFG,"w").write(f"""worker_processes 1;
events {{ worker_connections 128; }}
http {{
  toksec_header_bytes 16384;
  toksec_header_deadline 2000;
  toksec_upstream_deadline 3000;
  upstream backend {{ server 127.0.0.1:{UP}; }}
  server {{ listen 127.0.0.1:{LP}; server_name alpha.test; root {W}/alpha;
    location /api/ {{ proxy_pass http://backend/api/; }}
    location / {{ root {W}/alpha; }} }}
}}
""")
peer=subprocess.Popen([sys.executable,"ev_r11_R_peer100.py",str(UP),f"ev_r11_R_{TAG}.peer100.json","40"],stdout=subprocess.PIPE,text=True)
u=int(peer.stdout.readline().strip())
srv=subprocess.Popen([BIN,"--config",CFG],stdout=subprocess.DEVNULL,stderr=open(f"ev_r11_R_{TAG}.err2","w"))
for _ in range(80):
    time.sleep(0.05)
    try: socket.create_connection(("127.0.0.1",LP),timeout=1).close(); break
    except Exception: pass
time.sleep(0.2)
L=open(f"ev_r11_R_{TAG}.exp100.txt","w")
def go(tag,p):
    c=socket.create_connection(("127.0.0.1",LP),timeout=2); c.settimeout(1.5); c.sendall(p)
    g=b""; t0=time.time()
    while time.time()-t0<1.5:
        try: x=c.recv(8192)
        except socket.timeout: break
        if not x: break
        g+=x
    c.close(); time.sleep(0.15)
    L.write(f"{tag} recv_hex={g.hex()} recv={g!r}\n")
    print(tag, "|", g.split(b"\r\n")[0][:40], "| heads:", g.count(b"HTTP/1.1 "))
go("ctl_no_expect",b"POST /api%2fexec%20?cmd=id HTTP/1.1\r\nHost: alpha.test\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc")
go("with_expect",b"POST /api%2fexec%20?cmd=id HTTP/1.1\r\nHost: alpha.test\r\nExpect: 100-continue\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc")
go("with_expect_body_exec",b"POST /api%2fexec%20?cmd=id HTTP/1.1\r\nHost: alpha.test\r\nExpect: 100-continue\r\nContent-Length: 40\r\nConnection: close\r\n\r\nGET /api%2fexec%20?cmd=id HTTP/1.1\r\n\r\n")
L.close(); time.sleep(0.8)
srv.terminate()
try: srv.wait(3)
except Exception: srv.kill()
peer.kill()
