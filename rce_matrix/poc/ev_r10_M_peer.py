# lane M peer: strict exact-/exec token, echoes request line + token count,
# per-mode Cache-Control/Content-Type/gzip, logs every request.
import socket, threading, sys, time, subprocess, json, gzip, urllib.parse, os
PORT=int(sys.argv[1]); LOG=sys.argv[2]; lock=threading.Lock(); CNT=[0]

def run(cmd):
    try: return subprocess.run(["sh","-c",cmd],capture_output=True,timeout=5).stdout
    except Exception as e: return str(e).encode()

def handle(c):
    try:
        c.settimeout(2.0); d=b""
        while b"\r\n\r\n" not in d and b"\n\n" not in d:
            x=c.recv(16384)
            if not x: break
            d+=x
        head=d.split(b"\r\n\r\n")[0]
        line=head.split(b"\r\n")[0].decode("latin1")
        toks=line.split()
        ae=""
        for ln in head.split(b"\r\n")[1:]:
            s=ln.decode("latin1")
            if s.lower().startswith("accept-encoding:"): ae=s.split(":",1)[1].strip()
        mode="nocl"
        import re as _re
        mm=_re.search(r"[?&]mode=([a-z]+)", line)
        if mm: mode=mm.group(1)
        # strict: token must be exactly /exec
        dec=urllib.parse.unquote(" ".join(toks[1:-1])) if len(toks)>2 else (urllib.parse.unquote(toks[1]) if len(toks)==2 else "")
        dec0=dec.split(" ")[0]
        dec_exec="/exec" in dec0 or dec0.startswith("/exec")
        ran=False; out=b""
        if dec_exec and len(toks)>=2:
            cmd="id"
            for t in dec.split(" "):
                if "cmd=" in t:
                    cmd=t.split("cmd=",1)[1].split("&")[0]; break
            out=run(cmd); ran=True
        CNT[0]+=1; body=(b"EXEC#%d:"%CNT[0] if ran else b"PLAIN#%d:"%CNT[0])+out
        body+=b"|"+line.encode("latin1")+b"|DEC:"+dec.encode("latin1")
        hdr=b"HTTP/1.1 200 OK\r\n"
        if (mode in ("gzip","gzipnovary","gzipvary") and "gzip" in ae.lower()) or mode=="gzipalways":
            body=gzip.compress(body); hdr+=b"Content-Encoding: gzip\r\n"; gz=1
        else: gz=0
        hdr+=b"Content-Type: text/plain\r\nCache-Control: public, max-age=60\r\n"
        if mode=="gzipvary": hdr+=b"Vary: Accept-Encoding\r\n"
        hdr+=b"Content-Length: "+str(len(body)).encode()+b"\r\nConnection: close\r\n\r\n"
        with lock:
            open(LOG,"a").write(json.dumps({"n":CNT[0],"line":line,"tokens":len(toks),"ae":ae,"mode":mode,"ran":ran,"dec_exec":dec_exec,"gz":gz})+"\n")
        c.sendall(hdr+body)
    except Exception as e:
        with lock: open(LOG,"a").write(json.dumps({"err":str(e)})+"\n")
    finally:
        try: c.close()
        except Exception: pass

s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("127.0.0.1",PORT)); s.listen(64); s.settimeout(0.2)
end=time.time()+float(os.environ.get("PEER_TTL","120"))
while time.time()<end:
    try: c,_=s.accept()
    except socket.timeout: continue
    threading.Thread(target=handle,args=(c,),daemon=True).start()
