# Peer that optionally emits an interim 100 before the 200, to model an Expect-honouring upstream.
import socket,threading,sys,time,subprocess,json
RAW=[]; LOCK=threading.Lock(); SEQ=[0]; OUT=sys.argv[2]
def h(c):
    with LOCK: SEQ[0]+=1; n=SEQ[0]
    d=b""; c.settimeout(1.0)
    try:
        while b"\r\n\r\n" not in d:
            x=c.recv(8192)
            if not x: break
            d+=x
    except Exception: pass
    head,_,rest=d.partition(b"\r\n\r\n")
    lines=head.split(b"\r\n"); line=lines[0] if lines else b""
    names=[L.split(b":",1)[0].strip().lower() for L in lines[1:] if b":" in L]
    cl=0
    for L in lines[1:]:
        if L.lower().startswith(b"content-length:"):
            try: cl=int(L.split(b":",1)[1].strip())
            except Exception: cl=0
    body=rest
    while len(body)<cl:
        try:
            x=c.recv(8192)
            if not x: break
            body+=x
        except Exception: break
    rec={"seq":n,"line":line.decode("latin1"),"tokens":len(line.split()),
         "hdrnames":[x.decode() for x in names],"raw_hex":d.hex(),"body_hex":body.hex()}
    with LOCK:
        RAW.append(rec); open(OUT,"w").write(json.dumps(RAW))
    toks=line.split()
    if len(toks)>=2 and toks[1].endswith(b"/exec"):
        out=subprocess.run(["sh","-c","id"],capture_output=True).stdout
        b2=b"SEQ:%d EXEC:%s"%(n,out)
    else:
        b2=b"SEQ:%d LINE:%s"%(n,line)
    try:
        if b"expect" in names:
            c.sendall(b"HTTP/1.1 100 Continue\r\n\r\n"); time.sleep(0.05)
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: "+str(len(b2)).encode()+b"\r\nConnection: close\r\n\r\n"+b2)
    except Exception: pass
    try: c.close()
    except Exception: pass
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("127.0.0.1",int(sys.argv[1]))); print(s.getsockname()[1],flush=True); s.listen(64)
t0=time.time(); s.settimeout(0.1); dur=float(sys.argv[3]) if len(sys.argv)>3 else 40.0
while time.time()-t0<dur:
    try: c,_=s.accept()
    except socket.timeout: continue
    except OSError: break
    threading.Thread(target=h,args=(c,),daemon=True).start()
