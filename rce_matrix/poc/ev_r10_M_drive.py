import socket, sys, time, json, os, subprocess, signal, re
BUILD=sys.argv[1]; L=int(sys.argv[2]); UP=int(sys.argv[3]); TAG=sys.argv[4]
ROOT="/tmp/r10_www_M"
LOG=f"ev_r10_M_{TAG}_{L}_{L}_peer.log"; OUTF=f"ev_r10_M_{TAG}_{L}_{L}.json"
res={"build":BUILD,"port":L,"up":UP,"steps":[]}
def rec(name,**kw):
    kw["step"]=name; res["steps"].append(kw); print("STEP",name,json.dumps(kw)[:400],flush=True)
def raw(path,ae=None,host="alpha.test",save=None):
    b=b""
    try:
        c=socket.create_connection(("127.0.0.1",L),timeout=3); c.settimeout(3)
        h=f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
        if ae is not None: h+=f"Accept-Encoding: {ae}\r\n"
        h+="Connection: close\r\n\r\n"
        c.sendall(h.encode())
        while True:
            x=c.recv(65536)
            if not x: break
            b+=x
        c.close()
    except Exception as e: b+=b" SOCKERR:"+str(e).encode()
    if save: open(save,"wb").write(b)
    return b
def bodyof(b): return b.split(b"\r\n\r\n",1)[1] if b"\r\n\r\n" in b else b""
def decoded(b):
    x=bodyof(b)
    if x[:2]==b"\x1f\x8b":
        try:
            import gzip as _g; return _g.decompress(x)
        except Exception: return x
    return x
def n_of(b):
    m=re.match(rb"(?:EXEC|PLAIN)#(\d+)", decoded(b))
    return int(m.group(1)) if m else None
def statusof(b):
    try: return int(b.split(b" ")[1])
    except: return -1
cfg=f"ev_r10_M_{TAG}_{L}.conf"
tpl=open("cfgs/kv3_38095.conf").read().splitlines()
out=[]
for ln in tpl:
    if ln.startswith("listen="): ln=f"listen=127.0.0.1:{L}"
    elif ln.startswith("root="): ln=f"root={ROOT}/alpha"
    elif ln.startswith("host_root="): ln=f"host_root=beta.test:{ROOT}/beta"
    elif ln.startswith("alias="): ln=f"alias=/alias:{ROOT}/alias"
    elif ln.startswith("upstreams="): ln=f"upstreams=127.0.0.1:{UP}"
    elif ln.startswith("cache_ttl_ms="): ln="cache_ttl_ms=60000"
    elif ln.startswith("cache_bytes="): ln="cache_bytes=1000000"
    elif ln.startswith("proxy_prefix="): ln="proxy_prefix=/api"
    out.append(ln)
open(cfg,"w").write("\n".join(out)+"\n")
peer=subprocess.Popen([sys.executable,"ev_r10_M_peer.py",str(UP),LOG],env=dict(os.environ,PEER_TTL="420"))
srv=subprocess.Popen([f"bin/{BUILD}","--config",cfg],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
try:
    for _ in range(120):
        try: socket.create_connection(("127.0.0.1",UP),timeout=1).close(); break
        except: time.sleep(0.05)
    ok=False
    for _ in range(140):
        time.sleep(0.05)
        try: socket.create_connection(("127.0.0.1",L),timeout=1).close(); ok=True; break
        except: pass
    rec("start",listening=ok)
    if not ok: raise SystemExit
    b=b""
    for _try in range(4):
        b=raw("/api/ctl_plain.txt")
        if bodyof(b).startswith(b"PLAIN#"): break
        time.sleep(0.15)
    rec("control_plain",status=statusof(b),body=bodyof(b)[:100].decode("latin1","replace"),
        is_plain=bodyof(b).startswith(b"PLAIN#"))
    if statusof(b)!=200 or not bodyof(b).startswith(b"PLAIN#"): rec("control_FAIL"); raise SystemExit
    g=raw("/api/ctl_v.txt?mode=gzipvary",ae="gzip"); d=raw("/api/ctl_v.txt?mode=gzipvary",ae="identity")
    rec("control_gzipvary",first_gz=bodyof(g)[:2]==b"\x1f\x8b",
        second_gz=bodyof(d)[:2]==b"\x1f\x8b",second_n=n_of(d),first_n=n_of(g),
        second_replayed=(n_of(d)==n_of(g)),
        ce_to_identity=(b"content-encoding: gzip" in d.lower()))
    S={"A":"/api%2fexec%20?cmd=id","B":"/api/exec%20?cmd=id","C":"/api%2fexec ?cmd=id",
       "D":"/api%2Fexec%20?cmd=id","E":"/api%2fexec%20?cmd=id&","F":"/API%2FEXEC%20?cmd=id",
       "G":"/api%2fexec%20?cmd=id/","H":"/api//exec%20?cmd=id"}
    for k,p in list(S.items()):
        b=raw(p,ae="gzip",save=f"ev_r10_M_{TAG}_{L}_seed{k}.bytes")
        rec(f"seed_{k}",status=statusof(b),n=n_of(b),exec_ran=(n_of(b) is not None),
            body=bodyof(b)[:80].decode("latin1","replace"))
    for k,p in S.items():
        b=raw(p,ae="identity",save=f"ev_r10_M_{TAG}_{L}_c2id{k}.bytes")
        rec(f"c2_identity_{k}",status=statusof(b),n=n_of(b),
            replayed=(n_of(b) is not None and n_of(b)<=max([x["n"] for x in res["steps"] if x.get("n")])),
            gz_to_identity=bodyof(b)[:2]==b"\x1f\x8b", body=bodyof(b)[:70].decode("latin1","replace"))
    for k,p in S.items():
        b=raw(p,save=f"ev_r10_M_{TAG}_{L}_c4noae{k}.bytes")
        rec(f"c4_noae_{k}",status=statusof(b),n=n_of(b),gz_body=bodyof(b)[:2]==b"\x1f\x8b",
            body=bodyof(b)[:70].decode("latin1","replace"))
    # cross-spelling: seed X with gzip then read Y; hit iff counter unchanged
    for X,Y in (("A","B"),("A","D"),("A","E"),("B","A"),("D","A"),("E","A"),("A","F"),("G","A")):
        sx=raw(S[X],ae="gzip"); nx=n_of(sx)
        sy=raw(S[Y],ae="gzip"); ny=n_of(sy)
        rec(f"cross_{X}_to_{Y}",nx=nx,ny=ny,same_key_hit=(nx==ny),
            x_status=statusof(sx),y_status=statusof(sy))
    # second-client same-key test: seed gzip, then plain second client must replay
    for k in ("A","B"):
        s1=raw(S[k],ae="gzip"); n1=n_of(s1)
        s2=raw(S[k],ae="gzip"); n2=n_of(s2)
        rec(f"second_client_same_{k}",n1=n1,n2=n2,replayed=(n1==n2),
            gz_body=bodyof(s2)[:2]==b"\x1f\x8b", status=statusof(s2))
    # exec + gzip + no-Vary: wildcard entry carrying EXECUTED bytes
    GX="/api%2fexec%20?cmd=id&mode=gzipalways"
    gx=raw(GX,ae="gzip",save=f"ev_r10_M_{TAG}_{L}_execgz_seed.bytes")
    rec("execgz_seed",status=statusof(gx),n=n_of(gx),gz_magic=bodyof(gx)[:2]==b"\x1f\x8b",
        ce=(b"content-encoding: gzip" in gx.lower()),body=bodyof(gx)[:40].decode("latin1","replace"))
    gx2=raw(GX,ae="identity",save=f"ev_r10_M_{TAG}_{L}_execgz_identity.bytes")
    rec("execgz_identity",status=statusof(gx2),n=n_of(gx2),replayed=(n_of(gx2)==n_of(gx)),
        gz_body=bodyof(gx2)[:2]==b"\x1f\x8b",ce=(b"content-encoding: gzip" in gx2.lower()))
    gx3=raw(GX,save=f"ev_r10_M_{TAG}_{L}_execgz_noae.bytes")
    rec("execgz_noae",status=statusof(gx3),n=n_of(gx3),replayed=(n_of(gx3)==n_of(gx)),
        gz_body=bodyof(gx3)[:2]==b"\x1f\x8b",ce=(b"content-encoding: gzip" in gx3.lower()))
    # empty-AE alias: bare client must not be able to be preselected... or can it
    ea=raw("/api/z.txt?mode=gzipalways",ae="")
    eb=raw("/api/z.txt?mode=gzipalways")
    rec("emptyae_alias",n_empty=n_of(ea),n_bare=n_of(eb),aliased=(n_of(ea)==n_of(eb)),
        bare_gz=bodyof(eb)[:2]==b"\x1f\x8b",bare_ce=(b"content-encoding: gzip" in eb.lower()))
    # vary wildcard test on fresh key
    g=raw("/api/w.txt?mode=gzipnovary",ae="gzip",save=f"ev_r10_M_{TAG}_{L}_varyseed.bytes")
    rec("vary_seed_gzipnovary",status=statusof(g),n=n_of(g),gz_magic=bodyof(g)[:2]==b"\x1f\x8b",
        ce=(b"content-encoding: gzip" in g.lower()),vary_hdr=(b"\r\nvary:" in g.lower()))
    d=raw("/api/w.txt?mode=gzipnovary",ae="identity",save=f"ev_r10_M_{TAG}_{L}_varyid.bytes")
    rec("vary_identity_read",status=statusof(d),n=n_of(d),replayed=(n_of(d)==n_of(g)),
        gz_body=bodyof(d)[:2]==b"\x1f\x8b",ce=(b"content-encoding: gzip" in d.lower()))
    e=raw("/api/w.txt?mode=gzipnovary",save=f"ev_r10_M_{TAG}_{L}_varynoae.bytes")
    rec("vary_noae_read",status=statusof(e),n=n_of(e),replayed=(n_of(e)==n_of(g)),
        gz_body=bodyof(e)[:2]==b"\x1f\x8b",ce=(b"content-encoding: gzip" in e.lower()))
    try:
        r=subprocess.run(["curl","-s","-o",f"ev_r10_M_{TAG}_{L}_curl.out","-w","%{http_code}","--compressed",
                          "-H","Host: alpha.test",f"http://127.0.0.1:{L}/api/w.txt?mode=gzipnovary"],
                         capture_output=True,timeout=8)
        rec("curl_compressed",code=r.stdout.decode(),rc=r.returncode)
    except Exception as ex: rec("curl_compressed",err=str(ex))
    # eviction via reload with tiny cache
    open(cfg,"w").write(open(cfg).read().replace("cache_bytes=1000000","cache_bytes=300"))
    srv.send_signal(signal.SIGHUP)
    ok2=False
    for _ in range(60):
        time.sleep(0.1)
        try:
            probe=raw("/api/probe.txt"); ok2=bodyof(probe).startswith(b"PLAIN#")
        except Exception: pass
        if ok2: break
    rec("evict_reload",reloaded=ok2)
    pre=raw(S["A"],ae="gzip"); rec("evict_pre",n=n_of(pre))
    for i in range(8): raw(f"/api/e{i}.txt?mode=gzipalways",ae="gzip",host="beta.test")
    post=raw(S["A"],ae="gzip"); rec("evict_post",n=n_of(post),replayed=(n_of(post)==n_of(pre)))
finally:
    srv.terminate(); peer.terminate()
    try: srv.wait(3)
    except Exception: srv.kill()
    try: peer.wait(3)
    except Exception: peer.kill()
json.dump(res,open(OUTF,"w"),indent=1)
print("WROTE",OUTF)
