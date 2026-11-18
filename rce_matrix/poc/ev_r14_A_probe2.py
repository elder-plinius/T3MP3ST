import socket, sys, time, json
PORT=int(sys.argv[1]); LOG=sys.argv[2]; TAG=sys.argv[3]
HDR_CL=(b"POST /api/ HTTP/1.1\r\nHost: alpha.test\r\nConnection: content-length\r\nContent-Length: 38\r\n\r\n")
BODY=b"GET /exec?cmd=id HTTP/1.1\r\nHost: x\r\n\r\n"
HDR_EX=(b"POST /api/ HTTP/1.1\r\nHost: alpha.test\r\nExpect: 100-continue\r\nContent-Length: 38\r\n\r\n")
start=len(open(LOG).read().splitlines()) if __import__("os").path.exists(LOG) else 0

def drain(s,secs):
    s.settimeout(secs); d=b""; end=time.time()+secs
    while time.time()<end:
        try: c=s.recv(65536)
        except socket.timeout: break
        except Exception: break
        if not c: break
        d+=c
    return d

s=socket.create_connection(("127.0.0.1",PORT),timeout=5); s.sendall(HDR_CL); time.sleep(0.4)
s.sendall(BODY); d=drain(s,3.0); s.close(); time.sleep(0.4)
print(f"== {TAG} conn_cl_twophase"); print("REQ_HEX",(HDR_CL+BODY).hex()); print("CLI_HEX",d.hex())
print("CLI_STATUS", d.split(b"\r\n",1)[0].decode("latin1","replace") if d else "NOSP")
time.sleep(0.4)

s=socket.create_connection(("127.0.0.1",PORT),timeout=5); s.sendall(HDR_EX); d=drain(s,4.0)
print(f"== {TAG} expect_headers_only"); print("REQ_HEX",HDR_EX.hex()); print("CLI_HEX",d.hex())
print("CLI_STATUS", d.split(b"\r\n",1)[0].decode("latin1","replace") if d else "NOSP")
s.close(); time.sleep(0.6)

lines=open(LOG).read().splitlines()
print("UPSTREAM_SEGMENTS",len(lines)-start)
for i,l in enumerate(lines[start:],start):
    g=json.loads(l)
    print(f"UP[{i}] tokens={g['tokens']} raw={g['raw']!r} bodyhex={g['bodyhex']} tailhex={g['tailhex']}")
