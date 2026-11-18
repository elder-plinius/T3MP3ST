# PoC harness

`row.py` drives every positive cell of one matrix row against the real build, then reports an
upstream-side effect. `harness.py` is the lab underneath it: a proxy launcher for both config
dialects, a control peer that executes only on an exact `/exec` token, and a request-stream parser
that consumes `Content-Length` and chunked bodies before looking at leftovers - so "replayed as its
own request" is never confused with "framed body".

## Prerequisites

- The sweep directory with the built binaries, by default
  `/home/mouse9911/gits/toksec/temp/rce-sweep2`; override with `RCE_SWEEP`.
- Python 3.10+ (no third-party packages), `curl`-free: everything is raw sockets.
- Loopback only, ephemeral ports: no port band to reserve, nothing to preflight.

## Run

```
export RCE_SWEEP=/home/mouse9911/gits/toksec/temp/rce-sweep2   # if not the default
cd rce_matrix/poc
timeout 300 python3 row.py ../stage-10__cpp__20261116T025716Z__3aeb255d3d7f__6fb186ed
```

Every artifact lands under `$RCE_OUT` (default `/tmp/rce_matrix_poc/<run>/<cell>/`): `proxy.conf`,
`control.txt`, `req_<step>.hex`, `resp_<step>.txt`, and every upstream hit as `peer_up_<n>.hex`.
Always wrap the command in `timeout`; the harness terminates its own children on exit.

## Rules the harness enforces

- **Control first.** Each cell starts a fresh peer and proxy, sends a benign control, and refuses to
  grade the payload unless the control is `200`.
- **Upstream-side proof only.** A cell passes on an executed request line, a replay the peer accepted
  as a second request, an inner response after a 1xx, or a victim served from cache with zero fetches.
  A `200` to the client is never sufficient on its own.
- **Two-hop cells** stack a second real proxy and control both hops.
- **Retry cells** run a flaky peer that dies after the first hit plus a healthy peer, and require two
  distinct executions.

## Expected negatives

Several cells are deliberately negative here even though a source primitive exists - most notably
`f2b3415b` `cache_exec_poison`: it has a cacheable source line but never served a victim from cache
in this harness, so it stays a negative in `../SUMMARY.md` and is never counted. `multi_hop_chain`
is negative unless hop 1 emits genuine CRLF into a two-token line (`8d5ff1f2` as hop 1 always 400s).

## Scripts

- `row.py` - the driver (one run folder, all its cells).
- `harness.py` - peer, proxy, framing parser, config renderer.
- `poc_r15_E_chain.py` - shim for the lane-E two-hop chain cell.
- `ev_*.py`, `cspace.py` - the original per-lane probes these cells were distilled from.
