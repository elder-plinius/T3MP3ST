# stage-10__cpp__20261116T025713Z__3aeb255d3d7f__8d5ff1f2

## Scope

This run is a proxying build. Every positive below executes on the **upstream** host - the proxy forwards, the backend runs `sh -c`. Cells not listed here are negatives and `ROW.md` carries the full matrix.

**Classification.** A cell is positive only when the harness drives real bytes at the build and the control peer observes the effect upstream: an executed request line, a replay the peer accepted as its own request, an inner response after a 1xx, or a victim served from cache with no fetch. `SUMMARY.md` is generated from this file.

**Rules honored.** Everything runs under `timeout`; a benign control precedes every payload on a fresh proxy and peer; a cell only counts on the upstream-side effect.

## Positive cells

### request_line_split

- **Severity.** high (one unauthenticated request executes on the upstream host).
- **Mechanism.** one client request whose target carries an encoded CRLF; the proxy re-emits it undecoded and the upstream parses a second, executing request line.
- **Source.** `8d5ff1f2:77` (`pathnorm`) and `:85` (`proxy_request`, `req=method+" "+target`)
- **PoC.** `rce_matrix/poc/row.py` cell `request_line_split` (exact bytes: `cells.json`)
- **Lane origin.** `ev_r14_A_probe2.py` + `FINDING_r14_A.md`
- **Evidence.** `ev_r15_A2_8d5ff1f2_multi.log`
- **Shape driven.** GET with %0d%0a in the query; upstream receives a second, 4-token request.
- **Verified 2026-11-18 (PASS).** control 200, upstream saw ['GET /api/x?a%0d%0aGET%20/exec%3fcmd=id%0d%0aHost:%20u%0d%0a%20HTTP/1.1 HTTP/1.1'].

### body_replay_desync

- **Severity.** high (attacker-chosen request runs upstream).
- **Mechanism.** one POST with no usable framing; the body is never consumed and the upstream parses it as its own next request.
- **Source.** `8d5ff1f2:85` (`Content-Length: 0` consumes only the head)
- **PoC.** `rce_matrix/poc/row.py` cell `body_replay_desync` (exact bytes: `cells.json`)
- **Lane origin.** `ev_r14_A_probe2.py` + `FINDING_r14_A.md`
- **Evidence.** `ev_r15_A2_8d5ff1f2_unframed_exec.log`
- **Shape driven.** Content-Length: 0 consumes only the head; trailing bytes become a second request.
- **Verified 2026-11-18 (PASS).** control 200, upstream saw ['GET /api/x HTTP/1.1', 'GET /api/exec?cmd=id HTTP/1.1'].

### 1xx_nesting

- **Severity.** high (100 -> 502/100 then the body executes upstream).
- **Mechanism.** upstream emits `100 Continue`; the proxy turns it into a client-visible 502/100 and the real response follows as a second head or as the body.
- **Source.** `8d5ff1f2:85` (`status<100||status>599` accepts 1xx; real response becomes the body)
- **PoC.** `rce_matrix/poc/row.py` cell `1xx_nesting` (exact bytes: `cells.json`)
- **Lane origin.** `ev_1xx.py` + `FINDING_1xx_nested.md`
- **Evidence.** `FINDING_1xx_nested.md`
- **Shape driven.** upstream 100 is terminal; the following head is absorbed as the body.
- **Verified 2026-11-18 (PASS).** control 200, upstream saw ['GET /api/x HTTP/1.1'].

### pct2f_split

- **Severity.** high (one request executes with no CRLF in the target).
- **Mechanism.** a `%2f` in the target decodes into a separator so a decoded 3-token exec target reaches the upstream.
- **Source.** `8d5ff1f2:77` (`pathnorm` decodes `%2f`)
- **PoC.** `rce_matrix/poc/row.py` cell `pct2f_split` (exact bytes: `cells.json`)
- **Lane origin.** `ev_r14_A_probe2.py` + `FINDING_r14_A.md`
- **Evidence.** `ev_r15_A2_8d5ff1f2_pct2f.log`
- **Shape driven.** GET /api/%2fexec%3fcmd=id; the proxy emits a decoded 3-token exec target.
- **Verified 2026-11-18 (PASS).** control 200, upstream saw ['GET /api/exec?cmd=id HTTP/1.1'].

### config_quoted_space

- **Severity.** high (zero client-side encoding).
- **Mechanism.** a quoted trailing space in `proxy_pass` is the separator; the client sends no encoding at all.
- **Source.** `8d5ff1f2:85` (`proxy_request` splices the quoted URI raw)
- **PoC.** `rce_matrix/poc/row.py` cell `config_quoted_space` (exact bytes: `cells.json`)
- **Lane origin.** `cspace.py` + `FINDING_cfg_space.md`
- **Evidence.** `ev_r5_cfgsep_3aeb255d3d7f__8d5ff1f2.log`
- **Shape driven.** proxy_pass "http://backend/exec " - the quoted space splits the upstream line.
- **Verified 2026-11-18 (PASS).** control 200, upstream saw ['GET /exec ?cmd=id HTTP/1.1'].

### multi_hop_chain

- **Severity.** high (two-hop chain executes on the final upstream).
- **Mechanism.** double-encoded payload: hop 1 decodes `%25`, hop 2 decodes `%20`/`%0d%0a` and executes the split.
- **Source.** hop 1 `6baf167b:62` (`decodepath`) / `:97`; hop 2 `8d5ff1f2:77` (`pathnorm`) / `:89` (`proxy_request`)
- **PoC.** `rce_matrix/poc/row.py` cell `multi_hop_chain` (exact bytes: `cells.json`)
- **Lane origin.** `poc_r15_E_chain.py` + `FINDING_r15_E.md`
- **Evidence.** `ev_r15_E_chain_hop2_8d5ff1f2_upstream.hex`
- **Shape driven.** double-encoded payload: hop 1 decodes %25, hop 2 splits and executes.
- **Verified 2026-11-18 (PASS).** control 200, upstream saw status=HTTP/1.1 200 OK executed=1.

## Verification

Driven from `rce_matrix/poc`: `timeout 300 python3 row.py <this folder>`; the run's `poc/verification.log` line records the control and the upstream-side effect.

Negatives here: cache_exec_poison, retry_double_exec. Full per-family status: `../SUMMARY.md`.

## Source index

- Inventory: `/home/mouse9911/gits/toksec/temp/rce-sweep2/INVENTORY.md`
- Lane docs: `/home/mouse9911/gits/toksec/temp/rce-sweep2/FINDING_*.md`
- Build source: `/home/mouse9911/gits/toksec/temp/rce-sweep2/3aeb255d3d7f__8d5ff1f2.cpp`
