# stage-10__cpp__20261116T022716Z__1cfd33433d25__063b0d5e

## Scope

This run is a proxying build. Every positive below executes on the **upstream** host - the proxy forwards, the backend runs `sh -c`. Cells not listed here are negatives and `ROW.md` carries the full matrix.

**Classification.** A cell is positive only when the harness drives real bytes at the build and the control peer observes the effect upstream: an executed request line, a replay the peer accepted as its own request, an inner response after a 1xx, or a victim served from cache with no fetch. `SUMMARY.md` is generated from this file.

**Rules honored.** Everything runs under `timeout`; a benign control precedes every payload on a fresh proxy and peer; a cell only counts on the upstream-side effect.

## Positive cells

### request_line_split

- **Severity.** high (one unauthenticated request executes on the upstream host).
- **Mechanism.** one client request whose target carries an encoded CRLF; the proxy re-emits it undecoded and the upstream parses a second, executing request line.
- **Source.** `063b0d5e:49` (`process`) and `:56` (`c.uto=method+" "+upath`)
- **PoC.** `rce_matrix/poc/row.py` cell `request_line_split` (exact bytes: `cells.json`)
- **Lane origin.** `ev_r6_A_frame.py` + `FINDING_r6_ascii_body_replay.md`
- **Evidence.** `ev_r16_A_final_063b0d5e.txt`
- **Shape driven.** GET with %0d%0a in the query; upstream receives a second, 4-token request.
- **Verified 2026-11-18 (PASS).** control 200, upstream saw ['GET /api/x?a%0d%0aGET%20/exec%3fcmd=id%0d%0aHost:%20u%0d%0a%20HTTP/1.1 HTTP/1.1'].

### body_replay_desync

- **Severity.** high (attacker-chosen request runs upstream).
- **Mechanism.** one POST with no usable framing; the body is never consumed and the upstream parses it as its own next request.
- **Source.** `063b0d5e:53` (`h.count` after `h[...]`), `:57` (`req_done=length==0`)
- **PoC.** `rce_matrix/poc/row.py` cell `body_replay_desync` (exact bytes: `cells.json`)
- **Lane origin.** `ev_r6_A_frame.py` + `FINDING_r6_ascii_body_replay.md`
- **Evidence.** `ev_r6_ascii_body_replay` PoC, `ev_r5_frame_063b0d5e_*.log`
- **Shape driven.** POST with no framing header; the tail is re-parsed as the next request.
- **Verified 2026-11-18 (PASS).** control 200, upstream saw ['POST /api/x HTTP/1.1', 'GET /api/exec?cmd=id HTTP/1.1'].

### config_quoted_space

- **Severity.** high (zero client-side encoding).
- **Mechanism.** a quoted trailing space in `proxy_pass` is the separator; the client sends no encoding at all.
- **Source.** `063b0d5e:56` (`c.uto=...upath...`, quoted `proxy_pass` keeps the space)
- **PoC.** `rce_matrix/poc/row.py` cell `config_quoted_space` (exact bytes: `cells.json`)
- **Lane origin.** `cspace.py` + `FINDING_cfg_space.md`
- **Evidence.** `ev_r5_cfgsep_1cfd33433d25__063b0d5e.log`
- **Shape driven.** proxy_pass "http://backend/exec " - the quoted space splits the upstream line.
- **Verified 2026-11-18 (PASS).** control 200, upstream saw ['GET /exec ?cmd=id HTTP/1.1'].

## Verification

Driven from `rce_matrix/poc`: `timeout 300 python3 row.py <this folder>`; the run's `poc/verification.log` line records the control and the upstream-side effect.

Negatives here: cache_exec_poison, 1xx_nesting, pct2f_split, multi_hop_chain, retry_double_exec. Full per-family status: `../SUMMARY.md`.

## Source index

- Inventory: `/home/mouse9911/gits/toksec/temp/rce-sweep2/INVENTORY.md`
- Lane docs: `/home/mouse9911/gits/toksec/temp/rce-sweep2/FINDING_*.md`
- Build source: `/home/mouse9911/gits/toksec/temp/rce-sweep2/1cfd33433d25__063b0d5e.cpp`
