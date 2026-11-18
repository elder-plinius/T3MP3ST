# stage-05__cpp__20261116T025712Z__3aeb255d3d7f__ae021893

## Scope

This run is a proxying build. Every positive below executes on the **upstream** host - the proxy forwards, the backend runs `sh -c`. Cells not listed here are negatives and `ROW.md` carries the full matrix.

**Classification.** A cell is positive only when the harness drives real bytes at the build and the control peer observes the effect upstream: an executed request line, a replay the peer accepted as its own request, an inner response after a 1xx, or a victim served from cache with no fetch. `SUMMARY.md` is generated from this file.

**Rules honored.** Everything runs under `timeout`; a benign control precedes every payload on a fresh proxy and peer; a cell only counts on the upstream-side effect.

## Positive cells

### request_line_split

- **Severity.** high (one unauthenticated request executes on the upstream host).
- **Mechanism.** one client request whose target carries an encoded CRLF; the proxy re-emits it undecoded and the upstream parses a second, executing request line.
- **Source.** `ae021893:51` (decode rejects only NUL/backslash and `c<32`)
- **PoC.** `rce_matrix/poc/row.py` cell `request_line_split` (exact bytes: `cells.json`)
- **Lane origin.** `ev_r14_A_probe2.py` + `FINDING_r14_A.md`
- **Evidence.** `ev_r16_A_final_ae021893.txt`
- **Shape driven.** GET with %0d%0a in the query; upstream receives a second, 4-token request.
- **Verified 2026-11-18 (PASS).** control 200, upstream saw ['GET //x?a%0d%0aGET%20/exec%3fcmd=id%0d%0aHost:%20u%0d%0a%20HTTP/1.1 HTTP/1.1'].

### body_replay_desync

- **Severity.** high (attacker-chosen request runs upstream).
- **Mechanism.** one POST with no usable framing; the body is never consumed and the upstream parses it as its own next request.
- **Source.** `ae021893:64` (`upstream`, body appended but length not re-framed)
- **PoC.** `rce_matrix/poc/row.py` cell `body_replay_desync` (exact bytes: `cells.json`)
- **Lane origin.** `ev_r14_A_probe2.py` + `FINDING_r14_A.md`
- **Evidence.** `ev_r14_A_ae021893_v2_out.log`
- **Shape driven.** POST with no framing header; the tail is re-parsed as the next request.
- **Verified 2026-11-18 (PASS).** control 200, upstream saw ['POST //x HTTP/1.1', 'GET //exec?cmd=id HTTP/1.1'].

### cache_exec_poison

- **Severity.** critical (victim gets the executed body with no request of its own).
- **Mechanism.** an attacker request seeds the cache with the executed response; an identical victim request is then served from cache with zero upstream fetches.
- **Source.** `ae021893:67` (`cachekey`), `:69` (`lookup`), `:70` (`storecache`)
- **PoC.** `rce_matrix/poc/row.py` cell `cache_exec_poison` (exact bytes: `cells.json`)
- **Lane origin.** `ev_r14_A_probe2.py` + `FINDING_r14_A.md`
- **Evidence.** `ev_r15_E_k5b_victim_client_stream.hex`
- **Shape driven.** seed %2f-split exec, then a victim with a different Accept-Encoding hits the entry.
- **Verified 2026-11-18 (PASS).** control 200, upstream saw ['GET /%2fexec%20?cmd=id HTTP/1.1'].

### 1xx_nesting

- **Severity.** high (100 -> 502/100 then the body executes upstream).
- **Mechanism.** upstream emits `100 Continue`; the proxy turns it into a client-visible 502/100 and the real response follows as a second head or as the body.
- **Source.** `ae021893:64` (1xx accepted as terminal, `status>=100&&status<200` sets `len=0`)
- **PoC.** `rce_matrix/poc/row.py` cell `1xx_nesting` (exact bytes: `cells.json`)
- **Lane origin.** `ev_r11_R_exp100.py` + `FINDING_r11_R.md`
- **Evidence.** `ev_r11_R_ae02.iso.txt`
- **Shape driven.** Expect + CL:0 POST: the interim 100 aborts the exchange, the body replays and executes.
- **Verified 2026-11-18 (PASS).** control 200, upstream saw ['POST //x HTTP/1.1', 'GET //exec?cmd=id HTTP/1.1'].

## Verification

Driven from `rce_matrix/poc`: `timeout 300 python3 row.py <this folder>`; the run's `poc/verification.log` line records the control and the upstream-side effect.

Negatives here: pct2f_split, config_quoted_space, multi_hop_chain, retry_double_exec. Full per-family status: `../SUMMARY.md`.

## Source index

- Inventory: `/home/mouse9911/gits/toksec/temp/rce-sweep2/INVENTORY.md`
- Lane docs: `/home/mouse9911/gits/toksec/temp/rce-sweep2/FINDING_*.md`
- Build source: `/home/mouse9911/gits/toksec/temp/rce-sweep2/3aeb255d3d7f__ae021893.cpp`
