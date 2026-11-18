# stage-05__cpp__20261116T025714Z__3aeb255d3d7f__f2b3415b

## Scope

This run is a proxying build. Every positive below executes on the **upstream** host - the proxy forwards, the backend runs `sh -c`. Cells not listed here are negatives and `ROW.md` carries the full matrix.

**Classification.** A cell is positive only when the harness drives real bytes at the build and the control peer observes the effect upstream: an executed request line, a replay the peer accepted as its own request, an inner response after a 1xx, or a victim served from cache with no fetch. `SUMMARY.md` is generated from this file.

**Rules honored.** Everything runs under `timeout`; a benign control precedes every payload on a fresh proxy and peer; a cell only counts on the upstream-side effect.

## Positive cells

### request_line_split

- **Severity.** high (one unauthenticated request executes on the upstream host).
- **Mechanism.** one client request whose target carries an encoded CRLF; the proxy re-emits it undecoded and the upstream parses a second, executing request line.
- **Source.** `f2b3415b:49` (decode) and `:87` (`startup`, `c->upout=...`)
- **PoC.** `rce_matrix/poc/row.py` cell `request_line_split` (exact bytes: `cells.json`)
- **Lane origin.** `ev_r14_A_probe2.py` + `FINDING_r15_G.md`
- **Evidence.** `ev_r16_A_final_f2b3415b.txt`
- **Shape driven.** GET with %0d%0a in the query; upstream receives a second, 4-token request.
- **Verified 2026-11-18 (PASS).** control 200, upstream saw ['GET //x?a%0d%0aGET%20/exec%3fcmd=id%0d%0aHost:%20u%0d%0a%20HTTP/1.1 HTTP/1.1'].

### body_replay_desync

- **Severity.** high (attacker-chosen request runs upstream).
- **Mechanism.** one POST with no usable framing; the body is never consumed and the upstream parses it as its own next request.
- **Source.** `f2b3415b:87` (`startup`, body never framed back)
- **PoC.** `rce_matrix/poc/row.py` cell `body_replay_desync` (exact bytes: `cells.json`)
- **Lane origin.** `ev_r14_A_probe2.py` + `FINDING_r15_G.md`
- **Evidence.** `ev_r15_G_f2b_conncl.log`
- **Shape driven.** POST with no framing header; the tail is re-parsed as the next request.
- **Verified 2026-11-18 (PASS).** control 200, upstream saw ['POST //x HTTP/1.1', 'GET //exec?cmd=id HTTP/1.1'].

### retry_double_exec

- **Severity.** medium (the command runs twice; no new request is forged).
- **Mechanism.** the first upstream executes then dies; the retry sends the same command again.
- **Source.** `f2b3415b:87` (`startup` retry buffer), `FINDING_r13_C.md:49`
- **PoC.** `rce_matrix/poc/row.py` cell `retry_double_exec` (exact bytes: `cells.json`)
- **Lane origin.** `ev_r14_A_probe2.py` + `FINDING_r15_G.md`
- **Evidence.** `ev_r12_X_ev_f2b_post.txt`, `ev_r12_X_ev_f2b_execfail.txt`
- **Shape driven.** upstream executes then dies; the retry executes the same command again.
- **Verified 2026-11-18 (PASS).** control 200, upstream saw status=HTTP/1.1 200 OK executions=2 flaky=['GET ///exec?cmd=id HTTP/1.1'] healthy=['GET ///exec?cmd=id HTTP/1.1'].

## Verification

Driven from `rce_matrix/poc`: `timeout 300 python3 row.py <this folder>`; the run's `poc/verification.log` line records the control and the upstream-side effect.

Negatives here: cache_exec_poison (not reproduced: cacheable source line exists, but the victim was never served from cache in this harness), 1xx_nesting, pct2f_split, config_quoted_space, multi_hop_chain. Full per-family status: `../SUMMARY.md`.

## Source index

- Inventory: `/home/mouse9911/gits/toksec/temp/rce-sweep2/INVENTORY.md`
- Lane docs: `/home/mouse9911/gits/toksec/temp/rce-sweep2/FINDING_*.md`
- Build source: `/home/mouse9911/gits/toksec/temp/rce-sweep2/3aeb255d3d7f__f2b3415b.cpp`
