# stage-10__cpp__20261116T022713Z__1cfd33433d25__61cc738c

## Scope

This run is a proxying build. Every positive below executes on the **upstream** host - the proxy forwards, the backend runs `sh -c`. Cells not listed here are negatives and `ROW.md` carries the full matrix.

**Classification.** A cell is positive only when the harness drives real bytes at the build and the control peer observes the effect upstream: an executed request line, a replay the peer accepted as its own request, an inner response after a 1xx, or a victim served from cache with no fetch. `SUMMARY.md` is generated from this file.

**Rules honored.** Everything runs under `timeout`; a benign control precedes every payload on a fresh proxy and peer; a cell only counts on the upstream-side effect.

## Positive cells

### request_line_split

- **Severity.** high (one unauthenticated request executes on the upstream host).
- **Mechanism.** one client request whose target carries an encoded CRLF; the proxy re-emits it undecoded and the upstream parses a second, executing request line.
- **Source.** `61cc738c:67` (`proxy`, raw target into the line)
- **PoC.** `rce_matrix/poc/row.py` cell `request_line_split` (exact bytes: `cells.json`)
- **Lane origin.** `ev_r14_A_probe2.py` + `FINDING_r14_A.md`
- **Evidence.** `ev_r14_A_61cc738c_v2_out.log`
- **Shape driven.** GET with %0d%0a in the query; upstream receives a second, 4-token request.
- **Verified 2026-11-18 (PASS).** control 200, upstream saw ['GET /api/x?a%0d%0aGET%20/exec%3fcmd=id%0d%0aHost:%20u%0d%0a%20HTTP/1.1 HTTP/1.1'].

### body_replay_desync

- **Severity.** high (attacker-chosen request runs upstream).
- **Mechanism.** one POST with no usable framing; the body is never consumed and the upstream parses it as its own next request.
- **Source.** `61cc738c:67` (`proxy`), `:68` (`serve` passes `true`) - `Connection: content-length` strips the CL
- **PoC.** `rce_matrix/poc/row.py` cell `body_replay_desync` (exact bytes: `cells.json`)
- **Lane origin.** `ev_r14_A_probe2.py` + `FINDING_r14_A.md`
- **Evidence.** `ev_r15_G_61cc_conncl_cl_upstream.log`
- **Shape driven.** Connection: content-length strips the CL, body follows as a raw tail.
- **Verified 2026-11-18 (PASS).** control 200, upstream saw ['POST /api/x HTTP/1.1', 'GET /api/exec?cmd=id HTTP/1.1'].

## Verification

Driven from `rce_matrix/poc`: `timeout 300 python3 row.py <this folder>`; the run's `poc/verification.log` line records the control and the upstream-side effect.

Negatives here: cache_exec_poison, 1xx_nesting, pct2f_split, config_quoted_space, multi_hop_chain, retry_double_exec. Full per-family status: `../SUMMARY.md`.

## Source index

- Inventory: `/home/mouse9911/gits/toksec/temp/rce-sweep2/INVENTORY.md`
- Lane docs: `/home/mouse9911/gits/toksec/temp/rce-sweep2/FINDING_*.md`
- Build source: `/home/mouse9911/gits/toksec/temp/rce-sweep2/1cfd33433d25__61cc738c.cpp`
