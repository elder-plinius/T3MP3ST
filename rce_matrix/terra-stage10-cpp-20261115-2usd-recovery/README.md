# terra-stage10-cpp-20261115-2usd-recovery

## Scope

This run is a proxying build. Every positive below executes on the **upstream** host - the proxy forwards, the backend runs `sh -c`. Cells not listed here are negatives and `ROW.md` carries the full matrix.

**Classification.** A cell is positive only when the harness drives real bytes at the build and the control peer observes the effect upstream: an executed request line, a replay the peer accepted as its own request, an inner response after a 1xx, or a victim served from cache with no fetch. `SUMMARY.md` is generated from this file.

**Rules honored.** Everything runs under `timeout`; a benign control precedes every payload on a fresh proxy and peer; a cell only counts on the upstream-side effect.

## Positive cells

### request_line_split

- **Severity.** high (one unauthenticated request executes on the upstream host).
- **Mechanism.** one client request whose target carries an encoded CRLF; the proxy re-emits it undecoded and the upstream parses a second, executing request line.
- **Source.** `recovery__2usd.cpp:78` (`proxyfetch`, rebuilt target)
- **PoC.** `rce_matrix/poc/row.py` cell `request_line_split` (exact bytes: `cells.json`)
- **Lane origin.** `ev_terra_post.py` + `FINDING_r14_A.md`
- **Evidence.** `pub2/terra-stage10-cpp-20261115-2usd-recovery/security-20261116T200054Z-8a38ef2a/evidence/smuggle_body_desync.log`
- **Shape driven.** GET with %0d%0a in the query; upstream receives a second, 4-token request.
- **Verified 2026-11-18 (PASS).** control 200, upstream saw ['GET /api/x?a%0d%0aGET%20/exec%3fcmd=id%0d%0aHost:%20u%0d%0a%20HTTP/1.1 HTTP/1.0'].

### body_replay_desync

- **Severity.** high (attacker-chosen request runs upstream).
- **Mechanism.** one POST with no usable framing; the body is never consumed and the upstream parses it as its own next request.
- **Source.** `recovery__2usd.cpp:78` (`proxyfetch`) - body never consumed on proxy locations
- **PoC.** `rce_matrix/poc/row.py` cell `body_replay_desync` (exact bytes: `cells.json`)
- **Lane origin.** `ev_terra_post.py` + `FINDING_r14_A.md`
- **Evidence.** `pub2/terra-stage10-cpp-20261115-2usd-recovery/security-20261116T200054Z-8a38ef2a/evidence/smuggle_body_desync.log`
- **Shape driven.** POST with no framing header; the tail is re-parsed as the next request.
- **Verified 2026-11-18 (PASS).** control 200, upstream saw ['GET /api/exec?cmd=id HTTP/1.0'].

### pct2f_split

- **Severity.** high (one request executes with no CRLF in the target).
- **Mechanism.** a `%2f` in the target decodes into a separator so a decoded 3-token exec target reaches the upstream.
- **Source.** `recovery__2usd.cpp:78` (`proxyfetch`); `%2f` lands as a decoded separator
- **PoC.** `rce_matrix/poc/row.py` cell `pct2f_split` (exact bytes: `cells.json`)
- **Lane origin.** `ev_r14_A_probe2.py` + `FINDING_r14_A.md`
- **Evidence.** `ev_r15_A2_2usd_pct2f.log`
- **Shape driven.** GET /api/%2fexec%3fcmd=id; the proxy emits a decoded 3-token exec target.
- **Verified 2026-11-18 (PASS).** control 200, upstream saw ['GET /api/exec?cmd=id HTTP/1.0'].

## Verification

Driven from `rce_matrix/poc`: `timeout 300 python3 row.py <this folder>`; the run's `poc/verification.log` line records the control and the upstream-side effect.

Negatives here: cache_exec_poison, 1xx_nesting, config_quoted_space, multi_hop_chain, retry_double_exec. Full per-family status: `../SUMMARY.md`.

## Source index

- Inventory: `/home/mouse9911/gits/toksec/temp/rce-sweep2/INVENTORY.md`
- Lane docs: `/home/mouse9911/gits/toksec/temp/rce-sweep2/FINDING_*.md`
- Build source: `/home/mouse9911/gits/toksec/temp/rce-sweep2/recovery__2usd.cpp`
