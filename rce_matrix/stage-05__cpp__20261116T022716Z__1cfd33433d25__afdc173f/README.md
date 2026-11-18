# stage-05__cpp__20261116T022716Z__1cfd33433d25__afdc173f

## Scope

This run is a proxying build. Every positive below executes on the **upstream** host - the proxy forwards, the backend runs `sh -c`. Cells not listed here are negatives and `ROW.md` carries the full matrix.

**Classification.** A cell is positive only when the harness drives real bytes at the build and the control peer observes the effect upstream: an executed request line, a replay the peer accepted as its own request, an inner response after a 1xx, or a victim served from cache with no fetch. `SUMMARY.md` is generated from this file.

**Rules honored.** Everything runs under `timeout`; a benign control precedes every payload on a fresh proxy and peer; a cell only counts on the upstream-side effect.

## Positive cells

### request_line_split

- **Severity.** high (one unauthenticated request executes on the upstream host).
- **Mechanism.** one client request whose target carries an encoded CRLF; the proxy re-emits it undecoded and the upstream parses a second, executing request line.
- **Source.** `afdc173f:56` (`decode`, query kept undecoded) and `:80` (`proxy`)
- **PoC.** `rce_matrix/poc/row.py` cell `request_line_split` (exact bytes: `cells.json`)
- **Lane origin.** `ev_r12_X_run.sh` + `FINDING_r12_X.md`
- **Evidence.** `ev_r16_A_final_afdc173f.txt`
- **Shape driven.** GET with %0d%0a in the query; upstream receives a second, 4-token request.
- **Verified 2026-11-18 (PASS).** control 200, upstream saw ['GET //x?a%0d%0aGET%20/exec%3fcmd=id%0d%0aHost:%20u%0d%0a%20HTTP/1.1 HTTP/1.1'].

### cache_exec_poison

- **Severity.** critical (victim gets the executed body with no request of its own).
- **Mechanism.** an attacker request seeds the cache with the executed response; an identical victim request is then served from cache with zero upstream fetches.
- **Source.** `afdc173f:77` (`cacheget` tries `"*"` first), `:78` (`cacheput`)
- **PoC.** `rce_matrix/poc/row.py` cell `cache_exec_poison` (exact bytes: `cells.json`)
- **Lane origin.** `ev_r12_X_run.sh` + `FINDING_r12_X.md`
- **Evidence.** `ev_r10_M_afdc_36120_execgz_identity.bytes`
- **Shape driven.** seed %2f-split exec, then a victim with a different Accept-Encoding hits the entry.
- **Verified 2026-11-18 (PASS).** control 200, upstream saw ['GET //exec ?cmd=id HTTP/1.1'].

### retry_double_exec

- **Severity.** medium (the command runs twice; no new request is forged).
- **Mechanism.** the first upstream executes then dies; the retry sends the same command again.
- **Source.** `afdc173f:80` (`proxy` retry contract), `FINDING_r13_C.md:49-83`
- **PoC.** `rce_matrix/poc/row.py` cell `retry_double_exec` (exact bytes: `cells.json`)
- **Lane origin.** `ev_r12_X_run.sh` + `FINDING_r12_X.md`
- **Evidence.** `ev_r12_X_ev_afdc_post.txt`, `ev_r12_X_ev_afdc_execfail.txt`
- **Shape driven.** upstream executes then dies; the retry executes the same command again.
- **Verified 2026-11-18 (PASS).** control 200, upstream saw status=HTTP/1.1 200 OK executions=2 flaky=['GET //exec ?cmd=id HTTP/1.1'] healthy=['GET //exec ?cmd=id HTTP/1.1'].

## Verification

Driven from `rce_matrix/poc`: `timeout 300 python3 row.py <this folder>`; the run's `poc/verification.log` line records the control and the upstream-side effect.

Negatives here: body_replay_desync, 1xx_nesting, pct2f_split, config_quoted_space, multi_hop_chain. Full per-family status: `../SUMMARY.md`.

## Source index

- Inventory: `/home/mouse9911/gits/toksec/temp/rce-sweep2/INVENTORY.md`
- Lane docs: `/home/mouse9911/gits/toksec/temp/rce-sweep2/FINDING_*.md`
- Build source: `/home/mouse9911/gits/toksec/temp/rce-sweep2/1cfd33433d25__afdc173f.cpp`
