# level-5-a4ba853a82fe

## Scope

This run is a proxying build. Every positive below executes on the **upstream** host - the proxy forwards, the backend runs `sh -c`. Cells not listed here are negatives and `ROW.md` carries the full matrix.

**Classification.** A cell is positive only when the harness drives real bytes at the build and the control peer observes the effect upstream: an executed request line, a replay the peer accepted as its own request, an inner response after a 1xx, or a victim served from cache with no fetch. `SUMMARY.md` is generated from this file.

**Rules honored.** Everything runs under `timeout`; a benign control precedes every payload on a fresh proxy and peer; a cell only counts on the upstream-side effect.

## Positive cells

### request_line_split

- **Severity.** high (one unauthenticated request executes on the upstream host).
- **Mechanism.** one client request whose target carries an encoded CRLF; the proxy re-emits it undecoded and the upstream parses a second, executing request line.
- **Source.** `ev_r16_A_work/src_a4ba853a.cpp:77` (raw target into the upstream line)
- **PoC.** `rce_matrix/poc/row.py` cell `request_line_split` (exact bytes: `cells.json`)
- **Lane origin.** `ev_r16_F_run.py` + `FINDING_r16_F.md`
- **Evidence.** `ev_r16_F_a4ba853a_clientstream.txt`
- **Shape driven.** GET with %0d%0a in the query; upstream receives a second, 4-token request.
- **Verified 2026-11-18 (PASS).** control 200, upstream saw ['GET /x?%0d%0aGET%20/exec%3fcmd=id%0d%0aHost:%20u%0d%0a%20HTTP/1.1 HTTP/1.1'].

### cache_exec_poison

- **Severity.** critical (victim gets the executed body with no request of its own).
- **Mechanism.** an attacker request seeds the cache with the executed response; an identical victim request is then served from cache with zero upstream fetches.
- **Source.** `ev_r16_A_work/src_a4ba853a.cpp:70` (`cachebase`), `:72` (`cachelookup`, exact then `*`), `:73` (`maybe_cache`)
- **PoC.** `rce_matrix/poc/row.py` cell `cache_exec_poison` (exact bytes: `cells.json`)
- **Lane origin.** `ev_r16_F_run.py` + `FINDING_r16_F.md`
- **Evidence.** `ev_r16_F_a4ba853a_upstream.hex`, `ev_r16_F_a4ba853a_vary_clientstream.txt`
- **Shape driven.** seed %2f-split exec, then a victim with a different Accept-Encoding hits the entry.
- **Verified 2026-11-18 (PASS).** control 200, upstream saw ['GET /%2fexec%20?cmd=id HTTP/1.1'].

## Verification

Driven from `rce_matrix/poc`: `timeout 300 python3 row.py <this folder>`; the run's `poc/verification.log` line records the control and the upstream-side effect.

Negatives here: body_replay_desync, 1xx_nesting, pct2f_split, config_quoted_space, multi_hop_chain, retry_double_exec. Full per-family status: `../SUMMARY.md`.

## Source index

- Inventory: `/home/mouse9911/gits/toksec/temp/rce-sweep2/INVENTORY.md`
- Lane docs: `/home/mouse9911/gits/toksec/temp/rce-sweep2/FINDING_*.md`
- Build source: `/home/mouse9911/gits/toksec/temp/rce-sweep2/ev_r16_A_work/src_a4ba853a.cpp`
