# stage-05__cpp__20261116T022714Z__1cfd33433d25__6baf167b

## Scope

This run is a proxying build. Every positive below executes on the **upstream** host - the proxy forwards, the backend runs `sh -c`. Cells not listed here are negatives and `ROW.md` carries the full matrix.

**Classification.** A cell is positive only when the harness drives real bytes at the build and the control peer observes the effect upstream: an executed request line, a replay the peer accepted as its own request, an inner response after a 1xx, or a victim served from cache with no fetch. `SUMMARY.md` is generated from this file.

**Rules honored.** Everything runs under `timeout`; a benign control precedes every payload on a fresh proxy and peer; a cell only counts on the upstream-side effect.

## Positive cells

### request_line_split

- **Severity.** high (one unauthenticated request executes on the upstream host).
- **Mechanism.** one client request whose target carries an encoded CRLF; the proxy re-emits it undecoded and the upstream parses a second, executing request line.
- **Source.** `6baf167b:62` (`decodepath`) and `:97` (`target="/"+path.substr(...)+query`)
- **PoC.** `rce_matrix/poc/row.py` cell `request_line_split` (exact bytes: `cells.json`)
- **Lane origin.** `poc_r15_E_chain.py` + `FINDING_r15_E.md`
- **Evidence.** `ev_r15_E_chain_attack_req.hex`
- **Shape driven.** GET with %0d%0a in the query; upstream receives a second, 4-token request.
- **Verified 2026-11-18 (PASS).** control 200, upstream saw ['GET //x?a%0d%0aGET%20/exec%3fcmd=id%0d%0aHost:%20u%0d%0a%20HTTP/1.1 HTTP/1.1'].

### cache_exec_poison

- **Severity.** critical (victim gets the executed body with no request of its own).
- **Mechanism.** an attacker request seeds the cache with the executed response; an identical victim request is then served from cache with zero upstream fetches.
- **Source.** `6baf167b:88` (`cachekey` = host+target+`"\n"`+AE), `:89/:90` (`cached`/`storecache`)
- **PoC.** `rce_matrix/poc/row.py` cell `cache_exec_poison` (exact bytes: `cells.json`)
- **Lane origin.** `poc_r15_E_chain.py` + `FINDING_r15_E.md`
- **Evidence.** `ev_r15_E_k3b_victim_client_stream.hex`
- **Shape driven.** seed %2f-split exec, then a victim with a different Accept-Encoding hits the entry.
- **Verified 2026-11-18 (PASS).** control 200, upstream saw ['GET //exec ?cmd=id HTTP/1.1'].

### 1xx_nesting

- **Severity.** high (100 -> 502/100 then the body executes upstream).
- **Mechanism.** upstream emits `100 Continue`; the proxy turns it into a client-visible 502/100 and the real response follows as a second head or as the body.
- **Source.** `6baf167b:97` (`if(status<200||!parsefields(...))return false`) -> 502
- **PoC.** `rce_matrix/poc/row.py` cell `1xx_nesting` (exact bytes: `cells.json`)
- **Lane origin.** `ev_r11_R_exp100.py` + `FINDING_r11_R.md`
- **Evidence.** `ev_r11_R_6baf.iso.txt`
- **Shape driven.** Expect + CL:0 POST: the interim 100 aborts the exchange, the body replays and executes.
- **Verified 2026-11-18 (PASS).** control 200, upstream saw ['POST //x HTTP/1.1', 'GET //exec?cmd=id HTTP/1.1', 'GET //exec?cmd=id HTTP/1.1'].

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

Negatives here: body_replay_desync, pct2f_split, config_quoted_space, retry_double_exec. Full per-family status: `../SUMMARY.md`.

## Source index

- Inventory: `/home/mouse9911/gits/toksec/temp/rce-sweep2/INVENTORY.md`
- Lane docs: `/home/mouse9911/gits/toksec/temp/rce-sweep2/FINDING_*.md`
- Build source: `/home/mouse9911/gits/toksec/temp/rce-sweep2/1cfd33433d25__6baf167b.cpp`
