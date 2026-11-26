# PHP-SRC OCT-2026 EXPLOIT LAB — research, exploits, measured results

**CVEs:** CVE-2026-109618 (GHSA-w8hw-w9fx-j79w) and CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp) —
CVSS 9.2, published 2026-10-21, fixed in 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12.
The T3MP3ST exploit engine lives at `src/tools/php-src-oct26.ts`; routes:
`POST /api/exploit/php-oct26/oom`, `/uaf`, `/consumer-window` (private targets only).

## Part 1 — what "this CTF" is (range research)

The T3MP3ST CTF range (`ctf/`) is a docker-compose fleet behind a flag-verified
executor (`ctf/executor/ctf_executor.py`):

| Category | Ports | Notes |
|---|---|---|
| web_exploitation | 8080-8083 | SQLi, XSS, SSRF, SSTI — `CTF_FLAG` env per container |
| binary_exploitation | 9001-9002 | BOF (socat), Format String (socat) |
| cryptography | 9101 | weak RSA — gateway → `rsa-weak:8080` inner server |
| forensics | 9201 | memory analysis |

Hardening tiers exist per challenge (`read_only`, `cap_drop: ALL`,
`no-new-privileges`, `pids_limit`, `mem_limit`). Flags are verified against the
live target — a solve only counts when the flag matches. The two techniques
added to the tool belt on 2026-10-22 (format-string counter write, weak-RSA
factor) came from this range and are wired at `/api/ctf/*` + the CTF page
⚡ TOOL BELT pane.

The PHP targets for this lab are NOT range challenges — they are two lab
containers standing in for "any PHP host on a vulnerable branch":

| Lab | Image | Port | Role |
|---|---|---|---|
| bxlab | php:8.2.34-apache-bookworm | 8399 | 109618 determinism + 109619 producer/consumer + gadget plant |
| php85-lab | php:8.5.11-apache | 8398 | 8.5 consumer window (8.5.12 = fixed; 8.5.11 = vulnerable) |

Both run the single-worker prefork drop-in (`single-worker.conf` in this
directory → `/etc/apache2/conf-enabled/zz-single-worker.conf`) so the 109619
producer and consumer provably hit the SAME worker.

## Part 2 — the vulnerabilities, precisely

### CVE-2026-109618 — rfc1867 input-parsing OOM (deterministic)
One multipart part carrying N minimal header lines (`X:A\r\n`, 5 wire bytes
each) — rfc1867 stores EVERY header (duplicates included) into an array at
~190B PHP-side per line. A single 8.28MB body (under the 8M post_max_size
ceiling) carries 1,656,737 lines → blows the 128M memory_limit DURING input
parsing: `Allowed memory size of 134217728 bytes exhausted in Unknown on line 0`
— before any application code, every round.

### CVE-2026-109619 — stale worker-global state (producer/consumer)
A request that dies mid-operation (the 109618 OOM is the producer) leaves
worker-global error state pointing into freed request memory. Anything that
reads that state BEFORE RINIT on the next request is the consumer:
- an ini deprecation raised from `.htaccess` (pre-RINIT) — CONFIRMED on both
  8.2.34 and 8.5.11: `error_get_last()` carries `file: Unknown, line: 0`;
- the rfc1867 session decode (`PHP_SESSION_UPLOAD_PROGRESS`) — runs pre-RINIT
  too, but class tables are not registered that early.

## Part 3 — measured results (2026-10-22, this session)

| Test | Target | Result |
|---|---|---|
| 109618 determinism (tool, 3 rounds) | 8.2.34 :8399 | **3/3 exhaustion** (prior session: 13/13) |
| 109618 determinism (hand, 6 rounds) | 8.2.34 :8399 | **6/6 exhaustion** |
| 109618 on 8.5.11 | 8398 | **`zend_mm_heap corrupted` + worker abort (SIGABRT)** — memory-SAFETY violation on 8.5, not clean exhaustion (NEW this session) |
| 109619 consumer window (8.5.11) | 8398 | **PROVEN** — pre-RINIT deprecation lands in error_get_last (`file: Unknown, line: 0`) |
| 109619 stale bleed (8.5.11) | 8398 | no marker bleed on stock 8.5.11 — the confirmed vendor chain needs heap-craft |
| 109619 gadget RCE (8.2.34) | 8399 | **blocked** — planted `Gad::__wakeup` (writes pwned.txt) never fired: rfc1867 session decode pre-RINIT cannot resolve user classes (`__PHP_Incomplete_Class` wall) — re-confirmed |

## Part 4 — runbook

```bash
# 8.2.34 lab (bxlab) — Apache is started by hand, container PID1 = sleep infinity
docker start bxlab && docker exec bxlab apachectl start
# 8.5.11 lab (php85-lab)
docker run -d --name php85-lab -p 8398:80 \
  -v K:\coding\t3mp3st-lab\php85\htdocs:/var/www/html \
  -v K:\coding\t3mp3st-lab\php85\single-worker.conf:/etc/apache2/conf-enabled/zz-single-worker.conf \
  php:8.5.11-apache

# the exploits (through the T3MP3ST server on :3333)
curl -s -X POST http://127.0.0.1:3333/api/exploit/php-oct26/oom \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://127.0.0.1:8399/probe.php","rounds":3}'
curl -s -X POST http://127.0.0.1:3333/api/exploit/php-oct26/consumer-window \
  -H 'Content-Type: application/json' \
  -d '{"fatalUrl":"http://127.0.0.1:8398/fatal.php","consumerUrl":"http://127.0.0.1:8398/index.php"}'
```

The bomb is generated deterministically by `buildOomBomb()` — never commit the
8MB artifact.

## Part 5 — honest boundary

- 109618 = deterministic per-request memory exhaustion (DoS primitive), and on
  8.5.11 a heap-corruption abort — memory-UNSAFE, but turning corruption into
  execution needs heap craft this suite does not ship.
- 109619 = the consumer window is real and reproducible; both gadget-RCE paths
  (session-decode gadget, stale-backtrace bleed) stay bounded on stock builds —
  matching the advisory's note that the confirmed chain uses vendor-provided
  heap craft on 8.5 with `fatal_error_backtraces`.
- Only aim these at containers you own. The routes refuse public hosts.
