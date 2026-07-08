# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

---

## Reporting a Vulnerability

Report security vulnerabilities **privately** via the repository's **GitHub Security Advisories** — click "Report a vulnerability" under the **Security** tab. This keeps the report confidential until a fix ships.

**Do not** open a public GitHub issue for a security problem.

Target response times:
- Acknowledgement: within **3 business days**
- Remediation plan: within **30 days** of a confirmed report

---

## Authorized Use Only

T3MP3ST is a security testing framework designed for **authorized penetration testing and red team operations only**. Before using this tool:

- Obtain explicit written authorization from the system owner
- Define clear scope and rules of engagement
- Ensure compliance with applicable laws and regulations
- Document all testing activities

See [docs/SCOPE_AND_AUTHORIZATION.md](docs/SCOPE_AND_AUTHORIZATION.md) for the working model used by the API and UI: human intent, scope receipts, tool gates, evidence, findings, retests, and accepted memory.

---

## Built-in Security Controls

The following controls are implemented in the production codebase. This is a factual record of what the code does, not aspirational.

### Network / API Layer (`src/server.ts`)

| Control | Implementation |
|---|---|
| Security headers | `helmet()` applied before all routes |
| CORS origin allowlist | Scoped to `http://127.0.0.1:PORT`, `http://localhost:PORT`, and `T3MP3ST_CORS_ORIGIN` if set. Requests from other origins are rejected. |
| `null` origin rejection | `origin === 'null'` is explicitly rejected — blocks `file://` pages and sandboxed iframes that would otherwise bypass origin checks |
| DNS rebinding protection | All `/api/*` routes check the `Host` header against an allowlist (`localhost:PORT`, `127.0.0.1:PORT`, `[::1]:PORT`). Mismatches return HTTP 421. |
| Optional Bearer token auth | Set `T3MP3ST_API_TOKEN` to require `Authorization: Bearer <token>` on all `/api/*` routes. Public paths (`/api/health`, `/api/preflight`, `/api/status`) are exempt. |
| Body size limit | `express.json({ limit: '10mb' })` |
| Secret redaction | All SSE event payloads pass through `redactSecrets()` before broadcast — strips API keys, passwords, JWTs, URIs with credentials |

### MCP Server (`src/mcp-server.ts`)

| Control | Implementation |
|---|---|
| Target validation | Strict regex `^[a-zA-Z0-9][a-zA-Z0-9._:-]*$` — rejects any target containing shell metacharacters |
| Binary allowlist | Only `nmap` and `dig` may be invoked (`ALLOWED_BINARIES` map) |
| No shell | Uses `execFile` (not `exec`) — arguments are passed as an array, never interpolated into a shell string |

### Outbound Webhooks (`src/webhooks.ts`)

| Control | Implementation |
|---|---|
| URL validation | Registered URLs must match `^https?://` |
| HMAC-SHA256 signing | When a `secret` is set, each delivery includes `X-Tempest-Signature: sha256=<hmac>`. Consumers should verify this before processing. |
| Retry cap | Maximum 3 attempts per delivery (delays: 1s → 5s → 30s). Failure increments `failCount`; delivery is not retried indefinitely. |
| Timeout | Each HTTP attempt times out at 10 seconds (`AbortSignal.timeout(10_000)`) |

### Deep Scanner (`src/recon/deep-scanner.ts`)

| Control | Implementation |
|---|---|
| Path traversal prevention | All scan directories are checked for `..` sequences before use |
| Scan root constraint | Set `T3MP3ST_SCAN_ROOT` to restrict the scanner to a specific directory tree. Paths outside the root are rejected at startup. |

### Container Architecture

| Control | Implementation |
|---|---|
| GPU isolation | GPU access is confined within the container; not accessible from the host network |
| No host-side builds | All compilation happens inside the Docker build stage; the host never runs `npm install` or `pip install` |

### Local Agent Connectors (`src/agent/local-agents.ts`)

| Control | Implementation |
|---|---|
| Credential non-exposure | Auth detection checks only for the **presence** of credential files — contents are never read, logged, or transmitted |
| Provider key stripping | `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OPENROUTER_API_KEY` (and others) are stripped from the child process environment before spawning. The CLI uses its own native auth, never T3MP3ST's keys. |

---

## Payload Database

The framework includes payload databases for testing purposes:

- SQL injection (union, blind, error-based, stacked queries)
- XSS (HTML, attribute, JavaScript, polyglot)
- SSTI (Jinja2, Twig, ERB)
- LFI, SSRF, command injection, XXE

These exist for authorized security testing, security research, educational use, and CTF competitions. They are never sent to any external service — they are used by the operator tools against authorized targets only.

---

## Real Functionality

All core arsenal tools perform **real operations**, not simulations. Only use them against systems you have explicit authorization to test.

| Tool | Implementation |
|------|----------------|
| Port scanning | Real TCP connect scans via Node.js `net` module |
| DNS lookup | Real DNS resolution via Node.js `dns` module |
| Subdomain enumeration | Real DNS lookups for each subdomain candidate |
| Directory bruteforce | Real HTTP requests to discover paths |
| Technology detection | Real HTTP fingerprinting of headers/content |
| XSS scanning | Real payload injection with reflection detection |
| SQL injection scanning | Real error-based and boolean-based detection |
| SSL/TLS scanning | Real TLS connections via Node.js `tls` module |
| WHOIS lookup | Real WHOIS queries via TCP port 43 |
| Password spraying | Real HTTP POST requests to login endpoints |
| Hash cracking | Real dictionary attacks using `crypto` module |
| Network recon (MCP) | Real `nmap` and `dig` execution via allowlisted `execFile` |

---

## Data Handling

When using T3MP3ST:

- Do not exfiltrate real sensitive data
- Use test/dummy data for demonstrations
- Properly dispose of any captured credentials after testing
- Follow applicable data protection regulations (GDPR, CCPA, etc.)

Mission state (findings, evidence, credentials) is persisted to `/data/missions/` in the container volume. Protect this volume accordingly.

---

## Security Best Practices

1. **Run in isolated environments** — use Docker on an isolated network
2. **Set `T3MP3ST_API_TOKEN`** — enable bearer auth if the API is accessible beyond loopback
3. **Sign webhooks** — always set a `secret` when registering webhooks; verify `X-Tempest-Signature` on the receiving end
4. **Restrict the scan root** — set `T3MP3ST_SCAN_ROOT` before using the deep-scanner
5. **Scope adherence** — the approval gate exists for a reason; never approve actions outside the authorized scope
6. **Authorization documentation** — keep copies of all signed rules of engagement

---

## Compliance

T3MP3ST usage should comply with:

- Computer Fraud and Abuse Act (CFAA)
- General Data Protection Regulation (GDPR)
- PCI DSS (for payment card environments)
- HIPAA (for healthcare environments)
- Local and international cybersecurity laws
