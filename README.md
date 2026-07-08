# T3MP3ST (TEMPEST)
## Tactical Execution Multi-agent Platform for Elite Security Testing

```
 ▄▄▄█████▓▓█████  ███▄ ▄███▓ ██▓███  ▓█████   ██████ ▄▄▄█████▓
 ▓  ██▒ ▓▒▓█   ▀ ▓██▒▀█▀ ██▒▓██░  ██▒▓█   ▀ ▒██    ▒ ▓  ██▒ ▓▒
 ▒ ▓██░ ▒░▒███   ▓██    ▓██░▓██░ ██▓▒▒███   ░ ▓██▄   ▒ ▓██░ ▒░
 ░ ▓██▓ ░ ▒▓█  ▄ ▒██    ▒██ ▒██▄█▓▒ ▒▒▓█  ▄   ▒   ██▒░ ▓██▓ ░
   ▒██▒ ░ ░▒████▒▒██▒   ░██▒▒██▒ ░  ░░▒████▒▒██████▒▒  ▒██▒ ░
   ▒ ░░   ░░ ▒░ ░░ ▒░   ░  ░▒▓▒░ ░  ░░░ ▒░ ░▒ ▒▓▒ ▒ ░  ▒ ░░
     ░     ░ ░  ░░  ░      ░░▒ ░      ░ ░  ░░ ░▒  ░ ░    ░
   ░         ░   ░      ░   ░░          ░   ░  ░  ░    ░
             ░  ░       ░               ░  ░      ░

   T3MP3ST - Multi-Agent Red Team / Penetration Testing Framework
```

## The claim — verify it yourself ([`docs/THE_CLAIM.md`](docs/THE_CLAIM.md))

> **An open-source offensive-security harness built on a re-derivable measurement discipline:**
> contamination-audited, hint-free, live-exploit-verified, fully reproducible.

| Headline | Result | Comparison |
|---|---|---|
| **XBEN** (XBOW's *own* 104-suite) | **best-ball 98/104 (94.2%) black-box · 104/104 white-box** (pass@3 union of 3 gpt-5.5 sweeps, incl. 2 repaired targets) · best single sweep 96/104 bb · 103/104 wb · pass@1 mean 90.1% bb [86.2%, 92.9%] · 98.7% wb [96.8%, 99.5%] · pass@1 floor 91/104 bb · 102/104 wb · 0 canary, every flag live-exploit-verified | hint-free, **source-withheld black-box** (real external-attacker) |
| **Cybench** (real 40-task) | **23/40 pass@1 · 25/40 best-ball** (opus-4.8, hint-free, sandbox-jailed) · 21/40 on the full corpus incl. infra-rot · 0 fabrications, live-exploit flags | only contamination-audited public run we know of |
| **Capability** | 83-tool arsenal (48 adapters + 35 built-ins) · 8-operator kill-chain *(framework capability — the benchmarks above ran a single-agent ReAct loop, not the swarm)* · MCP · OPSEC | broadest implemented open-source kill-chain |

```bash
npm run verify-claims   # reproducibility check: re-derives the numbers from committed artifacts.
                        # NOT a third-party audit — re-run the harness from scratch to verify independently.
```

*Most self-reported scores ship no artifacts at all; ours re-derive from committed JSON.*

> **Read the XBEN numbers honestly:** the headline is **pass@1 mean 90.1% black-box [86.2%, 92.9%] (n=104×3, all gpt-5.5)**, reported alongside distinct metrics — **best-ball 98/104 (94.2%)** (pass@3 union of 3 gpt-5.5 sweeps; a challenge counts if *any* of the three sweeps lands it, incl. **two faithfully-repaired broken targets** — 042 SSH-port publish, 056 Django `settings`-context, documented in [`docs/WALL_FORENSICS.md`](docs/WALL_FORENSICS.md)), **best single sweep 96/104**, and the conservative **pass@1 floor (worst single sweep) 91/104 black-box · 102/104 white-box**. **Black-box = source withheld at runtime (real external-attacker); white-box = source staged.** Floor, mean, best-single, and best-ball are reported separately — never blended — and `npm run verify-claims` re-derives them from committed artifacts. The black-box misses at the floor are forensically diagnosed in `docs/WALL_FORENSICS.md` (multi-stage chaining + desync byte-precision walls, not noise); we retired the prior "100/104 best-across-runs" framing for this clean, labeled metric split.

---

## Docker Quickstart

Already have Docker? Four commands:

```bash
git clone https://github.com/elder-plinius/T3MP3ST
cd T3MP3ST
cp .env.example .env
# Open .env and set at least one API key (OPENROUTER_API_KEY recommended — free tier at openrouter.ai/keys)
docker compose build && docker compose up -d
```

Then open **https://localhost:8443** in your browser (accept the self-signed cert warning). A login page will appear.

**Getting the password:**

```bash
make logs
# or: docker compose logs | grep -A5 "WEB ACCESS"
```

The startup banner prints credentials every time the container starts:

```
══════════════════════════════════════════════════
  T3MP3ST — WEB ACCESS
  URL:      https://localhost:8443
  Username: admin
  Password: <32-char random>
══════════════════════════════════════════════════
```

The password is random by default and regenerates on each restart. To set a fixed one:

```bash
# In your .env file:
TEMPEST_PASSWORD=your-chosen-password
```

**Changing the port** (default is 8443):

```bash
# In your .env file:
TEMPEST_HTTPS_PORT=443   # use standard HTTPS port (may need sudo/root for <1024)
TEMPEST_HTTPS_PORT=9443  # or any other port you prefer
```

> **No API key required** if you connect a local agent (Claude Code, Codex, or Hermes) you're already logged into — T3MP3ST drives it directly, never reading its token. Configure agents under **Settings → Local Agents** after logging in.

**Day-to-day:**

```bash
make logs       # tail container logs (also shows the login password)
make rebuild    # rebuild image + restart after code changes
make shell      # bash inside the container
make health     # curl health + preflight endpoints
make help       # all available targets
```

---

## Run it — no API key required

Connect a local agent CLI you're already logged into — **Claude Code, Codex, or Hermes** — and t3mp3st runs missions through it with **zero API keys** (the agent uses its own auth; t3mp3st never reads a token). One click in Settings detects + connects them; the **War Room** then shows which agent is driving. Prefer your own OpenRouter/Anthropic key? That path works too.

- **Keyless missions** — `provider: 'local-agent'` routes the whole mission through your connected agent (verified live end-to-end: codex driving a real mission to a finding, no key).
- **War Room command center** — a live **SitRep** (kill-chain pipeline that lights up per stage) + a color-coded **System Events** stream straight from the backend, so you see exactly what the operators are doing.
- **Op Admiral** — give it a directive in plain English; it produces a structured operation plan (codename, targets, OPSEC level, hunt lanes, work orders) before you execute.
- **Scope + fidelity gates** — every active run is watermarked LIVE vs SIMULATION and gated to authorized/loopback targets.

---

## Live benchmarks (2026-05-27 — A/B controlled, honest)

| Bench | Result | vs Public peer |
|---|---|---|
| **CVE-Hunt** — 15 samples (10 published + 5 novel post-cutoff synthetics) | 15/15 detect, F1 **0.79 (t3mp3st) vs 0.49 (raw Claude)** — t3mp3st +0.30 F1, 0 decoy FP | **apex** (no public peer) |
| **OBSIDIVM** — full 14-target live web range + replay | **14/14 grade A · 99.76% · 122/125 findings** | **apex** (range is ours) |
| **OBSIDIVM evolution** — 11 targets × 3 gens with ablation | **98.32% → 99.85%** suite lift; per-tactic attribution | **apex** (loop is ours) |
| **T3MP3ST Hard Bench** — 12 hand-built CTF challenges | 9/12 strict / 10/12 semantic — t3mp3st = direct-claude (tied at LLM ceiling) | n/a |
| **Memorization-resistance** — 5 novel synthetic CVEs (Go/Python/JS/C/Rust) | 5/5 detected (both modes) · N=5, no variance bars | n/a |
| **Real Cybench — FULL 40 corpus** on **Opus 4.8**, true hard mode (no hints) + sandbox JAIL | **21/40 = 52.5% strict** · **21/32 = 65.6% of fair-shot tasks** | honest pass@1, jail-verified |
| ↳ by tier | service **12/18** · standalone **6/13** · LosFuzzys (recovered) **3/9** | 3 infra-rot + 5 LosFuzzys-service need live-target wiring |
| **Sandbox-jail integrity** — caught our agent `find /`-ing host answer keys; jailed it, re-ran clean | **19 escape attempts blocked / 0 succeeded** → all 21 solves clean-by-construction | jail-verified |
| **40-task coverage recovered** — 9 GlacierCTF challenges deleted upstream, recovered locally | full-corpus **18/40 → 21/40** (+3 clean solves) | completeness |
| Smokes (doctor + arsenal + exploit-chain + field + prompt + vitest) | **339/339 green** | — |

> *OBSIDIVM (rows above) is **our own** live web range — suite grades blend live-exploit probes with transcript-graded findings (per-finding provenance in [docs/RESULTS.md](docs/RESULTS.md)). XBEN and Cybench are independent public suites.*

See [docs/APEX.md](docs/APEX.md), [docs/RESULTS.md](docs/RESULTS.md), [docs/CYBENCH.md](docs/CYBENCH.md), [docs/OBSIDIVM.md](docs/OBSIDIVM.md), [docs/INTEGRITY_LEDGER.md](docs/INTEGRITY_LEDGER.md), [docs/COGNITIVE_ARCHITECTURE.md](docs/COGNITIVE_ARCHITECTURE.md).

---

## Stack Architecture

T3MP3ST ships as a single Docker container:

```
╔══════════════════════════════════════════════════════════════════╗
║                    tempest-stack:latest                          ║
║                                                                  ║
║  supervisord                                                     ║
║  └── t3mp3st           Node.js          0.0.0.0:3333  (exposed) ║
║                                                                  ║
║  /data/missions ← volume (mission ledger, evidence, findings)    ║
║  /data/uploads  ← bind  (scan-target binaries / archives)        ║
╚══════════════════════════════════════════════════════════════════╝
```

| Service | Role |
|---|---|
| **T3MP3ST** | REST API + SSE event bus + multi-agent mission orchestration |

Optional sidecar containers (cloud security tools, binary analysis, dynamic sandbox) are defined in `docker-compose.yml` and start independently — run `scripts/generate-certs.sh` first to wire them up.

For the full architecture with diagrams, data-flow maps, and the complete route table: **[docs/STACK_ARCHITECTURE.md](docs/STACK_ARCHITECTURE.md)**

---

## Full Quick Start (guided)

**Everything builds and runs inside Docker. Do not run `npm install` on the host.**

```bash
./quickstart.sh
```

The script checks for Docker, copies `.env.example` → `.env`, prompts for an API key (or skips if already set), builds the image, starts the stack, and runs the smoke suite. When it's done, T3MP3ST is live at **https://localhost:8443**.

**All day-to-day operations through `make`:**

```bash
make build          # rebuild after code changes
make build-nocache  # full rebuild, no layer cache
make up             # start the stack
make down           # stop
make restart        # restart without rebuild
make rebuild        # build + up in one step
make logs           # tail all container logs
make t3mp3st-logs   # tail T3MP3ST service logs only
make status         # show container + supervisor process status
make health         # curl health + preflight endpoints
make test           # re-run smoke suite inside the container
make shell          # bash shell inside the container
make clean          # stop + remove volumes (destroys mission data)
make help           # all targets with descriptions
```

**Without Docker (development only — no HTTPS, no login gate):**

```bash
cd T3MP3ST
npm install
npm run doctor      # check tool availability
npm run server      # start API server on http://localhost:3333 (auth bypassed, dev only)
```

> In dev mode T3MP3ST is reachable directly at `http://localhost:3333` without authentication. The login page and session routes are registered but not enforced — enforcement is done by Nginx, which only runs inside Docker. For production use, always run through Docker.

High-signal docs:
- [Operations Guide](docs/OPERATIONS.md): how to use every feature from the command line
- [Stack Architecture](docs/STACK_ARCHITECTURE.md): bird's-eye view, detailed diagrams, full API route table
- [Scope and Authorization](docs/SCOPE_AND_AUTHORIZATION.md): receipts, evidence, findings, retests, memory rules
- [Verified Provenance](docs/VERIFIED_PROVENANCE.md): how findings become tool-proven instead of model-asserted
- [Team Preview](docs/TEAM_PREVIEW.md): first-run path, review script, feedback prompts
- [Arsenal Activation Plan](docs/ARSENAL_ACTIVATION_PLAN.md): local workstation setup for wired tools
- [Install Matrix](docs/INSTALL_MATRIX.md): macOS/Linux readiness table
- [Contributing](CONTRIBUTING.md): how to add adapters, prompt packs, runbooks, smoke checks

Local-safe preview drills (run inside container or with `npm run` after `npm install`):

```bash
npm run field:drill
npm run exploit:smoke
npm run arsenal:smoke
npm run prompt:audit
```

---

## Agent Archetypes (Operators)

| Operator | Phase | MITRE Tactics | Primary Function |
|----------|-------|---------------|------------------|
| **RECON** | Reconnaissance | TA0043 | OSINT, network discovery, asset enumeration |
| **SCANNER** | Discovery | TA0007 | Vulnerability scanning, service fingerprinting |
| **EXPLOITER** | Initial Access | TA0001 | Vulnerability exploitation, payload delivery |
| **INFILTRATOR** | Lateral Movement | TA0008 | Post-exploitation, privilege escalation |
| **EXFILTRATOR** | Collection/Exfil | TA0009/TA0010 | Data extraction, credential harvesting |
| **GHOST** | Persistence | TA0003 | Persistence mechanisms, stealth, cleanup |
| **COORDINATOR** | Command & Control | TA0011 | Mission control, agent orchestration |
| **ANALYST** | Analysis | — | Pattern analysis, reporting, recommendations |

---

## Kill Chain Integration

```
[1] RECON ──► [2] WEAPON ──► [3] DELIVER ──► [4] EXPLOIT
                                                    │
                                    ┌───────────────┤
                                    ▼               ▼
[5] INSTALL ◄── [6] C2 ──► [7] ACTIONS ON OBJECTIVES
      │            │               │
   GHOST    COORDINATOR      EXFILTRATOR
                    │
              INFILTRATOR (lateral movement)
```

---

## LLM Providers

| Provider | Key env var | Notes |
|---|---|---|
| `openrouter` | `OPENROUTER_API_KEY` | Recommended — access to 50+ models |
| `anthropic` | `ANTHROPIC_API_KEY` | Direct Claude API |
| `openai` | `OPENAI_API_KEY` | GPT models |
| `bedrock` | `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` + `AWS_REGION` | Claude via AWS |
| `local` | — | Ollama or compatible local endpoint |
| `local-agent` | — | Drive Claude Code / Codex / Hermes as the LLM backend, keyless |
| `mock` | — | Stub adapter for testing |

All providers participate in the same fallback chain — if the primary fails, T3MP3ST cascades to the next configured provider automatically.

---

## MCP Integration

T3MP3ST operates in **both MCP roles** simultaneously.

### As an MCP Server (external LLMs call T3MP3ST)

Register T3MP3ST in your Claude Desktop / Claude Code config:

```json
{
  "mcpServers": {
    "t3mp3st": {
      "command": "node",
      "args": ["/path/to/T3MP3ST/dist/mcp-server.js"]
    }
  }
}
```

Build first: `make build` (or `npm run build` for host dev).

Available MCP tools:

| Tool | Input | Description |
|------|-------|-------------|
| `security_recon` | `{ target, scan_type? }` | nmap + dig recon (target validated, allowlisted binaries only) |

### As an MCP Client (T3MP3ST connects to external MCP servers)

```bash
# Connect to any MCP server (stdio or SSE transport)
curl -X POST https://localhost:8443/api/mcp/servers/connect \
  -H "Content-Type: application/json" \
  -d '{
    "id": "filesystem",
    "label": "Filesystem Server",
    "transport": "stdio",
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp/sandbox"]
  }'

# List all discovered remote tools
curl https://localhost:8443/api/mcp/tools

# Call a remote tool
curl -X POST https://localhost:8443/api/mcp/tools/call \
  -H "Content-Type: application/json" \
  -d '{"serverId": "filesystem", "toolName": "read_file", "args": {"path": "/tmp/sandbox/file.txt"}}'
```

---

## Outbound Webhooks

T3MP3ST fires signed POST requests to registered URLs on every internal event.

```bash
# Register a webhook
curl -X POST https://localhost:8443/api/webhooks \
  -H "Content-Type: application/json" \
  -d '{"url": "https://your-endpoint.com/hook", "events": ["finding.*", "mission:*"], "secret": "your-secret"}'

# Pre-load at startup
T3MP3ST_WEBHOOK_URL=https://your-endpoint.com/hook
```

Delivery headers: `X-Tempest-Event`, `X-Tempest-Delivery`, `X-Tempest-Signature: sha256=<hmac>`.
Retry: 3 attempts at 1s → 5s → 30s backoff.

---

## Automation Rules

Event-driven rules execute actions automatically when internal events match.

```bash
# Auto-dispatch Claude Code whenever a critical finding is created
curl -X POST https://localhost:8443/api/automation/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Escalate critical findings",
    "trigger": {
      "event": "finding.created",
      "condition": "payload.severity === '\''critical'\''"
    },
    "action": {
      "type": "dispatch-agent",
      "agentId": "claude",
      "promptTemplate": "Investigate and verify this critical finding: {{payload.title}}"
    }
  }'
```

Action types: `log`, `fire-webhook`, `dispatch-agent`, `spawn-operator`.

---

## Multi-turn Agent Sessions

Keep conversation context across multiple dispatch calls to a local agent.

```bash
# Create a session
SESSION=$(curl -s -X POST https://localhost:8443/api/agents/local/sessions \
  -H "Content-Type: application/json" \
  -d '{"agentId": "claude"}' | jq -r .id)

# First turn
curl -X POST https://localhost:8443/api/agents/local/dispatch \
  -H "Content-Type: application/json" \
  -d "{\"id\": \"claude\", \"prompt\": \"Analyze this target: 10.0.0.1\", \"sessionId\": \"$SESSION\"}"

# Second turn — agent sees the full prior exchange
curl -X POST https://localhost:8443/api/agents/local/dispatch \
  -H "Content-Type: application/json" \
  -d "{\"id\": \"claude\", \"prompt\": \"Now enumerate open ports on it\", \"sessionId\": \"$SESSION\"}"
```

Omit `sessionId` for the original stateless one-shot behaviour.

---

## Key API Endpoints

This is a representative subset. The complete table (100+ routes) is in [docs/STACK_ARCHITECTURE.md](docs/STACK_ARCHITECTURE.md).

```
── HEALTH ────────────────────────────────────────────────────────
GET  /health                          server + LLM status
GET  /api/events                      SSE real-time event stream
GET  /api/preflight                   tool + environment check

── MISSION ───────────────────────────────────────────────────────
POST /api/general/plan                Op Admiral: plan from a directive
POST /api/general/execute             Op Admiral: execute active plan
POST /api/mission/start               start mission with real operators
GET  /api/mission/status              live operator states
GET  /api/mission/findings            all findings

── OPERATORS ─────────────────────────────────────────────────────
POST /api/operators/spawn             spawn operator archetype
POST /api/operators/:id/task          dispatch task
GET  /api/operators/list              list all operators

── LOCAL AGENTS (keyless) ────────────────────────────────────────
GET  /api/agents/local/detect         detect installed+authed agents
POST /api/agents/local/connect        connect agent(s)
POST /api/agents/local/dispatch       dispatch prompt (+ sessionId for multi-turn)

── WEBHOOKS ──────────────────────────────────────────────────────
GET  /api/webhooks                    list registered webhooks
POST /api/webhooks                    register webhook
POST /api/webhooks/:id/test           send test ping

── MCP CLIENT ────────────────────────────────────────────────────
POST /api/mcp/servers/connect         connect to external MCP server
GET  /api/mcp/tools                   list remote tools
POST /api/mcp/tools/call              invoke remote tool

── AUTOMATION ────────────────────────────────────────────────────
GET  /api/automation/rules            list rules
POST /api/automation/rules            create rule
```

---

## Environment Variables

```bash
# ── Web access / HTTPS proxy ─────────────────────────────────────
TEMPEST_HTTPS_PORT=8443          # host port mapped to Nginx :8443 inside container
                                 # change to 443 for standard HTTPS (may need root)
TEMPEST_PASSWORD=                # login password; random 32-char if blank (see logs)

# ── T3MP3ST server ──────────────────────────────────────────────
T3MP3ST_PORT=3333                # internal port (not exposed to host; Nginx proxies to it)
T3MP3ST_API_TOKEN=               # if set, Bearer auth required on all /api/* routes
T3MP3ST_CORS_ORIGIN=             # additional allowed CORS origin
T3MP3ST_WEBHOOK_URL=             # comma-separated URLs pre-loaded as catch-all webhooks

# ── LLM providers (at least one, or connect a local agent) ───────
OPENROUTER_API_KEY=              # recommended — openrouter.ai/keys
ANTHROPIC_API_KEY=
OPENAI_API_KEY=

# ── LLM routing ──────────────────────────────────────────────────
LLM_PROVIDER=openrouter          # openrouter | anthropic | openai | bedrock | local
LLM_MODEL=                       # e.g. anthropic/claude-opus-4-8 (openrouter format)

# ── AWS Bedrock (optional) ───────────────────────────────────────
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_REGION=

# ── Local agents ─────────────────────────────────────────────────
HERMES_YOLO=0                    # set to 1 to enable --yolo on Hermes
```

---

## Project Structure

```
T3MP3ST/
├── src/
│   ├── server.ts              REST API server (100+ routes, SSE event bus)
│   ├── mcp-server.ts          MCP server (exposes security_recon via stdio)
│   ├── mcp-client.ts          MCP client (connects to external MCP servers)
│   ├── webhooks.ts            Outbound webhooks (HMAC-signed, retry)
│   ├── automation.ts          Event-driven automation rules engine
│   ├── index.ts               TempestCommand orchestrator + exports
│   ├── config/                Configuration management
│   ├── types/                 TypeScript type definitions
│   ├── llm/                   LLM backbone (multi-provider + fallback chain)
│   ├── agent/
│   │   ├── local-agents.ts    Claude Code / Codex / Hermes connectors
│   │   └── session-store.ts   Multi-turn conversation history
│   ├── operators/             Operator archetypes + system prompts
│   ├── arsenal/               83-tool arsenal (adapters + catalog)
│   ├── resources/             Prompt packs, runbooks, workflow presets
│   ├── integrations/          Third-party platform integrations
│   ├── recon/
│   │   ├── code-ingest.ts     Code ingestion pipeline
│   │   └── deep-scanner.ts    Deep file scanner
│   ├── mission/               Mission orchestration
│   ├── prompts/               Elite operator prompt library
│   └── general/               Op Admiral (autonomous operation planner)
├── scripts/
│   ├── test-container.sh      Container smoke test
│   ├── docker-entrypoint.sh   Container startup script
│   ├── generate-certs.sh      TLS cert + token generator for sidecars
│   └── *.mjs / *.sh           Bench and utility scripts
├── docs/
│   ├── STACK_ARCHITECTURE.md  Full architecture + route table + diagrams
│   └── *.md                   Benchmark results, claim docs, operations guide
├── docker/                    Optional sidecar Dockerfiles (cloud, binary, sandbox)
├── Dockerfile                 Multi-stage build: node:20-slim builder + runtime
├── docker-compose.yml         Stack definition: main container + optional sidecars
├── supervisord.conf           Process management (t3mp3st service)
├── Makefile                   All operational targets (build/up/down/logs/shell/…)
├── quickstart.sh              Guided first-run script
├── package.json
└── tsconfig.json
```

---

## Ethical Use

T3MP3ST is designed for **authorized security testing only**:

- Penetration testing engagements with proper authorization
- Red team exercises with signed rules of engagement
- Security research in controlled environments
- CTF competitions and educational contexts

**Never** use this framework for unauthorized access to systems. Every active-capability run is gated behind an authorization receipt — see [docs/SCOPE_AND_AUTHORIZATION.md](docs/SCOPE_AND_AUTHORIZATION.md).

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add tool adapters, prompt packs, runbooks, automation rules, and smoke checks.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
