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

Prefer to bring a key? Set one and skip the connect step:

```bash
export OPENROUTER_API_KEY=...     # or VENICE_API_KEY / ANTHROPIC_API_KEY / OPENAI_API_KEY
export XAI_API_KEY=...            # Grok Build (grok-build-0.1) — xAI's coding model, native tool-calling
```

Slow local agents can be given more room with `T3MP3ST_LOCAL_AGENT_TIMEOUT_MS`
for each CLI call, `T3MP3ST_TASK_TIMEOUT_MS` for mission tasks, and
`T3MP3ST_GENERAL_TIMEOUT_MS` for planning requests. Values are milliseconds.

Or run it **fully offline** on your own model — no key, no cloud. Defaults to Ollama; point it at any OpenAI-compatible server (LM Studio, vLLM, llama.cpp):

```bash
ollama serve && ollama pull llama3                          # or an OpenAI-compatible server
export TEMPEST_LOCAL_BASE_URL=http://localhost:11434/api    # LM Studio: http://localhost:1234/v1
export TEMPEST_LOCAL_MODEL=llama3
npx tempest                                                 # → "Change default provider" → local
```

Tool-calling works on any local model (it's driven over text), so the Arsenal runs even on models without native function-calling.

Check the numbers for yourself:

```bash
npm run verify-claims             # re-derives every headline from committed JSON in bench/
```

Library/SDK usage, the full HTTP API, and MCP setup live in [docs/](docs/).

## What ships today

The framework is an 8-operator kill chain, and this table won't blow smoke about it. **Recon is a live, tool-backed engine** — and the teeth are already real: 90.1% pass@1 on XBEN, 8/10 held-out post-cutoff CVEs pinned to exact file/line/CWE, and a coordinated-disclosure pipeline that's live enough to have drafts held for vendor coordination right now. What's *not* proven is the swarm. Each downstream operator — Exploiter, Infiltrator, Exfiltrator, Ghost — runs the **same real, tool-backed ReAct loop as recon** (real exploit tools, not stubs), but the headline numbers came from a single agent, not the coordinated 8-operator cell, and end-to-end swarm exploitation is unbenchmarked and still unreliable. The engine is real; the swarm is the part still earning its stripes. Loud where we've earned it, blunt about the rest.

| Component | Status | Notes |
|---|---|---|
| Re-derivable measurement (`verify-claims`) | ✅ Stable | every headline recomputes from committed artifacts |
| Recon engine | ✅ Stable | drives nmap / DNS / HTTP / fingerprinting; every finding traces to real tool output |
| Mission engine + War Room + Op Admiral | ✅ Stable | keyless through a connected local agent |
| Arsenal, MCP server, HTTP API | ✅ Stable | 35 built-in tools by default; 83 with the opt-in `T3MP3ST_FULL_ARSENAL` (+48 adapters, with the dangerous post-ex drivers — metasploit, hydra — behind a human-approval gate) — both counts re-derive via `verify-claims`. `security_recon` over MCP |
| Egress-scope containment | ✅ Stable (on by default) | once a mission target is set, built-in networked tools refuse off-scope public hosts — not the target/subdomains, not loopback/private (`SCOPE DENIED`) — a tightened default, not a bare tool runner |
| Coordinated-disclosure pipeline | ✅ Stable | OSV novelty + live PoC + refuter panel + CVSS; drafts only, a human sends |
| White-box source analysis | ⚠️ Experimental | Python-only regex ingest; multi-model decomposition costs more tokens, not fewer |
| DeFi (Damn Vulnerable DeFi) | ⚠️ Experimental | reproduces known exploit classes; not novel discovery |
| Exploiter / Infiltrator / Exfiltrator / Ghost | ⚠️ Experimental | run the real tool-backed ReAct loop (same engine as recon); unproven as a coordinated swarm — single-agent is the benchmarked path, live swarm exploitation still unreliable |
| Advanced modules (cloud, persistence, swarm, cognition) | 🚧 Planned | interface-only in `src/stubs/` |
| Self-improvement loop | 🧪 Research | records lessons + proposals today; feeding them back into planning is roadmap |

Full feature-by-feature breakdown: [FEATURES.md](FEATURES.md).

## Coverage by domain

Where the storm reaches today — and where it's headed. Same discipline as everything else: a domain is ✅ only when there's a receipt behind it.

| Domain | What it covers | Status |
|---|---|---|
| 🕸️ **Web** | apps, APIs, auth flows, OWASP Top 10 | ✅ **Core** — XBEN 90.1% pass@1 |
| 📂 **Code** | white-box source audits, SAST-style vuln hunting | ✅ **Proven (hunt result)** — held-out CVE-Zero: single-agent 8/10 exact file/line/CWE, 10/10 found (7 languages); the repo-ingest *engine* itself is still ⚠️ experimental |
| 🚩 **CTF** | wargames, practice ranges, challenges | ✅ **Proven** — Cybench 23/40 hint-free |
| 🔌 **Network / Infra** | recon, service/stack fingerprinting; lateral + privesc | ✅ recon (live nmap/DNS/HTTP engine) · ⚠️ lateral/privesc experimental |
| 🤖 **Embedded / IoT / OT** | firmware, robotics, ICS/SCADA OSS | ✅ **CVE pipeline live** — coordinated-disclosure drafts held for vendors |
| 📦 **Supply chain** | dependency audits, install-without-confirmation | ⚠️ **Real** — dedicated class; hit a CWE-829 on the held-out set |
| 💰 **Blockchain** | smart contracts, DeFi, Solidity | ⚠️ **Reproduction only** — Damn Vulnerable DeFi, not novel discovery |
| ☁️ **Cloud** | AWS/GCP/Azure misconfig, IAM, serverless | 🚧 **In development** |
| 📱 **Mobile** | Android/iOS app security | 🚧 **In development** |
| 🏢 **Identity / AD** | Kerberos, pass-the-hash, AD attacks | 🚧 **In development** |
| 🔐 **Binary / RE** | overflows, ROP, exploit dev | 🚧 **In development** — needs specialized tooling |

The class/squad architecture means new domains *compose* rather than fork — each is a loadout (specialist classes + arsenal + target adapter + a benchmark). 🚧 domains ship dark until they have a number.

## Benchmarks

Headline results. Each recomputes from the committed JSON with `npm run verify-claims`; full methodology and caveats are in the linked docs.

| Suite | Result | Context |
|---|---|---|
| **XBEN** — XBOW's 104-challenge suite, black-box | **pass@1 mean 90.1%** (Wilson-95 86.2–92.9), floor 91/104 · gpt-5.5 | XBOW self-reports 85% on the same suite; ours re-derives the graded verdict from committed artifacts (raw transcripts stripped for privacy) |
| **XBEN** — white-box (reported separately) | pass@1 98.7%, best-ball 104/104 · gpt-5.5 | never blended with the black-box number |
| **Cybench** — 40-task academic bench, Opus 4.8, no hints | **23/40 (58%) hint-free, single-run pass@1** (`verify-claims`-enforced) | not the raw-score record (Anthropic: 76.5% pass@10); every flag graded against the committed oracle |
| **CVE-Zero** — 10 real post-cutoff (2026) CVEs, **held-out**, 7 languages | **single-agent 8/10 exact file/line/CWE** (verified all-exact, stable) · **10/10 found** (full pack) | **memorization- & fitting-proof**: post-cutoff, and the hardened prompts were never tuned on these; `verify-claims` recomputes it. n=10, directional; the swarm's edge here is recall, not a coordination-beats-solo proof |

**How to read these:**

- Every solved flag is graded against a committed ground-truth oracle — not a self-report — and `verify-claims` recomputes the pass/fail. Raw per-step transcripts are stripped for operator privacy, so you re-check the **graded verdict**, not the raw tool output. Zero fabricated, enforced by an anti-fitting guard that runs on every push.
- Black-box (source withheld) and white-box (source staged) are reported separately and never blended.
- These ran a **single-agent ReAct loop, not the 8-operator swarm.** The swarm is framework architecture; it is not what scored these numbers.
- Results are system-vs-system: this harness driving a strong current model, not an isolated-harness claim.

The number isn't the flex — the **receipt** is. A keyless, open-source harness that hands you the re-run instead of asking you to trust it: clone it, run `npm run verify-claims`, and every verdict above recomputes from its committed oracle in front of you.

Deeper reading: [WALL_FORENSICS](docs/WALL_FORENSICS.md) (per-challenge misses), [CYBENCH](docs/CYBENCH.md), [INTEGRITY_LEDGER](docs/INTEGRITY_LEDGER.md) (contamination audit and every retraction), [OBSIDIVM](docs/OBSIDIVM.md) (our own live web range).

## Documentation

| Doc | Contents |
|---|---|
| [FEATURES.md](FEATURES.md) | feature-by-feature status (`[x]` shipped / `[~]` partial / `[ ]` planned) |
| [SCOPE_AND_AUTHORIZATION](docs/SCOPE_AND_AUTHORIZATION.md) | authority model, scope receipts, evidence and retest rules |
| [VERIFIED_PROVENANCE](docs/VERIFIED_PROVENANCE.md) | how findings become tool-proven instead of model-asserted |
| [TEAM_PREVIEW](docs/TEAM_PREVIEW.md) | first-run path and review script |
| [INSTALL_MATRIX](docs/INSTALL_MATRIX.md) | macOS / Linux readiness table |
| [ARSENAL_ACTIVATION_PLAN](docs/ARSENAL_ACTIVATION_PLAN.md) | optional external-tool setup |
| [CYBENCH](docs/CYBENCH.md) · [WALL_FORENSICS](docs/WALL_FORENSICS.md) · [INTEGRITY_LEDGER](docs/INTEGRITY_LEDGER.md) · [COGNITIVE_ARCHITECTURE](docs/COGNITIVE_ARCHITECTURE.md) | benchmark methodology |
| [RELEASE_CHECKLIST](docs/RELEASE_CHECKLIST.md) | the gates a release must pass |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        T3MP3ST COMMAND                          │
├─────────────────────────────────────────────────────────────────┤
│   MISSION CONTROL  ◄──  TARGET MODEL  ──►  ARSENAL (TOOLS)       │
│                          ▲                                       │
│   AGENT CELL:  RECON · SCANNER · EXPLOITER · INFILTRATOR ·       │
│                EXFILTRATOR · GHOST · COORDINATOR · ANALYST       │
│                          ▲                                       │
│   EVIDENCE VAULT  ·  CREDENTIAL STORE  ·  FINDINGS LEDGER        │
│                          ▲                                       │
│   OPSEC LAYER  ·  COMMS CHANNEL  ·  LLM BACKBONE                 │
└─────────────────────────────────────────────────────────────────┘
```

Operators map to MITRE ATT&CK and Cyber Kill Chain phases (recon is live; later phases are scaffolded):

| Operator | Phase | MITRE | Function |
|---|---|---|---|
| **Recon** | Reconnaissance | TA0043 | OSINT, network discovery, asset enumeration |
| **Scanner** | Discovery | TA0007 | vulnerability scanning, service fingerprinting |
| **Exploiter** | Initial Access | TA0001 | exploitation, payload delivery |
| **Infiltrator** | Lateral Movement | TA0008 | post-exploitation, privilege escalation |
| **Exfiltrator** | Collection / Exfil | TA0009/10 | data extraction, credential harvesting |
| **Ghost** | Persistence | TA0003 | persistence, stealth, cleanup |
| **Coordinator** | Command & Control | TA0011 | mission control, orchestration |
| **Analyst** | Analysis | — | pattern analysis, reporting |

**Providers:** OpenRouter, Venice, Anthropic, OpenAI, or a keyless local agent (Claude Code / Codex / Hermes). Set `OPENROUTER_API_KEY` / `VENICE_API_KEY` / `ANTHROPIC_API_KEY`, or connect an agent in Settings.

**Integrations:** `node dist/mcp-server.js` exposes `security_recon` to MCP-aware agents. `npm run server` starts the HTTP API (`POST /api/mission/start`, `GET /api/mission/status`, and more). Full reference in [docs/](docs/).

## Contributing — join the swarm

Red-teaming shouldn't be a priesthood. Bring an adapter, a prompt pack, a runbook, a new arsenal tool, or a bug report.

**One rule, non-negotiable:** everything here is for **authorized testing only**. Owned, scoped, or consenting targets. Build for defenders, or don't build it here.

1. Fork it, branch it.
2. Open a PR with tests. If you touch a headline number, `npm run verify-claims` has to stay green.

Release process and gates: [RELEASE_CHECKLIST](docs/RELEASE_CHECKLIST.md).

## License

AGPL-3.0. See [LICENSE](LICENSE).

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
