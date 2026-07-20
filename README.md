# 🌩️ T3MP3ST 🌩️

<!-- ⊰ sharp eye on the raw source. there's a flag for the curious: T3MP3ST{r3c31pt5_n0t_v1b3z} — the one that counts, you earn: run `npm run verify-claims`. LOVE PLINY ⊱ -->

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
```

<div align="center">

**A multi-agent offensive-security framework, built to turn the AI coding agent you already run into a zero-day hunter.**

![scores: re-derivable](https://img.shields.io/badge/scores-re--derivable-brightgreen) &nbsp; ![verify-claims 27/27](https://img.shields.io/badge/verify--claims-27%2F27-brightgreen) &nbsp; ![PRs welcome](https://img.shields.io/badge/PRs-welcome-purple) &nbsp; ![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue)

</div>

**Your AI coding agent is already a hacker — T3MP3ST hands it an arsenal.**

Point it at an authorized target and the kill chain runs itself: **recon → exploit → report**, from a browser War Room or the CLI, driven by the agent you're *already* signed into — Claude Code, Codex, Hermes — or a model you run **fully offline** (Ollama, LM Studio, vLLM). No new API keys, no cloud tenant, no second bill. Your agent is the brain; T3MP3ST is the war machine bolted around it. **Self-hosted storm. Keyless warfare.** ⚡

And it won't ask you to take its word for it. On **XBOW's own 104-challenge suite it scores 90.1% pass@1** — above XBOW's self-reported 85% — alongside hint-free CTF solves and a **cold hunt on real, post-cutoff CVEs the model had never seen**. Every number in this README recomputes from committed data with one command (`npm run verify-claims`). Loud about the mission, honest about the build — the [status table](#what-ships-today) says exactly what's live, what's scaffolding, and what's still roadmap; full receipts in [Benchmarks](#benchmarks).

Three things set it apart:

1. **Reproducible.** Every number in this README recomputes from committed data — `npm run verify-claims` re-derives all of them, 27/27 green. A claim that can't be reproduced doesn't ship. No trust-me numbers, ever.
2. **Keyless.** The AI coding agent already on your machine is the backbone. No API keys, no second bill, no gatekeeper.
3. **Honest about scope.** The [status table](#what-ships-today) marks exactly what's stable, experimental, or roadmap — because red-teaming shouldn't be a priesthood, and it damn sure shouldn't run on vibes.

**Jump to** → [Quick start](#quick-start) · [Usage guide](docs/GETTING_STARTED.md) · [Developer guide](docs/DEVELOPER_GUIDE.md) · [Updating](#updating-from-upstream) · [What it hunts](#what-it-hunts) · [What ships today](#what-ships-today) · [Benchmarks](#benchmarks) · [Architecture](#architecture) · [Docs](#documentation)

## ⚠️ Authorized use only

T3MP3ST is an **offensive** security tool, built for **authorized** testing, research, and education. Point it **only** at systems you own or have **explicit, written permission** to test. Unauthorized access to computers, networks, or data is illegal in most jurisdictions — **you alone are responsible** for how you use this software and for staying inside the law and your rules of engagement. Bring the storm to *your* targets, not someone else's.

T3MP3ST is provided **as-is under the AGPL-3.0 license, with no warranty and no liability** for any damage, loss, or misuse. The authors do not endorse, support, or condone unauthorized activity. Get permission. Stay in scope. Don't be a menace. 🫡

## Why it exists

Offensive security sits behind years of practice and expensive tooling. The bet behind T3MP3ST is that a coordinated agent swarm puts real bug-hunting in reach of people who never got the invite, across web apps, CTFs, smart contracts, source code, and embedded/robotics OSS. That is an ambitious bet, and the sections below are careful to separate what already works from what is still a bet.

## What it hunts

| Domain | What it does | Status |
|---|---|---|
| 🕸️ **Web apps** | Black-box, external-attacker recon → exploit (XBEN suite) | ✅ Stable |
| 🚩 **CTF** | Hint-free, sandbox-jailed solves (Cybench) | ✅ Stable |
| 🤖 **Robotics / OT / embedded** | Coordinated-disclosure pipeline for OSS vuln hunting (OSV + live-PoC + refuter) | ✅ Pipeline stable |
| 📂 **Source code** | White-box repo analysis with blind master-builder decomposition | ✅ Multi-language ingest (web-tree-sitter) |
| 💰 **Smart contracts** | Damn Vulnerable DeFi | ⚠️ reproduction, not novel discovery |
| ☁️ **Cloud (IaC)** | Misconfig-detection benchmark (`cloud:bench`) + opt-in cloud arsenal (aws/az/gcloud + scoutsuite/cloudfox/pmapper; pacu gated) | 🚧 IaC-misconfig scaffolding — live-cloud exploitation not yet benchmarked |
| 📱 **Mobile** | Built-in static analyzer (manifest misconfig + secret/cleartext detection, `mobile:bench`) + opt-in arsenal (mobsfscan/objection/drozer; frida gated) | 🚧 static-detection scaffolding — dynamic exploitation not benchmarked |
| 🔩 **Binary / RE** | Decompiled-output sink detector (unsafe-copy / format-string / cmd-injection / int-overflow, `binary:bench`) + opt-in arsenal (ghidra/radare2/objdump/checksec/strings; gdb gated) | 🚧 static sink-detection scaffolding — solving/pwn not benchmarked |

## Quick start

Fastest path to a running War Room (keyless, ~2 min to set up; mission time depends on the target):

```bash
npm install
npm run server        # War Room → http://127.0.0.1:3333/ui/
```

In the War Room, open **Settings** and connect a local agent (Claude Code / Codex / Hermes). Then describe a target to **Op Admiral** in plain English and launch. The agent you connected is the brain. No key required.

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
npm run build                                               # only needed from a git clone
npx tempest                                                 # → "Change default provider" → local
```

Tool-calling works on any local model (it's driven over text), so the Arsenal runs even on models without native function-calling.

Check the numbers for yourself:

```bash
npm run verify-claims             # re-derives every headline from committed JSON in bench/
```

Step-by-step operator usage lives in [Getting Started](docs/GETTING_STARTED.md). Library/SDK usage, the HTTP API, and MCP setup live in [docs/](docs/).

### Docker

Run T3MP3ST API server in a container (localhost only, not exposed externally):

```bash
cp .env.example .env       # configure API keys
docker compose up -d       # API → http://localhost:3333
docker compose logs -f     # view logs
```

**Security Note:** Container binds to `127.0.0.1:3333` - accessible only from localhost, not exposed to network.

Test the API:
```bash
curl http://localhost:3333/api/health
curl http://localhost:3333/api/bounty/platforms
```

Execute commands inside the container:

```bash
docker compose exec app npm run verify-claims
docker compose exec app npm run cve:bench
```

Full deployment guide: [docs/DOCKER.md](docs/DOCKER.md).

## Updating from upstream

If you installed from a release tarball or copied the tree instead of tracking `git pull`, use the built-in updater to sync with [github.com/elder-plinius/T3MP3ST](https://github.com/elder-plinius/T3MP3ST) without losing local secrets or bench output. It shows a numbered plan, asks **y/N** before changing anything, then runs `npm install`.

```bash
npm run update          # interactive sync from upstream main
npm run update:dry      # preview only — no git or npm changes
npm run update:hard     # hard reset to upstream/main (still restores protected paths)
```

Works on Windows (PowerShell), macOS, Linux, and WSL. Requires **git** and **npm** on your PATH.

### Safety modes

The updater is destructive **only when explicitly requested**:

| Command | What it does | Local changes |
|---|---|---|
| `npm run update` | Default interactive sync | `git merge upstream/main`; protected paths backed up and restored |
| `npm run update:dry` | Read-only preview | No git init, fetch, merge, reset, or `npm install`; safe on tarball installs |
| `npm run update:hard` | Opt-in hard reset | `git reset --hard upstream/main`; protected paths still restored |

All non-dry-run modes ask **y/N** before changing anything. Pass `--force` only in trusted automation. On the first-time path (no commits yet), the updater replaces the working tree with the upstream snapshot, but protected paths are backed up first and restored afterward.

### Protected paths (inside the repo)

Before replacing files, the updater backs up anything on disk that matches [`scripts/update-protected.txt`](scripts/update-protected.txt), then restores it after sync. **Only paths that exist locally are affected** — if you never created them, nothing happens.

| Path | Why it's protected |
|---|---|
| `.env`, `.env.*` | API keys and local env overrides. `!.env.example` is an exception — the template is **not** protected so upstream can update it. |
| `.keys.local` | One-off key paste file loaded by bench scripts (e.g. `VENICE_API_KEY`) without touching `.env`. |
| `.keys.bounty.json` | HackerOne / Bugcrowd / similar platform credentials. |
| `bench/cybench/corpus-stage/` | Large cloned Cybench corpus (not redistributed; expensive to re-download). |
| `bench/cybench/service-stage/`, `bench/cybench/challenges/` | Per-run Cybench Docker staging and challenge trees (regenerable, but slow to rebuild). |
| `bench/xbow/stage/`, `bench/xbow/challenges/` | XBOW/XBEN challenge staging (large third-party trees). |
| `bench/wild-hunt/` | Cold-hunt findings, PoCs, disclosure drafts, and campaign results — pre-coordination vuln material. |
| `bench/decomposition-results/` | White-box decomposition run JSON (may contain unreported analysis). |
| `bench/refusal-frontier/` | Refusal-boundary probe artifacts (raw model responses). |
| `bench/nyu/` | Staged NYU CTF content from `nyu-prep.mjs`. |
| `docs/disclosures/` | Generated vendor disclosure packages (`disclosure-gen` output). |
| `reports/` | Engagement and hunt reports (persistent output; same tree as Docker volume mounts in deployment setups). |
| `evidence/` | PoCs, screenshots, and other finding evidence kept across updates. |

Add your own patterns in `scripts/update-protected.local.txt` (optional local overlay; same glob syntax as the main manifest).

### Never touched (outside the repo)

These live outside the project tree — an update never reads or writes them:

- `%APPDATA%\t3mp3st-nodejs\Config\config.json` (or the macOS/Linux `conf` store path) — saved by `npm run setup`
- War Room browser **localStorage** on the War Room origin
- Local agent auth (`~/.codex`, `%LOCALAPPDATA%\hermes`, etc.)

## What ships today

The framework is an 8-operator kill chain, and this table won't blow smoke about it. **Recon is a live, tool-backed engine** — and the teeth are already real: 90.1% pass@1 on XBEN, 8/10 held-out post-cutoff CVEs pinned to exact file/line/CWE, and a coordinated-disclosure pipeline that's live enough to have drafts held for vendor coordination right now. What's *not* proven is the swarm. Each downstream operator — Exploiter, Infiltrator, Exfiltrator, Ghost — runs the **same real, tool-backed ReAct loop as recon** (real exploit tools, not stubs), but the headline numbers came from a single agent, not the coordinated 8-operator cell, and end-to-end swarm exploitation is unbenchmarked and still unreliable. The engine is real; the swarm is the part still earning its stripes. Loud where we've earned it, blunt about the rest.

| Component | Status | Notes |
|---|---|---|
| Re-derivable measurement (`verify-claims`) | ✅ Stable | every headline recomputes from committed artifacts |
| Recon engine | ✅ Stable | drives nmap / DNS / HTTP / fingerprinting; every finding traces to real tool output |
| Mission engine + War Room + Op Admiral | ✅ Stable | keyless through a connected local agent |
| Arsenal, MCP server, HTTP API | ✅ Stable | 35 built-in tools by default; 108 with the opt-in `T3MP3ST_FULL_ARSENAL` (+73 adapters, with dangerous/catalog-only drivers — metasploit, hydra, pacu, frida — behind narrow approved paths rather than generic execution) — both counts re-derive via `verify-claims`. `security_recon` over MCP |
| Egress-scope containment | ✅ Stable (on by default) | once a mission target is set, built-in networked tools refuse off-scope public hosts — not the target/subdomains, not loopback/private (`SCOPE DENIED`) — a tightened default, not a bare tool runner |
| Coordinated-disclosure pipeline | ✅ Stable | OSV novelty + live PoC + refuter panel + CVSS; drafts only, a human sends |
| White-box source analysis | ⚠️ Experimental | Multi-language ingest via web-tree-sitter (Python/JS/TS/Go/Java/C/C++); Python retains its regex parser, while other languages fail open to no extracted blocks; multi-model decomposition costs more tokens, not fewer |
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
| **Cybench model matrix** — identical 15-task committed subset, pass@1 | **Opus 4.7 vs 4.8**, with per-task source receipts and separate failure/abstention/infrastructure outcomes | [rebuild and inspect the model/harness matrix](docs/MODEL_MATRIX.md); historical system comparison, not an isolated model ranking |
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
| [Docs index](docs/README.md) | operator, developer, benchmark, and release documentation map |
| [Getting Started](docs/GETTING_STARTED.md) | install, first launch, first safe mission, CLI basics, updates, and troubleshooting |
| [Developer Guide](docs/DEVELOPER_GUIDE.md) | source map, scripts, SDK usage, extension points, and release checks |
| [API Reference](docs/API_REFERENCE.md) | local HTTP API route groups and integration notes |
| [MCP Guide](docs/MCP_GUIDE.md) | MCP server setup and `security_recon` usage |
| [FEATURES.md](FEATURES.md) | feature-by-feature status (`[x]` shipped / `[~]` partial / `[ ]` planned) |
| [SCOPE_AND_AUTHORIZATION](docs/SCOPE_AND_AUTHORIZATION.md) | authority model, scope receipts, evidence and retest rules |
| [VERIFIED_PROVENANCE](docs/VERIFIED_PROVENANCE.md) | how findings become tool-proven instead of model-asserted |
| [CONTRIBUTION_RECEIPTS](docs/CONTRIBUTION_RECEIPTS.md) | PR receipt template for scope, run mode, model/harness labels, redaction, and verification |
| [MODEL_MATRIX](docs/MODEL_MATRIX.md) | Reproducible cross-model benchmark matrix and arbitrary variant-test model selection |
| [TEAM_PREVIEW](docs/TEAM_PREVIEW.md) | first-run path and review script |
| [INSTALL_MATRIX](docs/INSTALL_MATRIX.md) | macOS / Linux readiness table |
| [ARSENAL_ACTIVATION_PLAN](docs/ARSENAL_ACTIVATION_PLAN.md) | optional external-tool setup |
| [PULL_REQUEST_DELIVERY](docs/PULL_REQUEST_DELIVERY.md) | contributor and maintainer checklist for scoped, reviewable PRs |
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

<div align="center">

*Fortes fortuna iuvat* — fortune favors the bold.

⊰•-•✧ LOVE PLINY ✧•-•⊱ 🌩️

</div>
