# 🌩️ T3MP3ST

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

![scores: re-derivable](https://img.shields.io/badge/scores-re--derivable-brightgreen) &nbsp; ![verify-claims 20/20](https://img.shields.io/badge/verify--claims-20%2F20-brightgreen) &nbsp; ![PRs welcome](https://img.shields.io/badge/PRs-welcome-purple) &nbsp; ![License: MIT](https://img.shields.io/badge/License-MIT-lightgrey)

</div>

Point T3MP3ST at a target and it works the offensive kill chain (**recon → exploit → report**) from a web War Room or the CLI, powered by a local agent you're already signed into (Claude Code, Codex, or Hermes). A full mission costs **no API keys**.

Today, the recon engine is live and tool-backed, and the exploit loop is benchmark-proven: 90.1% pass@1 on XBEN, every flag from a live exploit (reproducible below). The full 8-operator swarm is the architecture it grows into; the [status table](#what-ships-today) is exact about what's live, what's scaffolding, and what's still roadmap. Loud about the mission, honest that it's still a mission.

Three things set it apart:

1. **Reproducible.** Every benchmark number in this README recomputes from committed data. `npm run verify-claims` re-derives all of them. A number that can't be reproduced doesn't ship.
2. **Keyless.** The AI coding agent on your machine is the backbone. No second bill.
3. **Honest about scope.** The [status table](#what-ships-today) marks exactly what is stable, experimental, or still roadmap. No claim here comes from a mode this README doesn't name.

## Why it exists

Offensive security sits behind years of practice and expensive tooling. The bet behind T3MP3ST is that a coordinated agent swarm puts real bug-hunting in reach of people who never got the invite, across web apps, CTFs, smart contracts, source code, and embedded/robotics OSS. That is an ambitious bet, and the sections below are careful to separate what already works from what is still a bet.

## What it hunts

| Domain | What it does | Status |
|---|---|---|
| 🕸️ **Web apps** | Black-box, external-attacker recon → exploit (XBEN suite) | ✅ Stable |
| 🚩 **CTF** | Hint-free, sandbox-jailed solves (Cybench) | ✅ Stable |
| 🤖 **Robotics / OT / embedded** | Coordinated-disclosure pipeline for OSS vuln hunting (OSV + live-PoC + refuter) | ✅ Pipeline stable |
| 📂 **Source code** | White-box repo analysis with blind master-builder decomposition | ⚠️ Python-only ingest |
| 💰 **Smart contracts** | Damn Vulnerable DeFi | ⚠️ reproduction, not novel discovery |

## Quick start

Fastest path to a running War Room (keyless, ~2 min to set up; mission time depends on the target):

```bash
npm install
npm run server        # War Room → http://127.0.0.1:3333/ui/
```

In the War Room, open **Settings** and connect a local agent (Claude Code / Codex / Hermes). Then describe a target to **Op Admiral** in plain English and launch. The agent you connected is the brain. No key required.

Prefer to bring a key? Set one and skip the connect step:

```bash
export OPENROUTER_API_KEY=...     # or VENICE_API_KEY / ANTHROPIC_API_KEY
```

Check the numbers for yourself:

```bash
npm run verify-claims             # re-derives every headline from committed JSON in bench/
```

Library/SDK usage, the full HTTP API, and MCP setup live in [docs/](docs/).

## What ships today

The framework is an 8-operator kill chain. **Recon is a live, tool-backed engine.** Most downstream operators are scaffolding today, and this table says so. A live report currently shows `Successful Exploits: 0` outside the benchmarked path, and the copy here will never contradict that.

| Component | Status | Notes |
|---|---|---|
| Re-derivable measurement (`verify-claims`) | ✅ Stable | every headline recomputes from committed artifacts |
| Recon engine | ✅ Stable | drives nmap / DNS / HTTP / fingerprinting; every finding traces to real tool output |
| Mission engine + War Room + Op Admiral | ✅ Stable | keyless through a connected local agent |
| Arsenal, MCP server, HTTP API | ✅ Stable | 35 tools; `security_recon` over MCP |
| Coordinated-disclosure pipeline | ✅ Stable | OSV novelty + live PoC + refuter panel + CVSS; drafts only, a human sends |
| White-box source analysis | ⚠️ Experimental | Python-only regex ingest; multi-model decomposition costs more tokens, not fewer |
| DeFi (Damn Vulnerable DeFi) | ⚠️ Experimental | reproduces known exploit classes; not novel discovery |
| Exploiter / Infiltrator / Exfiltrator / Ghost | 🚧 Scaffolding | interface + orchestration stubs, not autonomous exploit engines |
| Advanced modules (cloud, persistence, swarm, cognition) | 🚧 Planned | interface-only in `src/stubs/` |
| Self-improvement loop | 🧪 Research | records lessons + proposals today; feeding them back into planning is roadmap |

Full feature-by-feature breakdown: [FEATURES.md](FEATURES.md).

## Benchmarks

Headline results. Each recomputes from the committed JSON with `npm run verify-claims`; full methodology and caveats are in the linked docs.

| Suite | Result | Context |
|---|---|---|
| **XBEN** — XBOW's 104-challenge suite, black-box | **pass@1 mean 90.1%** (Wilson-95 86.2–92.9), floor 91/104 · gpt-5.5 | XBOW self-reports 85% on the same suite; ours reproduces from artifacts |
| **XBEN** — white-box (reported separately) | pass@1 98.7%, best-ball 104/104 · gpt-5.5 | never blended with the black-box number |
| **Cybench** — 40-task academic bench, Opus 4.8, no hints | 21/40 full corpus, 23/40 clean subset, single-run pass@1 | not the raw-score record (Anthropic reports 76.5% pass@10); the point is measurement integrity |
| **CVE-Zero** — 10 real post-cutoff (2026) CVEs, hunted cold | 4/10 strict (exact file/line/CWE) | memorization-proof: targets postdate the training cutoff |

**How to read these:**

- Every solved flag came from a live exploit. Zero fabricated, enforced by an anti-fitting guard that runs on every push.
- Black-box (source withheld) and white-box (source staged) are reported separately and never blended.
- These ran a **single-agent ReAct loop, not the 8-operator swarm.** The swarm is framework architecture; it is not what scored these numbers.
- Results are system-vs-system: this harness driving a strong current model, not an isolated-harness claim.

XBOW self-reports 85% on its own suite. Ours reproduces from committed artifacts and clears it even at the Wilson floor. Find an open-source harness that does better with the receipts to prove it.

Deeper reading: [WALL_FORENSICS](docs/WALL_FORENSICS.md) (per-challenge misses), [CYBENCH](docs/CYBENCH.md), [INTEGRITY_LEDGER](docs/INTEGRITY_LEDGER.md) (contamination audit and every retraction), [OBSIDIVM](docs/OBSIDIVM.md) (our own live web range).

## Documentation

| Doc | Contents |
|---|---|
| [FEATURES.md](FEATURES.md) | feature-by-feature status (`[x]` shipped / `[~]` partial / `[ ]` planned) |
| [SCOPE_AND_AUTHORIZATION](docs/SCOPE_AND_AUTHORIZATION.md) | authority model, scope receipts, evidence and retest rules |
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

MIT. See [LICENSE](LICENSE).

---

<div align="center">

*Fortes fortuna iuvat* — fortune favors the bold.

⊰•-•✧ LOVE PLINY ✧•-•⊱ 🌩️

</div>
