# T3MP3ST: Tactical Execution Multi-agent Platform for Security Testing

## A Technical Whitepaper

**Version 1.0 | February 2026**

---

> **What is real vs. scaffolding — read this first.** T3MP3ST's live, tool-backed
> engine is **reconnaissance**: the recon operator drives a real ReAct tool-calling
> loop against a target and is what produces the re-derivable benchmark numbers (run
> under a **single-agent loop**, not the full operator swarm). The rest of the
> Cyber Kill Chain past recon — and the "advanced" / "Pliny Specials" modules — are
> **honestly-labeled scaffolding**: framework surface, interface stubs, and
> simulators, not autonomous exploitation. Reports from full-chain runs show `0`
> executed exploits. See [`FEATURES.md`](FEATURES.md) for the per-module
> `[x]` shipped / `[~]` partial / `[ ]` planned legend, and the README's
> "What is real vs. scaffolding" section. This document describes the **framework**;
> where it names a capability, check it against that legend before assuming it runs.

---

## Abstract

T3MP3ST (TEMPEST) is an open-source, TypeScript-based multi-agent framework for
penetration testing and red team operations. The platform models the workflow as a
structured Cyber Kill Chain pipeline of specialized AI-powered agents ("operators"),
backed by payload databases, real security tooling, and LLM-driven decision-making.
Today its live engine is the **reconnaissance operator** (a real tool-calling ReAct
loop); the downstream kill-chain phases and advanced modules are framework
scaffolding rather than autonomous exploitation (see the note above and
[`FEATURES.md`](FEATURES.md)). T3MP3ST exposes its capabilities through three
interfaces: a command-line interface, an HTTP REST API, and a Model Context Protocol
(MCP) server, for embedding recon-driven security testing into human-driven
workflows and agent pipelines.

This whitepaper details the architecture, agent model, execution pipeline, tooling, and integration surface of T3MP3ST, providing a comprehensive technical reference for security professionals, researchers, and developers.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Architecture Overview](#2-architecture-overview)
3. [The Operator Model](#3-the-operator-model)
4. [Kill Chain Execution Pipeline](#4-kill-chain-execution-pipeline)
5. [LLM Backbone](#5-llm-backbone)
6. [The Pliny Specials](#6-the-pliny-specials)
7. [Arsenal & Tooling](#7-arsenal--tooling)
8. [Evidence & Intelligence Pipeline](#8-evidence--intelligence-pipeline)
9. [OPSEC Layer](#9-opsec-layer)
10. [Integration Surfaces](#10-integration-surfaces)
11. [Web UI & War Room](#11-web-ui--war-room)
12. [Benchmark System](#12-benchmark-system)
13. [Security & Ethical Considerations](#13-security--ethical-considerations)
14. [Comparison with Existing Tools](#14-comparison-with-existing-tools)
15. [Future Directions](#15-future-directions)
16. [Conclusion](#16-conclusion)

---

## 1. Introduction

### 1.1 The Problem

Modern penetration testing demands coordination across multiple specialized tools, techniques, and phases. A typical engagement requires:

- Reconnaissance and OSINT across multiple vectors
- Vulnerability discovery using diverse scanning methodologies
- Exploit development and delivery
- Post-exploitation and lateral movement
- Evidence collection, correlation, and reporting

Traditionally, these are performed sequentially by human operators switching between dozens of tools. This is slow, error-prone, and difficult to scale. Existing automation approaches tend to be either too narrow (single-tool wrappers) or too broad (full autopilot without human oversight).

### 1.2 The T3MP3ST Approach

T3MP3ST addresses this gap by modeling the penetration testing workflow as a **multi-agent coordination problem**. Rather than building a monolithic scanner, T3MP3ST decomposes security testing into specialized agent roles (operators) that communicate, share intelligence, and advance through a structured kill chain. Each operator is powered by an LLM backbone that enables autonomous reasoning, tool selection, and finding extraction.

Key design principles:

- **Specialization over generalization** - Each operator is tuned for a specific kill chain phase
- **Intelligence sharing** - Findings from one phase feed directly into the next
- **Operational security by default** - Detection risk, cooldowns, and abort thresholds are first-class concepts
- **Multiple autonomy levels** - From fully manual to fully autonomous operation
- **Open integration** - CLI, REST API, and MCP server for embedding in any workflow

### 1.3 Scope of This Document

This whitepaper covers T3MP3ST v1.0, encompassing the core framework (~12,000 lines of TypeScript), the web UI (~14,000 lines), and the supporting infrastructure. All code is MIT-licensed.

---

## 2. Architecture Overview

### 2.1 System Topology

```
+------------------------------------------------------------------+
|                       T3MP3ST COMMAND                              |
|   (TempestCommand - Central EventEmitter-based Orchestrator)      |
+------------------------------------------------------------------+
|                                                                    |
|  +------------+  +------------+  +------------+  +------------+   |
|  |  OPERATOR  |  |   MISSION  |  |   TARGET   |  |  EVIDENCE  |   |
|  |    CELL    |  |  CONTROL   |  |   ENVIRON  |  |   VAULT    |   |
|  | (Agent     |  | (Task      |  | (Attack    |  | (Findings, |   |
|  |  Pool)     |  |  Queue,    |  |  Surface   |  |  Creds,    |   |
|  |            |  |  Phases,   |  |  Model)    |  |  Evidence) |   |
|  |            |  |  RoE)      |  |            |  |            |   |
|  +------------+  +------------+  +------------+  +------------+   |
|                                                                    |
|  +------------+  +------------+  +------------+  +------------+   |
|  |  ARSENAL   |  |   OPSEC    |  |   COMMS    |  |  ANALYSIS  |   |
|  | (15+ Real  |  | (Detection |  | (Inter-    |  | (Reporting |   |
|  |  Tools +   |  |  Mgmt,     |  |  Agent     |  |  Engine,   |   |
|  |  CLI Wrap) |  |  Cooldown) |  |  Channels) |  |  Summaries)|   |
|  +------------+  +------------+  +------------+  +------------+   |
|                                                                    |
|  +------------------------------------------------------------+   |
|  |                    LLM BACKBONE                              |   |
|  |  OpenRouter | Anthropic | OpenAI | Ollama | Mock            |   |
|  |  50+ models | Fallback chain | safeLLMCall()                |   |
|  +------------------------------------------------------------+   |
|                                                                    |
|  +------------------------------------------------------------+   |
|  |              ADVANCED MODULES (Stubs + Implemented)          |   |
|  |  KnowledgeBase | EvasionEngine | ReasoningEngine |           |   |
|  |  CognitionEngine | SwarmController | CloudSecurity | ...     |   |
|  +------------------------------------------------------------+   |
+------------------------------------------------------------------+
         |                    |                    |
    +----+----+         +----+----+         +----+----+
    | CLI     |         | REST    |         | MCP     |
    | (REPL)  |         | API     |         | Server  |
    |         |         | :3333   |         | (stdio) |
    +---------+         +---------+         +---------+
```

### 2.2 Core Components

**TempestCommand** (`src/index.ts`, 1039 lines) - The central orchestrator. Extends `EventEmitter` and owns all subsystems. Implements the tick-based execution loop, event forwarding, intelligence syncing, and lifecycle management.

**OperatorCell** (`src/operators/index.ts`, 861 lines) - Manages the pool of operator agents. Handles spawning, capacity limits, status aggregation, and archetype-based querying.

**MissionControl** (`src/mission/index.ts`) - Mission lifecycle, task queue, phase transitions, objective tracking, and Rules of Engagement enforcement.

**TargetEnvironment** (`src/target/index.ts`) - Attack surface model. Tracks targets, their status transitions (discovered -> scanning -> vulnerable -> exploited -> owned), services, and vulnerabilities.

**EvidenceVault** (`src/evidence/index.ts`) - Central repository for findings, credentials, and evidence artifacts. Supports severity classification and CVSS scoring.

**Arsenal** (`src/arsenal/index.ts`) - Tool registry with 15+ built-in tools and external CLI tool wrappers. Category-based filtering and execution history tracking.

**LLMBackbone** (`src/llm/index.ts`) - Multi-provider LLM client supporting OpenRouter (50+ models), Anthropic, OpenAI, Ollama, and a mock provider for testing.

### 2.3 Technology Stack

| Layer | Technology |
|-------|-----------|
| Language | TypeScript 5.3+ (strict mode) |
| Runtime | Node.js 18+ |
| Build | `tsc` (TypeScript compiler) |
| Events | `eventemitter3` (typed events) |
| CLI | `commander` + `inquirer` + `chalk` + `figlet` |
| API Server | Express.js 4 with CORS |
| MCP Server | `@modelcontextprotocol/sdk` (stdio transport) |
| Config | `conf` (persistent storage) + `dotenv` |
| Testing | Vitest |
| Linting | ESLint 9 with `typescript-eslint` |

---

## 3. The Operator Model

### 3.1 Agent Architecture

Each operator is an instance of `OperatorAgent`, which is an `EventEmitter` with:

- **Identity**: UUID, callsign, archetype
- **Profile**: MITRE ATT&CK tactics, tool categories, capabilities, system prompt
- **State machine**: idle -> tasked -> executing -> cooldown -> idle (or burned)
- **Intelligence**: locally accumulated findings and credentials
- **Execution**: LLM-powered task execution with optional AgentLoop (ReAct pattern)

### 3.2 Eight Archetypes

| Archetype | Kill Chain Phase | MITRE Tactics | Capabilities |
|-----------|-----------------|---------------|-------------|
| **Recon** | Reconnaissance | TA0043 | OSINT, DNS enum, subdomain discovery, port scanning |
| **Scanner** | Discovery | TA0007 | Vulnerability scanning, service fingerprinting, config audit |
| **Exploiter** | Initial Access | TA0001, TA0002 | Exploit dev, payload delivery, initial access |
| **Infiltrator** | Lateral Movement | TA0008, TA0004 | Privilege escalation, lateral movement, credential access |
| **Exfiltrator** | Exfiltration | TA0009, TA0010 | Data collection, exfiltration, staging |
| **Ghost** | Persistence | TA0003, TA0005 | Persistence, evasion, cleanup, anti-forensics |
| **Coordinator** | C2 | TA0011 | Orchestration, task management, decision making |
| **Analyst** | Reporting | - | Analysis, reporting, recommendations, risk assessment |

Each archetype has a dedicated system prompt (`src/prompts/index.ts`) that constrains the operator's reasoning to its domain. The prompts include:

- Role definition and operational constraints
- Preferred tools and techniques (mapped to MITRE ATT&CK technique IDs)
- Output format expectations (structured findings, credentials, next steps)
- OPSEC considerations specific to the phase

### 3.3 Task Execution Pipeline

When an operator receives a task, execution follows this priority order:

1. **AgentLoop (ReAct)** - If an `AgentLoop` is attached (LLM + Arsenal), the operator uses autonomous tool-calling in a Reason-Act-Observe loop. The loop selects tools from the Arsenal, executes them, observes results, and iterates (up to 15 iterations, 50K token budget).

2. **LLM-only** - If only an LLM is available (no Arsenal), the operator uses the LLM to analyze the task and produce structured output without executing real tools.

3. **No LLM** - Returns a descriptive error explaining that an LLM provider is required.

### 3.4 Team Factories

Pre-built team compositions for common scenarios:

- `createBalancedTeam()` - All 8 archetypes (one each), general-purpose
- `createStealthTeam()` - Recon + Scanner + Ghost with low detection thresholds
- `createBreachTeam()` - 2x Exploiter + Infiltrator + Exfiltrator with aggressive settings

### 3.5 State Management

```
          assignTask()
   idle ───────────> tasked ──────> executing
    ^                                    |
    |                                    v
    +──── cooldown <────────── (task complete)
    |
    +──── burned   <────── (detection risk exceeded)
```

- **Detection risk** accumulates with failed tasks (+0.1 per failure)
- When risk exceeds `maxDetectionRisk`, the operator is automatically "burned" (disabled)
- Cooldown duration is configurable per operator (default 5s, stealth configs use 30s)

---

## 4. Kill Chain Execution Pipeline

### 4.1 Phase Model

T3MP3ST implements the 7-phase Cyber Kill Chain:

```
RECON -> WEAPONIZE -> DELIVER -> EXPLOIT -> INSTALL -> C2 -> ACTIONS
```

Each phase maps to specific operator archetypes, ensuring the right specialist handles each stage.

### 4.2 Tick-Based Execution

The `TempestCommand.tick()` method runs every 1 second and implements the core execution loop:

1. **OPSEC check** - If abort is recommended, pause operations
2. **Task seeding** - On first tick with targets, generate reconnaissance tasks
3. **Phase advancement** - If all tasks for the current phase are complete, advance to the next phase and generate new tasks
4. **Task dispatch** - Match pending tasks to idle operators by archetype, checking dependencies before assignment
5. **Auto-spawning** - If no operator exists for a task's archetype, auto-spawn one (up to 3 per archetype)

### 4.3 Intelligence Flow

Findings from operators flow through an intelligence pipeline:

```
Operator discovers finding
    -> EvidenceVault stores it
    -> syncFindingToTarget() updates the Target model
        -> Services extracted from port/service findings
        -> Vulnerabilities added to target record
        -> Target status elevated (discovered -> vulnerable -> exploited)
    -> Next phase operators receive enriched target data
```

This ensures that a scanner's discovery of an open port is automatically available to the exploiter in the next phase.

### 4.4 Mission Control

Missions are created with:
- **Objectives** - High-level goals (e.g., "Achieve initial foothold")
- **Phases** - Ordered subset of kill chain phases
- **Rules of Engagement** - Scope limits, forbidden techniques, detection thresholds
- **Task Queue** - Priority-based, dependency-aware task scheduling

Two RoE presets are provided:
- `createDefaultRoE()` - Standard engagement rules
- `createStrictRoE()` - Tight scope, low detection tolerance

---

## 5. LLM Backbone

### 5.1 Multi-Provider Architecture

The `LLMBackbone` class (`src/llm/index.ts`) abstracts LLM access across providers:

| Provider | Models | Notes |
|----------|--------|-------|
| **OpenRouter** | 50+ models (Claude, GPT-4, Gemini, Grok, DeepSeek, Llama, Mistral) | Primary provider, recommended |
| **Anthropic** | Claude Opus, Sonnet, Haiku | Direct API |
| **OpenAI** | GPT-4o, GPT-4 Turbo, o1 | Direct API |
| **Ollama** | Any local model | For air-gapped environments |
| **Mock** | Deterministic responses | For testing |

### 5.2 Fallback Chain

The `safeLLMCall()` pattern implements resilient LLM communication:

1. Attempt call with primary model
2. If response is empty (<10 chars) or fails, retry with Hermes (via OpenRouter)
3. 3-tier JSON parsing: code block extraction -> non-greedy match -> plain-text regex
4. Empty response detection triggers automatic fallback

### 5.3 Model Configuration

```typescript
// Model IDs use DOT format for OpenRouter
const models = {
  opus: 'anthropic/claude-opus-4.6',
  sonnet: 'anthropic/claude-sonnet-4.5',
  haiku: 'anthropic/claude-haiku-4.5',
};
```

Configuration is managed through `src/config/index.ts` using the `conf` library for persistent storage, with environment variable override support.

---

## 6. The Pliny Specials

### 6.1 Overview

The "Pliny Specials" are T3MP3ST's nine elite capability organs. Each provides a specialized, high-level security operation backed by structured payload knowledge, local simulators, evidence contracts, and LLM-powered analysis. The intended shape is not a loose tool drawer: every Special should participate in the same loop of hypothesis, safe probe, evidence, finding, fix, and retest.

### 6.2 Tool Catalog

| Tool | Power | Domain | Primary Function |
|------|-------|--------|-----------------|
| **LEVIATHAN** | 99 | Orchestration | Autonomous kill chain orchestration - plans and executes full engagements |
| **SPHINX** | 88 | Validation | Vulnerability validation - confirms exploitability, eliminates false positives |
| **GORGON** | 92 | Exploitation | Precision strike engine - surgical exploitation with stealth priority |
| **CERBERUS** | 85 | Privilege Escalation | Identifies and ranks escalation vectors (50+ techniques for Linux/Windows) |
| **TYPHON** | 90 | Payload Engineering | Encoding, obfuscation, and WAF bypass (URL, Base64, hex, unicode, HTML entities) |
| **GRIFFIN** | 95 | Credential Harvesting | Secret extraction - AWS keys, GitHub tokens, JWTs, private keys (15+ patterns) |
| **SIMURGH** | 100 | Research | Zero-day research framework - attack surface mapping and primitive identification |
| **HYDRA** | 85 | Multi-Vector | Parallel multi-vector attack coordination (14 attack vectors) |
| **ARACHNE** | 87 | Chaining | Exploit chain builder - multi-step attack path construction (18 known chains) |

### 6.3 Payload Databases

The Pliny tools are backed by comprehensive, categorized payload databases (200+ total):

**SQL Injection** (5 categories):
- UNION-based (10 payloads)
- Blind boolean (7 payloads)
- Time-based blind (6 payloads)
- Error-based (4 payloads)
- Stacked queries (5 payloads)

**Cross-Site Scripting** (4 categories):
- HTML context, attribute injection, JavaScript context, polyglot

**Server-Side Template Injection**:
- Jinja2, Twig, ERB, generic detection

**Local/Remote File Inclusion**:
- Unix path traversal, Windows path traversal, PHP wrappers

**SSRF**:
- Localhost bypass, cloud metadata (AWS/GCP/Azure/DigitalOcean)

**Command Injection**:
- Unix and Windows variants

**XXE**:
- File read, SSRF, out-of-band exfiltration

### 6.4 Privilege Escalation Database

CERBERUS maintains 50+ escalation techniques:

**Linux** (25+ techniques):
- SUID/SGID binaries, sudo misconfigurations, capabilities
- Kernel exploits (DirtyPipe, DirtyCow, PwnKit)
- Cron jobs, writable paths, container escapes

**Windows** (25+ techniques):
- Potato family (JuicyPotato, PrintSpoofer, GodPotato)
- UAC bypass, unquoted service paths
- Token impersonation, registry autorun, DLL hijacking

### 6.5 Secret Pattern Detection

GRIFFIN uses 15+ regex patterns to detect:
- AWS access keys, secret keys, session tokens
- GitHub tokens (classic and fine-grained)
- Google API keys and OAuth secrets
- JWT tokens (with algorithm analysis)
- Database connection URIs
- Private keys (RSA, DSA, EC, OpenSSH)

---

## 7. Arsenal & Tooling

### 7.1 Built-in Tools (Real Implementations)

All built-in tools perform **real operations** using Node.js APIs:

| Tool | Category | Implementation |
|------|----------|---------------|
| `dns_lookup` | Recon | `dns` module - A, AAAA, MX, NS, TXT, CNAME records |
| `port_scan` | Recon | `net` module - TCP connect scan |
| `subdomain_enum` | Recon | DNS brute-force with wordlist |
| `whois_lookup` | Recon | TCP port 43 queries |
| `http_request` | Web | Full HTTP client with custom headers |
| `header_analysis` | Web | Security header scoring |
| `dir_bruteforce` | Web | HTTP directory enumeration |
| `technology_detect` | Web | Header/content fingerprinting |
| `xss_scan` | Vuln | Payload injection + reflection detection |
| `sqli_scan` | Vuln | Error-based and boolean-based detection |
| `ssl_scan` | Vuln | `tls` module - cipher analysis |
| `password_spray` | Auth | HTTP POST credential testing |
| `hash_crack` | Auth | Dictionary attack via `crypto` |
| `base64_decode` | Util | Base64 encoding/decoding |
| `jwt_decode` | Util | JWT parsing with security analysis |

### 7.2 External CLI Tool Wrappers

The Arsenal also wraps common security CLI tools when available on the system:

- **Network**: nmap, curl, wget, dig, host, whois
- **Web**: nikto, gobuster, ffuf, dirb
- **Exploitation**: sqlmap, wfuzz, hydra
- **Crypto/Forensics**: openssl, base64, xxd, strings, file, exiftool, binwalk

These are executed via `child_process.exec` with a whitelisted command set to prevent command injection.

### 7.3 Tool Execution Model

```typescript
// Tools are registered with typed schemas
arsenal.register({
  name: 'port_scan',
  category: 'recon',
  description: 'TCP port scanner',
  execute: async (params, context) => {
    // Real implementation using Node.js net module
    return { success: true, data: { openPorts: [...] } };
  }
});

// Operators access tools via the AgentLoop
agentLoop.run(task, systemPrompt, target);
// -> LLM selects tools -> Arsenal executes -> Observe results -> Iterate
```

---

## 8. Evidence & Intelligence Pipeline

### 8.1 Evidence Vault

The `EvidenceVault` centrally stores all operational intelligence:

**Findings** include:
- Title, description, severity (critical/high/medium/low/info)
- CVSS score, CVE identifiers, CWE classification
- Target ID, operator ID, kill chain phase
- Evidence artifacts (screenshots, HTTP traces, command output)
- Remediation recommendations
- Timestamp and exploitation status

**Credentials** are classified by type:
- Passwords, hashes, tokens, API keys, certificates

### 8.2 Intelligence Syncing

The `syncFindingToTarget()` method automatically enriches the target model:

1. **Service extraction** - Parses port/service findings and adds to target services
2. **Vulnerability registration** - Maps findings to target vulnerabilities
3. **Status escalation** - Automatically promotes target status based on severity
4. **Credential attachment** - Links credentials to their source targets

This creates a feedback loop where each operator's discoveries enrich the target model for subsequent operators.

### 8.3 Reporting Engine

The `AnalysisEngine` generates structured reports:

- **Executive summary** - Risk rating, finding counts, top recommendations
- **Technical findings** - Detailed vulnerability descriptions with evidence
- **Full report** - Combined executive + technical + attack paths
- **Export formats** - Markdown (implemented), with JSON support

---

## 9. OPSEC Layer

### 9.1 Detection Management

The `OpsecController` tracks operational security across the engagement:

- **Detection events** - Each detected interaction is logged with type and severity
- **Abort threshold** - Configurable limit; when exceeded, operations pause automatically
- **IOC tracking** - Indicators of Compromise are cataloged for post-engagement review

### 9.2 OPSEC Levels

| Level | Max Detections | Cooldown | Jitter | Traffic Blending |
|-------|---------------|----------|--------|-----------------|
| **Silent** | 1 | 5 minutes | 5-15s | Yes |
| **Covert** | 3 | 1 minute | 1-5s | Yes |
| **Loud** | 20 | 2 seconds | 0.1-0.5s | No |

### 9.3 Operator-Level OPSEC

Each operator maintains an independent detection risk score:
- Starts at 0
- Increases by 0.1 on task failure
- When it exceeds `maxDetectionRisk`, the operator is "burned" (permanently disabled)
- Cooldown periods between tasks reduce observable patterns

---

## 10. Integration Surfaces

### 10.1 Command-Line Interface

The CLI (`src/cli.ts`, 20K lines) provides an interactive REPL with:

- Operation presets (balanced, stealth, aggressive, custom)
- Operator spawning and management
- Target addition and status monitoring
- Mission creation and execution
- AI chat with the LLM backbone
- Report generation
- Full settings management

### 10.2 HTTP REST API

The API server (`src/server.ts`) exposes the mission-control + tool surface via Express.js:

```
POST /api/mission/start               # Start an autonomous mission (targets + operators)
GET  /api/mission/report              # Export the engagement report (markdown)
POST /api/whitebox/analyze            # White-box repo analysis (ingest -> decompose)
POST /api/operators/spawn             # Spawn an operator into the active mission
POST /api/general/plan                # Op Admiral -- draft an operation plan
GET  /api/codex/status                # Codex CLI availability (read-only)
POST /api/codex/probe                 # Codex exec readiness self-test
GET  /api/findings                    # Evidence-gated findings ledger
POST /api/tools/execute               # Direct tool execution
POST /api/tools/recon                 # Network reconnaissance
POST /api/llm/chat                    # LLM chat
GET  /api/health                      # Health check
```

The server also includes SSE endpoints for real-time event streaming to the web UI, plus mission dispatch endpoints for backend operator execution.

### 10.3 Model Context Protocol (MCP) Server

The MCP server (`src/mcp-server.ts`, 83K lines) implements the [Model Context Protocol](https://modelcontextprotocol.io/) specification, enabling AI assistants (Claude, etc.) to use T3MP3ST tools directly:

```json
{
  "mcpServers": {
    "t3mp3st-pliny": {
      "command": "node",
      "args": ["/path/to/t3mp3st/dist/mcp-server.js"],
      "env": { "OPENROUTER_API_KEY": "sk-or-..." }
    }
  }
}
```

Exposed MCP tools: `pliny_leviathan`, `pliny_sphinx`, `pliny_gorgon`, `pliny_cerberus`, `pliny_typhon`, `pliny_griffin`, `pliny_simurgh`, `pliny_hydra`, `pliny_arachne`, `security_recon`.

---

## 11. Web UI & War Room

### 11.1 Architecture

The web UI (`docs/index.html`, ~14K lines) is a single-page application with a dark cyberpunk theme. It communicates with the API server via REST and SSE for real-time updates.

### 11.2 Pages

| Page | Function |
|------|----------|
| **War Room** | Unified dashboard with kill chain visualization, operator status, live intel feed, OPSEC monitor |
| **Operators** | Agent management - spawn, monitor, view dossiers |
| **Missions** | Mission creation, phase tracking, objective management |
| **Evidence** | Findings vault with severity filtering |
| **Arsenal** | Tool registry with code viewer, stats, and demo capabilities |
| **Terminal** | Direct command execution |
| **Benchmarks** | Performance testing against Cybench and NYU CTF Bench |
| **Config Library** | OPSEC presets and templates |
| **CTF Range** | Practice targets for training |
| **Settings** | API key management, model selection, preferences |

### 11.3 Real-Time Features

- **SSE event stream** - Findings, operator status changes, phase transitions, and periodic status updates stream to the UI
- **Operator hover tooltips** - Full dossier on mouseenter
- **Console event tooltips** - Full event text on hover
- **Keyboard shortcuts** - Rapid navigation and actions
- **Sound cues** - Audio feedback for critical events

---

## 12. Benchmark System

### 12.1 Built-in Categories

T3MP3ST includes a comprehensive benchmarking system across 9 categories:

| Category | Description |
|----------|-------------|
| **web** | Web application security (XSS, SQLi, SSRF) |
| **binary** | Binary exploitation |
| **crypto** | Cryptographic challenges |
| **reverse** | Reverse engineering |
| **forensics** | Digital forensics |
| **autonomous_ops** | Autonomous operation scenarios |
| **owasp** | OWASP Top 10 coverage |
| **mitre** | MITRE ATT&CK technique coverage |
| **cwe** | CWE Top 25 vulnerability coverage |

### 12.2 External Benchmark Integration

The system integrates with two major CTF benchmark datasets:

**Cybench** (40 tasks):
- Sourced from `github.com/andyzorigin/cybench`
- Tasks include metadata, challenge files, and expected flags
- Fetched via `raw.githubusercontent.com` to avoid API rate limits

**NYU CTF Bench** (200 tasks):
- Sourced from NYU's CTF challenge repository
- Tasks include `challenge.json` with flag fields
- Fetched via a single GitHub git tree API call for efficiency

### 12.3 Scoring

- **Flag-based**: Exact flag match = instant 100%
- **Keyword + LLM judge**: `evaluateResponseRigorous()` combines keyword matching with an LLM judge for partial credit scoring
- Results are aggregated per category and displayed in the web UI

---

## 13. Security & Ethical Considerations

### 13.1 Authorized Use Only

T3MP3ST is designed exclusively for **authorized security testing**:

- Penetration testing engagements with written authorization
- Red team exercises with signed Rules of Engagement
- Security research in controlled environments
- CTF competitions and educational contexts

### 13.2 Safety Mechanisms

- **Rules of Engagement enforcement** - Scope limits, forbidden techniques
- **Detection thresholds** - Automatic pause when limits are exceeded
- **Operator burn mechanism** - Compromised agents are permanently disabled
- **Whitelisted CLI commands** - External tool execution is restricted to known security tools
- **No real exploitation by default** - Pliny tools provide analysis and planning; actual exploitation requires explicit configuration

### 13.3 API Key Security

- API keys are stored in persistent config, never in source code
- Environment variable override supported
- `.env` file loading via `dotenv`
- `.gitignore` excludes sensitive files

### 13.4 Compliance Considerations

Usage should comply with:
- Computer Fraud and Abuse Act (CFAA)
- General Data Protection Regulation (GDPR)
- PCI DSS, HIPAA as applicable
- Local cybersecurity laws and regulations

---

## 14. Comparison with Existing Tools

| Feature | T3MP3ST | Metasploit | Cobalt Strike | AutoPT Tools |
|---------|---------|-----------|---------------|-------------|
| Multi-agent architecture | Yes | No | Partial (teamserver) | Varies |
| LLM-powered reasoning | Yes (50+ models) | No | No | Some |
| Kill chain alignment | Full 7-phase | Exploit-focused | Post-exploitation | Varies |
| MCP integration | Yes | No | No | No |
| OPSEC management | Built-in | Limited | Strong | Minimal |
| Web UI | Yes | Armitage | Yes | Varies |
| Open source | MIT | BSD (Framework) | Commercial | Varies |
| Language | TypeScript | Ruby | Java | Python/Go |
| Payload databases | 200+ | 2000+ | Focused | Limited |
| Evidence management | Full pipeline | Database | Logs | Minimal |

T3MP3ST distinguishes itself through its **LLM-native multi-agent architecture** and **MCP integration**, enabling a new class of AI-assisted security testing workflows that don't exist in traditional tooling.

---

## 15. Future Directions

### 15.1 Near-Term (P0)

- Full REST API endpoint coverage for operators, targets, and missions
- PDF report generation
- Scanner import (Nmap XML, Nuclei JSON)
- Real exploit execution in Pliny tools

### 15.2 Mid-Term (P1-P2)

- **Cloud security module** - AWS/GCP/Azure enumeration and testing
- **Function calling** in LLM backbone for native tool use
- **WebSocket** real-time updates (replacing SSE)
- **Cognition patterns** - Chain-of-Thought, ReAct, Tree-of-Thought
- **Swarm intelligence** - Pheromone-based multi-agent coordination
- **Plugin system** for community-contributed tools

### 15.3 Long-Term (P3)

- Distributed operation across multiple nodes
- SaaS deployment model
- Marketplace for tools and operator profiles
- AI-powered remediation guidance
- Continuous security monitoring mode

---

## 16. Conclusion

T3MP3ST represents a new paradigm in security testing tooling: **LLM-native, multi-agent, kill-chain-aligned penetration testing**. By decomposing the security testing workflow into specialized operators that communicate, share intelligence, and advance autonomously through structured phases, T3MP3ST enables both deeper analysis and broader coverage than traditional single-tool approaches.

The platform's triple integration surface (CLI, REST API, MCP) makes it embeddable in any workflow, from human-driven engagements to fully autonomous AI agent pipelines. Its comprehensive payload databases, real tooling implementations, and OPSEC-first design philosophy provide a solid foundation for authorized security testing at scale.

T3MP3ST is open source under the MIT license, welcoming contributions from the security research community.

---

## Appendix A: Codebase Metrics

| Metric | Value |
|--------|-------|
| Backend TypeScript | ~12,000 lines |
| Web UI (HTML/JS/CSS) | ~14,000 lines |
| MCP Server | ~83,000 lines |
| API Server | ~52,000 lines |
| Total source files | 21 TypeScript modules |
| Dependencies | 12 production, 8 development |
| Built-in tools | 15 |
| External tool wrappers | 15+ |
| Payload database entries | 200+ |
| MITRE ATT&CK techniques | 40+ |
| CVE entries | 20+ |
| Privilege escalation techniques | 50+ |
| Secret detection patterns | 15+ |
| Supported LLM models | 50+ |

## Appendix B: Module Map

```
src/
  index.ts           # TempestCommand, factory functions, exports
  cli.ts             # Interactive CLI (commander + inquirer)
  server.ts          # Express API server + Pliny endpoints
  mcp-server.ts      # MCP server (stdio transport)
  setup.ts           # Configuration wizard
  types/index.ts     # Core TypeScript type definitions
  operators/index.ts # OperatorAgent, OperatorCell, archetype profiles
  mission/index.ts   # MissionControl, TaskQueue, RoE
  target/index.ts    # TargetEnvironment, target factories
  evidence/index.ts  # EvidenceVault, finding/credential management
  arsenal/index.ts   # Arsenal, built-in tools, CLI wrappers
  llm/index.ts       # LLMBackbone, provider adapters
  config/index.ts    # Configuration, API key management
  opsec/index.ts     # OpsecController, detection management
  comms/index.ts     # CommsChannel, inter-agent messaging
  analysis/index.ts  # AnalysisEngine, reporting
  agent/index.ts     # AgentLoop (ReAct execution pattern)
  benchmark/index.ts # Benchmark system, scoring
  prompts/index.ts   # System prompts, templates
  stubs/index.ts     # Advanced module stubs (KnowledgeBase, EvasionEngine, etc.)
docs/
  index.html         # Single-page web UI
ctf/
  challenges/        # CTF practice challenges
```

---

*T3MP3ST is developed for authorized security testing only. Never use this framework for unauthorized access to systems.*
