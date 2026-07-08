# TEMPEST STACK — Architecture Reference

> All diagrams and descriptions derive from the actual source code.
> Do not treat this as aspirational — it reflects what the runtime does.

---

## Part 1 — Bird's-Eye View

```
  Operator Browser
  https://localhost:8443
          │ HTTPS (self-signed TLS)
          ▼
╔══════════════════════════════════════════════════════════════════════════════╗
║                    tempest-stack:latest  (node:20-slim)                     ║
║                                                                              ║
║  ┌─────────────────────────────────────────────────────────────────────┐    ║
║  │  supervisord                                                         │    ║
║  │                                                                      │    ║
║  │  priority  5 ──► nginx      HTTPS :8443  (reverse proxy + auth gate)│    ║
║  │  priority 10 ──► t3mp3st    HTTP  :3333  (internal only)            │    ║
║  └─────────────────────────────────────────────────────────────────────┘    ║
║                                                                              ║
║  /data/missions ◄── named volume   (mission state, evidence vault)           ║
║  /data/uploads  ◄── bind mount     (scan-target binaries / archives)         ║
║                                                                              ║
╚══════╤══════════════════════════════════════════════════════════════════════╝
       │ EXPOSE ${TEMPEST_HTTPS_PORT:-8443}:8443
       │
       │  optional sidecars (require scripts/generate-certs.sh)
       │  communicate over mTLS HTTPS on the Docker network
       │
       ├──► tempest-cloud   :8080  (awscli · prowler · checkov)
       ├──► tempest-binary  :8080  (strings · nm · objdump · r2 · yara · binwalk)
       └──► tempest-sandbox :8080  (QEMU · Wine64 · Qiling — dynamic execution)

External cloud LLMs  ──────────────────────────────────────────────────────►
  openrouter / anthropic / openai / bedrock                  (outbound HTTPS)

Outbound webhooks    ──────────────────────────────────────────────────────►
  POST to registered URLs on every internal event            (outbound HTTPS)

External MCP servers ◄─────────────────────────────────────────────────────
  Claude Code MCP, custom servers, etc.   (stdio subprocess or SSE/HTTP)

Local agent CLIs     ◄─────────────────────────────────────────────────────
  claude / codex / hermes                 (child process, already-authed)
```

**Internal components (tempest-stack container):**

| Component | Language / Runtime | Port | supervisord priority | Purpose |
|---|---|---|---|---|
| `nginx` | Nginx | 8443 (host-exposed) | 5 — starts first | HTTPS termination, session auth gate, reverse proxy to t3mp3st |
| `t3mp3st` | Node.js (TypeScript) | 3333 (internal only) | 10 — starts after nginx | REST API + SSE event bus + mission orchestration |

**Optional sidecar containers (separate Docker services):**

| Container | Image | Internal port | Tools |
|---|---|---|---|
| `tempest-cloud` | `tempest-cloud:latest` | 8080 (HTTPS) | awscli, prowler, checkov |
| `tempest-binary` | `tempest-binary:latest` | 8080 (HTTPS) | strings, nm, readelf, objdump, radare2, yara, binwalk |
| `tempest-sandbox` | `tempest-sandbox:latest` | 8080 (HTTPS) | QEMU user-mode, Wine64, Qiling (ELF/PE/Mach-O dynamic execution) |

Sidecars are not started by default — they start automatically when `docker compose up -d` is run after certs are generated. T3MP3ST connects to them using bearer tokens set by `scripts/generate-certs.sh`.

**supervisord startup sequence (inside tempest-stack):**

```
Container starts
      │
      ▼
docker-entrypoint.sh
  1. mkdir -p /data/missions /data/uploads
  2. exec supervisord
          │
          ├── spawns nginx    (priority 5,  startsecs=2)
          │     └── /usr/sbin/nginx -g "daemon off;"
          │         listens on :8443 (HTTPS), proxies to 127.0.0.1:3333
          │
          └── spawns t3mp3st  (priority 10, startsecs=5)
                └── node /opt/t3mp3st/dist/server.js
                    listens on :3333 (HTTP, loopback only)
```

Both have `autorestart=true` — supervisord restarts either independently on crash.

---

## Part 2 — Detailed View

### 2.1 Event Bus: everything flows through broadcastEvent()

`broadcastEvent()` is the single internal event bus. Every subsystem that produces state changes calls it:

```
Any internal state change
        │
        ▼
  broadcastEvent(event: string, data: Record<string,unknown>)
        │
        ├──► SSE stream  ─────────────────────────────────────────────────────►
        │    GET /api/events                         connected browser clients
        │    event: <event-name>
        │    data: <redacted-secrets JSON>
        │
        ├──► fireWebhooks(event, data)  ──────────────────────────────────────►
        │    POST to registered URLs                 external systems
        │    Headers: X-Tempest-Event
        │             X-Tempest-Delivery
        │             X-Tempest-Signature: sha256=<hmac>  (if secret set)
        │    Retry: 3 attempts at 1s → 5s → 30s
        │
        └──► evaluateEvent(event, data, ctx)  ─── automation rules engine
             Checks every enabled rule:
               trigger.event pattern matches?  (glob, trailing *)
               trigger.condition passes?       (payload.key === 'value')
               → execute action:
                   log           — console.log
                   fire-webhook  — re-fire to specific webhook
                   dispatch-agent — send prompt to connected local agent
                   spawn-operator — spawn a new mission operator
```

**Events emitted by the platform (non-exhaustive):**

```
approval.*          approval.requested / .approved / .rejected
hypothesis.*        hypothesis.created / .updated / .promoted
work_order.*        work_order.created / .updated / .completed
evidence.*          evidence.created
finding.*           finding.created / .updated
retest.*            retest.created / .updated
draft.*             draft.created / .updated
mission:*           mission:started / :stopped / :paused / :resumed
operator:*          operator:spawned / :terminated / :prompt_updated
task:*              task:dispatched / :completed / :failed
general:*           general:planning / :plan_ready / :review / :sitrep
pressure.*          pressure.canary / .duel / .mutations / .chains
memory.*            memory.proposed / .accepted / .rejected
watch_loop.*        watch_loop.pulsed
mcp.*               mcp.server.connected / .disconnected / mcp.tool.called
automation.*        automation.triggered / .error
webhook.test        test ping
```

---

### 2.2 LLM Backbone and Provider Chain

```
Request to LLMBackbone.chat() / .prompt() / .stream()
        │
        ▼
   LLMConfig.provider  ──────────────────────────► which adapter to use
        │
        ├── 'openrouter'   ──► OpenRouter API        (outbound HTTPS)
        ├── 'anthropic'    ──► Anthropic Claude API   (outbound HTTPS)
        ├── 'openai'       ──► OpenAI GPT API         (outbound HTTPS)
        ├── 'bedrock'      ──► AWS Bedrock             (outbound HTTPS, @aws-sdk)
        ├── 'local'        ──► Ollama or compatible    (outbound HTTP, configurable)
        ├── 'local-agent'  ──► Claude Code/Codex/Hermes (child process, no API key)
        ├── 'codex'        ──► Codex CLI               (child process)
        └── 'mock'         ──► stub adapter             (testing)

Fallback chain (configured in LLMConfig.fallbackChain[]):
  Primary model fails (rate_limit / 5xx / timeout / auth / context_length)
        │
        ▼
  next entry in fallbackChain[] ──► retry with different provider+model
        │
        ▼
  On "soft refusal" (model refuses task):
        │
        └──► reframe prompt with authorized context → retry on next model
```

---

### 2.3 Mission Lifecycle

```
          ┌─── The Admiral (conversational intake) ───────────┐
          │ POST /api/admiral/converse                         │
          │   Chat → drafts MissionBrief                       │
          │ POST /api/admiral/launch                           │
          │   MissionBrief → Directive → Op General            │
          └───────────────────────────────────────────────────┘
                              │
                              ▼
          ┌─── Op General (autonomous orchestrator) ──────────┐
          │ POST /api/general/plan                             │
          │   Directive → OperationPlan (phases + tasks)       │
          │ POST /api/general/execute                          │
          │   Execute plan: spawn operators → assign tasks     │
          │ POST /api/general/auto                             │
          │   plan + execute in one call                       │
          └───────────────────────────────────────────────────┘
                              │
                              ▼
          ┌─── TempestCommand (mission runtime) ──────────────┐
          │ POST /api/mission/start  → creates TempestCommand  │
          │                                                     │
          │  Cell (operator pool)                               │
          │   ├── POST /api/operators/spawn                     │
          │   │     Archetype: RECON / EXPLOIT / EXFIL /        │
          │   │               ANALYST / EVADER / FIXER          │
          │   ├── POST /api/operators/:id/task                  │
          │   │     Dispatch task → operator.assignTask()        │
          │   │     Result → broadcastEvent('task:*')            │
          │   └── POST /api/operators/terminate                  │
          │                                                     │
          │  TargetEnvironment                                  │
          │   └── POST /api/mission/start {scope: [...]}        │
          │                                                     │
          │  EvidenceVault                                      │
          │   └── POST /api/evidence                            │
          │       GET  /api/mission/findings                    │
          └───────────────────────────────────────────────────┘
                              │
                              ▼
          ┌─── Watch Loop (autonomous self-healing) ───────────┐
          │ POST /api/watch-loop/run                            │
          │   Scans ledger → generates WatchSignals             │
          │   → spawns WorkOrders for blocking issues           │
          │ POST /api/self-heal/run                             │
          │   Proposes and executes self-healing actions        │
          └───────────────────────────────────────────────────┘
```

---

### 2.4 Approval Gate

Before any active execution against non-local targets, the platform enforces an authorization receipt:

```
Action requires approval?
        │
        ▼
POST /api/approvals/request
  { action, target, reason }
        │
        ▼
ApprovalRequest created (status: 'pending')
  broadcastEvent('approval.requested', ...)
        │
        ├── Operator/human reviews via UI or API
        │
        ├── POST /api/approvals/:id/approve  ──► status: 'approved'
        │                                         broadcastEvent('approval.approved')
        │                                         action may proceed
        │
        └── POST /api/approvals/:id/reject   ──► status: 'rejected'
                                                  action blocked
```

Approvals have an `expiresAt` field. Expired approvals are treated as rejected. The guard action types are: `command_execution`, `network_request`, `mission_execution`, `autonomous_execution`, `model_call`.

---

### 2.5 Local Agent Integration

Local agent CLIs (Claude Code, Codex, Hermes) are driven as headless operators without any API key — they use their own native authentication artifacts:

```
detectLocalAgents()
        │
        ▼
For each agent spec (claude / codex / hermes):
  1. Is binary in PATH? (execFileSync version check)
  2. Does any authArtifact exist?
       claude: ~/.claude/.credentials.json  OR  ~/.claude.json
       codex:  ~/.codex/auth.json           OR  ~/.config/codex/auth.json
       hermes: ~/.hermes/.env
  3. (macOS only) keychain service present?
        │
        ▼
POST /api/agents/local/connect { id: 'claude'|'codex'|'hermes', ping: true }
        │
        ▼
runLocalAgent(id, prompt, opts)
  - Strips ANTHROPIC_API_KEY, OPENAI_API_KEY, OPENROUTER_API_KEY (and others)
    from child env → CLI uses its OWN native login, not T3MP3ST's keys
  - Spawns: claude  → claude -p <prompt> --output-format text [--model M]
             codex  → codex exec [--model M] <prompt>
             hermes → hermes -z <prompt> [--yolo] [--model M]
  - stdout captured → AgentRunResult { ok, latencyMs, output, error? }

Multi-turn sessions (sessionId):
POST /api/agents/local/dispatch { id, prompt, sessionId }
        │
        ▼
getOrCreateSession(sessionId, agentId)
        │
        ├── buildContextPrefix(session) → inject prior history
        ├── effectivePrompt = prefix + prompt
        ├── runLocalAgent(id, effectivePrompt, opts)
        └── appendToSession(sessionId, 'user'|'assistant', content)
```

`HERMES_YOLO=0` disables `--yolo` (auto-approval) on Hermes if needed.

---

### 2.6 MCP Server and MCP Client

T3MP3ST operates in **both** MCP roles simultaneously:

```
                    ┌─────────────────────────────┐
External LLM        │  T3MP3ST as MCP SERVER       │
(Claude Code,  ────►│  npm run mcp / npm run mcp:prod│
 Cursor, etc.)      │  Transport: stdio             │
                    │  Tools exposed:               │
                    │    security_recon             │
                    │      (nmap + dig, allowlisted)│
                    └─────────────────────────────┘

                    ┌─────────────────────────────┐
External MCP        │  T3MP3ST as MCP CLIENT       │
servers       ◄────►│  POST /api/mcp/servers/connect│
(any stdio or       │  Transport: stdio or sse     │
 SSE server)        │  Discovered tools appear in  │
                    │  GET /api/mcp/tools           │
                    │  Callable via               │
                    │  POST /api/mcp/tools/call     │
                    └─────────────────────────────┘
```

MCP client connection flow:

```
POST /api/mcp/servers/connect
  {
    id: "my-server",
    label: "My Server",
    transport: "stdio",
    command: "npx",
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/path"]
  }
        │
        ▼
connectMcpServer(config)
  1. new Client({ name: 't3mp3st-client', version: '1.0.0' })
  2. new StdioClientTransport({ command, args, env })
        OR new SSEClientTransport(new URL(config.url))
  3. await client.connect(transport)
  4. await client.listTools()
        → cache as McpRemoteTool[]
        │
        ▼
GET /api/mcp/tools         → all tools across all connected servers
POST /api/mcp/tools/call
  { serverId, toolName, args }
        └──► client.callTool({ name, arguments })
```

---

### 2.7 Outbound Webhooks

```
Any internal event
        │
        ▼
broadcastEvent() calls fireWebhooks(event, data)
        │
        ▼
For each registered webhook:
  events.some(pattern => matches(pattern, event))?
  enabled === true?
        │
        ▼
Build delivery:
  body = JSON.stringify({ event, data, deliveryId, ts })
  headers:
    X-Tempest-Event:    <event-name>
    X-Tempest-Delivery: <uuid>
    X-Tempest-Signature: sha256=<hmac-sha256(secret, body)>  [if secret set]
        │
        ▼
POST to webhook.url (timeout: 10s)
  attempt 1 → success? done.
  attempt 1 → fail?
        wait 1s → attempt 2
        fail? wait 5s → attempt 3
              fail? log warning, increment failCount

Startup pre-load:
  T3MP3ST_WEBHOOK_URL=https://a.com/hook,https://b.com/hook
  → registers catch-all ('*') hooks at container start
```

---

### 2.8 Automation Rules Engine

```
                       ┌──── Rule ────────────────────────────────────────────┐
                       │  trigger:                                             │
                       │    event: 'finding.*'       ← glob pattern            │
                       │    condition: "payload.severity === 'critical'"       │
                       │  action:                                              │
                       │    type: 'dispatch-agent'                            │
                       │    agentId: 'claude'                                  │
                       │    promptTemplate: 'Verify finding: {{payload.title}}'│
                       └──────────────────────────────────────────────────────┘

Every broadcastEvent() call:
        │
        ▼
evaluateEvent(event, payload, ctx)
  for each enabled rule:
    1. eventMatches(trigger.event, event)?
         '*'          → always matches
         'finding.*'  → matches 'finding.created', 'finding.updated', etc.
         'mission:started' → exact match only
    2. evaluateCondition(trigger.condition, payload)?
         "payload.severity === 'critical'" → checks payload.severity
         "payload.count !== '0'"
         unknown syntax → false (fail-safe)
    3. execute action:

  action.type = 'log'
    → console.log message
    → broadcastEvent('automation.triggered', ...)

  action.type = 'fire-webhook'
    → fireWebhooks(event, payload)
    → broadcastEvent('automation.triggered', ...)

  action.type = 'dispatch-agent'
    → prompt = interpolate(promptTemplate, payload)
         "{{payload.title}}" → replaced with payload.title value
    → ctx.dispatchAgent(agentId, prompt)
         calls runLocalAgent(agentId, prompt, {})
    → broadcastEvent('automation.triggered', ...)

  action.type = 'spawn-operator'
    → ctx.spawnOperator(archetype, model)
    → broadcastEvent('automation.triggered', ...)

  rule.triggerCount++
  rule.lastTriggeredAt = Date.now()
```

---

## Part 3 — Individual Services

### 3.1 Nginx (HTTPS proxy, port 8443)

**Config:** `docker/nginx/nginx.conf` (copied into image at build time)
**Binding:** `:8443` (host-exposed via `${TEMPEST_HTTPS_PORT:-8443}:8443` in docker-compose.yml)
**Proxies to:** `http://127.0.0.1:3333` (t3mp3st, loopback-only)

**Changing the host port:**
```bash
# In .env:
TEMPEST_HTTPS_PORT=443   # standard HTTPS (may need root / cap binding)
TEMPEST_HTTPS_PORT=9443  # any other port

# To change the internal listen port (rarely needed), edit docker/nginx/nginx.conf:
#   listen 8443 ssl;  → change 8443 to your target port
# and update docker-compose.yml ports mapping accordingly.
```

**Request flow through nginx:**

```
Browser → https://localhost:8443/...
        │
        ▼
nginx (:8443) — TLS termination (certs/nginx.{crt,key}, self-signed)
        │
        ├─ /auth/*              → proxy_pass 127.0.0.1:3333  (no auth gate)
        ├─ /health, /api/health → proxy_pass 127.0.0.1:3333  (no auth gate)
        ├─ /api/events          → proxy_pass 127.0.0.1:3333  (auth_request + no buffering)
        ├─ /api/*               → auth_request /internal/auth → proxy_pass 127.0.0.1:3333
        │                         401 → {"error":"Unauthorized"}
        └─ /*  (UI + other)     → auth_request /internal/auth → proxy_pass 127.0.0.1:3333
                                  401 → 302 /auth/login
```

The auth sub-request calls `GET /auth/validate` on t3mp3st, which checks the `t3mp3st_session` cookie.

---

### 3.2 T3MP3ST (Node.js, internal port 3333)

**Entry point:** `/opt/t3mp3st/dist/server.js`
**Source:** `src/server.ts` (compiled to `dist/server.js` by `tsc`)
**Host binding:** `T3MP3ST_HOST=0.0.0.0` (container env) — reachable from nginx on loopback; never directly exposed to the host.

**Security middleware stack (applied in order):**

```
Request arrives at port 3333 (from nginx or docker healthcheck)
        │
        ▼
helmet()               — security headers
        │
        ▼
cors()                 — origin allowlist (loopback only in production)
        │
        ▼
express.json()         — body parser, 10mb limit
        │
        ▼
Bearer token auth      — optional, enabled by T3MP3ST_API_TOKEN env var
  /api/* paths         — public: /api/health, /api/preflight, /api/status
                         returns 401 if token mismatch
        │
        ▼
Request logger         — [ISO timestamp] METHOD /path
        │
        ▼
Route handlers         — see full route table below
        │
        ▼
Error handler          — 500 Internal Server Error (logs full error)
```

**Complete API route table:**

```
── HEALTH & STATUS ────────────────────────────────────────────────────────────
GET  /health  /api/health        → { ok, status, mode, organ, version, llm, ... }
GET  /api/preflight              → tool availability, LLM status, env check
GET  /api/mission-context/latest → latest mission bundle context

── REAL-TIME EVENTS ───────────────────────────────────────────────────────────
GET  /api/events                 → SSE stream (text/event-stream)
                                   heartbeat every 30s
                                   event: <name>\ndata: <json>\n\n

── ARSENAL ────────────────────────────────────────────────────────────────────
GET  /api/arsenal/catalog        → full tool catalog
POST /api/arsenal/plan           → plan tool activation for a family
GET  /api/arsenal/status         → activation status
GET  /api/arsenal/activation     → current activation plan
GET  /api/ai-redteam/playbook    → AI red-team techniques

── APPROVALS / AUTHORIZATION GATE ────────────────────────────────────────────
GET  /api/approvals              → list all approval requests
POST /api/approvals/request      → request authorization for an action
POST /api/approvals/:id/approve  → approve (unlocks action)
POST /api/approvals/:id/reject   → reject

── RESOURCE PACKS & RUNBOOKS ─────────────────────────────────────────────────
GET  /api/workflow-presets               → workflow preset library
GET  /api/resource-packs                 → all resource packs
GET  /api/resource-packs/:id            → specific pack
POST /api/resource-packs/search         → search by query
GET  /api/agent-prompt-packs            → all prompt packs
GET  /api/agent-prompt-packs/:id        → specific pack
GET  /api/operator-runbooks             → all runbooks
GET  /api/operator-runbooks/:family     → by mission family
GET  /api/forefront-radar               → Forefront pressure lanes
GET  /api/forefront-radar/:id           → specific lane
GET  /api/agent-context/:family         → context bundle for family
GET  /api/operator-doctrine             → Plinian operator doctrine

── MISSION BUNDLES & GATE ────────────────────────────────────────────────────
POST /api/mission-bundles               → create mission bundle
GET  /api/mission-bundles/:missionId    → get bundle
POST /api/mission-gate                  → check gate (approval/receipt required?)

── HYPOTHESIS TRACKING ───────────────────────────────────────────────────────
GET  /api/hypotheses                    → list all hypotheses
POST /api/hypotheses                    → create new hypothesis
PATCH /api/hypotheses/:id               → update status/confidence
POST /api/hypotheses/:id/promote        → promote to finding
POST /api/hypotheses/:id/decompose      → generate work orders

── EVIDENCE ──────────────────────────────────────────────────────────────────
GET  /api/evidence                      → list all evidence
POST /api/evidence                      → add evidence entry
GET  /api/evidence-graph                → evidence graph (nodes + edges)

── FINDINGS & RETESTS ────────────────────────────────────────────────────────
GET  /api/findings                      → list all findings
POST /api/findings                      → create finding
PATCH /api/findings/:id                 → update finding status
POST /api/findings/:id/retest           → queue retest
GET  /api/retests                       → list all retests
PATCH /api/retests/:id                  → update retest result
GET  /api/repro-packs                   → list repro packs
POST /api/repro-packs                   → create repro pack

── PRESSURE PATHS ────────────────────────────────────────────────────────────
GET  /api/pressure-paths                → list pressure paths
POST /api/pressure-paths                → plan pressure paths
POST /api/pressure-paths/canary         → simulate top path locally
POST /api/pressure-paths/duel           → hunter vs skeptic route duel
POST /api/pressure-paths/mutate         → fork survived routes into mutation gauntlet
POST /api/pressure-paths/chains         → compose mutations into fang chains

── WORK ORDERS ───────────────────────────────────────────────────────────────
GET  /api/work-orders                   → list work orders
POST /api/work-orders                   → create work order
PATCH /api/work-orders/:id              → update work order
POST /api/work-orders/:id/complete      → complete work order

── WATCH LOOP & SELF-HEAL ────────────────────────────────────────────────────
GET  /api/watch-loop/status             → last watch cycle status + signals
POST /api/watch-loop/run                → trigger watch cycle
POST /api/self-heal/run                 → trigger self-heal pass

── DRAFTS & ROUTES ───────────────────────────────────────────────────────────
POST /api/mission-drafts                → create mission draft
GET  /api/mission-drafts                → list all drafts
GET  /api/mission-drafts/:id            → get draft
PATCH /api/mission-drafts/:id           → update draft
DELETE /api/mission-drafts/:id          → delete draft
POST /api/route-preview                 → preview routing for draft
GET  /api/routes/:routeId/scorecards    → route scorecards
POST /api/improvement/proposals         → propose improvement
GET  /api/improvement/proposals         → list proposals
POST /api/promotion/evaluate            → evaluate for promotion

── LEARNING / MEMORY ─────────────────────────────────────────────────────────
GET  /api/learning/status               → learning module status
POST /api/learning/run-review           → run route review cycle
GET  /api/memory/capsule                → memory capsule
GET  /api/memory/proposals              → memory proposals
POST /api/memory/proposals              → propose memory entry
POST /api/memory/proposals/:id/accept   → accept proposal
POST /api/memory/proposals/:id/reject   → reject proposal
GET  /api/selfimprove/ledger            → self-improvement ledger

── LLM / TOOLS ───────────────────────────────────────────────────────────────
GET  /api/llm/status                    → LLM provider + model status
POST /api/llm/chat                      → direct LLM chat
POST /api/tools/execute                 → execute a whitelisted tool
POST /api/tools/recon                   → run recon tool
GET  /api/tools                         → tool availability + cache (60s TTL)

── MISSION RUNTIME ───────────────────────────────────────────────────────────
POST /api/mission/start                 → create TempestCommand, spawn operators
POST /api/mission/stop                  → stop active mission
POST /api/mission/pause                 → pause mission
POST /api/mission/resume                → resume mission
GET  /api/mission/status                → operator states, mission info
GET  /api/mission/findings              → all findings from active mission

── OPERATORS ─────────────────────────────────────────────────────────────────
GET  /api/operators/prompts             → list operator system prompt overrides
POST /api/operators/prompt              → override a system prompt
POST /api/operators/prompt/reset        → reset to default
POST /api/operators/spawn               → spawn operator (archetype + model)
POST /api/operators/terminate           → terminate operator
GET  /api/operators/list                → list all operators
POST /api/operators/:id/task            → dispatch task to operator

── OP GENERAL ────────────────────────────────────────────────────────────────
POST /api/general/plan                  → plan operation from directive
POST /api/general/execute               → execute planned operation
POST /api/general/auto                  → plan + execute combined
GET  /api/general/plan                  → current plan
GET  /api/general/sitreps               → situation reports
POST /api/general/sitrep                → force situation report
POST /api/general/assess                → final strategic assessment

── ATTACK GRAPH ──────────────────────────────────────────────────────────────
POST /api/attack-graph                  → scaffold graph for target
POST /api/attack-graph/ingest           → validate recon-supplied graph

── THE ADMIRAL ───────────────────────────────────────────────────────────────
POST /api/admiral/converse              → chat → draft mission brief
POST /api/admiral/suggest               → suggest based on context
POST /api/admiral/launch                → hand brief to Op General

── BOUNTY PLATFORMS ──────────────────────────────────────────────────────────
GET  /api/bounty/platforms              → list supported platforms
POST /api/bounty/format                 → format finding for platform
POST /api/bounty/submit                 → submit report (dry-run default)
GET  /api/bounty/programs/:platform     → search programs
GET  /api/bounty/credentials            → check configured credentials

── LOCAL AGENTS ──────────────────────────────────────────────────────────────
GET  /api/agents/local/detect           → detect installed+authed agents
POST /api/agents/local/connect          → connect agent(s), optional ping
POST /api/agents/local/ping             → liveness probe (spends quota)
POST /api/agents/local/dispatch         → dispatch prompt (+ optional sessionId)
POST /api/agents/local/disconnect       → disconnect agent
GET  /api/agents/local/status           → connected agents

── SESSIONS ──────────────────────────────────────────────────────────────────
GET  /api/agents/local/sessions         → list all multi-turn sessions
GET  /api/agents/local/sessions/:id     → get session + message history
POST /api/agents/local/sessions         → create new session (returns sessionId)
DELETE /api/agents/local/sessions/:id   → delete session + history

── OUTBOUND WEBHOOKS ─────────────────────────────────────────────────────────
GET  /api/webhooks                      → list registered webhooks
POST /api/webhooks                      → register webhook { url, events[], secret? }
PATCH /api/webhooks/:id                 → enable/disable
DELETE /api/webhooks/:id                → remove
POST /api/webhooks/:id/test             → send test ping

── MCP CLIENT ────────────────────────────────────────────────────────────────
GET  /api/mcp/servers                   → list connected MCP servers
POST /api/mcp/servers/connect           → connect to external MCP server
POST /api/mcp/servers/:id/disconnect    → disconnect
GET  /api/mcp/tools                     → list all remote tools
POST /api/mcp/tools/call                → call { serverId, toolName, args }

── AUTOMATION RULES ──────────────────────────────────────────────────────────
GET  /api/automation/rules              → list all rules
POST /api/automation/rules              → create rule
PATCH /api/automation/rules/:id         → update name/enabled/trigger/action
DELETE /api/automation/rules/:id        → remove rule

── STATIC ────────────────────────────────────────────────────────────────────
GET  /ui/*                              → docs/index.html (embedded UI)
```

---

### 3.3 Sidecar Containers

Each sidecar runs as a separate Docker container and exposes an HTTPS API on port 8080 (container-internal only). T3MP3ST calls them via bearer-token-authenticated HTTPS.

**Setup (one-time):**
```bash
scripts/generate-certs.sh   # generates TLS certs + bearer tokens, writes them to docker/certs/ and .env
docker compose up -d         # starts all four containers
```

**Communication flow:**
```
t3mp3st (:3333)
    │
    ├─ CLOUD_SIDECAR_URL  = https://tempest-cloud:8080
    │    Authorization: Bearer <CLOUD_SIDECAR_TOKEN>
    │    → awscli / prowler / checkov commands
    │
    ├─ BINARY_SIDECAR_URL = https://tempest-binary:8080
    │    Authorization: Bearer <BINARY_SIDECAR_TOKEN>
    │    → strings / nm / readelf / objdump / radare2 / yara / binwalk
    │    → shared /data/uploads volume (read-only in binary sidecar)
    │
    └─ SANDBOX_SIDECAR_URL = https://tempest-sandbox:8080
         Authorization: Bearer <SANDBOX_SIDECAR_TOKEN>
         → ELF execution (QEMU user-mode + strace/ltrace/gdb)
         → PE execution  (Wine64, Windows 10 Pro disguise)
         → Mach-O emulation (Qiling)
         → cap_add: SYS_PTRACE, NET_RAW, NET_ADMIN
         → seccomp:unconfined (required for strace/gdb inside container)
```

If a sidecar is unreachable, T3MP3ST logs a warning and the affected tool calls return an error — the core stack continues running.

---

### 3.4 Persistent State

```
/data/missions/                ← named Docker volume (persists across restarts)
  state.json                  → mission ledger snapshot
  events.jsonl                → append-only event log (one JSON per line)
  evidence/                   → evidence vault entries
  findings/                   → finding records

/data/uploads/                 ← bind mount (scan-target binaries / archives)
```

T3MP3ST loads `state.json` at startup (`loadPersistedState()`) and writes it after every mutation event. This means the mission ledger — hypotheses, findings, evidence, work orders, approvals — survives container restarts as long as the volume is mounted.

---

### 3.5 Environment Variables Reference

```
── Web access / HTTPS proxy ──────────────────────────────────────────────────
TEMPEST_HTTPS_PORT    default: 8443  (host port mapped to nginx :8443 in container)
                      change to 443 for standard HTTPS (may need root)
TEMPEST_PASSWORD      login password; random 32-char if blank (printed to logs)

── T3MP3ST core ──────────────────────────────────────────────────────────────
T3MP3ST_PORT          default: 3333  (internal; nginx proxies to this)
T3MP3ST_HOST          default: 0.0.0.0 (in Docker — nginx handles external access)
T3MP3ST_API_TOKEN     if set, Bearer auth required on all /api/* routes
T3MP3ST_CORS_ORIGIN   additional allowed CORS origin
T3MP3ST_WEBHOOK_URL   comma-separated URLs, pre-loaded as catch-all webhooks

── LLM providers ────────────────────────────────────────────────────────────
ANTHROPIC_API_KEY     for provider: 'anthropic'
OPENROUTER_API_KEY    for provider: 'openrouter'
OPENAI_API_KEY        for provider: 'openai'
AWS_ACCESS_KEY_ID     for provider: 'bedrock'
AWS_SECRET_ACCESS_KEY for provider: 'bedrock'
AWS_REGION            for provider: 'bedrock'

── Local agents ─────────────────────────────────────────────────────────────
HERMES_YOLO           default: enabled  (set to '0' to disable --yolo on Hermes)

── Sidecar connections (set automatically by scripts/generate-certs.sh) ──────
CLOUD_SIDECAR_URL     default: https://tempest-cloud:8080
CLOUD_SIDECAR_TOKEN   bearer token for cloud sidecar (mTLS)
BINARY_SIDECAR_URL    default: https://tempest-binary:8080
BINARY_SIDECAR_TOKEN  bearer token for binary sidecar (mTLS)
SANDBOX_SIDECAR_URL   default: https://tempest-sandbox:8080
SANDBOX_SIDECAR_TOKEN bearer token for sandbox sidecar (mTLS)

── File upload directory ─────────────────────────────────────────────────────
TEMPEST_UPLOADS_DIR   default: ./scan-targets  (bind-mounted to /data/uploads)

── Security scanning ────────────────────────────────────────────────────────
T3MP3ST_SCAN_ROOT     constrains deep-scanner to this directory tree
```

---

### 3.6 MCP Server (Outbound — how external LLMs call T3MP3ST)

The MCP server is a **separate process**, not part of the supervisord container. It is meant to be registered with an external LLM tool like Claude Code.

```
External LLM (Claude Code, Cursor, etc.)
   registers T3MP3ST as an MCP server:
   {
     "mcpServers": {
       "t3mp3st": {
         "command": "node",
         "args": ["/path/to/dist/mcp-server.js"]
       }
     }
   }
           │
           ▼
   Spawns: node dist/mcp-server.js
           │
           ▼
   StdioServerTransport — reads JSON-RPC from stdin, writes to stdout
           │
           ├── ListTools request → returns: security_recon
           │
           └── CallTool: security_recon
                 { target: 'example.com', scan_type: 'standard' }
                         │
                         ▼
                   validateTarget()  ← strict regex: ^[a-zA-Z0-9][a-zA-Z0-9._:-]*$
                         │
                         ▼
                   execFileAsync('nmap', [...args])
                   execFileAsync('dig', [...args])
                         │
                         ▼
                   returns combined stdout as text/plain content
```

Security constraints on the MCP server:
- Target validated against `^[a-zA-Z0-9][a-zA-Z0-9._:-]*$` (no shell metacharacters)
- Only `nmap` and `dig` may be invoked (strict `ALLOWED_BINARIES` map)
- Uses `execFile` (not `exec`) — no shell involved, no injection surface

---

*Generated from source: `src/server.ts`, `src/webhooks.ts`, `src/mcp-client.ts`, `src/mcp-server.ts`, `src/agent/local-agents.ts`, `src/agent/session-store.ts`, `src/automation.ts`, `docker/nginx/nginx.conf`, `supervisord.conf`, `Dockerfile`, `docker-compose.yml`*
