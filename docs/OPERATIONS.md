# T3MP3ST Operations Guide

Day-to-day reference for running, connecting, and operating the full tempest-stack.

> **curl note:** All `curl` examples target `https://localhost:8443`. Because Nginx uses a self-signed certificate by default, add `-k` (or `--insecure`) to skip cert verification, or add the cert (`docker/certs/nginx.crt`) to your local trust store.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [First-time setup](#2-first-time-setup)
3. [Build and start](#3-build-and-start)
4. [Verify the stack is healthy](#4-verify-the-stack-is-healthy)
5. [Connect an LLM provider](#5-connect-an-llm-provider)
6. [Connect a local CLI agent](#6-connect-a-local-cli-agent)
7. [Start a mission via the Admiral](#7-start-a-mission-via-the-admiral)
8. [Monitor the event stream (War Room / SSE)](#8-monitor-the-event-stream-war-room--sse)
9. [Multi-turn agent sessions](#9-multi-turn-agent-sessions)
10. [Register outbound webhooks](#10-register-outbound-webhooks)
11. [Create automation rules](#11-create-automation-rules)
12. [Connect an external MCP server](#12-connect-an-external-mcp-server)
13. [Day-to-day commands](#13-day-to-day-commands)
14. [Troubleshooting](#14-troubleshooting)

---

## 1. Prerequisites

| Requirement | Notes |
|---|---|
| Docker Engine 24+ | `docker --version` |
| Docker Compose v2+ | `docker compose version` |
| NVIDIA Container Toolkit | For GPU; omit `deploy:` block in compose for CPU-only |
| At least one LLM provider key | OpenRouter is the default backbone |

No local Node.js, Python, or npm needed — all compilation happens inside Docker.

---

## 2. First-time setup

```bash
# From the T3MP3ST/ directory:
cp .env.example .env
```

Open `.env` and fill in at least one LLM provider key. Everything else can stay blank to use defaults.

Minimum viable `.env` (cloud LLM, no local model):
```bash
OPENROUTER_API_KEY=sk-or-v1-your-key-here
LLM_PROVIDER=openrouter
LLM_MODEL=anthropic/claude-opus-4-8
```

---

## 3. Build and start

```bash
# From the Projects/ parent directory (build context spans all three services):
docker compose -f T3MP3ST/docker-compose.yml build

# Start in the background:
docker compose -f T3MP3ST/docker-compose.yml up -d

# Tail logs:
docker compose -f T3MP3ST/docker-compose.yml logs -f
```

After startup, T3MP3ST is reachable at **https://localhost:8443** (accept the self-signed cert warning). Nginx terminates HTTPS on port 8443 and proxies to the Node.js server on the internal port 3333 — port 3333 is never exposed to the host.

**To change the host port**, set `TEMPEST_HTTPS_PORT` in `.env`:
```bash
TEMPEST_HTTPS_PORT=443   # standard HTTPS (may need root)
TEMPEST_HTTPS_PORT=9443  # any other port
```
To change the internal listen port on nginx itself (rarely needed), edit `docker/nginx/nginx.conf` line `listen 8443 ssl;` and update the `ports:` mapping in `docker-compose.yml` to match.

---

## 4. Verify the stack is healthy

```bash
# Docker compose health:
docker compose -f T3MP3ST/docker-compose.yml ps

# T3MP3ST health endpoint (via Nginx — add -k for self-signed cert):
curl -sk https://localhost:8443/health

# Full smoke suite:
docker exec tempest-stack /opt/t3mp3st/scripts/test-container.sh

# Preflight (checks installed tools, providers, API connectivity):
curl -sk https://localhost:8443/api/preflight | jq .
```

---

## 5. Connect an LLM provider

T3MP3ST supports 8 providers. Set vars in `.env` and restart.

| Provider | Key var | `LLM_PROVIDER` value |
|---|---|---|
| OpenRouter | `OPENROUTER_API_KEY` | `openrouter` |
| Anthropic direct | `ANTHROPIC_API_KEY` | `anthropic` |
| OpenAI | `OPENAI_API_KEY` | `openai` |
| Groq | `GROQ_API_KEY` | `groq` |
| Together AI | `TOGETHER_API_KEY` | `together` |
| HuggingFace | `HUGGINGFACE_TOKEN` | `huggingface` |
| Replicate | `REPLICATE_API_TOKEN` | `replicate` |
| Venice | `VENICE_API_KEY` | `venice` |

To switch provider at runtime without restarting:

```bash
curl -s -X POST https://localhost:8443/api/llm/provider \
  -H "Content-Type: application/json" \
  -d '{"provider": "anthropic", "model": "claude-opus-4-8"}'
```

Test it:

```bash
curl -s -X POST https://localhost:8443/api/llm/chat \
  -H "Content-Type: application/json" \
  -d '{"messages": [{"role": "user", "content": "ping"}]}' | jq .content
```

---

## 6. Connect a local CLI agent

T3MP3ST can spawn Claude Code, OpenAI Codex, and Hermes as local agents — using their own credentials, not T3MP3ST's keys.

### 6.1 Check which agents are detected

Auth detection is presence-only (file existence, not contents):

```bash
curl -s https://localhost:8443/api/agents/local/status | jq .
# Returns: { "claudeCode": true, "codex": false, "hermes": true }
```

### 6.2 Dispatch a task to a local agent

```bash
curl -s -X POST https://localhost:8443/api/agents/local/dispatch \
  -H "Content-Type: application/json" \
  -d '{
    "agent": "claude-code",
    "prompt": "Review the authentication logic in this repo and list any issues.",
    "cwd": "/opt/t3mp3st"
  }' | jq .output
```

### 6.3 Dispatch with a persistent session (multi-turn)

```bash
# First turn — create a new session
curl -s -X POST https://localhost:8443/api/agents/sessions \
  -H "Content-Type: application/json" \
  -d '{"agentId": "claude-code"}' | jq .id
# → "sess_abc123"

# Subsequent turns — pass sessionId to carry context forward
curl -s -X POST https://localhost:8443/api/agents/local/dispatch \
  -H "Content-Type: application/json" \
  -d '{
    "agent": "claude-code",
    "prompt": "Now look at the rate limiting — is it consistent?",
    "sessionId": "sess_abc123"
  }' | jq .output
```

---

## 7. Start a mission via the Admiral

The Admiral is the natural-language mission planner. Describe what you want to test; it produces a phased runbook.

```bash
# Start a conversation with the Admiral
curl -s -X POST https://localhost:8443/api/admiral/converse \
  -H "Content-Type: application/json" \
  -d '{"message": "I need to test the authentication on api.example.com"}' \
  | jq .reply

# List active missions
curl -s https://localhost:8443/api/missions | jq '.[].id'

# Get mission detail
curl -s https://localhost:8443/api/missions/<id> | jq .

# Approve a pending action (approval gate)
curl -s -X POST https://localhost:8443/api/missions/<id>/approve \
  -H "Content-Type: application/json" \
  -d '{"actionId": "<action_id>", "approved": true}'

# View findings for a mission
curl -s https://localhost:8443/api/missions/<id>/findings | jq .

# Accept a finding
curl -s -X POST https://localhost:8443/api/missions/<id>/findings/<fid>/accept \
  -H "Content-Type: application/json" \
  -d '{"risk": "high", "notes": "Confirmed auth bypass on /api/admin"}'
```

---

## 8. Monitor the event stream (War Room / SSE)

All internal events broadcast over SSE. The War Room UI connects here; you can also tail it from the CLI.

```bash
# Tail all events
curl -N https://localhost:8443/api/events

# Or with jq parsing:
curl -N https://localhost:8443/api/events | while read line; do
  echo "$line" | grep '^data:' | sed 's/^data://' | jq -c . 2>/dev/null
done
```

Key event types:

| Event | Meaning |
|---|---|
| `mission:created` | New mission started |
| `mission:phase:started` | Phase transition |
| `finding:added` | New finding surfaced |
| `finding:accepted` | Finding accepted with risk rating |
| `approval:requested` | Agent awaiting operator approval |
| `approval:decision` | Approval gate resolved |
| `agent:started` | Agent operator spawned |
| `agent:output` | Streamed agent output chunk |
| `agent:done` | Agent finished |
| `tool:execute` | Arsenal tool invoked |
| `tool:result` | Tool completed |
| `automation:triggered` | An automation rule fired |
| `webhook:fired` | Outbound webhook delivery attempted |

---

## 9. Multi-turn agent sessions

Sessions maintain conversation history across multiple dispatches, so agents build on prior context.

```bash
# Create a session
curl -s -X POST https://localhost:8443/api/agents/sessions \
  -H "Content-Type: application/json" \
  -d '{"agentId": "claude-code"}' | jq .

# List sessions
curl -s https://localhost:8443/api/agents/sessions | jq '.[].id'

# Get session history
curl -s https://localhost:8443/api/agents/sessions/<id> | jq .messages

# Delete a session
curl -s -X DELETE https://localhost:8443/api/agents/sessions/<id>
```

Pass `"sessionId": "<id>"` in any `/api/agents/local/dispatch` call to use an existing session.

---

## 10. Register outbound webhooks

Webhooks deliver signed POST requests to external receivers whenever events fire.

```bash
# Register a webhook (subscribe to all events with "*")
curl -s -X POST https://localhost:8443/api/webhooks \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://your-receiver.example.com/tempest",
    "events": ["finding:added", "approval:requested"],
    "secret": "your-hmac-secret"
  }' | jq .

# List registered webhooks
curl -s https://localhost:8443/api/webhooks | jq '.[].id'

# Enable / disable a webhook
curl -s -X PATCH https://localhost:8443/api/webhooks/<id> \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}'

# Send a test delivery
curl -s -X POST https://localhost:8443/api/webhooks/<id>/test

# Delete a webhook
curl -s -X DELETE https://localhost:8443/api/webhooks/<id>
```

Pre-register catch-all webhooks at startup via `.env`:
```bash
T3MP3ST_WEBHOOK_URL=https://receiver1.example.com/hook,https://receiver2.example.com/hook
```

### Verifying signatures on the receiving end

Every delivery includes:
- `X-Tempest-Signature: sha256=<hmac>` — HMAC-SHA256 of the raw body using your secret
- `X-Tempest-Event: <event-type>`
- `X-Tempest-Delivery: <uuid>`

Retry behaviour: 3 attempts total (immediately, +1s, +5s, +30s). Idempotency key = `X-Tempest-Delivery`.

---

## 11. Create automation rules

Automation rules fire actions when specific events match a condition — no polling required.

```bash
# Create a rule: log when any finding is added
curl -s -X POST https://localhost:8443/api/automation/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Log all findings",
    "trigger": { "event": "finding:added" },
    "action": { "type": "log", "message": "New finding: {{payload.title}}" }
  }' | jq .id

# Create a rule: dispatch an agent when a critical finding is accepted
curl -s -X POST https://localhost:8443/api/automation/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Auto-investigate critical findings",
    "trigger": {
      "event": "finding:accepted",
      "condition": "payload.risk === '\''critical'\''"
    },
    "action": {
      "type": "dispatch-agent",
      "agentId": "claude-code",
      "promptTemplate": "Investigate this finding and suggest a remediation: {{payload.title}}"
    }
  }' | jq .id

# List all rules
curl -s https://localhost:8443/api/automation/rules | jq '.[] | {id, name, triggerCount}'

# Toggle a rule
curl -s -X PATCH https://localhost:8443/api/automation/rules/<id> \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}'

# Delete a rule
curl -s -X DELETE https://localhost:8443/api/automation/rules/<id>
```

### Action types

| Type | What it does |
|---|---|
| `log` | Emits a message to the event stream (`message` field, supports `{{payload.x}}` interpolation) |
| `fire-webhook` | Triggers a registered webhook by ID (`webhookId` field) |
| `dispatch-agent` | Runs a local agent with a generated prompt (`agentId` + `promptTemplate`) |
| `spawn-operator` | Spawns a full mission operator (`archetype`, `model`, `promptTemplate`) |

### Condition syntax

Conditions are evaluated safely without `eval()`. Supported forms:

```
payload.fieldName === 'value'
payload.fieldName !== 'value'
```

---

## 12. Connect an external MCP server

T3MP3ST is both an MCP server (exposes `security_recon`) and an MCP client (connects to external servers to use their tools).

### 13.1 Connect a stdio server

```bash
curl -s -X POST https://localhost:8443/api/mcp/servers/connect \
  -H "Content-Type: application/json" \
  -d '{
    "id": "filesystem",
    "label": "Filesystem MCP",
    "transport": "stdio",
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
  }' | jq .
```

### 13.2 Connect an SSE server

```bash
curl -s -X POST https://localhost:8443/api/mcp/servers/connect \
  -H "Content-Type: application/json" \
  -d '{
    "id": "remote-recon",
    "label": "Remote Recon Server",
    "transport": "sse",
    "url": "https://your-mcp-server.example.com/sse"
  }' | jq .
```

### 13.3 List connected servers and their tools

```bash
# Servers
curl -s https://localhost:8443/api/mcp/servers | jq '.[].label'

# All remote tools
curl -s https://localhost:8443/api/mcp/tools | jq '.[] | {server: .serverLabel, tool: .name}'
```

### 13.4 Call a remote tool

```bash
curl -s -X POST https://localhost:8443/api/mcp/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "serverId": "filesystem",
    "toolName": "read_file",
    "args": {"path": "/data/missions/latest.json"}
  }' | jq .result

# Disconnect a server
curl -s -X POST https://localhost:8443/api/mcp/servers/<id>/disconnect
```

### 12.5 T3MP3ST as an MCP server

External agents can call T3MP3ST's `security_recon` tool:

```bash
# T3MP3ST MCP server is accessible via the Nginx proxy:
# URL: https://localhost:8443/mcp

# Example: an external Claude Code agent connecting
claude mcp add tempest --transport sse https://localhost:8443/mcp
```

Available tool: `security_recon` — runs `nmap` or `dig` against an authorized target.

---

## 13. Day-to-day commands

```bash
# Rebuild after source changes
docker compose -f T3MP3ST/docker-compose.yml build

# Restart without rebuilding
docker compose -f T3MP3ST/docker-compose.yml restart

# Stop the stack
docker compose -f T3MP3ST/docker-compose.yml down

# Stop and wipe volumes (destroys missions + model weights)
docker compose -f T3MP3ST/docker-compose.yml down -v

# Enter a shell in the container
docker exec -it tempest-stack bash

# View T3MP3ST logs only
docker exec tempest-stack supervisorctl tail -f t3mp3st

# View Nginx logs only
docker exec tempest-stack supervisorctl tail -f nginx

# Check supervisor process status
docker exec tempest-stack supervisorctl status

# Run the smoke suite
docker exec tempest-stack /opt/t3mp3st/scripts/test-container.sh
```

---

## 14. Troubleshooting

### Container won't start

```bash
docker compose -f T3MP3ST/docker-compose.yml logs tempest-stack
```

Common causes:
- Port 8443 already in use on the host — change `TEMPEST_HTTPS_PORT=9443` in `.env`
- Missing `.env` file — run `cp .env.example .env`
- Missing sidecar TLS certs — run `scripts/generate-certs.sh` before first start

### T3MP3ST reports "no LLM provider configured"

Check that at least one provider key is set and `LLM_PROVIDER` matches:

```bash
curl -s https://localhost:8443/api/preflight | jq '.providers'
```

### Local agent not detected

Auth detection checks for credential files on the host, which are mounted into the container at `/root/`. Verify the host paths exist:

```bash
ls ~/.claude/.credentials.json   # Claude Code
ls ~/.codex/auth.json            # Codex
ls ~/.hermes/.env                # Hermes
```

These paths must be bind-mounted in docker-compose.yml if you want local agent support inside the container.

### Webhook deliveries failing

```bash
curl -s https://localhost:8443/api/webhooks | jq '.[] | {id, failCount, lastFiredAt}'
```

High `failCount` means the receiver is unreachable or returning non-2xx. Check receiver logs. The `X-Tempest-Signature` header must be verified before the receiver accepts — make sure the secret matches on both ends.

### Bearer auth rejecting requests

If `T3MP3ST_API_TOKEN` is set, add to every request:

```bash
curl -H "Authorization: Bearer $T3MP3ST_API_TOKEN" https://localhost:8443/api/missions
```

Public paths exempt from auth: `/api/health`, `/api/preflight`, `/api/status`.
