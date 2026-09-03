---
title: "API Reference"
summary: "Local HTTP API endpoints grouped by workflow."
description: "Local HTTP API endpoints grouped by workflow."
audience: ["developer", "integrator"]
category: "developer"
status: "current"
source: "T3MP3ST repository"
sourcePath: "docs/API_REFERENCE.md"
updated: "2026-07-20"
---
# T3MP3ST API Reference

The API server is implemented in `src/server.ts`.

Default base URL:

```text
http://127.0.0.1:3333
```

Start it with:

```bash
npm run server
```

The War Room UI is served from `/ui/`; `/` redirects there.

## Security Model

The API is a local operator surface, not a multi-user internet service.

- Default host: `127.0.0.1`
- Default port: `3333`
- Override port with `T3MP3ST_PORT`
- Override bind host with `T3MP3ST_HOST`
- State-changing requests are guarded against foreign browser origins
- Loopback binds reject non-loopback Host headers to reduce DNS-rebinding risk
- Active or networked tool use should have a scope/authorization receipt

Do not expose the server on a public interface without adding your own authentication and network controls.

## Health And Runtime

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Basic server health |
| `GET` | `/api/health` | API health alias |
| `GET` | `/api/preflight` | Local preflight and readiness summary |
| `GET` | `/api/events` | Server-sent event stream |
| `GET` | `/api/mission-context/latest` | Latest mission context snapshot |
| `GET` | `/api/net/proxy` | Current outbound SOCKS5 proxy configuration, with credentials redacted |
| `POST` | `/api/net/proxy` | Set or clear outbound SOCKS5 proxy URL |
| `GET` | `/api/net/ip` | Check observed outbound IP path |

Example:

```bash
curl http://127.0.0.1:3333/api/health
```

## Arsenal And Approvals

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/arsenal/catalog` | Tool catalog and adapter metadata |
| `GET` | `/api/arsenal/status` | Installed/readiness status for arsenal tools |
| `POST` | `/api/arsenal/plan` | Plan tool activation for a mission family |
| `GET` | `/api/arsenal/activation` | Activation guidance |
| `GET` | `/api/arsenal/approvals` | Arsenal approval state |
| `GET` | `/api/approvals` | Approval requests |
| `POST` | `/api/approvals/request` | Create an approval request |
| `POST` | `/api/approvals/:id/approve` | Approve a request |
| `POST` | `/api/approvals/:id/reject` | Reject a request |
| `POST` | `/api/approvals/authorize-target` | Record target authorization |
| `GET` | `/api/tools` | Built-in tool metadata |
| `POST` | `/api/tools/execute` | Execute a named tool |
| `POST` | `/api/tools/recon` | Run recon helper flow |

Tool requests should be scoped to authorized targets. External binary availability comes from the local workstation, not from package installation alone.

## Mission Planning And Execution

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/mission/start` | Start a mission |
| `POST` | `/api/mission/stop` | Stop the current mission |
| `POST` | `/api/mission/pause` | Pause the current mission |
| `POST` | `/api/mission/resume` | Resume the current mission |
| `GET` | `/api/mission/status` | Current mission status |
| `GET` | `/api/mission/report` | Current mission report |
| `GET` | `/api/mission/:id/report` | Report for a mission ID |
| `GET` | `/api/mission/findings` | Findings for the active mission |
| `POST` | `/api/mission-drafts` | Create a mission draft |
| `GET` | `/api/mission-drafts` | List mission drafts |
| `GET` | `/api/mission-drafts/:id` | Read a mission draft |
| `PATCH` | `/api/mission-drafts/:id` | Update a mission draft |
| `DELETE` | `/api/mission-drafts/:id` | Delete a mission draft |
| `POST` | `/api/mission-bundles` | Create a mission bundle |
| `GET` | `/api/mission-bundles/:missionId` | Read mission bundle |
| `POST` | `/api/mission-gate` | Evaluate mission readiness gate |

## General Planner And Admiral

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/general/plan` | Generate an Op General plan |
| `GET` | `/api/general/plan` | Read current plan |
| `POST` | `/api/general/execute` | Execute plan steps |
| `POST` | `/api/general/auto` | Plan and execute automatically |
| `GET` | `/api/general/sitreps` | Read sitrep history |
| `POST` | `/api/general/sitrep` | Create a sitrep |
| `POST` | `/api/general/assess` | Run strategic assessment |
| `POST` | `/api/admiral/converse` | Converse with Op Admiral |
| `POST` | `/api/admiral/suggest` | Request mission suggestions |
| `POST` | `/api/admiral/launch` | Launch from Admiral flow |

## Evidence, Findings, And Retests

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/evidence` | List evidence |
| `POST` | `/api/evidence` | Add evidence |
| `GET` | `/api/evidence-graph` | Evidence graph |
| `GET` | `/api/findings` | List findings |
| `POST` | `/api/findings` | Create finding |
| `PATCH` | `/api/findings/:id` | Update finding |
| `POST` | `/api/findings/:id/retest` | Queue or run retest |
| `GET` | `/api/retests` | List retests |
| `PATCH` | `/api/retests/:id` | Update retest |
| `GET` | `/api/repro-packs` | List reproduction packs |
| `POST` | `/api/repro-packs` | Create reproduction pack |

Evidence and finding payloads must avoid raw secrets. Use redaction helpers in `src/redact.ts` and `src/evidence/` when adding new paths.

## Hypotheses And Work Orders

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/hypotheses` | List hypotheses |
| `POST` | `/api/hypotheses` | Create hypothesis |
| `PATCH` | `/api/hypotheses/:id` | Update hypothesis |
| `POST` | `/api/hypotheses/:id/promote` | Promote hypothesis |
| `POST` | `/api/hypotheses/:id/decompose` | Decompose into work orders |
| `POST` | `/api/hypotheses/:id/work-orders` | Work-order decomposition alias |
| `GET` | `/api/work-orders` | List work orders |
| `POST` | `/api/work-orders` | Create work order |
| `PATCH` | `/api/work-orders/:id` | Update work order |
| `POST` | `/api/work-orders/:id/complete` | Complete work order |

## Resources And Operator Context

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/workflow-presets` | Workflow presets |
| `GET` | `/api/resource-packs` | Resource packs |
| `GET` | `/api/resource-packs/:id` | Resource pack details |
| `POST` | `/api/resource-packs/search` | Search resource packs |
| `GET` | `/api/agent-prompt-packs` | Agent prompt packs |
| `GET` | `/api/agent-prompt-packs/:id` | Prompt pack details |
| `GET` | `/api/operator-runbooks` | Operator runbooks |
| `GET` | `/api/operator-runbooks/:family` | Runbook for a family |
| `GET` | `/api/forefront-radar` | Forefront pressure lanes |
| `GET` | `/api/forefront-radar/:id` | Forefront lane details |
| `GET` | `/api/agent-context/:family` | Combined agent context |
| `GET` | `/api/operator-doctrine` | Operator doctrine |
| `GET` | `/api/ai-redteam/playbook` | AI red-team playbook |

## LLMs, Local Agents, And Operators

Operative prompt save/reset responses include an additive `capabilityDiagnostics` array on the returned operator record. Each diagnostic has a stable `code`, capability identifier, level, and safe message. Edited instruction text is never copied into a diagnostic or update event. See [Authenticated Workflow Boundaries](#authenticated-workflows) for the outcome-code contract.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/llm/status` | LLM status |
| `POST` | `/api/llm/chat` | Send a chat request |
| `POST` | `/api/llm/local` | Test or use a local OpenAI-compatible model endpoint |
| `POST` | `/api/models` | Resolve model list |
| `GET` | `/api/codex/status` | Codex local status |
| `POST` | `/api/codex/probe` | Probe Codex integration |
| `GET` | `/api/agents/local/detect` | Detect local coding agents |
| `POST` | `/api/agents/local/connect` | Connect local agent |
| `POST` | `/api/agents/local/ping` | Ping local agent |
| `POST` | `/api/agents/local/dispatch` | Dispatch to local agent |
| `POST` | `/api/agents/local/disconnect` | Disconnect local agent |
| `GET` | `/api/agents/local/status` | Local agent status |
| `GET` | `/api/operators/prompts` | Operator prompt overrides |
| `POST` | `/api/operators/prompt` | Set operator prompt override |
| `POST` | `/api/operators/prompt/reset` | Reset operator prompt override |
| `POST` | `/api/operators/spawn` | Spawn operator |
| `POST` | `/api/operators/terminate` | Terminate operator |
| `GET` | `/api/operators/list` | List operators |
| `POST` | `/api/operators/:id/task` | Assign operator task |

## White-Box And Attack Graph

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/whitebox/analyze` | Analyze a local repository path |
| `POST` | `/api/attack-graph` | Build or update attack graph |
| `POST` | `/api/attack-graph/ingest` | Ingest graph material |

Repository paths are contained by resolver logic before analysis. Keep that containment intact when extending white-box features.

## Learning And Improvement

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/watch-loop/status` | Watch Loop status |
| `POST` | `/api/watch-loop/run` | Run Watch Loop pulse |
| `POST` | `/api/self-heal/run` | Run self-heal flow |
| `GET` | `/api/pressure-paths` | Pressure path list |
| `POST` | `/api/pressure-paths` | Create pressure path |
| `POST` | `/api/pressure-paths/canary` | Canary pressure path |
| `POST` | `/api/pressure-paths/duel` | Duel pressure path |
| `POST` | `/api/pressure-paths/mutate` | Mutate pressure path |
| `POST` | `/api/pressure-paths/chains` | Chain pressure paths |
| `POST` | `/api/route-preview` | Preview route |
| `GET` | `/api/routes/:routeId/scorecards` | Route scorecards |
| `POST` | `/api/improvement/proposals` | Create improvement proposal |
| `GET` | `/api/improvement/proposals` | List improvement proposals |
| `POST` | `/api/promotion/evaluate` | Evaluate promotion |
| `GET` | `/api/learning/status` | Learning status |
| `POST` | `/api/learning/run-review` | Run learning review |
| `GET` | `/api/memory/capsule` | Memory capsule |
| `GET` | `/api/memory/proposals` | List memory proposals |
| `POST` | `/api/memory/proposals` | Create memory proposal |
| `POST` | `/api/memory/proposals/:id/accept` | Accept memory proposal |
| `POST` | `/api/memory/proposals/:id/reject` | Reject memory proposal |
| `GET` | `/api/selfimprove/ledger` | Self-improvement ledger |

## Bounty Helpers

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/bounty/platforms` | Supported bounty platforms |
| `GET` | `/api/bounty/programs/:platform` | Programs for a platform |
| `GET` | `/api/bounty/credentials` | Credential readiness |
| `POST` | `/api/bounty/format` | Format a report |
| `POST` | `/api/bounty/submit` | Submit through configured platform integration |
