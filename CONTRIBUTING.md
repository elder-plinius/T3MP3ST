# Contributing To T3MP3ST

T3MP3ST needs contributions from prompt engineers, cyber operators, bug bounty hunters, red-teamers, AI-security researchers, and product-minded builders.

The best contributions make the system more capable while making its evidence and authority boundaries clearer.

---

## High-Value Contribution Types

- Add a tool adapter in `src/arsenal/catalog.ts`
- Add or improve a mission-family prompt pack in `src/resources/`
- Add a runbook phase with evidence requirements and exit criteria
- Add a local-safe demo mission in `examples/demo-missions.json`
- Add a smoke-test check in `scripts/arsenal-smoke.mjs` or `scripts/field-drill.mjs`
- Improve UI truth labels for preview, wired, installed, gated, synthetic, and live states
- Add parser support that turns tool output into structured evidence
- Add an outbound webhook integration (document in `docs/` what events to subscribe to)
- Add an MCP server connection example (stdio or SSE) that exposes useful external tools
- Add an automation rule preset (event pattern + condition + action) for common workflows

---

## Review Standard

**All builds and tests run inside Docker.** Do not run `npm install` or `pip install` on the host.

```bash
# From the Projects/ root (parent of T3MP3ST/):
docker compose -f T3MP3ST/docker-compose.yml build    # must succeed (TypeScript compile + all deps)

# Start the container and run the smoke suite
docker compose -f T3MP3ST/docker-compose.yml up -d
docker exec tempest-stack /opt/t3mp3st/scripts/test-container.sh    # must be 10/10

# Host-side type and lint checks (requires a local npm install, dev only):
npm run typecheck
npm run lint
npm test
npm run doctor
```

If the API is running:

```bash
npm run arsenal:smoke
npm run field:drill
```

---

## Adapter Checklist

Every adapter in `src/arsenal/catalog.ts` should define:

- `id`, `binary`, and human-readable `name`
- `category` and mission `families`
- `risk`: `local_read`, `passive`, `active`, `intrusive`, `credential`, or `dangerous`
- `execution`: `safe_command`, `receipt_required`, `import_only`, or `catalog_only`
- `networked`: whether it can touch remote systems
- `evidenceKinds`: what proof the tool should produce
- `outputFormats`: expected output shape
- `installHint` and `commandHint`
- `parserStatus`: `structured`, `text`, or `planned`
- `notes`: the operational caution or value

---

## Prompt Pack Checklist

Prompt packs in `src/resources/` should include:

- A sharp role frame
- Operating rules that bind the agent to scope and evidence
- Expected outputs that reviewers can inspect
- Escalation rules for uncertainty, scope, and dangerous actions
- Evidence contracts that say what must be captured before making claims

---

## Automation Rule Contributions

Automation rules (`src/automation.ts` + `POST /api/automation/rules`) bind event patterns to actions. When contributing rule presets:

- Document which events trigger the rule (see event list in `docs/STACK_ARCHITECTURE.md`)
- Specify what condition (if any) gates the action
- Choose the least-privileged action type that achieves the goal
- Test that `triggerCount` increments correctly after container smoke run

---

## Webhook Integration Contributions

When adding documentation or examples for webhook integrations:

- Document which events the integration should subscribe to
- Provide a sample receiver that verifies `X-Tempest-Signature: sha256=<hmac>` before processing
- Note retry behaviour (3 attempts: 1s → 5s → 30s) so receivers can handle duplicates

---

## Style

- Prefer clear adapters and evidence contracts over clever hidden behavior
- Label preview surfaces honestly
- Keep dangerous capability modeled, gated, and auditable
- Make the nontechnical path simpler without weakening the expert path
- No unused TypeScript locals or parameters (`noUnusedLocals` and `noUnusedParameters` are enforced) — prefix intentionally unused params with `_`
