# Contributing To T3MP3ST

T3MP3ST needs contributions from prompt engineers, cyber operators, bug bounty hunters, red-teamers, AI-security researchers, and product-minded builders.

The best contributions make the system more capable while making its evidence and authority boundaries clearer.

The canonical repository and tracker are
[`elder-plinius/T3MP3ST`](https://github.com/elder-plinius/T3MP3ST). Open issues
and pull requests there against `main`. The project uses focused branches,
squash merges, green exact-head CI, and does not permit force-pushing published
review history.

## High-Value Contribution Types

- Add a tool adapter in `src/arsenal/catalog.ts`.
- Add or improve a mission-family prompt pack in `src/resources/`.
- Add a runbook phase with evidence requirements and exit criteria.
- Add a local-safe demo mission in `examples/demo-missions.json`.
- Add a smoke-test check in `scripts/arsenal-smoke.mjs` or `scripts/field-drill.mjs`.
- Improve UI truth labels for preview, wired, installed, gated, synthetic, and live states.
- Add parser support that turns tool output into structured evidence.

## Adapter Checklist

Every adapter should define:

- `id`, `binary`, and human-readable `name`.
- `category` and mission `families`.
- `risk`: `local_read`, `passive`, `active`, `intrusive`, `credential`, or `dangerous`.
- `execution`: `safe_command`, `receipt_required`, `import_only`, or `catalog_only`.
- `networked`: whether it can touch remote systems.
- `evidenceKinds`: what proof the tool should produce.
- `outputFormats`: expected output shape.
- `installHint` and `commandHint`.
- `parserStatus`: `structured`, `text`, or `planned`.
- `notes`: the operational caution or value.

## Prompt Pack Checklist

Prompt packs should include:

- A sharp role frame.
- Operating rules that bind the agent to scope and evidence.
- Expected outputs that reviewers can inspect.
- Escalation rules for uncertainty, scope, and dangerous actions.
- Evidence contracts that say what must be captured before making claims.

## Review Standard

Behavior changes must include outcome-oriented regression coverage. A change
with no relevant tests is blocked. Changed executable lines should reach at
least 50% coverage; documentation-only and metadata-only changes may mark this
not applicable with a reason. Trust-boundary, scope, evidence, provider,
installation, and release changes also need the focused checks for that risk.

Before opening a PR, run the same correctness gate used by CI:

```bash
npm run test:pr
```

For changes that affect claims, run modes, agent/tool execution, target scope,
egress, redaction, reports, or benchmark artifacts, include a contribution
receipt using [`docs/CONTRIBUTION_RECEIPTS.md`](docs/CONTRIBUTION_RECEIPTS.md).

If the API is running:

```bash
npm run arsenal:smoke
npm run field:drill
```

Follow the full [Pull Request Delivery Guide](docs/PULL_REQUEST_DELIVERY.md)
before requesting review. In particular, run:

```bash
git diff --name-status upstream/main...HEAD
```

The PR must stay scoped to its title. Do not include stale-base deletions,
unrelated provider/config churn, benchmark fixture removals, provenance doc
removals, or safety-test removals. If the branch has drifted, recreate it from
current `main` and reapply only the intended change.

Maintainers run `npm run test:release` and `npm audit --audit-level=high` against
the exact release tag before publishing. The tag workflow creates one
deterministic source ZIP, verifies it, records SHA-256 checksums, and retains a
Sigstore provenance bundle. A green PR gate is necessary for review and merge,
but it is not release certification.

Do not include secrets, private tracker content, unlicensed corpora, or
uncoordinated vulnerability details. Use the disclosure channel in
`SECURITY.md` for security-sensitive reports.

## Style

- Prefer clear adapters and evidence contracts over clever hidden behavior.
- Label preview surfaces honestly.
- Keep dangerous capability modeled, gated, and auditable.
- Make the nontechnical path simpler without weakening the expert path.
