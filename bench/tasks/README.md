# Agent Tasks — reproducible, observable, graded

A **task** is a committed, self-contained directory that pins everything needed to
answer "did the agent actually do the job?":

- the **prompt** and **allowed tools** handed to the agent,
- the **grader**: named success AND failure criteria,
- optionally a **deterministic stub script** that replays a scripted run.

Every run produces a **run bundle** — `events.jsonl` (an ordered, append-only
event stream: every tool call with its arguments, every gate denial, the final
answer) and `verdict.json` (one line per named check, plus the outcome).

```
bench/tasks/<id>/
  task.json          # the task contract (schema t3mp3st_agent_task/v1)
  negatives/*.json   # negative fixtures: runs that MUST fail, and on which check
```

## Run it

```bash
npm run build                                   # harness modules load from dist/
node scripts/agent-task.mjs --list
node scripts/agent-task.mjs --task egress-receipt-check
npm run test:agent-task                          # all tasks + negative fixtures
```

The default backend is `stub`: it replays the committed script — zero network,
zero real tool execution, CI-safe — so the graded pipeline itself is what is
being exercised. A stub run is **byte-reproducible**: the event log uses a
logical clock (`ts === seq`), so the same task yields byte-identical
`events.jsonl`/`verdict.json` on any machine (pinned by tests).

## Outcome taxonomy

Matches the model-matrix convention; these are graded states, not vibes:

| Outcome | Meaning |
| --- | --- |
| `pass` | every named check green |
| `fail` | a capability/process criterion was not met (the failing checks name it) |
| `abstain` | the agent declined/skipped — counted separately from failure |
| `infrastructure_error` | the harness/backend failed (no `task_finished`, backend error) — never a capability miss |

## Graders

- **`flag-exact`** — CTF-shaped: the final answer must exactly match the
  committed flag.
- **`event-policy`** — process-shaped: the event stream IS the deliverable.
  PASS requires every `requiredCalls` entry (tool + min count + argument
  constraints) satisfied by successful calls, denied calls within budget
  (`forbidDeniedCalls: true` by default — any `tool_denied` fails the run), and
  every `artifacts` entry byte-identical (sha256-pinned).

Because denials are events, an agent that completes the objective **and** tried
to reach an out-of-scope host still fails — observable behavior is graded, not
just the end state.

## Event stream (`events.jsonl`)

One JSON object per line, schema `t3mp3st_agent_task_event/v1`. The log assigns
`seq` (1..n, never edited) and a logical `ts`. Kinds:

- `task_started` — taskId, backend, runner version (exactly one; must be first)
- `tool_call` — tool, parameters (secret-redacted), success, durationMs, result/error preview (capped; full output stays in the evidence vault). A successful tool with **empty output** logs an empty preview — empties are valid.
- `tool_denied` — tool, parameters, reason (`scope` | `approval`), detail
- `note` — free text from the backend
- `task_finished` — answer / abstained / infrastructureError (exactly one)

Lines are strictly validated on parse (fail closed on tampered logs), and the
log enforces the lifecycle invariants: one `task_started` first, one
`task_finished` — a backend that double-finishes violates the contract instead
of silently re-grading.

**Redaction scope, honestly:** event `parameters` pass through Arsenal's
configured-secret scrubbing (the same path as tool results). That scrubber only
masks *configured target-header secrets*. A credential the model itself pastes
into an ordinary parameter value is recorded as-is — treat `events.jsonl` as
operator-private and redact before sharing.

## Runner guarantees

- **Fresh workspace or refusal.** The runner writes each bundle into a fresh
  temp dir; a provided `--out`/`workspaceDir` must be empty or nonexistent. A
  leftover artifact from an earlier run can never satisfy an artifact check.
- **Reserved names.** `events.jsonl` and `verdict.json` belong to the runner; a
  stub or grader artifact path may not shadow them (rejected at validation).
- **Crashes still leave evidence.** A backend that throws gets a
  `task_finished(infrastructureError)` appended, and the partial `events.jsonl`
  plus an `infrastructure_error` verdict are persisted — the bundle is always
  diagnosable. If the backend *finished and then* threw, the finish stands and
  the throw is preserved as a note (never a second, illegal finish).
- **Instrumentation never changes results — and never hides a hole.** `tapArsenal`
  subscribers are fault-isolated: a logging failure drops the event, never the
  tool result. Drops are *counted*: any dropped event makes the evidence
  incomplete, so the run grades `infrastructure_error` (a check named
  `no_dropped_events` fails) — an unloggable scope denial can never quietly
  vanish from a passing run.

## Adding a task

1. Create `bench/tasks/<id>/task.json` (`parseAgentTask` in
   `src/benchmark/task-contract.ts` is the strict validator — when in doubt,
   run the self-test and it will tell you).
2. Add a `stub` script and pin `expectedOutcome`.
3. Add at least one **negative fixture** under `negatives/` with the check it
   must fail (`expectFailingCheck`) — failure criteria are part of the contract.
4. Only name tools that are actually registered in the Arsenal (or mintable
   adapters) — the test suite enforces "advertised = wired" over every
   `allowedTools` / `requiredCalls[].tool` in `bench/tasks/`, the same discipline
   as `no-phantom-tools`.
5. `npm run test:agent-task` (and the vitest suite) must be green; both re-grade
   the committed fixtures.

## Live backends (roadmap)

`tapArsenal` (`src/benchmark/task-runner.ts`) mirrors real Arsenal tool calls —
including arguments and scope-gate refusals — into the same event format, so a
live run through the Arsenal ReAct loop produces a stream the same graders can
score. Wiring a live LLM / local-agent backend is follow-up work; note that a
bare local-agent CLI run is not yet per-tool-call observable (its internal tool
use sits outside the Arsenal receipt boundary).

## Receipt alignment

Task files are benchmark artifacts: PRs that add or change tasks should include
a contribution receipt per `docs/CONTRIBUTION_RECEIPTS.md`. Stub runs are
`static_fixture` / network `none` — that is the whole point: the grading
machinery must be verifiable without touching anything.
