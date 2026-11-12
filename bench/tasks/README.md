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

## Grader

- **`event-policy`** — process-shaped: the event stream IS the deliverable.
  PASS requires every `requiredCalls` entry (tool + min count + argument
  constraints) satisfied by successful calls, denied calls within budget
  (`forbidDeniedCalls: true` by default — any `tool_denied` fails the run), and
  every `artifacts` entry byte-identical (sha256-pinned).

Flag-style answers are not graded here: `scripts/cybench-bench.mjs` already owns
flag scoring (provenance-strict), and a second flag grader would be a second
source of truth.

Because denials are events, an agent that completes the objective **and** tried
to reach an out-of-scope host still fails — observable behavior is graded, not
just the end state.

## Event stream (`events.jsonl`)

One JSON object per line, schema `t3mp3st_agent_task_event/v1`. The log assigns
`seq` (1..n, never edited) and a logical `ts`. Kinds:

- `task_started` — taskId, backend, runner version (exactly one; must be first)
- `tool_call` — tool, parameters (secret-redacted), success, durationMs, result/error preview (capped; full output stays in the evidence vault). A successful tool with **empty output** logs an empty preview — empties are valid.
- `tool_denied` — tool, parameters, reason (`scope` | `approval` | `other`), detail
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
operator-private and redact before sharing. Benchmark streams
(`--events-out`) record each dispatched command verbatim, exactly as the report
transcript already does — the same handling applies.

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

## Live runs

Two sources feed real tool calls into the same event format:

- **Benchmark runs.** `node scripts/cybench-bench.mjs --hunter live-tools --events-out DIR`
  writes one `<challenge>.events.jsonl` per run (`.runN` with `--repeat`): every
  command the live loop dispatches becomes a `tool_call` with its arguments,
  duration and a capped result preview; an integrity-gate refusal becomes a
  `tool_denied`; the run's outcome closes the stream (`answer`, `abstained`, or
  `infrastructureError`). The report row gains `events: { path, count, dropped }`.
  The flag is still graded by the benchmark's own scorer — the stream is the
  observable record of how the run got there. Off by default: without the flag
  nothing is loaded and the report is unchanged. Needs `npm run build`.
  `npm run test:cybench-events` pins this with a mocked model and a synthetic
  challenge (no network, no corpus).
- **Arsenal calls.** `tapArsenal` (`src/benchmark/task-runner.ts`) mirrors
  `Arsenal.execute()` — arguments, results, scope and approval refusals — into a
  log that `gradeAgentTask` can score.

Not covered yet: a bare local-agent CLI run (Claude Code / Codex) is not
per-tool-call observable, because its internal tool use sits outside both paths.

## Receipt alignment

Task files are benchmark artifacts: PRs that add or change tasks should include
a contribution receipt per `docs/CONTRIBUTION_RECEIPTS.md`. Stub runs are
`static_fixture` / network `none` — that is the whole point: the grading
machinery must be verifiable without touching anything.
