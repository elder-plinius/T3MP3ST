# Model and Harness Comparisons

T3MP3ST model comparisons are built from committed benchmark receipts. The
matrix command aggregates existing artifacts; it never starts containers,
calls a model, or contacts a target.

## Reproduce the committed comparison

```bash
npm run bench:model-matrix
npm run verify:model-matrix
```

The committed Cybench matrix compares Claude Opus 4.7 and 4.8 on the same 15
task IDs, `live-tools` harness label, artifact schema, and pass@1 policy. Its
JSON contains every source artifact path; its Markdown output provides the
human-readable table.

Outcome categories stay separate:

- `success`: the committed strict oracle verdict detected the expected flag;
- `failure`: the benchmark ran but did not satisfy the oracle;
- `abstention`: the artifact explicitly records a refusal, abstention, or
  no-action outcome;
- `infrastructure_error`: the run failed because of a timeout, API, spawn, or
  equivalent harness error;
- `skipped`: the expected artifact is unavailable.

These are system results: model, provider, harness, runtime, tools, target
class, and attempt policy all matter. Historical dates and model versions also
differ. Do not interpret the table as an isolated model-quality ranking.

## Run arbitrary model variants

The refusal-frontier harness accepts any comma-separated OpenRouter model IDs
without source edits:

```bash
# Offline: prints the exact shared corpus and call count; spends no API quota.
node scripts/refusal-frontier.mjs \
  --models anthropic/model-a,openai/model-b \
  --classes crypto,memory \
  --n 3 \
  --dry-run

# API-backed and cost-bearing: requires OPENROUTER_API_KEY.
node scripts/refusal-frontier.mjs \
  --models anthropic/model-a,openai/model-b \
  --classes crypto,memory \
  --n 3 \
  --at comparison-2026-07
```

Every selected model receives the same classes, five-rung corpus, sample count,
judge, and concurrency settings. JSON output retains raw responses and judge
rationales; Markdown output renders model-by-model and cross-model deltas.

Use the fields in [CONTRIBUTION_RECEIPTS](CONTRIBUTION_RECEIPTS.md) when adding
new results. Never commit credentials or private target data, and never present
live external runs without a target-specific authorization receipt.
