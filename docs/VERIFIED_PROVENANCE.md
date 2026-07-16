# Verified Provenance

T3MP3ST is evidence-first: a finding should say whether it is backed by tool
output, context, or only model reasoning.

If the evidence vault says `Provenance: none` or `model-asserted`, the finding is
not yet verified. Treat it as a hypothesis until a tool result, retest, or
operator-supplied artifact backs the claim.

## What Counts As Tool-Proven

A finding becomes tool-proven when all of these are true:

- The agent requests an Arsenal tool.
- T3MP3ST executes that tool through the harness.
- The returned output is captured as evidence.
- The finding records the tool name or evidence reference that supports it.

Final prose from a model is useful analysis, but it is not the same thing as
tool-backed evidence.

## Keyless And Local-Agent Runs

For keyless runs, connect a local agent in the War Room Settings first: Claude
Code, Codex, Hermes, or another supported local-agent backend.

The local agent must request tools through T3MP3ST. If it only writes a final
answer in prose, the harness has no tool output to attach and findings should stay
unverified/model-asserted.

For a quick sanity check:

1. Start the War Room with `npm run server`.
2. Connect a local agent in Settings.
3. Use a local or explicitly authorized target.
4. Run a harmless reconnaissance path.
5. Open the evidence/finding view and check that at least one finding cites a
   tool name and captured output.

If every finding remains `Provenance: none`, the run may still be useful as a
planning pass, but it did not verify findings through the tool loop.

## Common Reasons Provenance Is Missing

- No API provider or local agent is connected.
- The chosen agent produced prose instead of a tool request.
- The tool request could not be parsed by the local-agent/tool-call bridge.
- The tool was catalog-only, missing locally, or receipt-gated.
- The target or action was out of scope, so the harness correctly refused it.
- The final report promoted model analysis before a retest or evidence item was
  attached.

## Operator Checklist

Before trusting a finding:

- Is there an evidence item?
- Does the evidence item include tool output, a command result, a screenshot, or
  another reproducible artifact?
- Does the finding cite the evidence or tool name?
- Did any receipt or scope gate apply?
- Has the claim been retested or falsified?

When in doubt, keep the finding labeled as unverified and queue a retest.
