# Benchmark artifacts

Every headline number in the top-level README re-derives from the committed result
JSONs in this directory. Run `npm run verify-claims` from the repo root — it recomputes
each claim from these files under a provenance-strict scorer and fails if any number
drifts from its artifact.

Each result file records the **structured verdict** for a challenge run: the score /
detection, canary status, the target id, and (for CVE hunts) the finding metadata. Those
are the fields the scorer reads.

## A note on transcripts

The raw per-run agent **transcripts are intentionally omitted from this public release**.
During a run, an operator's recon commands (`find`, `ls`, `env`) get captured verbatim
into the transcript, which means they can photograph the author's local machine. Rather
than hand-scrub an unbounded capture surface, the release ships the structured verdicts
only. This is lossless for reproducibility: `verify-claims` never reads the transcript
field — it re-derives everything from the verdicts — so every number here remains
independently checkable. To regenerate full transcripts, re-run the harness against the
same challenge suites from scratch.
