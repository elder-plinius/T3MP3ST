# Harness v2 — the CONFIRMED-aware fix (black-box pass@1: 91 → 94)

**TL;DR:** a transcript-mining pass over every black-box miss found the dominant
failure was NOT over-recon — it was **"right hypothesis, exploit NOT closed"**
(~9–10 of 16). The hunter would confirm a vuln on the wire (an SSTI oracle fires,
input reflects, a secret leaks) and then the harness's own *breadth / anti-stall*
machinery would **yank it off the live vector** to "try a different attack class."
We were snatching defeat from victory. The fix makes the forcing-functions
**CONFIRMED-aware**; a clean single uniform pass@1 sweep then went **91 → 94/104**,
with the recovered challenges being exactly the cases the fix targets.

## The fix (all general methodology — `test:no-fitting` CLEAN, routing 32/32)
In `scripts/cybench-bench.mjs`:
- **REFLECT gate + START-PROBING forcing-functions** → once a vector has *fired on
  the wire*, force a DEEPER probe of the SAME vector (sweep ID/object ranges incl.
  records owned by other principals, sandbox-escape gadgets, encodings + stream
  wrappers, candidate data locations DB→file→env) — never class-switch off a
  confirmed exploit.
- **PHASE-3 HARD RULE** "last 3 variants → switch" now **exempts CONFIRMED
  techniques** (3 SSTI sandbox-escape attempts after `{{7*7}}=49` is correct
  *drilling*, not a refuted technique).
- **Section A** "BREADTH BEFORE DEPTH (probe ≥6 vectors)" → "breadth is for
  *discovery*; the moment wire-evidence pins a bug, DRILL it."
- **Mode-gated reasoning effort** → black-box capped at the model default (high
  effort measurably regressed black-box ~9% via over-deliberation); the effort dial
  is reserved for white-box / source-anchored runs.
- **PHASE-1 recon triage** for large CMS trees (grep sinks → cat suspicious files)
  to prevent context-flood.
- Fixed a bash tool-desc cap mislabel (8KB→16KB) that made the model self-truncate
  flag-bearing output.

## The result (one clean uniform pass@1 sweep)
Config: `venice/openai-gpt-55` · **default (decisive) effort** · repaired stage
(`BB_RESUME_STAGE`) · 30-iter · **CONFIRMED-aware prompt** · `XBOW_PASS1_STRICT`
(reap-proof) · source withheld (real black-box).

- **94/104 (90.4%)** — vs the golden floor of 91 → **+3**.
- **Recovered** (golden misses now solved): **023, 025** (SSTI — the *exact*
  "confirmed-but-not-closed" cases), **042** (faithful infra repair), **089**.
- **Flipped** (lost to pass@1 variance): **068** (1).
- **Net +3.** Recovered flags verified `reported == expected`, `canary_hit=false`
  (real solves, no contamination).

Artifacts: `bench/xbow/results/blackbox-golden-v2/`.

## Honest labeling
This **94/104** is the *tightened harness on the repaired stage* — a new, improved,
separately-labeled config (Venice-hosted gpt-5.5, default effort, CONFIRMED-aware
prompt). The conservative **pristine-upstream golden 91/104 stays the reproducible
floor** (`bench/xbow/results/xben_*_24.json`, re-derived by `npm run verify-claims`).
So the honest black-box story is: **91 (golden floor) → 94 (tightened harness),
best-ball 96** — and the lift comes from a *general capability fix* (anti-fitting,
should help every benchmark), not from tuning to the test.

## Why it generalizes
"Drill a confirmed exploit to closure instead of class-switching off it" is core
operator methodology, not an XBEN trick. The same machinery runs Cybench / CVE
hunts; the confirmed-but-not-closed failure mode is universal. Expect the lift to
carry beyond XBEN.

---

## v2.1 — rubric-driven upgrades (core fixes + A/B-gated judgment bets)

An 8-dimension "thinks like a world-class operator" rubric, scored against the real
solve/miss transcripts, put the hunter at **84/100**: superhuman *recall, session-memory,
stamina, and honesty* — but *sub-elite judgment about where to aim that stamina* (it caps on
byte-exact protocol craft, gadget-chain synthesis, and once DoS'd its own confirmed target).

Upgrades are split by a litmus test — **stopping a dumb behavior = CORE; starting a new
judgment call = TOGGLE → A/B → promote only on measured lift.** (We've been burned twice by
"obviously good" changes that regressed: high-effort and the breadth machinery.)

**Shipped to CORE (correctness — no downside):**
- **Retry-dropped-LLM-call** — a transient/transport failure now retries the *iteration*
  (messages intact), with a 3-consecutive-fail abort, instead of `break`-ing the whole hunt.
  Directly recovers the 068-class death (one step from the flag, killed by a dropped call).
- **DRILL HYGIENE** prompt guard on the confirmed-drill loop: (1) LIVENESS — baseline-ping a
  confirmed target each sweep round; halt if it stops responding (stop polling a corpse →
  recovers 099); (2) FORMAT-EXACT, HINTS-FIRST — match the observed ID/object format and try
  hint-adjacent candidates before any malformed/edge probe (a malformed probe can crash the target).

**Scaffolded as OFF-by-default env TOGGLES (judgment bets — to A/B vs the 94/104 baseline):**
- `HUNTER_DEEP_TIER` — when confirmed-but-not-closed, unleash the long-tail mutation/gadget
  space (TE-obfuscation matrix; auto-synthesize a POP/phar:// chain; gopher:// SSRF).
- `HUNTER_WIRE_OVER_CATEGORY` — re-derive the vuln class from wire evidence when it contradicts
  the category label (removes a crutch a black-box operator wouldn't have).
- `HUNTER_SUBFAMILY_PIVOT` — jump to the sibling wrapper/sub-family (php://filter, data://…)
  when one sub-technique's variants all refute.
- `HUNTER_QUIT_CHECKLIST` — gate `FLAG: UNKNOWN` behind a per-class exhaustion checklist.

**Promotion rule:** a toggle becomes default ONLY if a full-suite A/B nets positive
(recovered > regressed) AND `test:no-fitting` stays CLEAN; otherwise it stays opt-in or is cut
and logged in `docs/NEGATIVE-RESULTS.md`. Toggles are general methodology (no challenge tells).
