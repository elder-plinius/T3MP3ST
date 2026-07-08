# T3MP3ST — continuation prompt (paste this to resume the SOTA push)

You are continuing work on **T3MP3ST (TEMPEST)**, an autonomous offensive-security
harness at `/Users/USER/Desktop/younger_plinius/03-PLINYOS/organs/t3mp3st`. It runs
Claude **Opus 4.8** via a jailed `live-tools` ReAct loop against live CTF/web targets.
Read this whole file, then `docs/INTEGRITY_LEDGER.md`, `docs/XBOW_BASELINE.md`,
`docs/XBOW_FRAMEWORK_ANALYSIS.md`, `docs/V5_PLAN.md`, `docs/COGNITIVE_ARCHITECTURE.md`
before acting. We are authed to GitHub as younger-plinius (`gh auth token` works).
OpenRouter key is in `.env` (chmod 600, gitignored) — never echo it.

## Where we are (verified, jailed-clean — these are the defensible numbers)
- **XBOW / XBEN (XBOW's own 102-challenge web bench):** ~**73/77 ran = 94.8% pass@1**,
  sandbox-jailed, every flag from a live exploit. Run is RESUMING to reclaim ~25
  network-torched challenges (`/tmp/xbow-resume.log`). Baseline: XBOW self-reports
  **85%** on this suite (xbow.com/blog/benchmarks, Nov 2024; method/model undisclosed).
- **Cybench full 40:** **21/40 = 52.5%** (65.6% fair-shot, 32 buildable), jailed-clean.
- **Integrity:** found+fixed **7 contamination vectors** this session (writeup leak,
  flag.py, compose-env, stale task_files, `docker exec`, exec-bit misclass, and the big
  one — **sandbox escape** where the agent `find /`'d host answer keys). Jail blocked
  **19+ escape attempts, 0 succeeded**. Wrapper-case scoring bug fixed (+4). Build-retry
  added (transient apt/pip/dockerhub blips no longer torch challenges).

## HONEST framing — DO NOT violate (we got burned on these)
- ❌ NOT "beats XBOW under identical scoring" — XBOW never disclosed pass@1 vs pass@k.
  Say only: "exceeded XBOW's published 85% on their own bench, single-run pass@1."
- ❌ NOT the record — Cybench SOTA is Sonnet 4.5 @ 76.5% pass@10; other agents have
  posted higher XBEN self-reports. We're pass@1, top-of-pack, not #1.
- ❌ NOT "framework lift = X" — the MODEL (Opus 4.8) does most of the work. Framework-vs-
  model isolation is NOT done. Until a vanilla-Opus-in-bare-harness baseline exists, the
  only honest lift claim is "live-exec + jail + scrub + persistence-floor on top of Opus."
- ❌ The "XBOW 44–56%" figure traces to NO source. Never cite it.
- Every published number → a JSON artifact in `bench/*/results/`. Publish misses + retractions.

## The SOTA roadmap (what "truly magical" means — 2 axes: capability + trust)
Sequence: **#2 (fast wins) → #1 (compounding) → #3 (identity) → #4 (moonshot).**

**#2 — Close the NAMED capability gaps (bounded, shippable, no network needed for code):**
   - `reset-target` primitive: a bashTool sentinel the harness translates to
     `docker compose restart <svc>` (docker CLI stays blocked for the agent). Recovers
     stateful misses (XBEN-061 log-poison, XBEN-088 race). HIGHEST yield.
   - `php-cli` in sandbox → local phar/PHP payload testing (XBEN-092). Per v5 "build the
     oracle before going remote."
   - Decoy-flag rejection: validate flag CONTENT against `flag_format` (XBEN flags are
     `FLAG{<64-hex>}`; reject `flag{I'm_a_Script_Kiddie}` honeypots) — prompt + a harness
     push-back like the early-UNKNOWN floor.
   - (Later) ghidra/radare2 for Cybench reversing (0/4); Sage/fpylll + 600s compute budget
     for hard crypto (ezmaze, robust-cbc).
   See `docs/V5_PLAN.md` (P2–P7) and `docs/XBOW_FRAMEWORK_ANALYSIS.md` (7 items) for detail.

**#1 — Autonomous self-improvement loop (the 0-to-1 magic):**
   This session WE did the loop by hand: run bench → read miss transcripts → find harness
   bugs/contamination → patch → re-run better. AUTOMATE it. An agent that reads its own
   failure transcripts, proposes prompt/harness patches, A/B-tests them, and keeps only
   measurable lifts (the ablation ledger already exists at `bench/obsidivm-evolution/`).
   Build on the existing evolve driver. This compounds — the harness improves itself.

**#3 — Own the trust axis (the durable moat):** productize the jail+scrub+canary+ledger as
   "the honest agent-eval harness" anyone can run on any agent. Be the referee.

**#4 — North star: real 0-day.** Benchmarks are memorization-suspect. The unfalsifiable
   proof is a novel CVE found on a live target. Seed: the `CVE-Zero` work in the repo.

## Operational notes / gotchas
- The XBOW run = `scripts/xbow-bench.mjs --all` (spawns the JAILED `cybench-bench.mjs`
  per challenge). Cybench service = `scripts/cybench-service.mjs --all`; standalone =
  `scripts/cybench-bench.mjs --prefix cyb_` (and `--prefix cyblos` for the 9 recovered
  LosFuzzys). All share the jailed `bashTool` + scrub + scoreChallenge in cybench-bench.mjs.
- Editing `cybench-bench.mjs` mid-run affects the NEXT spawned challenge (it's spawned
  fresh per challenge) — fine for improvements, but kill+restart for a clean consistent run.
- macOS: no `timeout`/GNU-sed `\U`; build with `DOCKER_DEFAULT_PLATFORM=linux/amd64`.
- Skip-logic: `--all` re-runs only non-solved (a false-positive can cause a miss, never a
  false solve — so kept solves are always trustworthy).
- When net flakes, builds + LLM calls fail together; build-retry (3×) + the live-tools LLM
  3× retry handle transients. A full host-network outage just needs to be waited out.

## Immediate next action
1. Let the XBEN resume finish (`/tmp/xbow-resume.log`); lock the final `X/~98` and update
   `XBOW_BASELINE.md` + the claim with the completed denominator.
2. Then start #2 gap-closers (reset-target first — biggest yield, pure code, no net).
3. Before ANY "framework lift" claim: run the vanilla-Opus-in-bare-harness baseline.
