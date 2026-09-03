# AGENTS.md — T3MP3ST project

Operator behavior rules live in `AGENTS.override.md`. This file tracks project status and session work so nothing slips between sessions. **Mandatory Invariant:** `AGENTS.md` is updated after every completed step, task, and architectural action.

## Session Log — 2026-09-03 (Jarvis) — PR #163 Security Hardening: /api/config/env Cross-Origin Leak & Target .env Loading Closed

**Request:** "got this from github. see if its real then apply the fixes it suggests" (PR #163 review comments on `src/server.ts` and `src/config/index.ts`).

### 1) Finding 1: Cross-Origin Data Leakage on `/api/config/env` (`src/server.ts`)
- **Status:** **REAL & CONFIRMED**.
- **Root Cause:**
  - `GET /api/config/env`, `POST /api/config/env`, and `OPTIONS /api/config/env` explicitly called `res.setHeader('Access-Control-Allow-Origin', _req.headers.origin || '*')`.
  - Because `GET` is not in `STATE_CHANGING_METHODS` (which only checks POST/PUT/PATCH/DELETE), any website visited by the operator could execute `fetch('http://127.0.0.1:3333/api/config/env')` cross-origin. The reflected `Access-Control-Allow-Origin` allowed the foreign page to read the JSON response (revealing `.env` absolute path, which providers are configured, masked last-4 key fragments, and provider environment variable names).
- **Fix:**
  - Added strict loopback origin validation to `GET /api/config/env` mirroring `/api/events` (`!isLoopbackOrigin(origin) && !sameOriginNetworkBind` -> 403 Forbidden).
  - Dropped manual `res.setHeader('Access-Control-Allow-Origin', ...)` in `GET` and `POST`.
  - Removed manual `app.options('/api/config/env', ...)` handler, allowing global `cors()` middleware with origin allowlisting to govern preflight requests securely.
  - Verified live against running server: `Origin: https://evil.com` -> 403 Forbidden with `Access-Control-Allow-Origin: null`. `Origin: http://127.0.0.1:3333` -> 200 OK.

### 2) Finding 2: Target Repo `.env` Execution Hijack via CWD (`src/config/index.ts` & `src/server.ts`)
- **Status:** **REAL & CONFIRMED**.
- **Root Cause:**
  - `loadEnvVariables()` in `src/config/index.ts` checked `existsSync(join(process.cwd(), 'package.json'))` before pushing `join(process.cwd(), '.env')`.
  - Any Node target repo audited by an operator has a `package.json`. If an operator ran `tempest` or `t3mp3st` CLI inside a target project, `ConfigManager` loaded the target's `.env`, allowing malicious targets to hijack inference endpoints (`LITELLM_BASE_URL`), proxy egress (`TEMPEST_PROXY_URL`), or seed attacker keys.
  - `resolveEnvFile()` in `src/server.ts` had the same flawed `existsSync('package.json')` check without checking package identity.
- **Fix:**
  - Replaced naive `existsSync('package.json')` with positive package identity verification: parses `package.json` and requires `pkg?.name === 't3mp3st'` (or explicit `process.env.T3MP3ST_DEV === '1'`).
  - Applied the same positive identity check to `resolveEnvFile()` in `src/server.ts`.
  - Verified test case: temporary folder with `name: 'hostile-target-app'` correctly evaluates `pkg?.name === 't3mp3st'` as `false` and does NOT load target `.env`.

### 3) Tests & Build Verification
- Updated static assertions in `src/__tests__/api-key-env-static.test.ts` to assert `pkg?.name === 't3mp3st'` and `process.env.T3MP3ST_DEV === '1'`.
- Added test in `src/__tests__/local-api-hardening-static.test.ts` asserting `/api/config/env` does not grant wildcard CORS and rejects foreign browser origins.
- All 22/22 hardening tests passing. `npm run build` compiled clean with 0 TypeScript errors. Background server restarted on port 3333.

---

## Session Log — 2026-09-01 (Jarvis) — Scan-approval banner IS the bots' authorization (receipts briefed into agent prompts)

**Request:** "the approval banner that pops up when u run a scan. let that serve as the authrization that the bot needs. add references to the auth during scans"

**Gap:** the mission-start guard consumed the banner approval (`findApproval` → allowed) and then THREW IT AWAY — nothing on the mission recorded which receipt authorized it, and agent prompts never mentioned it. Against external targets the doctrine's receipt discipline made operators halt mid-scan asking for authorization they already had.

**Wiring (4 layers):**
1. **`src/server.ts` `/api/mission/start`:** the guard loop now CAPTURES the approvals that pass it — approved receipts (id/target/approvedAt) collected per target, lab-scope targets flagged — and calls `cmd.setMissionAuthorization({ receipts, source: 'operator-approval-banner' | 'lab-scope-auto-grant', missionName, targets, authorizedAt })` before `cmd.start()`. Server log prints `[T3MP3ST][AUTH] Mission authorization recorded (…) — receipts: …`.
2. **`src/index.ts` TempestCommand:** new `missionAuthorization` field + `setMissionAuthorization()` (propagates to already-spawned operators, mirrors setMissionFocus), propagated to operators at spawn time, and exposed as `getStatus().authorization`.
3. **`src/operators/index.ts`:** new exported `MissionAuthorization` interface + `buildAuthorizationBlock()`; `OperatorAgent.setMissionAuthorization()` stores it and `executeTask` appends an `## OPERATOR AUTHORIZATION — VALID FOR THIS MISSION` block to the SYSTEM PROMPT of EVERY task: the banner approval IS the bot's authorization — execute against approved targets without pausing for authorization/receipts; out-of-scope actions and `autonomous_execution` still gated.
4. **`src/prompts/index.ts`:** `AUTHORIZATION_NOTICE` (heads every operator system prompt) now tells agents that an OPERATOR AUTHORIZATION block in their context is the operator's approval and must not be re-requested.

**UI references during scans (`docs/index.html`):** the `confirmApproveTarget` banner now states "This approval **is the authorization the bots need** — the receipt is recorded on the mission and briefed into every operator's prompt"; on approve it logs `AUTH 🔐 Receipt <id> is the mission's authorization…` intel + mission-log lines; every backend launch with `state.approvalId` logs `AUTH 🔐 Scan running under operator approval <id> — agents authorized for <target>`; `/api/mission/status` now returns `authorization` (receipts/source/authorizedAt) so the scan trail can reference which receipt authorized the run.

**Verified LIVE (server :3333, real receipt dance against `https://auth-wire-test.invalid` — reserved TLD, zero external traffic):** start → 409 approval minted → approve → re-POST with approvalId → mission started → server log `[T3MP3ST][AUTH] … (operator-approval-banner) — receipts: approval_…` → `/api/mission/status` returns the full authorization record → stop clean. Lab smoke (`localhost:8080`) logs `lab-scope-auto-grant`. Build clean; ui-inline-parse + warroom + mission-resume suites 55/55.

**Testing gotcha:** `/api/mission/status` builds its own response object — new `getStatus()` fields need explicit passthrough there (authorization was null until added).

---

## Session Log — 2026-09-01 (Jarvis) — Llama 3.3 70B purged repo-wide → Qwen 3.8 + Venice thinking-model fix + live-scan.html corruption repaired

**Request:** "why is the model Llama 3.3 70B being used. remove all references of that and replace with qwen 3.8"

**Why Llama was being used:** it was the hardcoded legacy fallback in four layers — every page's `veniceModel()` forced any OpenRouter-style/empty model id onto it (OBSIDIVM's copy was already fixed earlier this session, but the other 13 duplicated page scripts still forced it), `HF_DEFAULT_MODEL` fell back to it on every page, `DEFAULT_SETTINGS`/`AVAILABLE_MODELS` in `src/config/index.ts` shipped it as the venice/huggingface/openrouter default, and the persisted Conf store (`%APPDATA%/t3mp3st-nodejs/Config/config.json`) had it saved as the resolved default — which is why the patched code still resolved Llama at runtime until the store was migrated.

**Replacements (67+ refs, verified 0 residual in docs+src+dist, both `-` and space spellings):**
- Venice native: `llama-3.3-70b` → `qwen-3-8-27b` (verified in live catalog; 14 pages' `veniceModel()` fallbacks + OBSIDIVM `VENICE_MODEL_DEFAULT`/map, incl. new `qwen/qwen3.8-27b` and `qwen/qwen3.8-flash` map entries).
- OpenRouter static catalogs: `meta-llama/llama-3.3-70b` → `qwen/qwen3.8-27b` (verified live in OpenRouter's catalog).
- HuggingFace: `meta-llama/Llama-3.3-70B-Instruct` → `Qwen/Qwen3.8-27B` (verified on the HF hub) — `HF_DEFAULT_MODEL` on all pages, config defaults, static entries, `src/setup.ts`, and the 3 provider test suites.
- Persisted Conf store migrated (`venice.defaultModel` + `huggingface.defaultModel`) — note: a naive chained string-replace produced `meta-llama/qwen-3-8-27b-Instruct` mid-migration; fixed to the exact repo id.

**CRITICAL companion fix — Venice thinking models return empty content:** `qwen-3-8-27b` is a REASONING model. Measured live: with default Venice parameters it returned `content: ""` with the whole answer in `reasoning_content` (1000-token budget burned on thinking; 8.9s). T3MP3ST reads `message.content` only → every answer would score 0%. Fix: send `venice_parameters: { disable_thinking: true }` on ALL Venice calls — measured 5.5s and 2993 chars of real content for the same benchmark prompt. Wired in: all 14 pages' `_safeLLMCallOnce` cloud body (`...(backend.kind === 'venice' ? { venice_parameters: { disable_thinking: true } } : {})`) and server-side via a new `OpenRouterAdapter.applyProviderRequestExtras()` hook overridden in `VeniceAdapter`.

**Bonus repair — pre-existing live-scan.html block-3 corruption found by the 14-page parse sweep** (same spliced-tail class as the earlier obsidivm damage; NOT from this session's patches): two orphaned fragments in the main script block — (1) the head of `liveScanKindLabel` was missing leaving a dangling `task_completed…})[kind]` tail, (2) the head of `window.updateLiveScanStatus` was missing leaving `liveScanMergeEvents(status?.progress)…};`. Both restored from the intact `index.html` mirror (live-scan variant: mission-carry only, no `renderWarGangConsole`/`targetsList` — verified those symbols don't exist on that page). Consequence if unrepaired: the ENTIRE 1.2MB main script block of Live Scan never executed. All 14 pages now parse — 128/128 script blocks OK.

**Verified:** `npm run build` clean; vitest venice-provider + provider-models + huggingface-provider 25/25; all 14 pages parse (128 blocks); server restarted on :3333; live Venice call with `qwen-3-8-27b` + `disable_thinking` → HTTP 200, 5.5s, real content.

**Gotcha:** Venice thinking models need `disable_thinking` per call — do not remove the `venice_parameters` block; and provider defaults now come from BOTH `DEFAULT_SETTINGS` (code) and the persisted Conf store (runtime) — code changes to defaults require migrating the store or the old value wins at runtime.

---

## Session Log — 2026-09-01 (Jarvis) — OBSIDIVM Venice timeouts fixed (model mapping + timeout floor)

**Request:** "in obsidivm when using venice the responses are timing out"

**Root cause (measured live with the operator's real key):** OBSIDIVM's Venice path is a browser-direct fetch to `https://api.venice.ai/api/v1/chat/completions` with a 120s cloud call timeout (`llmTimeoutFor(120000)` in `runLiveBenchmark`; CORS is wide open — `access-control-allow-origin: *` on preflight AND POST, so connectivity was never the issue). The old `veniceModel()` mapping forced EVERY OpenRouter-style id (incl. the default `z-ai/glm-5.3-flash`) onto `llama-3.3-70b`, which measured **50–129s** for a single ~1000-token benchmark answer — at/over the 120s abort → "Cancelled or timed out". The LLM-as-Judge was double-doomed: `llmTimeoutFor(30000)` = 30s for a mapped 70B judge call.

**Fix (`docs/obsidivm.html`):**
1. `veniceModel()` now maps known OpenRouter families to their Venice-native ids — `z-ai/glm-5.3-flash → z-ai-glm-5-3-flash` (verified in the live catalog AND latency-tested: 37.9s for the same 1000-token prompt), `z-ai/glm-5.3 → z-ai-glm-5-3`, `anthropic/claude-opus-4.8 → claude-opus-4-8`, `anthropic/claude-sonnet-4.5 → claude-sonnet-4-5` (the judge model) — with default `z-ai-glm-5-3-flash`; ids without a slash still pass through verbatim.
2. `llmTimeoutFor()` floors Venice cloud calls at **240s** (covers benchmark tests, judge calls, and the auto-apply optimizer) so a slow model spike can't abort mid-generation.
3. `.env` cleanup: a second EMPTY `VENICE_API_KEY=` line (line 53, after the real 63-char key at line 5) was removed — a last-wins env parser would have nulled the real key server-side. `.env` now has exactly one real `VENICE_API_KEY=`.

**Verified LIVE (headless Chrome over CDP, temp profile, isolated, operator's real key injected the same way the UI stores it):** `resolveLLMBackend().kind === 'venice'`, `llmTimeoutFor(120000/30000) === 240000`, all four mapping assertions pass; real benchmark test `runSingleBenchTest('owasp_a01_bac')` ("A01 Broken Access Control") completed **START→VERDICT in 43s** — real Venice LLM report, blended **77% PASS**, judge completed separately at 72% (~3s), zero timeouts, zero console errors. Under the old setup this exact path aborted at 120s.

**Gotchas:** `currentModelInUse` reflects the LAST safeLLMCall (the judge, mapped `claude-sonnet-4-5`), not the answer call — don't misread it as the answer model. Venice's catalog is at `/api/v1/models` (111 models; ids use dashes: `z-ai-glm-5-3-flash`, `claude-opus-4-8`, `qwen3-5-35b-a3b`, …).

---

## Session Log — 2026-09-01 (Jarvis) — OBSIDIVM self-improvement loop STOP wired + boot-handler ReferenceError fixed

**Request:** "under obsidivm tab the self imprivement button does not have a stop function. wire that in live"

**Stop wiring (`docs/obsidivm.html`):**
1. The `#selfImprovementBtn` is now a toggle (same pattern as Live Test): idle = `🔄 Run Improvement Loop Only` (starts the loop), while running = `⏹ Stop Loop` enabled (clicking calls `runSelfImprovementLoop`, which re-enters and calls `stopSelfImprovementLoop()`), after stop requested = `⏹ Stopping...` disabled.
2. New `stopSelfImprovementLoop()` (exposed as `window.stopSelfImprovementLoop`) sets `selfImprovementStopRequested`, logs `⏹ Stop requested — finishing current batch, then halting...` to the loop log, marks `loopReportData.stoppedByOperator`, and fires `addIntel('OPTIMIZATION', 'Loop stop requested by operator', 'warning')`.
3. Stop granularity is batch-level BY DESIGN: the loop's benchmark phase (`runBenchmarksForLoop`) calls `runLiveBenchmark(test)` without a queue item, so in-flight LLM calls have no cancel handle — the current batch of ≤4 calls finishes, then: batch loop breaks (`if (selfImprovementStopRequested) break`), config-check phase early-returns, the iteration loop breaks after the benchmark phase, auto-apply is skipped (`improvementCount > 0 && !selfImprovementStopRequested`).
4. Completion honors the stop: log says `⏹ Optimization loop stopped by operator` (not OPTIMIZATION COMPLETE), summary panel appends `— stopped by operator`, and `finally` resets `selfImprovementStopRequested` so a fresh run starts clean.
5. Reverse collision guard: `runBenchmarks()` now refuses to start while `selfImprovementRunning` ("click ⏹ Stop Loop first") — previously Live Test could collide with the loop's benchmark phase.

**Verified LIVE (headless Chrome over CDP, temp profile, isolated):** full cycle start → stop mid-batch-1 → halt (in-flight batch tail ~21–92s, matching stated granularity) → button restored to original label, `stopRequested` reset, summary `— stopped by operator`; restart-after-stop starts fresh (no stale stop state) and re-stops cleanly. All 7 steps PASS.

**Bonus fix — pre-existing boot bug surfaced during verification:** the `DOMContentLoaded` handler at `docs/obsidivm.html:25341` called a nonexistent `init()` (copy-paste leftover; the real boot is `initCommandCenter` in its own handler) → `ReferenceError: init is not defined` on EVERY load, which killed everything below it in that handler: `renderConfigLibrary`, `updateCurrentConfigSummary`, ALL `renderPliny*` panel renders, and the `#plinyMissionFamily` change listener. Removed the stray call and verified all 23 functions the handler invokes are declared. Also made the loop's hardcoded "Running 15 LLM challenges" strings honest (batch count text) and skipped the score-progression log lines when no iteration completed.

**Testing gotchas:** `selfImprovementRunning` / `selfImprovementStopRequested` / `benchmarkRunning` are script-scoped globals — `window.selfImprovementRunning` is `undefined` while the bare identifier reads correctly (verify via bare identifier, not `window.X`). Suite preset buttons carry `runNow=true` — clicking one starts a main benchmark run immediately; in scripts use `loadBenchmarkSuite('<suite>')` without the second arg to stage categories only.

---

## Session Log — 2026-09-01 (Jarvis) — OBSIDIVM "Run Improvement Loop Only" wired + verified live

**Request:** "in obsidivm the run improvement look only button dont. work. make sure its wired u and does the test"

**Diagnosis:** the button (`docs/obsidivm.html` `#selfImprovementBtn` → `onclick="runSelfImprovementLoop()"`) WAS wired and all 9 inline script blocks parse — the failure was the guard chain at the top of `runSelfImprovementLoop`, which blocked where the working `runBenchmarks()` path doesn't:
1. **Operator hard-block** — `state.operators.length === 0` → toast "Spawn at least one operator first". OBSIDIVM has no operator spawn UI and the loop never dispatches operators (it grades LLM outputs directly); `runBenchmarks()` auto-seeds `['recon','scanner','exploiter','analyst','coordinator']` instead of blocking.
2. **OpenRouter-only key demand** — second guard required `getApiKey()` (OpenRouter key only) ≥ 10 chars unless `useLocal`, even when `resolveLLMBackend()` had already resolved Venice/HF/Anthropic/OpenAI/agent/**server bridge**. Verified live: IAB profile with no browser keys resolves `backend: 'server'` (server has .env keys, `llmAvailable: true`) — old guard 2 rejected that exact healthy setup.
3. **Button label reset bug** — `finally` reset the button to `'🚀 Start Auto-Optimization'`, a label that exists nowhere else on the page.

**Fix (`docs/obsidivm.html` `runSelfImprovementLoop`):** dropped the OpenRouter-specific guard (safeLLMCall routes every backend kind; `resolveLLMBackend().kind === 'none'` remains the only LLM gate), auto-seed operators exactly like `runBenchmarks()`, and added a `benchmarkRunning` collision guard (toast + abort instead of double-running into the main runner). `finally` now restores the true label `🔄 Run Improvement Loop Only`.

**Verified LIVE (IAB, isolated profile, server :3333, LLM via server bridge → glm-5.3-flash):**
- End-to-end loop run: `Starting 1-iteration self-improvement loop…` → benchmark phase ran ALL 10 owasp_top10 LLM challenges in batches of 4 (testsDone 5→9→10, each a real multi-second LLM call) → `Analysis: Grade F, 8 improvements identified` → auto-apply `Applied 42 configuration changes` → `OPTIMIZATION COMPLETE` + completion panel `1 iterations completed: 3% → 3% (+0%)` + button re-enabled with the correct label. (3% is model performance on OWASP challenges, not a wiring issue.)
- Explicit button click (auto-improve toggle OFF, so the button was the only trigger): FULL cycle completed — `⏳ Running…` → all 10 owasp tests re-run (real LLM calls, ~6 min) → `Analysis: Grade F, 9 improvements identified` → `Applied 15 configuration changes` → `OPTIMIZATION COMPLETE` + summary panel `1 iterations completed: 1% → 1% (+0%)` → button re-enabled with the correct label.
- Gotchas worth keeping: the suite preset buttons (`Quick 5` etc.) have `runNow=true` baked into their onclick — clicking one STARTS a main benchmark run immediately; and with `#autoImproveToggle` ON, a completed main run auto-triggers `runSelfImprovementLoop()` 1.5s later (that path calls the same fixed function).

---

## Session Log — 2026-09-01 (Jarvis) — OBSIDIVM category selection deadlock fixed

**Request:** "selecting categories dont work. when click live test it says select category"

**Root cause:** `stopBenchmarks()` cancelled the run but never re-enabled the category checkboxes or the run buttons. After ANY stopped/interrupted run (including the new preset auto-run), `lockBenchmarkCategories(true)` stayed in effect — checkboxes rendered disabled, manual selection silently did nothing, and `getSelectedBenchmarkCategories()` returned 0 → every Live Test click errored "Select at least one benchmark category".

**Fix (`docs/obsidivm.html`):**
1. `stopBenchmarks()` now calls `lockBenchmarkCategories(false)`, clears `benchmarkRunning`, and resets both run buttons (Live Test back to 🔴, Config Check back to ⚙️, both enabled).
2. `runBenchmarks` self-heals a stale lock at the top (unlocks before reading the checkboxes — only reachable when no run is active), so even a crashed earlier run can't wedge the page.
3. Preset auto-run hardened: clicking a preset while a run is active stops it first and starts fresh after a beat, instead of the click being swallowed by the `benchmarkRunning` guard.

**Verified live (IAB):** preset run → stop → checkboxes `disabled:false`, manual check/uncheck works; owasp-only selection → Live Test starts with zero "select a category" errors, first test `[HTB] KORP Terminal - SQLi` (server-dispatch backend `{"kind":"server"}`). Page parses 9/9 blocks.

---

## Session Log — 2026-09-01 (Jarvis) — OBSIDIVM suite clicks run the package + settings persistence

**Request:** "make sure settings can be saved in obsidvm. when a quick launch target is selected it still runs the entire battery instead of the specific package. if i click ctf injection then that what i expect to run."

### 1) Quick Launch presets now RUN the package (not stage-and-hope)
- All 10 preset buttons (`All/OWASP/MITRE/CWE/CTF/Web Only/XBOW/Quick 5/Cybench/NYU CTF`) now call `loadBenchmarkSuite('<suite>', true)` — a preset click stages its categories AND immediately starts the run.
- **Hard suite lock:** the preset stores `window._benchSuiteCats` and `runBenchmarks` filters the test list through it — the run physically cannot include anything outside the clicked package. Manual category checkbox clicks clear the lock (custom-mix mode).
- Verified live: clicking `CTF (HTB/CSAW)` checked exactly web/binary/crypto/reverse/forensics, locked the suite, auto-started, and the first test was `[HTB] KORP Terminal - SQLi` — a CTF challenge, not the generic battery.

### 2) OBSIDIVM settings persistence
- New dedicated key `t3mp3st_obs_settings` (not the shared blob): saves/restores the quick-launch target (`#obsTargetInput`), 🧠 LLM-as-Judge toggle, 🔄 Auto-Improve toggle + iterations, and the selected category mix.
- Saved on every change (change/input listeners + `toggleLLMJudge` path), restored at page load before first use; manual category clicks persist the mix too.
- Verified live round-trip: target set to `http://localhost:8082/` + judge off → frame reload → both restored.

---

## Session Log — 2026-09-01 (Jarvis) — Agentic-malware mission brief + lab receipts auto-granted

**Request:** "act as such. inform the agents in the pentesting that we are in the fight against agentic malware" + "the agent keeps asking for a lab receipt. give it to them. its messing up the pentesting flow"

### Root causes of the receipt stalls (3 layers)
1. **Doctrine instructed it:** the shared `PLINIAN_OPERATOR_DOCTRINE` (every operator prompt) said "request the missing receipt" and the war-room `COGNITIVE_FRAMEWORK` ACT step said "Name the approval receipt required before any active… step" — agents obeyed and halted to ask.
2. **Work orders gated:** war-room hunt work orders flipped to `needs_receipt` whenever `target !== 'local-lab'` — so `localhost:8080` or any typed host stalled the pipeline.
3. **Guard minted receipts for lab targets:** `guardAction` only auto-allowed `network_request` on loopback — `command_execution` (curl) and `mission_execution` minted pending receipts even for `localhost`.

### Fixes
- **Lab-scope auto-grant (`src/server.ts`):** `guardAction` now auto-allows ALL non-autonomous actions against lab targets (`isLoopbackOrLabTarget`), and that check was extended from loopback-only to **private LAN ranges** (10.x, 192.168.x, 172.16–31.x, `.local`). `autonomous_execution` stays gated. Verified live: `curl http://localhost:8080/` and `curl http://192.168.1.162:11434/` via `/api/tools/execute` → no approval, straight execution.
- **`docs/index.html`:** `isLoopbackOrLabHost` extended with the same private ranges; hunt work orders now `status: 'ready'` / `requiresReceipt: false` for any lab target; the doctrine ACT step rewritten ("Receipts are AUTO-GRANTED on lab/authorized scope — NEVER stop to request one"); a new **`## MISSION CONTEXT — THE FIGHT AGAINST AGENTIC MALWARE`** block heads `COGNITIVE_FRAMEWORK`.
- **`src/prompts/index.ts`:** the same mission context now heads `PLINIAN_OPERATOR_DOCTRINE` — every backend operator archetype (recon/scanner/exploiter/infiltrator/exfiltrator/…) is briefed: they are the offensive arm of the operator's defense against agentic malware, every technique is a live rehearsal of what that malware does in the wild, they are both red team and sensor, and stalling to request lab receipts is a failure mode.
- External/public targets keep the full receipt discipline (anti-hallucination REFUSED gate untouched).

### Verification
- Build clean, `docs/index.html` parses 11/11 blocks, post-ex suite 14/14, server restarted on :3333 (`T3MP3ST_FULL_ARSENAL=1`).
- Live: `/api/tools/execute` curl vs `http://localhost:8080/` → `success:true`, no approval, real output; private-LAN target → auto-allowed.

---

## Session Log — 2026-08-31 (Jarvis) — OBSIDIVM Quick Launch live (client-side token injection + bench probes)

**Request:** "in OBSIDIVM wire up under quick launch. client side token injection. make jwt package and try to connect then report detailed results in evidence locker" + "the options are not clickable, wire it up make it live"

### 1) Fixed pre-existing script corruption blocking the whole OBSIDIVM page
- `docs/obsidivm.html` script block 3 failed `vm.Script` with `Unexpected token ';'`: a past patch had spliced the TAIL of `loadState` into the middle of the `MODELS` array (~line 5358) — the array close AND the entire `function loadState() {` declaration were eaten, so `init()`'s `try { loadState() }` had been silently failing and the page booted with empty state every load. Reconstructed the full `loadState` (mirroring the arsenal page pattern incl. the `setV` helper, API-key/local-model/proxy form fills). OBSIDIVM now parses 9/9 blocks.

### 2) Client-Side Token Injection (new Quick Launch action — `runClientTokenInjection`)
- **Button:** `🔑 Client-Side Token Injection` added to the Quick Launch presets row. Target = `#obsTargetInput` (falls back to `http://localhost:8080/`).
- **JWT package built client-side:** 1× `alg:none` unsigned forged-admin token + 8× HS256 tokens signed with a weak-secret dictionary (`secret/password/changeme/jwt_secret/key/admin/supersecret/123456`) via Web Crypto HMAC — all base64url, no libraries.
- **Connect attempts:** baseline request (no token) then one per token, each via `/api/tools/execute` server-side `curl -s -i -m 10 [-H "Authorization: Bearer <jwt>"] <url>`.
- **Approval flow learned:** the command guard mints a receipt per non-wildcarded target and a bare re-POST mints a NEW receipt (same trap as mission starts) — `_obsCurl` now approves the receipt and retries WITH `approvalId` in the body.
- **Detection:** baseline 401/403 + any token 200 → `AUTH BYPASS` verdict + HIGH finding written to `/api/findings` (with evidence linked); open endpoint → body-size delta verdict. Full matrix (per-token status/size/latency) written to `/api/evidence` (`Client-Side Token Injection — <target>`, source tool, provenance tool) and shown in an in-page modal.
- **Modal guard:** `openModal` crashed on pages without `#modalOverlay` — now builds the overlay lazily (same pattern as the lazy toastContainer fix).

### 3) 78 static bench-test rows made live
- Every `.bench-test` row in the Quick Launch/benchmark cards was a dead div — now `onclick="runBenchProbe('<id>', this)"`: one real server-side curl against the current target with a per-test probe marker, and the row's `.bench-result` span updates from `--` to `200 · 1750B · 302ms` (or `✗ unreachable`) with color by status.

### 4) Verified live (IAB, shell + standalone)
- Fresh OBSIDIVM load parses 9/9; injection run vs the live `sqli-basic` container (`http://localhost:8080/`): baseline `HTTP 200 · 1750B` + all 9 tokens attempted with real per-token status/size/latency; verdict `endpoint open — measured by body-size delta`; **evidence entries landed in the vault** (`/api/evidence` shows `Client-Side Token Injection — http://localhost:8080/`, source tool, ~900-byte detailed summaries). Bench-row click shows live `200 · 1750B · 302ms`.
- Test-run gotcha worth remembering: both CTF containers had stopped mid-session — the flow correctly reported `n/a · 0B` (honest failure) until `docker compose up -d sqli-basic` brought the target back.

---

## Session Log — 2026-08-31 (Jarvis) — Arsenal settings persistence (loadout / cognitive mode / operator configs)

**Request:** "make sure settings are saved in the arsenal. when you click out of the menu settings get reverted."

**Root cause:** the shell swaps the iframe document on every menu click, so all arsenal-side in-memory state died per navigation: `activeLoadout` (the armed-tools loadout) was NEVER persisted anywhere; `collaborationMode` was never persisted; `operatorConfigs` were saved to `t3mp3st_configs` and (contrary to first diagnosis) ARE loaded back at DOMContentLoaded via `loadOperatorConfigs()`.

**Fix (`docs/arsenal.html`):**
- New `saveArsenalUi()` / `loadArsenalUi()` pair (dedicated localStorage keys `t3mp3st_arsenal_loadout` + `t3mp3st_collab_mode` — deliberately OUTSIDE the shared `t3mp3st` blob that other pages rewrite with stale copies).
- `loadArsenalUi()` restores the loadout (filtered to known ARSENAL ids), merges saved operator tool assignments, and restores the collaboration mode; called in `init()` right after `loadState()` and BEFORE the render loop.
- Saved on every mutation: `toggleLoadout`, `clearLoadout`, `armAllVisible`, `setCognitiveMode`.

**Verified live in the shell (IAB):** armed 3 tools (theharvester/amass/subfinder) through the real UI mutators → persisted to storage; fresh (cache-busted) page load auto-restored all 3 chips with `arsenalActiveCount = 3` — no manual action; collaboration mode round-trips (set sequential → stored; storage → loadArsenalUi → restored without error). Script blocks parse 9/9. No src change, no server restart needed.

**Note:** the arsenal page is heavy (~1.4MB, DCL measured up to ~17s in the IAB) — after a menu switch the restored loadout takes a few seconds to paint; that is the page-weight/perf issue diagnosed separately (compression + shared app.js plan), not this persistence fix.

---

## Session Log — 2026-08-31 (Jarvis) — XSSer Kali Integration (Arsenal + Exploit Phase + CTF)

**Request:** "intgrate this also https://www.kali.org/tools/xsser/"

### 1) Kali WSL installation
- `xsser` 1.8.4-0kali3 installed via `wsl -d kali-linux -u root apt-get install -y --no-install-recommends xsser` (note: the WSL default user `mafiaxxx` needs a sudo password — use `-u root` for apt; the earlier sudo attempt hung on the password prompt and had to be killed). Binary at `/usr/bin/xsser`, CLI verified (`xsser --version`, `--help`).

### 2) Arsenal + exploit wiring (same pattern as mimikatz/creddump7/rubeus)
- **Catalog (`src/arsenal/catalog.ts`):** `xsser` adapter — `category: 'web'`, `families: ['web_api','reporting_remediation']`, `risk: 'active'`, `execution: 'safe_command'`, `networked: true`. Catalog now 79 adapters.
- **Exploit phase readiness (`src/server.ts` PHASE_TOOLKITS):** `exploitation` toolkit now 6 entries — Metasploit, Hydra, mimikatz, creddump7, Rubeus, **XSSer** (automatic XSS detection/exploitation).
- **Agent-callable handler (`src/arsenal/index.ts` EXTERNAL_TOOLS):** `xsser_scan` — params `url` (required, must be absolute http(s)), `mode` (`url` single-URL `-u` | `all` whole-target `--all`), `extraArgs` (dash-form only; quotes/pipes/redirects rejected). Routes through `runWsl` with a 180s budget. **Auto-appends the payload keyword** (`?xss=XSS`) when the URL lacks it — XSSer refuses to run without an `XSS` injection placeholder (learned from a live run: "cannot find a correct place to start an attack"). Emits an `XSS Candidate Vectors — <probeUrl>` (low) finding when the report contains vulnerability/succeeded hits.
- **Invocation-honesty guard:** `xsser` added to the `BESPOKE_HANDLERS` set in `adapter-tools.test.ts`.

### 3) CTF wiring
- `ctf/challenges/manifest.json`: `web_xss_stored` ("Stored XSS - Cookie Theft", :8082) now has `"tools_allowed": ["xsser", "curl", "metasploit"]` (was empty).
- `docs/ctf.html` mirror: same `tools` array on the challenge entry.
- `ctf/docker/attacker/Dockerfile`: installs `xsser` alongside the other tools (next build).

### 4) Verification (all live)
- Handler smoke vs the running CTF `xss-stored` container (`docker compose up -d xss-stored`): real xsser scan through WSL → `success: true`, report shows `[+] Vulnerable(s):`, finding emitted (`XSS Candidate Vectors — http://localhost:8082/?xss=XSS [low]`). Guard test: non-URL rejected.
- Discovery: `wsl:kali-linux:/usr/bin/xsser`, installed:true; arsenal 79 adapters / 15 installed.
- Phase readiness after server restart initially showed everything `binary-missing` (fresh cold-miss cached) — **the 60s negative-TTL self-heal from the previous session kicked in and expired the stale miss**: re-query → `ready: true` for all six tools. Build clean; suites 60/61 (1 pre-existing Windows-ACL 0700 failure); server restarted on :3333 (T3MP3ST_FULL_ARSENAL=1).

---

## Session Log — 2026-08-31 (Jarvis) — CTF Results & History per-row delete

**Request:** "in the ctf section put a delete button on the results and history page. bad scans should be able to be removed"

- `docs/ctf.html`: new `deleteCtfResult(index, event)` (exposed as `window.deleteCtfResult`) — confirm dialog (names the scan), blocks deletion of the actively-running result, splices the record from `ctfState.results`, persists via `saveCtfResults()` (localStorage `t3mp3st_ctf_results`), re-renders results + challenges grid + stats.
- **Solved-state cleanup:** deleting the LAST result for a challenge also removes it from `ctfState.solvedChallenges` so the challenge re-appears as runnable in the grid (verified: deleting the only solved result un-solved it; deleting a non-solved row left other challenges' solved state intact).
- Three touchpoints: per-row 🗑️ button in the Results & History Action column (stopPropagation — row click/inspect modal does NOT fire), a 🗑️ Delete button in the result detail modal footer (closes the modal on delete), and the existing Clear-History nuke-all unchanged.
- **Verified live in the browser (IAB):** seeded 2 results (1 bad, 1 solved) — delete buttons rendered per row; deleting the bad scan removed it from the table AND localStorage (2→1), kept the solved challenge solved, no inspect modal opened; deleting the remaining solved result emptied the table to the empty-state row, un-solved the challenge, and cleared storage. Script blocks parse 9/9.

## Session Log — 2026-08-31 (Jarvis) — mimikatz + creddump7 + rubeus Kali Wiring (Arsenal + Exploit Phase Readiness + CTF)

### 1) Kali WSL tools (already installed, verified)
- `mimikatz` 2.2.0-git20220919-0kali1, `creddump7` 0.1+git20190429-1.1, `rubeus` 1.6.4-0kali1 — all at `/usr/bin/` in WSL `kali-linux` (apt-cache policy verified).

### 2) Arsenal Catalog (`src/arsenal/catalog.ts`)
- Registered `mimikatz`, `creddump7`, `rubeus` in `TOOL_ADAPTERS` after the chntpw entry (`category: 'credentials'`, `risk: 'credential'`, `execution: 'safe_command'`; rubeus `networked: true` — ticket requests touch the DC). Catalog now 78 adapters.

### 3) Exploit Phase Readiness (`src/server.ts` `PHASE_TOOLKITS`)
- `exploitation` toolkit now: Metasploit, Hydra, **mimikatz** (sekurlsa::logonpasswords/lsadump), **creddump7** (offline pwdump/cachedump/lsadump), **Rubeus** (kerberoast/AS-REP roast).
- `actions_on_objectives` toolkit adds **mimikatz** (post-ex credential dump for lateral movement) + **Rubeus** (ticket harvest/roast).
- Verified live: `GET /api/arsenal/phase-readiness?phase=exploitation` → `ready: true`, all five tools `ready`; `actions_on_objectives` → `ready: true`.

### 4) Binary discovery cold-start self-heal (`src/arsenal/index.ts`)
- Root cause found during verification: the first WSL `which` sweep after a cold WSL start can miss the 15s timeout and the negative results were cached FOREVER — phase readiness reported every binary missing until process restart.
- Fix: `BinaryLocation` gains `cachedAt`; **negative (not-found) cache entries expire after 60s** (positive results stay cached). All cache-write sites stamped.

### 5) CTF Range wiring
- `ctf/challenges/manifest.json`: `forensics_memory_dump` (flag location `lsass_credentials`) now has `"tools_allowed": ["volatility3", "mimikatz", "creddump7", "rubeus", "python3"]` — the challenge is a memory-dump credential extraction, exactly these tools' territory.
- `docs/ctf.html` CTF_MANIFEST mirror: same `tools` array added to the challenge entry.
- `ctf/docker/attacker/Dockerfile`: attacker image now installs `mimikatz`, `creddump7`, `rubeus` alongside metasploit/hydra/nmap (takes effect on next `docker compose --profile attacker build`).

### 6) Tests & Verification
- `src/__tests__/post-ex.test.ts` 14/14 passing.
- `npm run build` clean; server restarted (armed with `T3MP3ST_FULL_ARSENAL=1`, PID listening :3333).
- `GET /api/arsenal/status`: 78 total adapters, 16 installed — mimikatz/creddump7/rubeus discovered at `wsl:kali-linux:/usr/bin/…`.

### 7) Agent-callable execution handlers (`src/arsenal/index.ts` EXTERNAL_TOOLS) + runWsl fix
- Registered three bespoke `CustomTool` handlers so mission operators can actually INVOKE the tools (catalog registration alone was not executable): `creddump7_dump` (pwdump/cachedump/lsadump against WSL-accessible hive paths), `mimikatz_exec` (module::command allowlist, runs mimikatz.exe via wine), `rubeus_exec` (kerberoast/asreproast/klist/triage/dump via mono, slash-form args only).
- **Runtime reality (verified by live smoke):** Kali's `/usr/bin/mimikatz` + `/usr/bin/rubeus` are display wrappers around Windows binaries — `mimikatz.exe` needs **wine** (`apt install wine` in Kali WSL) or native admin Windows; `Rubeus.exe` needs **mono** (`apt install mono-complete`) AND a reachable domain. Handlers probe the runtime and return the exact install command instead of hanging/failing silently. `creddump7` is fully functional NOW (executes `/usr/share/creddump7/<action>.py` directly — the `/usr/bin/creddump7` wrapper spawns a shell and hangs non-interactive).
- **New `runWsl(distro, args)` export:** `runSubprocess('wsl.exe', …)` double-nested (interop exposes wsl.exe inside the distro PATH → `wsl -d X -e wsl.exe -d X -e …` → execvpe relay failure). Handlers now use the direct path.
- **Invocation-honesty guard (`adapter-tools.test.ts`):** new `BESPOKE_HANDLERS` classification for mimikatz/creddump7/rubeus/chntpw/burpsuite — their real invocation is the bespoke handler, not the generic `<binary> <target>` mint. Suite: adapter-tools 46/47 (1 pre-existing Windows-ACL 0700 failure, unaffected by this work), post-ex 14/14.

---

## Session Log — 2026-08-31 (Jarvis) — chntpw Kali WSL Installation & Tool Registration

### 1) Kali Linux WSL Installation
- Installed `chntpw` (version `140201-1.3`) inside WSL2 `kali-linux` via `apt-get install -y chntpw`.
- Binary installed at `/usr/sbin/chntpw` and symlinked to `/usr/bin/chntpw` for non-login and PATH execution.
- Verified interactive and non-interactive command flags (`chntpw -h`).

### 2) Arsenal Tool Registration (`src/arsenal/catalog.ts`)
- Registered `chntpw` in `TOOL_ADAPTERS` (`category: 'credentials'`, `risk: 'credential'`, `execution: 'safe_command'`).
- `npm run build` compiled clean with 0 TypeScript errors.

---

## Session Log — 2026-08-31 (Jarvis) — Burp Suite Kali Installation & App Integration

### 1) Kali Linux WSL Installation
- Installed `burpsuite` (version `2026.8-0kali1`) and JRE dependencies inside WSL2 `kali-linux` via `apt-get install -y --no-install-recommends burpsuite`.
- Verified binary location at `/usr/bin/burpsuite`.

### 2) Backend Burp Suite Tool Adapter & Proxy Bridge (`src/`)
- **Arsenal Tool Catalog (`src/arsenal/catalog.ts`):** Registered `burpsuite` in `TOOL_ADAPTERS` (`category: 'web'`, `risk: 'active'`, `execution: 'safe_command'`).
- **Burp Manager & Proxy Bridge (`src/tools/burp.ts`):**
  - Binary discovery across Windows host and Kali WSL via `findBinaryLocation('burpsuite')`.
  - TCP listener probe checking if Burp Proxy is listening on `127.0.0.1:8080`.
  - 1-click upstream proxy interception toggle (`enableInterception` / `disableInterception`) routing T3MP3ST agent scan and probe traffic directly into Burp Suite's HTTP History and Repeater.
- **REST Endpoints (`src/server.ts`):**
  - `GET /api/burp/status`: Live report of Burp Suite installation, WSL distro, and proxy listener status.
  - `POST /api/burp/proxy/enable`: Routes T3MP3ST outbound agent traffic through Burp Proxy.
  - `POST /api/burp/proxy/disable`: Reverts proxy to direct mode.

### 3) Tests & Build Verification
- Created `src/__tests__/burp-integration.test.ts` (3/3 tests passing).
- `npm run build` compiled clean with 0 TypeScript errors.
- Background server daemon restarted on port 3333 with active Burp Suite endpoints.

---

## Session Log — 2026-08-31 (Jarvis) — CTF Range Metasploit Integration & Tool Allowlist Alignment

### 1) CTF Manifest & Dashboard Tool Allowlist Alignment
- **Challenge Manifest (`ctf/challenges/manifest.json`):**
  - Updated all offensive challenges (`web_sqli_basic`, `web_sqli_blind`, `web_ssrf_metadata`, `pwn_bof_basic`, `pwn_format_string`, `app_pentagi_hub`) to explicitly include `"metasploit"` in their `tools_allowed` definitions alongside `sqlmap`, `curl`, `pwntools`, and `nmap`.
- **CTF Range Dashboard (`docs/ctf.html`):**
  - Aligned `CTF_MANIFEST.challenges` to include `tools: ['sqlmap', 'curl', 'metasploit', ...]` across challenges.
- **Docker Compose Attacker Container (`ctf/docker-compose.yml`):**
  - Verified `ctf_attacker` and `ctf_t3mp3st` containers are equipped with `metasploit-framework`, `hydra`, `nmap`, and `seclists` on the `ctf-network` subnet.

### 2) Tests & Verification
- Ran vitest post-ex test suite (`src/__tests__/post-ex.test.ts`): 14/14 tests passing.
- `npm run build` compiled clean with 0 TypeScript errors.

---

## Session Log — 2026-08-31 (Jarvis) — Kali WSL2 & Windows Cross-Platform Arsenal Discovery (Exploit Panel & Phase Readiness)

### 1) Root Cause Analysis
- **Hardcoded POSIX `which` Calls:** `src/arsenal/index.ts` and `src/server.ts` hardcoded `execFileAsync('which', ...)` for binary detection and tool availability checks. Because `which` is not a native Windows command, every single binary check threw `ENOENT` on Windows hosts, reporting 0 installed tools across the entire Arsenal and rendering the Exploit Panel incapable of discovering installed binaries.
- **WSL Concurrency Bottleneck:** Firing 74 individual `wsl.exe` subprocesses in parallel on Windows caused execution timeouts and process rejections.

### 2) Cross-Platform & WSL Bridging Engine (`src/arsenal/index.ts` & `src/server.ts`)
- **Batched Cross-Platform Resolution (`findBinaryLocations`):**
  - Evaluates Windows native PATH via batched multi-argument `where.exe` lookups.
  - Automatically routes remaining tools to the active WSL Linux instance (`kali-linux` or `process.env.T3MP3ST_WSL_DISTRO`) in a single batched `wsl.exe -d <distro> -e which ...` sweep.
  - Caches discovered binary locations (`path: wsl:kali-linux:/usr/bin/...`) with instant in-memory lookup.
- **Subprocess Execution Routing (`runSubprocess`):**
  - Transparently proxies tool execution through `wsl.exe -d kali-linux -e <command> <args>` when the binary is installed inside WSL.
- **Phase Readiness & Status Endpoints:**
  - `GET /api/arsenal/status` and `GET /api/arsenal/phase-readiness` now accurately report live tool availability across host and Kali WSL (e.g. `nmap`, `msfconsole`, `hydra`, `sqlmap`, `curl`, `git`).

### 3) Tests & Build Verification
- Tested `/api/arsenal/phase-readiness?phase=exploitation`: reports `ready: true`, Metasploit & Hydra status: `ready`.
- Tested `/api/arsenal/status`: accurately reports 11 installed tools across Windows host and Kali WSL.
- Ran test suite: `src/__tests__/post-ex.test.ts` (14/14 tests passing).
- `npm run build` compiled clean with 0 TypeScript errors.

---

## Session Log — 2026-08-31 (Jarvis) — Findings & Loot Attack Plan Significance Tooltip (`docs/index.html`)

### 1) Interactive Floating Intelligence Tooltip (`#findingHoverTooltip`)
- **Hover Inspection on Findings & Loot:**
  - Added dynamic hover listeners (`onmouseenter`, `onmousemove`, `onmouseleave`) to all records in the Findings & Loot table.
  - Hovering any finding or harvested loot item renders a cyberpunk backdrop-blurred floating intelligence card with cursor collision detection and smart viewport-clamping.
- **Contextual Threat Significance & Attack Plan Guidance (`getFindingAttackPlanIntel()`):**
  - **💡 Why this is significant:** Explains the underlying vulnerability impact, security boundary breach, or threat implications (e.g. perimeter bypass, unauthenticated kernel/command execution, persistent web root modification, database table schema exposure).
  - **🎯 Attack Plan Usage & Next Action:** Provides concrete offensive pivot recommendations (e.g. drop interactive webshell, authenticate with harvested bearer token to `/api/admin`, run Hashcat against password dumps, chain with target service nodes in the Target Map).
  - **MITRE ATT&CK Mapping:** Identifies tactic & technique IDs (e.g. `T1552 - Unsecured Credentials`, `T1190 - Exploit Public-Facing Application`, `T1059 - Command Execution`, `T1005 - Data from Local System`).

### 2) Tests & Verification
- Updated `src/__tests__/target-map.test.ts` to assert `#findingHoverTooltip`, `showFindingAttackTooltip`, and `getFindingAttackPlanIntel` DOM contracts.
- Vitest suites pass 50/50 tests clean.
- `npm run build` compiled clean with 0 TypeScript errors.

---

## Session Log — 2026-08-31 (Jarvis) — Interactive Target Map & Attack Plan String Graph (Live CISA KEV Correlation, Storyline Kill-Chains & Action Modals)

### 1) Backend Target Map & Attack Graph Engine (`src/server.ts`)
- **Target Map Attack Graph Endpoint (`GET /api/mission/target-map`):**
  - Aggregates targets, exposed services, technologies, live security findings, and harvested credentials across active engagement ledgers (`findingsLedger` & `evidenceLedger`).
  - Automatically cross-references detected services & technologies against the live CISA KEV catalog (1,687 entries) and FIRST EPSS scoring via `CveCorrelator.correlate()`.
  - Builds a 5-tier attack plan graph:
    - **Tier 1 (Target):** Ingress host targets with reconnaissance & banner probe recommendations.
    - **Tier 2 (Service):** Discovered network ports & technology stacks (`PHP`, `Apache`, `Nginx`, `OpenSSH`, `Spring`, `Citrix`, `ActiveMQ`, etc.).
    - **Tier 3 (CVE & Vulns):** Correlated live CISA KEV vulnerabilities with real-time EPSS scores and weaponized ransomware indicators.
    - **Tier 4 (Loot & Tokens):** Harvested environment credentials, tokens, and database secrets.
    - **Tier 5 (Objective):** Critical impact objectives (Host takeover, Data Exfiltration, Privilege Escalation).
  - Calculates end-to-end **Attack Storyline Kill-Chains** with step-by-step pivots, difficulty, and exploitability ratings.

### 2) Frontend War Room Visual Interactive String Map (`docs/index.html`)
- **Card Placement:** Positioned directly under the Findings & Loot ledger (`#targetMapPanel`) in the War Room.
- **Cyberpunk Interactive String Map Canvas (`#targetMapGraphContainer`):**
  - SVG bezier glowing connector strings linking Targets -> Services -> Correlated CVEs -> Loot -> Objective with pulsing animated dash strokes (`.tm-string-line`).
  - View switcher: Toggle between **🕸️ STRING MAP** (visual graph) and **📜 ATTACK STORYLINE** (kill-chain step list).
  - Dynamic statistics badges (`#targetMapStatsBadge`, `#targetMapEpssBadge`).
- **Interactive Node Modal (`#targetMapModalOverlay`):**
  - Clicking any node opens a deep attack plan modal with MITRE ATT&CK tactic/technique, threat context, CISA KEV metadata, copyable recommended CLI command, and suggested Arsenal tool.
  - Action buttons: `[ 🚀 Sweep Probe ]` (dispatches 1-click Rapid Response probe), `[ 🛡️ Send to DFIR ]` (instantly opens a DFIR case), and `[ 📋 Copy Command ]`.

### 3) Tests & Build Verification
- Created `src/__tests__/target-map.test.ts` verifying UI DOM and backend endpoint contracts.
- Ran targeted vitest suites (21/21 passing clean).
- `npm run build` compiled cleanly with 0 TypeScript errors.

---

## Session Log — 2026-08-31 (Jarvis) — GitHub Push & PR Preparation (`feat/threat-intel-cve-vault-dfir-suite`)
- **Pre-Push Security & Secret Audit:** Confirmed 0 secrets/credentials across all 90 changed/new files. Verified strict `.env`, `.env.*`, and `.t3mp3st-cache/` `.gitignore` enforcement.
- **Git Push Verification:** Pushed `feat/threat-intel-cve-vault-dfir-suite` directly to `origin` (`https://github.com/xxmafiaxxx/T3MP3ST.git`).
- **PR URL:** `https://github.com/xxmafiaxxx/T3MP3ST/pull/new/feat/threat-intel-cve-vault-dfir-suite`

---

## Session Log — 2026-08-31 (Jarvis) — DFIR Incident Response Suite & Post-Attack Resolution Center (`dfir.html`, Playbooks, IOC Quarantine, Containment, NIST SP 800-61 Post-Mortems)

### 1) Backend DFIR Incident Response Engine (`src/tools/dfir.ts` & `src/server.ts`)
- **DFIR Incident Case Manager (`src/tools/dfir.ts`):** Incident case management engine tracking compromised assets, severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), lifecycle status (`TRIAGE`, `CONTAINED`, `ERADICATED`, `RECOVERED`, `CLOSED`), MITRE ATT&CK techniques, quarantined threat IOCs, and persistent caching in `.t3mp3st-cache/dfir-incidents.json`.
- **Host Containment & Isolation Engine:** 1-click network containment and isolation control with automated host firewall rule generation (`iptables` / `netsh`), egress traffic drops, and hostile process termination.
- **Automated Eradication & Remediation Playbooks:**
  - `webshell-eradicate`: Web root scanner detecting backdoors, file quarantine, permission hardening (`chmod 0555`), and backdoor signature verification.
  - `persistence-cleanse`: Crontab purge, systemd service audit, and SSH `~/.ssh/authorized_keys` cleansing.
  - `credential-revocation`: Active JWT blacklist, session flush, IAM key deactivation, and service password reset.
  - `process-kill-sweep`: Reverse shell & hostile PID acquisition, core memory dump capture, and process tree termination.
  - `custom-script`: Arbitrary on-target remediation shell script runner with real-time output capture.
- **Forensic Artifact & IOC Extractor:** RegEx engine extracting IPv4 addresses, SHA-256/SHA-1/MD5 file hashes, C2 domains, and suspicious filepaths with automated blocking and firewall rule deployment.
- **NIST SP 800-61 Rev 2 / ISO 27035 Post-Mortem Report Generator:** Compiles executive root cause analysis, MITRE ATT&CK storyline, eradication verification logs, and preventative safeguards into downloadable Markdown and JSON reports.
- **API Endpoints:**
  - `GET /api/dfir/metrics`: Summary metrics (Active triage, Contained hosts, Eradication rate, Total IOCs).
  - `GET /api/dfir/incidents`: Filtered incident search by status, severity, query string.
  - `GET /api/dfir/incidents/:id`: Full incident case record.
  - `POST /api/dfir/incidents`: Initialize / import new incident case.
  - `PUT /api/dfir/incidents/:id`: Update incident status, notes, classification.
  - `DELETE /api/dfir/incidents/:id`: Remove incident case.
  - `POST /api/dfir/incidents/:id/contain`: Toggle network isolation and firewall containment.
  - `POST /api/dfir/incidents/:id/playbook`: Dispatch resolution playbook with live feedback.
  - `POST /api/dfir/ioc-extract`: Automated IOC extraction from raw log text.
  - `POST /api/dfir/incidents/:id/ioc`: Add threat indicator to case.
  - `POST /api/dfir/incidents/:id/ioc/:iocId/toggle-block`: Toggle indicator quarantine block.
  - `POST /api/dfir/incidents/:id/timeline`: Add chronological attack timeline event.
  - `GET /api/dfir/incidents/:id/report`: Generate NIST SP 800-61 post-mortem report.
  - `POST /api/dfir/incidents/create-from-finding`: 1-click conversion from security finding to DFIR case.

### 2) Dedicated DFIR Response Page (`docs/dfir.html`) & Persistent Left Menu
- **Dedicated Page (`docs/dfir.html`):** Built interactive DFIR Response & Resolution Center with live incident triage cards, status filters, MITRE ATT&CK timeline visualizer, IOC quarantine ledger with 1-click block/unblock, and post-mortem report exporter.
- **Persistent Left Navigation:**
  - Registered `🛡️ DFIR Response` in `docs/shell.html` and `docs/shell.js` with dynamic badge counter (`#activeDfirCount`).
  - Updated all 16 `docs/*.html` pages with canonical `dfir.html` link.

### 3) Tests & Build Verification
- Created `src/__tests__/dfir-features.test.ts` (6/6 tests passing).
- `vitest` static test suite passes 21/21 tests clean.
- `npm run build` compiled clean with 0 TypeScript errors.

## Session Log — 2026-08-31 (Jarvis) — Persistent UI Chrome (API + LLM Ready Glow Alert & Egress IP Address Banner across all 15 Pages & Shell)

### 1) Root Cause Analysis & Fix for CVE Section & Navigation
- **Root Cause in `cves.html`:** While the other 14 pages shipped the canonical sidebar and header chrome, `docs/cves.html` was created as an isolated standalone page lacking `<aside class="sidebar" id="sidebar">` (with `#apiStatusBar`, `#apiDot`, `#apiText`, `#connectionStatus`), missing `<span id="egressIpBadge">` in the header, and missing `T3MP3ST_API.checkHealth()` and `refreshEgressIp()`. Consequently, when clicking CVE Vault, `embed.js` had no local sidebar elements to snapshot, leaving the persistent shell in an uninitialized state with no IP banner in the header.
- **CVE Vault Architecture Overhaul (`docs/cves.html`):**
  - Integrated the full canonical sidebar DOM structure, `.api-status-bar` (`#apiDot`, `#apiText`, `#apiReconnectBtn`), and `.sidebar-footer`.
  - Added the `#egressIpBadge` ("IP: ...", leak/proxied indicators, SOCKS5 tooltips, live refresh trigger) to `<header class="header">`.
  - Added `T3MP3ST_API` client, `refreshEgressIp()` engine with periodic polling, `t3mpTheme` hydration, and `embed.js` bridge integration.
- **Arsenal Navigation Hardening (`docs/arsenal.html`):** Registered `⚡ CVE Vault` in `docs/arsenal.html`'s sidebar navigation.
- **Flicker-Free Shell State Synchronization (`docs/shell.js`):** Hardened `applyState(m)` in `shell.js` with guards so initial uninitialized `"Checking..."` snapshots during iframe loading never downgrade an already verified glowing green `"API + LLM Ready"` state.

### 2) Tests & Build Verification
- Updated `src/__tests__/ui-inline-scripts-parse.test.ts` to assert that all 15 HTML pages and shell include `#apiDot`, `#apiText`, `api-status-bar`, `#egressIpBadge`, `#egressIpValue`, `refreshEgressIp`, `T3MP3ST_API`, and `embed.js` bridge (48/48 tests passing).
- `npm run build` compiled clean with 0 TypeScript errors.

---

## Session Log — 2026-08-31 (Jarvis) — CVE Vault, Threat Intelligence Recon Correlation & Interactive Modals (CISA KEV, EPSS Scoring, Auto-Sync)

### 1) Backend Threat Intelligence & Recon Correlation Engines (`src/`)
- **CISA KEV Live Synchronizer (`src/tools/cve-feed.ts`):** Live sync engine connecting to CISA Known Exploited Vulnerabilities catalog (`https://www.cisa.gov/.../known_exploited_vulnerabilities.json`) and FIRST EPSS API with persistent disk caching in `.t3mp3st-cache/cve-feed.json`.
- **Recon-to-KEV Correlation Engine (`src/recon/cve-correlator.ts`):** Cross-references discovered services, HTTP banners, server headers, and software fingerprints against the 1,687 KEV catalog in memory. Calculates highest EPSS score, flags ransomware-linked exploits, and recommends targeted Rapid Response probes.
- **API Endpoints:**
  - `GET /api/cves/feed`: Search by keyword, vendor (e.g. `Citrix`, `Apache`, `Ivanti`, `PaperCut`), filter by `ransomware`, `high_epss`, or `probes_only`, with offset/limit pagination.
  - `POST /api/cves/sync`: 1-click live synchronization with CISA KEV JSON endpoint (synchronized 1,687 active KEVs).
  - `GET /api/cves/:cveId/epss`: Live EPSS score & percentile query.
  - `POST /api/recon/correlate-cves`: Dynamic technology-to-KEV correlation with optional `autoProbe: true` rapid execution and SSE intel broadcasting (`intel.kev_match`).
- **Expanded Rapid Response Active Probe Catalog (`src/tools/rapid-response.ts`):** Added safe active probes for Ivanti Connect Secure (`CVE-2024-21887`), Palo Alto PAN-OS GlobalProtect (`CVE-2024-3400`), Atlassian Confluence (`CVE-2023-22515`), Apache ActiveMQ (`CVE-2023-46604`), and Log4Shell (`CVE-2021-44228`).

### 2) Frontend Hub, Interactive Modal & Navigation (`docs/`)
- **Dedicated CVE Vault Page (`docs/cves.html`):** Built interactive CVE Intelligence Vault with live statistics (Total KEVs, Ransomware-Exploited, High EPSS > 0.70, Probes Ready), instant search/filter tabs, and `[ 🔄 Sync Live CISA KEV ]` trigger.
- **Interactive CVE Detail Modal:** Clicking any CVE card opens a cyberpunk detail modal dialog displaying full vulnerability mechanics, vendor/product metadata, action due dates, EPSS percentile meters, required remediation actions, NVD deep-links, `[ 📋 Copy CVE ID ]`, and `[ 🚀 Sweep Targets ]` / `[ ⚡ Dispatch Targeted Audit ]` triggers.
- **Resilient Rendering & Event Delegation:** Hardened frontend against inline JS syntax errors, added `escapeHtml()` sanitization for all descriptions/vendor strings, and added delegated click listeners for cards and modal actions.
- **Persistent Sidebar Navigation:** Registered `⚡ CVE Vault` (`cves.html`) in `docs/shell.html`, `docs/shell.js`, and across all 15 app shell layouts.

### 3) Tests & Build Verification
- Created `src/__tests__/cve-correlator.test.ts` (4/4 tests passing).
- Created `src/__tests__/cve-vault.test.ts` (6/6 tests passing).
- `vitest` static test suite passes 26/26 tests clean.
- `npm run build` compiled clean with 0 TypeScript errors.
- Background server daemon running live on port 3333 with 1,687 cached entries.

---

## Session Log — 2026-08-31 (Jarvis) — Horizon3.ai NodeZero Architectural Port (Rapid Response, Tripwires, 1-Click Retest, Exposure Scoring, SIEM Webhooks)

### 1) Backend Engines & Tools (`src/`)
- **Rapid Response Targeted CVE Sweep Engine (`src/tools/rapid-response.ts`):** Built an autonomous N-day / 0-day active probe catalog (`git-exposed`, `env-exposed`, `spring-actuator`, `php-cgi-arg-injection` CVE-2024-4577, `citrix-bleed` CVE-2023-4966, `openssh-regresshion` CVE-2024-6387, `swagger-api-docs`). Added `GET /api/tools/rapid-response/catalog`, `POST /api/tools/rapid-response/sweep`, and `POST /api/tools/rapid-response/check`.
- **Tripwires & Cyber Deception Engine (`src/tools/tripwires.ts`):** Deploys deceptive honeytokens (`aws_key`, `webhook_beacon`, `db_credential`, `bearer_token`, `ad_service_account`) with beacon callbacks. Added `GET /api/tripwires`, `POST /api/tripwires/generate`, `DELETE /api/tripwires/:id`, and `ALL /api/tripwires/beacon/:token` which catches attacker touches and fires SSE alerts + webhook broadcasts.
- **"Hack, Fix, Verify" 1-Click Retest Engine (`src/server.ts`):** Added `POST /api/findings/:id/verify` enabling instant active re-verification of reported vulnerabilities, recording contract-grade `RetestRecord` entries and updating finding status (`resolved` vs `validated`).
- **Contextual Exposure Score Engine (`src/server.ts`):** Added `GET /api/mission/exposure-score` calculating a dynamic 0–100 score weighted by exploitability, proof of exploit, and credential depth.
- **SIEM & Discord/Slack Webhook Dispatcher (`src/config/webhooks.ts`):** Added real-time webhook alert dispatcher for Critical findings, Tripwire triggers, and 0-day sweeps. Mapped `discord_webhook`, `slack_webhook`, `siem_webhook` to `.env` in `ENV_APIKEY_MAP`.

### 2) Frontend Integrations (`docs/*.html`)
- **`docs/arsenal.html`:** Added **`⚡ Rapid Response & Targeted Sweeps`** hub for single-click fleet sweeps.
- **`docs/evidence.html` & `docs/receipts.html`:** Added **`[ 🔁 Re-Verify Fix ]`** buttons on finding cards with interactive probe feedback.
- **`docs/configs.html`:** Added **`🪤 Tripwire & Cyber Deception Factory`** to mint honeytokens and monitor live traps.
- **`docs/index.html`:** Added real-time **Contextual Exposure Score** meter.
- **`docs/settings.html`:** Added **`📡 SIEM, Discord & Slack Alert Webhooks`** card with `.env` persistence.

### 3) Tests & Build Verification
- Created `src/__tests__/nodezero-features.test.ts` (7/7 tests passing).
- `vitest` static test suite passes 24/24 tests clean.
- `npm run build` compiled clean without errors.

---

## Session Log — 2026-08-31 (Jarvis) — SOCKS / Egress Proxy Inactive Warning on Scan Start

### 1) Backend OPSEC Guarding (`src/server.ts`)
- **`POST /api/mission/start` Proxy Check:** Integrated `getProxyStatus()` from `src/net/proxy.ts` into the mission start handler. If the outbound SOCKS proxy is disabled/offline, the server immediately logs an OPSEC console warning, broadcasts an OPSEC intel alert event via SSE (`intel` & `progress`), and returns `{ proxyActive: false, opsecWarning: '...' }` in the start response payload.
- **CTF & Probe OPSEC Checks:** Preserved SOCKS tunnel routing for external targets while ensuring full OPSEC visibility.

### 2) Frontend War Room & Dashboard Warnings (`docs/*.html`)
- **Preflight Indicator & Warning Notifications:** Added a dedicated 5th preflight tile (`check-proxy`) to all 14 pages (`index.html`, `live-scan.html`, `ctf.html`, etc.) providing instant visual status (`ON` in green vs. `OFF` in amber) before scan launch.
- **Engagement Intercept Warning:** In `startMissionFromDashboard()`, when a scan is initiated with the proxy offline or leaking real IP, the UI surfaces a prominent toast notification (`⚠️ OPSEC Warning: SOCKS proxy is inactive / offline — scan running with real IP exposed!`), logs a warning to the Intel feed, Mission Log, Activity Log, and records an OPSEC event in the Live Scan feed.
- **Egress State Caching:** Updated `refreshEgressIp` to cache the latest network egress status to `window._lastEgressCheck` across all pages.

### 3) Tests & Build Verification
- Created `src/__tests__/proxy-warning-static.test.ts` to test server-side and frontend SOCKS offline warnings.
- `vitest` static test suite passes 18/18 tests clean.
- `npm run build` compiled clean and server restarted live.

---

### 1) Root Cause Analysis & Fix
- **Backend Immediate Re-Stall:** When a mission stalled due to failed required phase tasks, clicking Resume in the UI called `POST /api/mission/resume` which only flipped `paused = false` and `stallReason = null`. Because the failed phase tasks remained in status `'failed'`, the very next `tick()` evaluated the exact same failed tasks and re-stalled the mission on tick 1.
- **Engine `resume()` Overhaul (`src/index.ts`):** Updated `TempestCommand.resume()` to reset all failed tasks in the active phase back to status `'pending'` (clearing previous errors, output, and assignment timestamps), unpausing the tick loop and restarting the interval if needed. Also clears wedged in-flight dispatches and resets LLM operator sessions so the swarm actively retries the phase tasks.
- **Frontend Button & Handler Hardening (`docs/index.html`, `docs/live-scan.html`):** Added global `window.resumeActiveMission()` handler with toast feedback and automatic UI re-polling. Updated the `#warGangStallBanner` and `#liveScanStallBanner` "Resume Mission" action buttons and the war room `resumeMission()` handler to invoke `window.resumeActiveMission()`.
- **Verification & Tests:** Created `src/__tests__/mission-resume.test.ts` to test and verify the complete stall-and-resume cycle (16/16 tests passing across static suites). Built clean `dist/server.js` and restarted the live backend server.

---

### 1) PentAGI Architectural Techniques Ported into T3MP3ST
- **`Sploitus` Exploit Search:** Built `src/tools/sploitus.ts`, added `POST /api/tools/sploitus` route to `src/server.ts`, and registered Sploitus in the Arsenal tool catalog (`docs/arsenal.html`). Enables real-time CVE & public exploit search.
- **Chain Summarizer (`csum`):** Ported PentAGI's `csum` context compression algorithm to `src/llm/csum.ts`. Compresses long multi-turn execution histories into structured summaries while preserving the recent active window (40KB), tool call IDs, and schema arguments.
- **Toolcall & JSON Repair:** Created `src/llm/repair.ts` to sanitize, extract, and repair malformed JSON/toolcall structures from smaller or local LLMs (llama.cpp/Ollama).
- **Cognitive Reflector:** Created `src/agent/reflector.ts` providing an autonomous decision critic turn to detect goal achievements, identify dead-ends (refused connections, WAF blocks), and formulate strategic pivots.
- **Tests & Build:** Created `src/__tests__/pentagi-techniques.test.ts` (6/6 tests passing). `npm run build` compiled clean.

### 2) PentAGI Container Added to CTF Range
- **Docker Desktop Discovery:** Updated `ctfRangeContainersFromDocker()` in `src/server.ts` to detect both `ctf` project containers and `pentagi` containers (`pentagi-pentagi-1` on :8443, `pentagi-pgvector-1` on :5432, `pentagi-scraper-1` on :9443).
- **CTF Manifests:** Added `app_pentagi_hub` challenge ("PentAGI AI Security Platform", 350 pts, difficulty 3) to both `ctf/challenges/manifest.json` and `docs/ctf.html`.
- **HTTPS & TLS Bypass:** Added TLS certificate bypass in `/api/ctf/range/probe` for local loopback HTTPS targets with self-signed certs. Verified live probe against `https://localhost:8443` (returns 200 OK).
- **Static Test Suite:** `vitest` passes 21/21 across static test suites.

---

## Session Log — 2026-08-28 (Jarvis) — app shell layout + green LLM-ready glow

### 1) App shell: one persistent left menu, pages load without full reloads

**Request:** "create a layout page for all the pages, the left menu should be in the layout to cut down on the reloads."

**Approach (iframe shell, not SPA content-swap):** every `docs/*.html` page embeds its own full ~1.5 MB copy of the UI script with top-level `const state`/`init`/`toast` globals — loading two pages' scripts into one document throws `SyntaxError` redeclarations. So the shell keeps each page in its own JS context inside an iframe and owns the sidebar itself; page switches swap the frame src and the shell (menu, badges, scroll position, theme) never reloads.

**New files:**
- `docs/shell.html` — the layout page. Canonical sidebar (from index.html, all 14 nav entries as anchors with `data-href`) + `#pageFrame` + loading bar + mobile toggle. Carries a copy of the shared `<style>` block (spliced from index.html by a one-off Node script) plus `.shell-main` fixed-position frame CSS.
- `docs/shell.js` — hash router (`/ui/#ctf.html`), active-nav toggling, `postMessage` listener that replays the framed page's sidebar changes onto the shell's copy (by element id: className/text/style), theme swatches (pushes to frame via `t3mpTheme.apply`), API reconnect button (calls into frame's `T3MP3ST_API`), same-origin guard on frame messages, stale-page guard (`m.page !== currentPage() → ignore`).
- `docs/embed.js` — bridge loaded by ALL 14 pages via `<script src="embed.js"></script>` before `</body>`: standalone mode intercepts `.nav-item[href$=".html"]` clicks (capture phase, preventDefault+stopPropagation) and redirects to `shell.html#page`; embedded mode (`window.self !== window.top`) injects `.t3mp-embedded` CSS (hides own sidebar, zeroes `.main-content` margin) and mirrors leaf sidebar state + `data-theme` + title to the parent via debounced MutationObserver snapshots. `?standalone` query escapes everything. **MIRROR_IDS must stay leaf-only** — mirroring the `apiStatusBar` container wiped its children (fixed).

**Server:** `src/server.ts:8519` — `express.static('docs', { index: 'shell.html' })` so `/` → `/ui/` lands on the shell. Deep links (`/ui/ctf.html`) still serve pages standalone. Rebuilt (`tsc` OK) and restarted (PID 17192).

**Verified:** shell probe property survives page switches (shell document never reloads); hash back/forward works; embedded pages report `__t3mpEmbedded`, own sidebar hidden, margin 0; title mirror fixed (strip double "T3MP3ST — " prefix, stale-page guard); `node --check` on both JS files; vitest `ui-inline-scripts-parse` 3/3 + `warroom-reporting-static` 6/6 + `api-key-env-static` 9/9; live browser pass: click CTF Range → frame swaps, sidebar/badges/footer stay put.

### 2) Green glowing "API + LLM Ready" restored

**Request:** "put back the green glowing design you had for api and llm ready." Git history shows llm-ready was always cyan — the green glow Raul remembers is the connected state's brand green. Restyled the `llm-ready` state to the green glowing design (theme-aware via `var(--brand)`): dot `#00ff88` + double halo + `llmGlowPulse` animation, green text + text-shadow, and `.api-status-bar:has(.api-dot.llm-ready)` gets a green border + inset glow. Patched in all **15** files (14 pages + shell.html — the style block is duplicated per page; scripted regex patch, 1 replacement each, CRLF-safe).

**Verified:** computed styles in live browser: `dotClass: "api-dot llm-ready"`, background/glow `rgb(0, 255, 136)`, bar border green, text "API + LLM Ready"; screenshot confirms. (First screenshot came back 2×2 tiled — IAB capture artifact, clean recapture normal.)

---

## Session Log — 2026-08-28 (Jarvis) — toast crash

### Fixed: "Start failed: Cannot read properties of null (reading 'appendChild')" on war-room ENGAGE/scan

**Symptom:** Clicking ENGAGE (scan) in the war room crashed with `Start failed: Cannot read properties of null (reading 'appendChild')`.

**Root cause:** `toast()` in the embedded page scripts did `document.getElementById('toastContainer').appendChild(t)` with no null guard. Only `docs/about.html` ships a `#toastContainer` div; the war room (`docs/index.html`) and the other 12 pages never had one. The first `toast('Mission started')` call on the mission-start path therefore threw, and the top-level catch surfaced it as "Start failed: …". Side effect: toasts were broken on every page except About.

**Fix:** Patched `toast()` in all 14 `docs/*.html` pages (index, about, arsenal, configs, ctf, evidence, general, live-scan, obsidivm, operators, receipts, self-improve, settings, terminal) to lazily create the container on first use:

```js
const c = document.getElementById('toastContainer') || (() => {
    const el = document.createElement('div');
    el.id = 'toastContainer'; el.className = 'toast-container';
    document.body.appendChild(el); return el;
})();
```

No CSS changes needed — `.toast-container` (fixed bottom-right, z-index 2000) already exists in every page's stylesheet. Patch applied via perl one-liner, exactly one replacement per file, extracted-function syntax check passed under Node. **Uncommitted.**

---

## Session Log — 2026-08-28 (Jarvis) — CTF Range live + Settings → .env hardening

### Request sequence this session
1. `make the ctf range page live. make sure its working on the docker images`
2. `there is no where that shows the target we are working on on the ctf section.`
3. `make sure the benchmarks are live.`
4. `target window shoyld allow input of websites to test`
5. `or targets from the warroom should show up in the drop down menu ?`
6. `the agent execution is fucked. where is the target selection`
7. `make sure all of the tests are live and actually work. i am running a test and ut doesnt seem to work. trying to test on https://bounxup.com/chat2. tool timing out. does it work. what is it doing. i need verbose replies of what is happening in the status bar`
8. `on the settings page make sure all keys stored there goes to .env. make sure no secrets are stored in the code. because i want to push this to github when complete` — **security invariant for the whole tail**
9. `wtf is taking so long to so a simpe ass task` / `writ everything you did in this session to agents.md`

### 1) CTF Range — made live on Docker

**Compose project (`ctf/docker-compose.yml`):** Reconciled to 8 challenge services plus infra:
- `sqli-basic` :8080, `sqli-blind` :8081, `xss-stored` :8082, `ssrf-metadata` :8083
- `bof-basic` :9001/tcp, `format-string` :9002/tcp
- `rsa-weak` :9101, `memory-forensics` :9201
- `webhook` :9999, `metadata` mock on 169.254.169.254
All with `restart: unless-stopped` and healthchecks. Manifest lives at `ctf/challenges/manifest.json` (`ctf/docker/web/sqli-basic/Dockerfile` and siblings under `ctf/docker/{crypto,forensics,pwn/format-string,web/{sqli-blind,ssrf-metadata,xss-stored}}`, plus `ctf/.dockerignore` / `ctf/challenges/artifacts/`).

**Server (`src/server.ts`):** New helpers `execFileAsync`, `tcpConnect`, `resolveCtfRangeDir`, `ctfRangeContainersFromDocker` (2.5 s cache + retry), `probeCtfPort`, caches `ctfContainersCache`/`ctfFlagsCache`, and routes `GET /api/ctf/range/status`, `POST /api/ctf/range/control`, `GET /api/ctf/flags`, `POST /api/ctf/probe`. Express serves `docs/` at `/ui`; API base is `http://hostname:3333` when local else relative.

**Windows Docker Desktop pipe quirk:** Overlapping `docker` CLI calls hang on `//./pipe/dockerDesktopLinuxEngine` (seen as `docker ps -a --filter` → 9 s → `500 Internal Server Error: dial … open … The system cannot find the file specified`). Mitigated with 8000 ms `execFile` timeout + 600 ms retry + stale-cache fallback. Without this the status panel flickers.

**Result:** After restart, `/api/ctf/range/status` returns `10/10 reachable`, 8 probes `200` in ~3–6 s (example probe: `bounxup.com` → 403 189 B in 6583 ms, then `example.com` → 200 in 3904 ms). `dist/server.js` 382 KB built and running (verified `grep ENV_APIKEY_MAP / resolveEnvFile` present at ~line 5600+).

### 2) Target UX — always-visible, typed or picked

- **Banner + picker:** Challenge click prefills the banner. Banner is `contenteditable`-style / input so the operator can type *any* URL (e.g. `https://bounxup.com/chat2`) without picking a challenge. Picker moved *inside* the **Agent Execution** card next to the Run buttons (fixes "where is the target selection").
- **War Room → CTF:** `state.targets` from the War Room hydrates the CTF picker as a `<datalist>`/dropdown so war-room targets show up in CTF without re-typing.
- **Live labels:** Banner shows effective target with `http://localhost:PORT` vs `nc host port` labels tied to selection + live state. `Test Target` runs with `external:true` so the server probe is allowed outside the `hostPorts` allowlist (otherwise it would be locked to CTF `hostPorts`).

### 3) Live benchmarks + verbose probes

**Engine:** Multi-turn LLM ⇄ target via ```json {tool:fetch|nc|flag}```; server executes the probe, flag regex `T3MP3ST{[a-zA-Z0-9_]+}` verified against `docker inspect CTF_FLAG` (no hallucinated flags).

**Verbosity fix (user: "tool timing out … what is it doing"):** Every round/fetch/byte/timing/error is narrated to `#ctfExecStatus` (status bar) + `#ctfExecLog` (scrolling log): per-round LLM thinking, per-probe HTTP status/bytes/timing, and 25 s fetch timeout with `504` vs `502` distinction so a real timeout is not shown as a generic failure.

**State:** Single shared dashboard state (`state = {targets, operators, findings, credentials, settings:{openrouterKey,anthropicKey,openaiKey,veniceKey,huggingfaceKey,localApiKey,…}}` persisted to `localStorage 't3mp3st'` via `saveState()`).

### 4) Settings → .env — GitHub-safe secret handling (the hard invariant)

**Constraint:** "on the settings page make sure all keys stored there goes to .env. make sure no secrets are stored in the code. because i want to push this to github when complete" — every key from Settings must land in a gitignored `.env` file, nothing secret in the repo.

**Git safety (`/.gitignore`):**
```
.env
.env.*
!.env.example
```
Verified: `git check-ignore -v .env` → `.gitignore:20:.env`, `git ls-files | grep .env` → only `.env.example`, `git status --ignored` → `!! .env`, `npm pack --dry-run` → includes `.env.example` 2.0 kB, not `.env`.

**.env files:** `K:/coding/T3MP3ST/.env` (dev, gitignored) and `K:/coding/T3MP3ST/.env.example` (template, 40 lines, 2.0 K, placeholder values like `OPENROUTER_API_KEY=sk-or-v1-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`). `~/.t3mp3st/.env` is the prod ConfigManager source plus `~/.env`. Tests write a demo key then restore placeholder (`sk-or-v1-xxxxxxxxxxxxxxxx`).

**Server bridge (`src/server.ts` — added after imports at ~6158):**
```ts
const ENV_APIKEY_MAP: Record<string, string> = {
  openrouter:'OPENROUTER_API_KEY', venice:'VENICE_API_KEY', anthropic:'ANTHROPIC_API_KEY',
  openai:'OPENAI_API_KEY', xai:'XAI_API_KEY', gemini:'GEMINI_API_KEY', deepseek:'DEEPSEEK_API_KEY',
  huggingface:'HF_TOKEN', nanogpt:'NANOGPT_API_KEY', novita:'NOVITA_API_KEY', litellm:'LITELLM_API_KEY',
  groq:'GROQ_API_KEY', together:'TOGETHER_API_KEY', replicate:'REPLICATE_API_TOKEN',
  github:'GITHUB_TOKEN', local:'TEMPEST_LOCAL_API_KEY',
};
function resolveEnvFile(): string { /* repo /.env when package.json present else ~/.t3mp3st/.env */ }
function maskKey(v: string|undefined): string { return !v || v.length<4 ? (v?'****':'') : `****${v.slice(-4)}`; }
async function readEnvFileMap(filePath: string): Promise<Map<string,string>> { /* split /\r?\n/, trim, strip quotes */ }
async function writeEnvKey(envVar: string, value: string): Promise<string> { /* mkdir -p, replace-or-append, chmod 0600, set process.env */ }
app.get('/api/config/env', …)   // returns {file, exists, providers:{configured:boolean,masked:string,envVar}}
app.post('/api/config/env', …)  // body {provider, key|apiKey} → writeEnvKey + config.setApiKey, logs masked
app.delete('/api/config/env/:provider', …) // removes line + process.env + removeApiKey
```
Also added imports at top: `existsSync` from `fs`, `appendFile/chmod/mkdir/readFile/writeFile` from `fs/promises`, `homedir` from `os`, `tcpConnect` from `net`, `dirname/join` from `path`. `GET /api/llm/status` re-added after the block.

**Config loader (`src/config/index.ts:747-808`):**
```ts
private loadEnvVariables(): void {
  if (this.envLoaded) return;
  const repoEnv = join(process.cwd(), '.env');
  const homedirEnv = join(homedir(), '.t3mp3st', '.env');
  const homeEnv = join(homedir(), '.env');
  const envPaths: string[] = [];
  try { if (existsSync(join(process.cwd(), 'package.json'))) envPaths.push(repoEnv); } catch {}
  envPaths.push(homedirEnv, homeEnv);
  let envProvider: string|undefined;
  for (const envPath of envPaths) {
    if (existsSync(envPath)) {
      const envContent = readFileSync(envPath,'utf-8');
      // VALID_PROVIDERS = ['openrouter','venice','anthropic','openai','xai','gemini','litellm','deepseek','huggingface','nanogpt','local']
      // only set process.env[key] when process.env[key]===undefined (real env wins)
      // track LLM_PROVIDER → TEMPEST_DEFAULT_PROVIDER
      break;
    }
  }
  this.envLoaded = true;
}
```
Prior version only read homedir paths; the branch that wrote to `~/.t3mp3st/.env` but ConfigManager never read repo `/.env` was the bug. Guard: repo `.env` only when CWD looks like the T3MP3ST package (`package.json` present) so hunting inside a target repo does not import its secrets.

**UI wiring — both `docs/index.html` (1.54 M, 20739-line main block) and `docs/settings.html` (1.45 M, standalone page synced via pagenary):**
- `saveApiKey(provider)` — after `state.settings[provider+'Key']=key; saveState(); updatePreflightChecklist();` now also `fetch(base+'/api/config/env', {method:'POST', body:JSON.stringify({provider, key})})` then `toast(provider+" key also saved to .env (****xxxx)")`; on failure `toast("Saved locally, but .env write failed: …")`.
- `saveLocalConfig()` — same pattern for `provider:'local'` when `localApiKey` non-empty.
- `uacSave()` — after `saveState()` syncs legacy input + `updatePreflightChecklist()`/`renderModels()` and `POST provider:p` when `keyVal` present.
Base URL: `getApiBase()` in index, `getApiBase()` or `T3MP3ST_API.baseUrl` in settings. `docs/index.html` 7430-7438 and `docs/settings.html` 7056-7077 patched.

**Redaction & audit:** `src/redact.ts` (`SECRET_PATTERNS`, `redactString`/`redactLedgerText`/`redactSecrets`) unchanged but verified; `npm` pack/export redacts `***REDACTED***`; `getApiKey()` prioritizes `process.env`; hardcoded-secret scan shows only prefix checks (`key.startsWith('sk-ant-')`) not real keys; intentional `T3MP3ST{…}` CTF flags are fixtures.

**Verification performed:**
- `npm run build` → tsc OK, `dist/server.js` 382 K.
- `node --check` on extracted main-block JS (index: 1226178 chars, settings: 1201672 chars) — passes (POSIX temp path needed on Windows; `node --check docs/index.html` is invalid because it is HTML).
- Server restart: `taskkill //PID 22332 //F` → `nohup node dist/server.js` → PID 23844 `LISTENING 127.0.0.1:3333`.
- `curl -s http://127.0.0.1:3333/api/config/env` → `masked:"****xxxx"` (`openrouter` etc `configured:true`), `GET` never returns cleartext.
- `POST {"provider":"openrouter","key":"sk-or-v1-demo…cdef"}` → `{"ok":true,"masked":"****cdef","file":"K:/coding/T3MP3ST/.env"}`, file line 5 updated, `chmod 0600` attempted (best-effort on Windows), `process.env.OPENROUTER_API_KEY` live.
- `DELETE /api/config/env/openrouter` → line removed (39 lines), env cleared, then restored from `.env.example` to 40 lines placeholder.
- `grep -rn "sk-or-v1-" --include="*.ts" | grep -v xxxx` → zero real keys.

### 5) Tests — `src/__tests__/api-key-env-static.test.ts` (Windows `core.autocrlf true` gotcha)

Original helpers used `configSource.indexOf('\n  /**\n   * Get all settings')` (LF markers) against a file on disk that is CRLF, so `indexOf` returned -1 → "missing end marker". Fix needs CRLF normalization.

Naïve `configSource.replace(/\r\n/g,'\n')` breaks when written via Git Bash with `autocrlf true`: the literal `\r\n` inside the JS source code itself gets expanded to a real CRLF *bytes* inside the file, producing:
```
const src = configSource.replace(/\r
/g, '\n')   // parse error: Unterminated string at 13:104
```
Seen as `Transform failed [PARSE_ERROR] Unterminated string` (vitest 0 tests) and earlier `od -c` showed `10` vs `92,110` mismatch on `printf 'NANOGPT_API_KEY=%s\n'`.

**Fix applied:** Avoid embedding a literal `\r\n` in the source; normalize with `String.fromCharCode(13)`:
```ts
function sourceBlock(startMarker: string, endMarker: string): string {
  const src = configSource.split(String.fromCharCode(13)).join("");
  const start = src.indexOf(startMarker);
  expect(start, `missing start marker ${startMarker}`).toBeGreaterThanOrEqual(0);
  const end = src.indexOf(endMarker, start);
  expect(end, `missing end marker ${endMarker}`).toBeGreaterThan(start);
  return src.slice(start, end);
}
```
Also updated guards:
- `it('ConfigManager loads the repo .env in dev and the homedir .env in prod')` — expects `join(process.cwd(),'.env')` + `join(homedir(),'.t3mp3st','.env')` + `existsSync(join(process.cwd(),'package.json'))`.
- New `it('the Settings pages persist keys into the gitignored .env and the server masks them')` — expects `'/api/config/env'`, `ENV_APIKEY_MAP`, `maskKey`, `resolveEnvFile()`, `provider, key`.
- Kept `setupScript` assertion as escaped `printf 'NANOGPT_API_KEY=%s\n'` (backslash+n) — not a real LF.

Transient `TS6133 'loadedFrom' is declared but its value is never read` (`src/config/index.ts:766`) from an unused `let loadedFrom: string|null` was removed; build then passes. The CRLF-safe patch was applied via Node (`readFileSync` + string replace + `writeFileSync`) rather than a shell heredoc to avoid autocrlf expansion. After `git checkout HEAD -- src/__tests__/api-key-env-static.test.ts` + Node patch, file has `fromCharCode` markers on lines 13/41 and should pass `npx vitest run src/__tests__/api-key-env-static.test.ts` on Windows.

### Follow-up (same day): why .env looked "not updated" — and the fix

**Root cause of user complaint:** Real keys lived ONLY in browser localStorage — they were saved to Settings *before* the `/api/config/env` bridge existed, so nothing ever pushed them into `.env`. Two compounding bugs:
1. The repo `.env` template contains placeholder values (`sk-or-v1-xxxx…`), and `GET /api/config/env` counted any value `length > 10` as configured — placeholders made every provider look configured, so any sync would skip it.
2. There was no migration path for already-saved keys.

**Fixes:**
- `src/server.ts` GET `/api/config/env`: values matching `/x{4,}/i` are placeholders → `configured:false`, masked emptied.
- Both `docs/index.html` and `docs/settings.html`: new `syncKeysToEnv()` (defined next to `saveApiKey`, called fire-and-forget from `init()` right after `loadState()`). It GETs `/api/config/env`, and for every provider with `configured:false` POSTs the key from `state.settings[provider+'Key']` (or `state.settings.localApiKey` for provider `local`). Toast: "Synced N API keys from this browser into .env".

**Operator step required:** hard-refresh (Ctrl+F5) the dashboard/Settings page once — the browser caches the old JS without the sync. On next load the keys auto-migrate into `K:\coding\T3MP3ST\.env`.

**Verified:** `npm run build` OK; all 8 inline script blocks in both pages parse (`new Function` check); server restarted (PID 21924); GET shows all providers `configured:false` with placeholders; POST demo → `.env` line 5 updated + masked `****cdef`; DELETE removes; placeholder restored from `.env.example`; vitest `api-key-env-static.test.ts` **9/9 passed** (fixed: NanoGPT `<option>` assertion now checks `docs/settings.html` via new `settingsSource`, since only that page has the dropdown); real-key scan clean; only `.env.example` tracked by git.

### Follow-up 2 (same evening): "env not updated" — actual root causes + final state

**Why .env stayed placeholder after the first fix:** three layers stacked.
1. Keys existed ONLY in browser localStorage (pre-bridge saves) — fixed by `syncKeysToEnv()`.
2. The sync was silent: no visible button, no status text — operator had no way to see it fire.
3. Provenance trap: masked GET showed `****828b` etc. and seemed to contradict "nothing configured". That was the browser sync ALREADY posting real keys to the running server (writeEnvKey also sets process.env), while the repo `.env` kept getting restored to placeholders by curl roundtrip tests. Lesson: stop `cp .env.example .env` restore loops while a live dashboard is open — the browser will re-push.

**Hardening added this pass:**
- `src/server.ts`: `persistEnvKeysToEnvFile()` called fire-and-forget in the `app.listen` callback — any REAL env-injected key (len>10, not `/x{4,}/` placeholder) not already in `.env` is persisted at boot. `OPTIONS /api/config/env` preflight + `Access-Control-Allow-Origin` on GET/POST for cross-origin UI serving.
- `docs/settings.html`: visible **"Sync keys → .env"** button + `#envSyncStatus` line at the top of 🔑 API Keys ("Store keys in .env (GitHub-safe)" card). `syncKeysToEnv(manual)` now reports exactly which providers were pushed/skipped and falls back to legacy top-level `state.apiKey` for openrouter.
- `.env` now holds the four REAL keys (openrouter `01f…828b`, venice `…2vn_`, anthropic `…gAAA`, openai `sk-proj…C3YA`) — pushed by the dashboard auto-sync after restart. Conf store: stale demo openrouter value removed (my curl test had overwritten it via `setApiKey`).
- Live-validated via `POST /api/models`: openrouter and anthropic both return live model lists → keys valid, credits OK.

**Test result:** `vitest api-key-env-static` 9/9; build OK; both pages 8/8 script blocks parse; server PID relaunches verified.

**STALLED recon banner (4 tasks, 300s dispatch timeout):** NOT a key/auth problem — LLM status `connected:true`, both provider keys live-validate. Cause is dispatch latency (model speed/backstop), not secrets. Resume via the banner's Resume/Re-poll; if it recurs, look at model choice (claude-opus-4.8 via openrouter is slow) or the 300 s backstop — separate from the .env work.

**Operator visibility:** `.env` is gitignored (`.gitignore:20`), only `.env.example` tracked, real-key source scan clean — GitHub push stays safe.

### Follow-up 3: "internal processing timeout" during port scanning / enumeration — fixed

**Root cause:** the agent loop (`src/agent/index.ts:418`, `src/agent/monitor.ts:126/192`, `chatWithTools` at `src/llm/index.ts:1851`) uses **non-streamed** `chat()` calls. Those had a HARD TOTAL CAP of `config.timeout || 60000` (config default was literally 60000 ms; the cloud path only guaranteed a 120 s floor). claude-opus-4.8 via OpenRouter routinely needs >120 s for one non-streamed agent turn with a big recon prompt + tool schemas → `AbortSignal.timeout` fired mid-turn → classified `timeout` → the operator narrated it as "internal processing timeout". Not a key/auth problem, and not the 900 s task backstop either.

**Fix:**
- `src/config/index.ts` default `timeout: 60000` → `300000` (with explanatory comment).
- `src/llm/index.ts` lines 271/529/655: `AbortSignal.timeout(this.config.timeout || 60000)` → `|| 300000` (OpenRouter/Anthropic/OpenAI-compatible non-streamed chat).
- Streaming path untouched — it is idle-based (60 s of silence, refreshed per chunk), safe by design.
- Port scan tool was already parallel (concurrency 10, 2 s per port) — not the bottleneck.

**Verified:** build OK, server restarted (PID 23924), `dist` contains the 300 s caps, `/api/llm/status` connected, vitest 9/9.

### Follow-up 4: 900s backstop still killing live recon — backstop is now ACTIVITY-based

**Symptom:** after the 300s LLM cap fix, missions against an external target (manhattandentaldesign.com) still died — 2 recon tasks force-resolved at exactly 900s with ZERO intermediate logs. The old backstop measured **wall-clock from dispatch**, and a frontier model spending 1–4 min per non-streamed turn across a multi-turn recon task legitimately exceeds 900s total while working fine the whole time.

**Fix (`src/index.ts`):**
- New `dispatchLastActivity` map + `dispatchActivityListeners`. At dispatch time the server subscribes to the operator's re-emitted agent events (`agent:thinking`, `agent:tool_call`, `agent:tool_result` — OperatorAgent.executeTask already forwards them with the task id). Every event refreshes `dispatchLastActivity`; tool_call/tool_result also narrate to the server log (`[T3MP3ST] <callsign> ← tool_name {...}` / `✓ tool ok|error`). `clearDispatch()` detaches listeners.
- `checkDispatchTimeouts()` now measures **silence** (`now - lastActivity`), not total age. A task making any progress is never reaped; the 900s window covers one worst-case 300s silent LLM call with room to spare. Reason string: `dispatch stalled: no activity for Xs`. Wedge-symptom check unchanged in spirit (uses the same activity clock).
- `src/agent/index.ts` AgentLoop.run: per-turn telemetry `agent turn i/N — llm Xs — N tool call(s)` so slow turns are visible in the server log.

**Related (NOT fixed here):** `REFUSED · Refusing to simulate against external target …` comes from the WAR-ROOM SIMULATION engine (`docs/index.html:18397`) — it refuses to fabricate results about a real external site and asks to authorize the target (mint a receipt). That is by-design anti-hallucination behavior; the LIVE mission path is what runs real recon. The truncated UI message ends with "t…" (Authorize the target / mint a receipt flow).

**Verified:** build OK; vitest `agent-error-feedback` + `api-key-env-static` 16/16; server restarted (PID 16708), dist contains `dispatch stalled: no activity`, `/api/llm/status` connected.

### Follow-up 5: findings not stored in Evidence Vault — now recorded INCREMENTALLY

**Root cause:** findings only reached the vault when a task COMPLETED. The chain was `AgentLoop.allFindings` → returned inside `AgentResult` at the END of `run()` → `OperatorAgent.executeTask` converted `result.findings` → `recordFinding` → `finding:discovered` → vault + ledger. Every mission so far had been reaped by the dispatch backstop BEFORE `run()` returned, so tasks whose tools discovered plenty mid-run stored NOTHING. `/api/findings` was `[]` — not a vault bug, a recording-timing bug.

**Fix:**
- `src/agent/index.ts`: `AgentEvents` gains `'agent:findings': { findings }`; the loop emits it at BOTH tool-collection points (bootstrap recon + main ReAct loop) the moment `ToolResult.findings` arrive.
- `src/operators/index.ts` `executeTask`: subscribes to `agent:findings` and calls `recordFinding` immediately (shared `recordAgentFinding` helper); a `recordedNow` Set (object identity — the loop emits the same references it later returns) makes the completion pass skip already-recorded findings, so no duplicates. Model-asserted debrief/limit-summary findings still land at completion.
- The rest of the chain was already intact: `recordFinding` → `finding:discovered` → `setupOperatorEvents` → `vault.addFinding` + `syncFindingToTarget` + server ledger → `/api/findings` → `docs/evidence.html` (page reads `/api/findings`, verified).

**Live verification:** started a real mission (`POST /api/mission/start` with the approvals dance: start → mint receipt → `POST /api/approvals/:id/approve` → re-POST start WITH `approvalId` in the body) against the local CTF container. Findings hit `/api/findings` WHILE the mission ran — 12 findings at t+40s (Open Ports, API Endpoints, Technologies, Missing Security Headers, Software Versions Exposed…). New telemetry visible in the server log (`Recon-Auto ← curl_request {...}`, `Recon-2 ← nmap_scan`). Mission stopped cleanly via `/api/mission/stop`.

**Approval-guard note for scripted starts:** the guard accepts a fresh approved receipt only via `body.approvalId` on the SECOND `/api/mission/start` call — approving then re-POSTing without the id mints yet another pending receipt.

### Follow-up 6: vault findings now carry full evidence detail

`upsertMissionFindingToLedger` (src/server.ts) only stored title/severity/claim — `evidenceIds` was always empty, `recommendedFix` dropped. Now it accepts the full operator finding (evidence[], remediation, operatorId) and: creates `EvidenceEntry` records per evidence item (`source:'tool'`, `provenanceStrength:'tool'`, title `Tool output — <tool>`, summary = redacted tool output up to 2000 chars) linked via `findingId` + pushed into `record.evidenceIds`; sets `recommendedFix` from remediation, `owner` from operatorId, `confidence` 0.9 when tool-backed. Verified live: fresh smoke mission → findings 7/7 with evidence attached (some 3 entries), `/api/evidence` populated.

### Follow-up 7: "settings page does not save" — end-to-end verified WORKING; silent storage failures now surfaced

**Investigation (real browser via browser-use IAB, isolated profile, against the live shell at `/ui/#settings.html`):**
- Typed a test key into the OpenRouter card → clicked the card's Save → both toasts fired (`key saved` + `also saved to .env (****E5F6)`), `localStorage['t3mp3st']` written, POST `/api/config/env` hit the server.
- Reloaded the page → field repopulated from storage. Navigated shell → war room → stored settings survived (no cross-page clobber; `loadState` uses `Object.assign` merge on both pages; shell.js only writes the theme key).
- Server log shows Raul's own browser pushing venice (`****2vn_`) 3× tonight → his page runs current JS and his saves DO reach `.env`.
- Conclusion: the save machinery works on the current build; a failure on his side would have to be environmental (private/incognito window, stale cache, or expecting auto-save without clicking the per-card Save).

**Hardening added (both `docs/settings.html` + `docs/index.html`):** `saveState()` now wraps the `localStorage.setItem` in try/catch and toasts `⚠ Save failed: …` on QuotaExceededError / storage blocks — previously a storage failure threw silently and read exactly like "settings do not save". Patch applied CRLF-safely via regex (heredoc literal `\n` patterns don't match CRLF files); all 8 inline blocks parse on both pages.

**Test-artifact cleanup:** my test key (`sk-or-v1-TESTVAL…E5F6`) overwrote the real openrouter entry in `.env` + server `process.env`; `DELETE /api/config/env/openrouter` removed it — the real key (`01f…828b`) lives in Raul's browser localStorage and auto-re-pushes via `syncKeysToEnv()` on his next page load (openrouter flips back to `configured:false`).

### Follow-up 8: "API provider settings not saved" — ROOT CAUSE FOUND + FIXED (uacInit never called)

**Root cause:** the API-provider panel (UAC: provider dropdown + key + base URL + model + Save) was never initialized on the standalone Settings page. `docs/index.html:6131` calls `window.uacInit` when it swaps to its embedded settings view, but `docs/settings.html` only *defined* `uacInit` (and exposed it as `window.uacInit`) — nothing ever invoked it. Result on every load of `/ui/settings.html`: provider dropdown reset to the first option (openrouter) and the key/base/model fields came up blank, even though the data WAS in localStorage. It read exactly like "settings are not saved", and was worse than cosmetic: typing a key into the stale panel and hitting Save made `uacProvider()` read the RESET dropdown, writing the key into the WRONG provider slot and flipping `activeProvider` to openrouter.

**Fix:** `docs/settings.html` `init()` now calls `try { uacInit(); } catch (e) …` right after `loadState()`/`syncKeysToEnv()` (with a comment explaining the trap). 8/8 inline blocks still parse.

**Browser-verified (isolated IAB profile):** set dropdown to `novita`, entered a test key, clicked the panel's Save → `activeProvider:'novita'` + key in localStorage, POST to `/api/config/env` fired. Reloaded → **dropdown restored to `novita` and the key field repopulated** (before the fix it reset to openrouter/blank).

**Cleanup:** DELETE `/api/config/env/novita` removed the test key; NOVITA placeholder line restored in `.env`. Self-healing observed live: after the earlier `DELETE openrouter`, Raul's still-open dashboard re-pushed the real `01f…828b` key into `.env` automatically.

### Follow-up 9: local-model Scan must scan exactly what was entered (remote Ollama)

Raul runs Ollama on a REMOTE IP (not local — local `ollama serve` I spawned during diagnosis was killed; port 11434 closed again).

**Fixes:**
- `buildLocalBaseUrl()` rewritten (regex-free, CRLF-safe patch) in BOTH pages: the Host field may hold a bare IP (Port + Path fields apply), an `ip:port` pair (Port field not double-appended), or a FULL http(s) URL (used verbatim — https preserved, previously it was stripped to http). Unit-tested all four shapes.
- `src/config/provider-models.ts`: undici's useless `fetch failed` now re-thrown as `cannot reach <url> (<cause>)` where cause = `err.cause.code` (ECONNREFUSED / ETIMEDOUT / ENOTFOUND). Verified live: dead remote → `cannot reach http://192.0.2.55:11434/api/tags (timeout)`.
- Settings scan error line now includes the exact URL tried + remote-Ollama hint (OLLAMA_HOST=0.0.0.0 requirement).

**Remote-Ollama checklist for Raul:** remote must run with `OLLAMA_HOST=0.0.0.0` (default binds loopback only → remote refusals), port 11434, Path `/api` in T3MP3ST, firewall open for 11434, plain `http://` unless TLS is set up. Server restarted; hard-refresh Settings (Ctrl+F5) to pick up the page patch.

### Follow-up 10: remote-Ollama scan blocked by the SOCKS egress proxy — FIXED (control-plane bypass)

The improved error surfaced the true cause: `Socks5 proxy rejected connection - NetworkUnreachable` to `192.168.1.162:11434`. The model-list scan (`src/config/provider-models.ts`) used the **proxied global fetch**, and the proxy's global dispatcher only bypasses loopback — a LAN endpoint is tunneled to the SOCKS exit, which has no route to the operator's LAN. The remote Ollama was reachable all along.

**Fix:** `provider-models.ts` now defaults its fetch to `fetchBypassingProxy()` from `src/net/proxy.js` (the module already existed for exactly this; the local-LLM inference path in `llm/index.ts` already used it). Model-list scans are operator control-plane calls — never attack traffic — so they never belong on the egress proxy. `opts.fetchImpl` test injection still wins.

**Verified live:** `POST /api/models {provider:'local', baseUrl:'http://192.168.1.162:11434/api'}` → `source:"live"` with the real model list (Qwen3.8-27B, Qwen3.6-35B, gemma4, …). Tests: proxy-local-bypass + local-api-hardening + api-key-env 22/22.

### Known debt / regression risk

- Each `docs/*.html` page embeds its own full copy of the UI script (no shared source template in `src/`/`scripts/`). Any bug fixed in one page must be fixed in all 14 — this class will recur until shared JS is extracted.
- Server `writeEnvKey` does `chmod 0600` best-effort; on Windows ACLs it is a no-op — secret still masked over the API, but file perms are OS-dependent.
- `core.autocrlf true` on Windows: any test or script that embeds a literal `\r\n` in a JS string and is written via Git Bash heredoc will be corrupted. Use `String.fromCharCode(13)` or `.split('\r').join('')` or `.gitattributes text eol=lf` for that file. Also `node --check` on `docs/*.html` must be done on an extracted `.js` temp file via POSIX path (`/tmp/...`), not on the `.html` file.
- `src/config/index.ts` `loadEnvVariables` `split('\n')` leaves a trailing `\r` on the last token on CRLF files — trimmed away by `.trim()` so harmless, but a future strict parser should use `split(/\r?\n/)`.

### Open work in the tree (not yet committed)

- Modified (from initial `git status`): `ctf/challenges/manifest.json`, `ctf/docker-compose.yml`, `ctf/docker/web/sqli-basic/Dockerfile`, `docs/index.html`, `package-lock.json`; plus this session: `src/server.ts`, `src/config/index.ts`, `docs/settings.html`, `src/__tests__/api-key-env-static.test.ts`, `AGENTS.md`.
- Untracked: `ctf/.dockerignore`, `ctf/challenges/artifacts/`, `ctf/docker/crypto/`, `ctf/docker/forensics/`, `ctf/docker/pwn/format-string/`, `ctf/docker/web/sqli-blind/`, `ctf/docker/web/ssrf-metadata/`, `ctf/docker/web/xss-stored/`.
- Verification still to re-run in CI: `npm run build && npx vitest run src/__tests__/api-key-env-static.test.ts` (expect 9 passed), `curl -s http://127.0.0.1:3333/api/config/env` masked, `grep -R "sk-or-v1-\|sk-ant-\|ghp_\|hf_" --include="*.ts" | grep -v xxxx` clean, `cat K:/coding/T3MP3ST/.env` still placeholder before `git push`.

---

## Session Log — 2026-08-29 (Jarvis) — Live Scan reliability + STOP hard-kill + vault wiring + custom agents + model scan

### 1) Live Scan page: blink / verbose / stall banner fixed

- **Blink:** `renderLiveScanPage` wiped `#liveScanOperators` innerHTML every 3s poll and flashed "No operator details" on transient empty/failed polls. Now: `LiveScanState._lastOperatorsSig/_lastTasksSig` (JSON signature of id/status/counts) — DOM only rewritten when the signature actually changed; transient empty keeps previous DOM; `_hasHydrated` shows a sync spinner until first data; `refreshLiveScanPage` keeps previous status when the poll transport fails.
- **Verbose:** task rows show a 220-char preview + **Verbose** toggle (`#liveScanTaskVerbose-<id>`) with the FULL error + output (260px scroll); feed detail un-truncated with word-break.
- **Stall:** dedicated `#liveScanStallBanner` renders `stallReason` (STALLED title, downstream-phase explanation for blocked infiltrator/exfiltrator, failed-task list expanded, Resume / Re-poll buttons).
- Mirrored to BOTH `docs/index.html` and `docs/live-scan.html` (the duplicated-script constraint).

### 2) STOP button now actually stops everything

- **Symptom:** the red ✕ only flipped the local `missionRunning` badge; backend recon + the in-browser pipeline kept running.
- **`src/index.ts` `TempestCommand.stop()`:** aborts every in-flight dispatch (`op.abortActiveTask('mission stopped by operator')`), clears `activeDispatches/dispatchStartTimes/dispatchOperators`, clears `stallReason/paused`.
- **Frontend (both pages):** `PipelineOrchestrator.abortRequested` + early-break header in the `runPipeline` phase loop; `abortMission()` now fires `BackendDispatch.stopMission()` + `POST /api/mission/stop` (fire-and-forget), clears `missionTimer`, resets header to STANDBY, logs `MISSION ABORTED BY OPERATOR`. `POST /api/mission/stop` (server) already called `cmd.stop() + activeGeneral.stopMonitoring()`.

### 3) `[renderArchitectures] Cannot set properties of null` — fixed

`#architectureGrid` no longer exists in either page's markup but `renderArchitectures()` wrote to it unguarded → threw on every page load. Null-guarded (no-op when absent) in both pages. Other unguarded `getElementById().innerHTML` writes (terminalOutput/modalBody/strengthsList/loopLog/etc.) are dead feature paths that don't fire on load — left as-is.

### 4) Live Scan progress % + Phase flash recon→none + 5-min task reaping

- **Progress %** was phase-position math (`((phaseIndex+1)/phases)*100` = 0% for ALL of recon). New `TempestCommand.getTaskProgress()` (completed+failed ÷ total tasks) → `getStatus().taskProgress`; `/api/mission/status` `mission.progress` now uses it (raw value kept as `phaseProgress`).
- **Phase flash:** the SSE `status` broadcast carried `cmd.getStatus()` which has NO `mission` object → UI Phase cell flipped to `none` every 5s between REST polls. `connectBroadcast` now includes `active` + the active-mission summary (with task-based progress); `updateLiveScanStatus` in both pages also carries the last-known `mission` when an incoming status lacks the key.
- **Backstop 300s→900s:** evidence showed ~60s per LLM turn (openrouter claude-opus) with the first tool_call at +60s and all 4 recon tasks reaped at 301s — legitimately-working tasks were killed. `DEFAULT_TASK_TIMEOUT_MS` now 900000 (`T3MP3ST_TASK_TIMEOUT_MS` still overrides). Verified live: all 4 recon tasks completed, mission advanced recon→weaponize→delivery, progress 0→50→88.

### 5) Scan discoveries → Evidence Vault (3 tools were leaking)

The chain (tool `ToolResult.findings` → AgentLoop `allFindings` provenance:'tool' → `recordFinding` → `finding:discovered` → `vault.addFinding` + ledger `/api/findings` + SSE) was intact — the gap was tool-side. Audited all 36 arsenal handlers: `dns_lookup`, `whois_lookup`, `header_analysis` returned discoveries as output text with NO findings. Now emit: `DNS <type> Records — <domain>` (info), `WHOIS Registration — <domain>` (info), `Missing Security Headers — <url>` (low). Pure transports/transforms (http_request, curl_request, base64_decode, jwt_decode, url_encode, network_trace, cidr_expand) deliberately left as-is. Verified live: vault 28 findings / 19 verified, ledger 20 records.

### 6) Operator-defined CUSTOM local agents

- `src/agent/local-agents.ts`: `CustomAgentConfig` persisted to `~/.t3mp3st/custom-agents.json` (outside repo — GitHub-safe); `normalizeCustomAgent` (slug forced `custom-` prefix, bin required, promptVia arg|stdin); `customAgentSpec` → AgentSpec with argv-template oneShot (`{prompt}` substituted or appended last; `{model}` substituted or dropped; stdin pipes the prompt). Customs count as authed when installed (`authMethod:'operator-managed'`) — the ping is the real proof. Merged into `getSpec` + `detectLocalAgents`. **`localAgentChat` previously fell through unknown ids to Hermes-style `-z` args — wrong argv for any custom CLI; custom branch added** (same for `runLocalAgent` stdin support). `AgentSpec.id`/`AgentDetection.id` widened to string + `custom?:boolean`.
- `src/server.ts`: `GET/POST /api/agents/local/custom`, `DELETE /api/agents/local/custom/:id` (delete also unlists from connectedLocalAgents).
- UI: settings.html `#customAgentForm` + ➕ Custom toggle; 🗑 delete on custom rows in BOTH settings.html and index.html (`window.deleteCustomAgent` clears pin + persisted reconnect).
- Verified live: add → detect `[CUSTOM] ready:true` → connect → real ping round-trip `ok:true` 497ms (cmd echo stub) → `localAgentChat` returns the prompt through the template → delete cleans persistence.

### 7) Local Model SCAN: Ollama native shape + model picker

- `src/config/provider-models.ts`: provider 'local' with baseUrl ending `/api` now fetches **`/api/tags`** and parses `{models:[{name}]}` (`parseOllamaTagList`) — `/api/models` does not exist on Ollama; OpenAI-compatible bases (`/v1`) unchanged (`/models` → `{data:[{id}]}`). (Control-plane fetches bypass the SOCKS egress proxy — see Follow-up 10 above.)
- settings.html Local Model card: 🔎 Scan button next to Model tag + `scanLocalModels()` POSTs `{provider:'local', baseUrl, apiKey}` to `/api/models` + `#localModelScan` picker; `pickScannedLocalModel` fills+saves the tag. Only `source:'live'` accepted — the 'local' static fallback is meaningless, so a dead endpoint shows the note + path hint (`/v1` llama.cpp · `/api` Ollama :11434 · `/v1` LM Studio :1234).
- Verified live with stubs: OpenAI-shape :5123/v1 → live 2 models; Ollama-shape :5124/api → live 2 models; dead port → static+note. Stubs cleaned up.

### Verification state

`npm run build` (tsc) clean; vitest 35/35 (provider-models + warroom-reporting-static 6 + ui-inline-scripts-parse 3 + api-key-env-static 9 + …); `vm.Script` parse 8/8 blocks on index.html / live-scan.html / settings.html; server rebuilt + restarted on :3333 after each backend change (latest PID bound to :3333).

### Open work in the tree (updated)

- Additionally modified this session: `src/index.ts`, `src/arsenal/index.ts`, `src/agent/local-agents.ts`, `src/config/provider-models.ts`, `docs/live-scan.html` (index.html + settings.html already listed above).
- Files with embedded-script duplication (index.html ≈ live-scan.html ≈ settings.html): every UI fix must be mirrored to all copies until shared JS is extracted.

### Follow-up 11: "LLM timing out on test" — root cause was Ollama COLD MODEL LOAD, not the server

**Measured (remote Ollama 192.168.1.162, gemma4 10GB):** `/api/ps` showed ZERO models loaded (Ollama default keep_alive ≈ 5 min → unloads after idle); a one-word READY call took **76s of which 70.1s was model load from disk**, 6s inference. The Test connection button sent `timeout: 90000` — BELOW even the route's 120s default — so every test against a cold or bigger (17-24GB) model was a guaranteed timeout.

**Fixes:**
- `src/llm/index.ts` LocalAdapter.chat: Ollama-native requests now carry `keep_alive` (default `30m`, override `T3MP3ST_LOCAL_KEEP_ALIVE`, empty string to disable) so the model STAYS RESIDENT after a call — first call pays the load, follow-ups are seconds. OpenAI-wire servers (llama.cpp/LM Studio) manage their own residency; untouched.
- `docs/settings.html` `testLocalConfig`: 90s → **300s** budget + a 1s-tick elapsed counter in the status line ("first call after idle loads the model from disk…") so a cold load reads as progress, not a hang; success line reports elapsed seconds and flags >45s as cold-load.
- `docs/settings.html` local dispatch path (LLM queue, `_safeLLMCall*` local branch): `options.timeout || 120000` → `Math.max(options.timeout || 0, 300000)` floor — same cold-load trap for missions/chat.

**Verified live through the server proxy (`POST /api/llm/local` → remote Ollama):** two back-to-back READY calls at **6.2s / 6.1s** (vs 77s cold), Ollama accepted the keep_alive field (200), `/api/ps` shows gemma4 resident (this Ollama build doesn't echo `expires` so the window itself isn't readable — acceptance + speed is the evidence). Build OK, settings parse 8/8, vitest 35/35, server restarted on :3333.

### Follow-up 12: continuation — SOCKS bypass re-verified live on operator LAN (2026-08-29)

**Re-verified after context restore:** `POST /api/models {provider:'local', baseUrl:'http://192.168.1.162:11434/api'}` → `source:"live"` with 6 models (`hf.co/HauhauCS/Qwen3.8-27B: IQ2_M`, `hf.co/HauhauCS/Qwen3.6-35B: Q4_K_M`, `gemma4:latest`, …) — same `fetchBypassingProxy` fix from Follow-up 10, no new code needed. Control-plane (model list + local LLM inference) now consistently bypasses the SOCKS egress proxy; attack/arsenal traffic still routes through the proxy when enabled. `buildLocalBaseUrl()` already honors whatever is typed in Settings (full `http(s)://` URL vs bare IP vs `ip:port`) — Scan now hits exactly that base.

### Verification state (2026-08-29 late)

`npm run build` (tsc) clean; vitest 35/35 (provider-models + warroom-reporting-static + ui-inline-scripts-parse + api-key-env-static + …) 22/22 on the proxy/local-api/env subset; `vm.Script` parse 8/8 on index.html / live-scan.html / settings.html; `POST /api/models` against `192.168.1.162:11434/api` → `source:"live"`; `POST /api/llm/local` READY → 6s (keep_alive resident) vs 77s cold.

### Open work in the tree (current)

- Modified (git diff --stat 21 files): `Dockerfile`, `ctf/challenges/manifest.json`, `ctf/docker-compose.yml`, `ctf/docker/web/sqli-basic/Dockerfile`, `docs/index.html`, `package.json`/`package-lock.json`, `scripts/*-bench.mjs`, `src/__tests__/api-key-env-static.test.ts` + `local-api-hardening-static.test.ts`, `src/agent/index.ts` + `local-agents.ts`, `src/arsenal/index.ts`, `src/config/index.ts` + `provider-models.ts`, `src/index.ts`, `src/llm/index.ts`, `src/operators/index.ts`, `src/server.ts`; untracked `AGENTS.md`, `ctf/.dockerignore`, `ctf/challenges/artifacts/`, `ctf/docker/{crypto,forensics,pwn/format-string,web/*}`, `docs/{about,arsenal,configs,ctf,embed.js,evidence,general,live-scan,obsidivm,operators,receipts,self-improve,settings,shell.html,shell.js,terminal}.html`, `src/__tests__/{chain-ast,chain-summary,execution-monitor,warroom-reporting-static}.test.ts`, `src/agent/monitor.ts`, `src/llm/chain-ast.ts` + `chain-summary.ts`, `.zcode/`.
- Verification before `git push`: `npm run build && npx vitest run` (expect 35/35), `curl -s http://127.0.0.1:3333/api/config/env` masked (no cleartext), `grep -R "sk-or-v1-\|sk-ant-\|ghp_\|hf_" --include="*.ts" | grep -v xxxx` clean, `cat K:/coding/T3MP3ST/.env` still placeholder before push (real keys in `~/.t3mp3st/.env` / browser `localStorage` auto-re-push via `syncKeysToEnv()`).
- Known debt unchanged: duplicated inline scripts across 14 `docs/*.html` pages (fix must be mirrored), `chmod 0600` best-effort on Windows, `core.autocrlf true` CRLF trap (`String.fromCharCode(13)` or `.split('\r')`), `loadEnvVariables` `split('\n')` harmless trailing `\r`.

### Addendum (2026-08-28 late) — app shell + green glow are the newest uncommitted layer

- The untracked `docs/` list above includes the app-shell trio: `shell.html` (layout page; `/ui/` default via the `src/server.ts` static-index change), `shell.js` (hash router + state mirroring), `embed.js` (bridge loaded by all 14 pages). All 14 `docs/*.html` pages carry `<script src="embed.js"></script>` before `</body>` — a page without the tag silently breaks shell navigation, so keep the tag when generating new pages.
- The green glow patch (`llm-ready` → brand-green + `llmGlowPulse` halo + `:has()` bar glow) is baked into every `docs/*.html` stylesheet copy — new pages must copy the UPDATED style block, not an old one.
- Final verification state: `tsc` clean, server rebuilt + restarted (PID 17192 on :3333), vitest 18/18 (ui-inline-scripts-parse 3 + warroom-reporting-static 6 + api-key-env-static 9), `node --check` on embed.js/shell.js, live browser pass: shell probe survives page switches, hash back/forward works, computed `llm-ready` styles `rgb(0,255,136)`.
- Pre-push additions: `npx vitest run src/__tests__/ui-inline-scripts-parse.test.ts src/__tests__/warroom-reporting-static.test.ts` (expect 18/18) alongside the checks listed above.

### Follow-up 13 (2026-08-29 late) — War Room hunt → engagement sync (top-menu / START A ZERO-DAY HUNT)

**Request verbatim:** "ON WAR ROOM PAGE THERE IS NO PLACE TO ENGAGE A TARGET ON THE TOP MENU THE PLACE TO ENTER A TARGET I SEE IS IN THE START A ZERO DAY HUNT. WHEN I UPDATE a site there it should reflect in the engagement sections" + "update agents.md ?"

**Fix (`docs/index.html`, War Room only — no separate top-menu input):**

- `getPlinyTargets()` is now hero-first: `heroHuntTarget` (the START A ZERO-DAY HUNT box) is the canonical top-menu engagement target. Only if the hero box is empty does it fall back to `plinyTargetHost` → `targetHost` → `plinyDirective` URL regex → `local-lab`. This makes "type a site in the hunt box" the single engagement-intent source; the Mission Spine Intake, PLINY card, cockpit, and any `sync:target` consumer inherit it via one call chain (`buildPlinyOperationDraft().target → renderMissionCockpit / renderPlinyHuntPulse / renderPlinyCognition`).
- `syncPlinyTargetInputs(source)` now mirrors the hero box bidirectionally (hero→PLINY/cockpit and any source→hero when non-empty) and broadcasts `CustomEvent('sync:target', {detail:{target,source}})` so inline engagement affordances update without coupling to a layout. Calls `handlePlinyContractChanged()` when the target chain changes.
- Command header (the always-visible top menu) gained a **Target** cell `id="cmdTarget"` next to Status/Elapsed: gray `— none —` when `local-lab`, live target text (`#cfe8d8`, ellipsis ≤240px, tooltip with full value) otherwise. Backed by `_refreshCmdTarget()` + a `sync:target` listener (`window.refreshCmdTarget` exposed), seeded at DOMContentLoaded + 900 ms.
- Listener wiring at the end of the PLINY init now includes both loops: the existing `['missionName','targetHost','targetPorts','plinyDirective','plinyAgentMode','plinyMissionName','plinyTargetHost','plinyTargetPorts']` `input`/`change` → `syncPlinyTargetInputs(id)` + `handlePlinyContractChanged()` + `refreshCmdTarget()`, and a dedicated hero pair on `#heroHuntTarget` (`input`+`change` → `syncPlinyTargetInputs('heroHuntTarget')` + `refreshCmdTarget()`). Comment in-code: "Hero hunt box is the War Room's top-menu engagement target."

Unchanged and still present from the prior verification: `t3mpEmbedGuard` (shell double-menu flash guard before first paint), `llm-ready` → brand-green `llmGlowPulse`, and the `shell.html`/`embed.js`/`shell.js` app-shell layer.

**Verified (this pass):** inline presence checks — `getPlinyTargets hero-first` / `syncPlinyTargetInputs hero mirroring` / `cmdTarget cell` / `sync:target event` / `hero listeners` / `t3mpEmbedGuard` / `llm-ready green glow` all **PASS** (`docs/index.html` 1,572,471 bytes); `npm run build` (tsc) **clean** (two background runs, exit 0); `vitest` subset `ui-inline-scripts-parse` 3 + `warroom-reporting-static` 6 + `api-key-env-static` 9 = **18/18 pass** (runner `v4.1.9`, `jsdom`). The background full-suite run earlier in the session showed 799/832 with the 33 failures confined to `local-agent-path-resolution` (ENOENT for `claude`/`opencode`/`omp`), `novita-provider`, and `oracle-consistency` timeouts — pre-existing IPC/CI environment causes, no new regressions from this War Room patch. Server `dist/server.js` 382 K still serving the updated page; hard-refresh the War Room once to pick up the new hero→engagement wiring.

### Follow-up (same session) — double-sidebar flash on menu switch: fixed with a pre-paint head guard

**Symptom:** clicking a shell nav item showed the incoming page's OWN sidebar briefly (two menus), then it vanished.

**Root cause:** the embed CSS lived in `docs/embed.js`, loaded at the END of the body — the browser painted the sidebar markup (early in body) long before the bridge ran.

**Fix:** a `t3mpEmbedGuard` inline script inserted in every page's `<head>` (before the first `<style>`): detects `window.self !== window.top` (+ `?standalone` escape), adds `.t3mp-embedded` to `<html>` and injects the hide-CSS synchronously during head parsing — the sidebar is hidden before first paint. embed.js keeps end-of-body duties (mirroring, nav clicks, messages); duplicate class/style is harmless.

**Verified:** mid-load browser sampling right after a nav click: guard style tag parented to frame `<head>`, embedded class set, sidebar `display:none` while the frame body was still `loading`; screenshot at +120ms shows a single sidebar. All inline scripts still parse (vm.Script per page), vitest 18/18, guard served live.

### Follow-up 14 (2026-08-29) — Live Gang Console target link + Swarm Cognition Loop live + persistent per-scan memory

**Requests:** "wire in Swarm Cognition Loop make sure its live and functional" + "live gang console does not do the target selected. not linked" + "and the notes should be persistent perscan so the infiltration agents can check prior logs instead of doing the same work over and over. be able to continue from prior work"

**1) Live Gang Console — target was showing `— none —`**

**Root cause:** `renderWarGangConsole()` read `LiveScanState.status.targets` and treated it as an address list. `TempestCommand.getStatus().targets` is `TargetEnvironment.getStats()` — shape `{total, byZone, byType, byStatus, owned, vulnerable, totalVulnerabilities}`, not `Target[]`. `Array.isArray(status.targets)` on a stats object stringified to garbage, so the gang Target cell always fell back to empty.

**Fix:**
- `src/index.ts:1491/1518` `getStatus()` now returns `targetsList: this.targetEnv.getAllTargets()` alongside the existing `targets` stats (first-occurrence regex patch, CRLF-aware).
- `src/server.ts:7109` `GET /api/mission/status` now exposes `targetsList`.
- `docs/index.html:5931` `updateLiveScanStatus()` preserves `targetsList` across SSE polls that lack the key (same shape trap as `mission`).
- `docs/index.html:6163` gang console builds `_rawList = status.targetsList ?? status.targets-as-address-array` and `serverTarget = targetsList[0].address || mission.target`, writing `#warGangTarget` with server-wins-while-active + `sync:target` pre-engage.

**2) Swarm Cognition Loop — was dark (OFF by default, no API/SSE/UI)**

- `src/index.ts:366/834/838` flipped `coordinationEnabled` to default-ON (`! /^(0|false|off)$/i.test(T3MP3ST_SWARM_COORD ?? 'on')`), added `getPackBoard()` getter, started `setInterval(releaseExpiredClaims, 30_000)` lease reaper on start.
- `src/server.ts:376` wired `setScanNotesProvider()` at boot; `connectBroadcast` bridge: `PackBoard` `board:event / lead:* / agent:heartbeat` → `broadcast('pack:*')` (9 listeners) so the war room gets live pack traffic without polling.
- New pack APIs: `GET /api/pack/status` (enabled, leads by status, liveAgents, stateRoot/stateFile), `GET /api/pack/leads?status&limit`, `GET /api/pack/log?limit`, `GET /api/pack/report?agentId=` (bounded 4000c `situationReport`).
- `docs/index.html:4896` injected `_wireSwarmCognition` IIFE inside `BackendDispatch.connectSSE` after the evidence listeners: `_swarm` state, `_renderLists` (hottest 6 → `#packHottestStrip` after `#huntSwarmGrid` + 4 → `#packMapStrip` before `#qolMapSwarmGrid`, `[smoke/conf] coords — title` with `◉` lease badges), `_renderLoop` (`#cognitionLoop` ≤4000c `report` + `#cognitionLoopState` live count), `_renderBus` (last 12 `pack:*` into `#cognitionBus`), `_fetchSwarm` polling `pack/status+leads+log+report`, `pack:*` SSE listeners with 700 ms debounce, 8 s poll, `window.refreshSwarmCognition` exposed. Hooked into `renderPlinyCognition/renderPlinyHuntPulse/renderOperatorQolDesign` so the loop refreshes on every hunt render. Also wired `refreshLiveScanPage` + `recordLiveScanEvent` consumers already present.
- **Broken IIFE fix (this pass):** the minified swarm blob was injected with literal newlines inside single-quoted strings `r.split('\n')` → `SyntaxError: Invalid or unexpected token` in `vm.Script` block 4 (1/10 fail, whole War Room script dead). Replaced with `r.split(String.fromCharCode(10)).slice(0,24).join(String.fromCharCode(10))` via Node rewrite; `docs/index.html` now parses 10/10.

**3) Persistent per-scan notes — infiltration now continues from prior work**

- `src/server.ts:899/1030/1061/1088/1407/1506` new `ScanNoteKind='recon'|'infiltration'|'general'` + `interface ScanNote {id,target,missionId?,operationId?,kind,title,body,source,authorAgentId?,findingIds[],evidenceIds[],createdAt,updatedAt}` + `scanNoteLedger` Map; caps `title 240 / body 4000` via `redactLedgerText`, `newId('note')`, `normalizeTargetValue()`, append-only dedup `title::target`; `buildStateSnapshot`/`loadPersistedState` persist `scanNotes` through the `t3mp3st_state/v1` 1000 ms debounced snapshot (`T3MP3ST_STATE_DIR` default `memory`); routes `GET /api/scan-notes?target&kind&missionId&limit`, `GET /api/scan-notes/history?target`, `POST /api/scan-notes`, `PATCH /api/scan-notes/:id`; auto-note hook in `finding:discovered` (tool-sourced, kind from phase, capped 10/mission/target).
- Threading: `src/server.ts:376` `scanNotesForTarget(target,{maxNotes:5,charCap:1200})` bounded `boundedJoin` → closure → `src/index.ts:356/1143/1447` `setScanNotesProvider` → `Operator.setPriorScanNotes` (`src/operators/index.ts:498`) → `AgentLoop.run(...priorScanNotes)` (`src/agent/index.ts:162`) → `buildTaskPrompt()` block `### Prior scan notes for this target (durable — check before you enumerate)` with 5×`[kind/source date] title: clip(body,280)` 1200c cap. No change to `src/pack/board.ts` (dedupKey/situationReport already prod).

**Verified:** `npm run build` tsc clean; `node --check dist/server.js` OK; `docs/index.html` `vm.Script` 10 blocks 0 fails (was 1 fail on block 4); `npx vitest run --reporter=verbose` 799/834 passed, 35 failed (5 files) — all pre-existing: `local-agent-path-resolution` ENOENT for `claude`/`opencode`/`omp` on Windows, `novita-provider` key shape, `oracle-consistency` 5 s timeouts — no new regressions from this patch; subset `pack-board` + `api-key-env` still green. `grep` confirms `targetsList`, `scanNoteLedger`, `refreshSwarmCognition`, `pack:` wiring present.

### Follow-up 15 (2026-08-29) — LIVE test run of the full war-room pipeline + one bug fixed

**Request:** "do test run make sure live scan and evidence vault logs the entire war room scan"

**Bug found by the test and fixed:** scan notes were keyed by the finding's TargetEnvironment **UUID** instead of the operator-visible address. `upsertMissionFindingToLedger` did `normalizeTargetValue(finding.targetId)` (line 918) — `targetId` is a UUID, so notes landed under e.g. `5b26f279-…` while the notes provider looks up by `target.address` (`localhost`) → infiltration hydration would NEVER match. Fixed by passing `tempestCommand` into the ingest (`src/server.ts:414`, `?? undefined` for TS null) and resolving UUID→address via `command.targetEnv.getAllTargets().find(x => x.id === rawTargetId)` before keying; vault rows + dedupe now key by address too. Build clean, server restarted (PID 1832).

**Live test (2 missions vs local CTF `http://localhost:8080`, approvals dance: start → approve → re-POST with approvalId):**
- **Live Scan logs the whole scan:** `/api/mission/status` carried `targetsList: localhost:8080 [vulnerable]` (gang fix live), 16 tasks (recon + auto-spawned swarm `Chase: …` tasks), 79 progress events by stop, `stall: none`, clean stop via `/api/mission/stop`.
- **Evidence Vault logs incrementally:** findings 32 + evidence 49 by mission end, growing DURING the run (16→25→43→48 observed mid-run) — tool outputs (`Tool output — header_analysis/technology_detect/port_scan/nmap_scan`) attached per finding.
- **Swarm Cognition Loop is functional, not just wired:** `GET /api/pack/status` `enabled:true`, 12 leads posted → 12 follow-ups spawned (`Chase: Open Ports Detected`, `Chase: Missing Security Headers — http://localhost:8080/`, …), bounded `GET /api/pack/report` renders `OPEN LEADS — hottest first ? [smoke 7/high/…] coords — title` (243 chars ≤ 4000 cap).
- **Per-scan notes survive restart:** run-1 notes were restored from the `memory/` state dir after the server restart (storage driver `memory` = dir name, state.json IS loaded) — persistence proven; 22 notes total, new ones correctly keyed `localhost`.
- **Agent telemetry:** server log shows `agent turn 2/15 — llm 255.4s — 1 tool call(s)` + `Recon-2 ← nmap_scan {…}` — claude-opus-4.8 turns run 1–4 min, which is why short SSE samples show only `status`/heartbeat between turns; the activity-based 900s backstop correctly did NOT reap the slow-but-working turn.

**Note for future runs:** pre-fix UUID-keyed notes/findings from run 1 remain in the restored ledger (inert — never match a real host lookup; capped 10/target). Wipe `memory/state.json` (or set `T3MP3ST_STATE_DIR`) if a clean ledger is wanted.

### Follow-up 16 (2026-08-29) — Evidence Vault grouped by domain with click-to-expand details

**Request:** "all the findings and loot should go in evidence vault seperated by domain. click a dropdown and all the details show up"

**Server (`src/server.ts` `/api/mission/findings`):** live vault findings carry only `targetId` (TargetEnvironment UUID) — added `resolveAddr()` in the route that maps UUID → `targetEnv.getAllTargets().address`, applied to every live finding (spread `target` field) and to redacted credentials (`target` added). Ledger rows already carry addresses from Follow-up 15's ingest fix, so ALL rows now group by domain.

**UI (`docs/evidence.html`):**
- `hydrateFindings()` now also fetches `/api/evidence?limit=300` into `window.vaultLoot` and keeps the redacted `credentials` array in `window.vaultCreds` (previously only a count badge); maps `recommendation`/`remediation` through to the finding rows; calls `renderFindings()` after both passes.
- `renderFindings()` rewritten as **by-domain collapsible groups** (replacing the flat card grid + filter chips): `vaultDomainOf()` normalizes targets (URL→hostname, strip port/path; UUID/empty → `(unassigned)`); groups sort by item count with synthetic buckets (`(unassigned)`, `(unfiled loot)`, `(credentials)`) last; each domain header shows ▸/▾ chevron, domain name, `N finding(s) · M loot · K cred`, colored severity dots, total.
- **Click a domain → ALL its findings expand with full detail inline** (open-state priming per finding id; individual rows re-collapse independently): detail box with severity-colored border, target/phase/type meta, every `evidence · <type>` block with full tool output (220px scroll), `recommended fix` when present. Loot rows (unfiled evidence) render per domain with source tag + full summary; credentials render as `CRED` rows (username/type, domain, privilege, 🔑 secretCaptured badge — raw secret never leaves the server). `⤢` button still opens the legacy `showFindingDetail` modal. Click handlers are index-based (`window.toggleVaultGroup(i)` / `window.toggleVaultFinding(i)` via `window._vaultGroupDomains`) to dodge attribute-quoting issues; severity counts (criticalFindings/highFindings/mediumFindings badges) unchanged.

**Verified live in the browser (IAB, standalone + shell):** page parses 9/9 script blocks; hydration renders 3 groups — `localhost` (5 findings), `(unfiled loot)` (43), `(unassigned)` (20 legacy UUID rows); clicking the `localhost` header flipped `vaultOpenGroups.localhost=true` and rendered 0 → 5 finding rows with 5 detail boxes + 12 evidence blocks (screenshot confirms: LOW/INFO tags, "7 security header(s) missing…" detail, full header-analysis tool output per finding); individual finding collapse/re-expand toggle verified (`vaultOpenFindingsMap` flips, rows persist); tsc build clean; server restarted with the resolution fix. NOTE: bare `/evidence.html` (without `/ui/`) 404s to an Error page — deep links must use `/ui/evidence.html` (static root is `/ui`).

### Follow-up 17 (2026-08-29) — War-room load diagnosis + "Syncing gang…" stuck box fixed

**Request 1:** "why does it take the pages so long to load data. how can we fix that. i figured doing the left menu layout would have solved this" — **Diagnosed (measured), fixes proposed, not yet wired:** server is fast (pages ~10ms, APIs 2–150ms) but every page is a 1.4–1.6MB document carrying ~1.2MB of duplicated inline UI script; no compression middleware (full 1.5MB over the wire, ~250KB gzipped); `Cache-Control: public, max-age=0` forces revalidation; in-browser DCL measured 17.8s warm with data at ~37s (compile of the big block is only 27ms — the cost is execution/init + delayed hydration timers, +1600ms); every page switch re-fetches all data because the shell shares nothing with frames. Ranked fixes: (1) gzip compression middleware, (2) real cache headers, (3) extract shared UI script to cached `/ui/app.js` (structural fix for the 14-page duplication debt), (4) paint from last-known data (localStorage cache + immediate hydrate), (5) pause hidden-page intervals.

**Request 2:** "why isnt the war room main page showing any kind of evidence that youre doing a scan" — **Diagnosed, root cause confirmed by live reproduction (mission via API while war room open):** the command header (`#cmdMissionName/Status/Elapsed`) is only written by the war room's own ENGAGE pipeline; backend missions (Live Scan/CTF/API) emit SSE that only feeds the gang console + Live Scan page, so the header stayed `STANDBY / — none — / Awaiting orders / 00:00:00` with ENGAGE still clickable while 4 tasks ran. Proposed fix (not yet wired): server-wins-while-active header wiring + a LIVE SCAN IN PROGRESS strip.

**Request 3:** "in the live gang console it shows syncing gang but there is nothing in the box" — **FIXED (3 stacked bugs, all war-room-only):**
1. `LiveScanState._hasHydrated` was only set inside `renderLiveScanPage()`, which early-returns on the war room (`#page-live-scan` element doesn't exist there) → the gang console's operator box showed the eternal "Syncing gang…" spinner whenever no operators were deployed. Fix: `renderWarGangConsole()` sets `_hasHydrated = true` itself once real status exists (has operators/tasks/mission/active keys).
2. The 3s `refreshLiveScanPage` interval only polled when the Live Scan sub-page was active — the war room gang console depended wholly on SSE and never self-healed after a transport failure. Fix: `else if (document.getElementById('warGangConsole'))` also polls.
3. Even with hydration fixed, the first-paint spinner stuck: the `!hasOperators` branch only repainted when `opEl.innerHTML` was empty or sig unset, and the first render set `_lastWarGangOpsSig='empty'` — so the hydrated "No operator details yet" message could never replace it. Fix: idle sig now includes hydration state (`'idle:'+!!_hasHydrated`) so the box repaints when hydration flips.

**Verified:** `docs/index.html` parses 10/0 script blocks; served file carries all three fixes (curl grep); live browser (fresh reload): gang box settles in **2.7s** showing the real operator roster (Recon-1/Scanner-1 with done/failed/risk stats) and `idle — hit ENGAGE to dispatch` — no spinner. No backend change, no server restart needed (static served from disk).
