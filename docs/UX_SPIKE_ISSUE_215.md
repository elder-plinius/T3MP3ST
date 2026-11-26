# UX Spike — Model Setup, Target Import, Mission Control (Issue #215)

Origin: [#215](https://github.com/elder-plinius/T3MP3ST/issues/215) (from #157). Related: #164 (Ollama provider — now implemented on the feature branch), #38.

## Method and evidence bounds

This spike is a **code-and-markup heuristic review** of current `main`-line sources
(`docs/index.html`, `docs/settings.html`, `src/server.ts`, `src/config/*`). Every "as-is"
claim below cites a file and line. **No moderated usability testing was run** — findings
that would need real users are explicitly marked `[hypothesis]`. Accessibility findings
reference WCAG 2.2 success criteria by name; contrast values were not measured with a
tool and are marked as such. External "common pattern" claims cite the pattern, not a
measured comparison.

Line numbers refer to this tree and will drift; the anchor is the identifier quoted
alongside each one.

---

## Journey 1 — First-time custom/local model setup

### As-is

| Step | Where | Notes |
|---|---|---|
| Provider choice | `docs/settings.html` `#uacProvider` (select, ~line 3639) and per-provider key cards below | Two competing surfaces: the Universal API Config panel and the legacy per-provider sections |
| Base URL / key | `#uacBaseUrl`, `#uacApiKey` (~3649–3660) | Placeholder shows an OpenRouter URL for every provider until `uacLoadProvider()` swaps it |
| Model discovery | "Fetch models" → `uacFetchModels()` (~7480) → `POST /api/models` | Fail-open to a static list with `source:'static'`; the hint line explains it, but the static list for custom base URLs is frequently irrelevant |
| Save | `uacSave()` (~7450) | Writes to `state.settings` (localStorage) and the key to `.env` via `/api/config/env`; no "saved ✓ / active ✓" confirmation beyond state |
| Activation | `state.settings.activeProvider` — but the War Room renders its own `#modelSelector` (`docs/index.html` ~5870, render ~9841) | Two model pickers in two pages; neither shows the other's state |

### Friction

1. **Split-brain provider config** — Settings' UAC panel and the War Room `#modelSelector`
   hold different state shapes (`selectedModel` vs the selector's own list). `[hypothesis]`
   a first-time user who picks a model in Settings never sees it reflected in the War Room
   header, and vice versa.
2. **No "what is actually active" surface.** The command header shows Status / Elapsed /
   API / Findings / Quality (`docs/index.html` ~3785–3802) — the provider and model that a
   mission *will* use appear nowhere persistent; server truth lives in `GET /api/llm/status`
   (`src/server.ts` ~7574) which the header does not render.
3. **Static-fallback ambiguity.** After a failed Fetch, the panel fills with built-in ids
   that are *not real served tags* for `local`/`ollama` (the code even has to special-case
   placeholder ids `local-model` / `local/ollama` at `src/config/index.ts` ~1170). A user
   can "select" a model the server will reject at launch.
4. Errors from Fetch surface only in the small `#uacModelHint` line; unreachable-host
   causes (ECONNREFUSED vs timeout) are preserved server-side but easy to miss.

### Recommendation (incremental)

- **W1 (quick win):** Add a persistent **"Execution: ⟨provider⟩ · ⟨model⟩ · ⟨keyed/keyless⟩"**
  chip to the command header, populated from `GET /api/llm/status` on load and after every
  config save, with a stale-state tooltip when the UI and server disagree.
- **W2 (quick win):** In the UAC panel, when `source:'static'` is returned, badge each
  option "built-in" and add one line: "These are placeholders for custom endpoints — type
  the exact served tag or fix the endpoint and re-fetch."
- **W3 (structural):** Single source of truth for provider/model selection. The War Room
  selector should read and write the same record as Settings (server-backed config), and
  the header chip renders that record. Requires a small `/api/config` read/write contract —
  no secrets returned, same-origin only (existing trust boundary preserved).

### #164 dependency

The new named `ollama` provider removes the worst local-setup trap (users had to know
Ollama hides behind `local` with an `/api` base). UAC now lists it and Fetch calls
`/api/tags` for it. W3 should treat `ollama`'s served-tag list as the canonical example of
"live list or honest placeholder" behavior.

---

## Journey 2 — Target import

### As-is

- Entry point: Targets panel "From File" button + hidden `#targetFileInput`
  (`docs/index.html` ~4451–4452), `accept=".txt,.csv,.json"`.
- Parser: `importTargetsFromFile()` (~16261) — JSON: array of strings or
  `{host|ip|target}` objects; text: split on newline/comma/semicolon. Scope is inferred
  (`host.includes('/') → 'network'`).
- Result: a success toast with a count, and `addIntel` event. **If zero targets were
  added (all dupes/empty/invalid), nothing happens at all** — no toast, no reason.

### Friction

1. **Silent zero-import failure** — the most likely first-contact bug: pick the wrong
   file, get no feedback at all.
2. **No preview/validation step.** Lines are added verbatim; malformed entries become
   target cards that fail later at launch or tool time, far from the mistake.
3. **Format contract is undiscoverable.** The `accept` attribute and the parser encode
   the schema (one host per line; JSON `[{host}]`), but the UI never states it.
4. **Conceptual conflation** `[hypothesis]`: "import" reads like source/repository
   ingestion to new users; this is a scope list. Issue #157's screenshots support the
   confusion.

### Recommendation

- **W4 (quick win):** Always toast an import outcome: "Imported N targets (M skipped:
  K duplicates, J malformed)" and list the first 3 rejected lines with reasons in the
  intel feed.
- **W5 (quick win):** One-line hint under the button: "One host/CIDR per line, or JSON
  `[{\"host\": \"...\"}]`".
- **W6 (structural):** Two-step import: parse → review table (host, inferred scope,
  keep/drop) → confirm. Reuses the existing per-line validators used at launch time so
  "reviewed" and "will launch" mean the same thing. Explicitly label the section
  "Target scope" and keep source/repo ingestion wording separate.

---

## Journey 3 — Mission preflight and launch

### As-is

- Capability Preflight panel (`#preflightScore`, `runPlinyPreflight()` ~4171–4175)
  covers tooling readiness.
- Target readiness: `updatePreflightChecklist()` recalculated on target changes
  (~8316, ~8629).
- Model/backbone: not part of the preflight surface; chosen via the selectors covered in
  Journey 1. Server-side, missions targeting `local`/`ollama` pre-verify the served model
  (`verifyLocalLLMServed`, `src/server.ts` ~10352) and fail 503 with the served list.

### Friction

1. Preflight answers "are my tools there", not "what will run and against what".
2. The good server-side fail-fast for local models reaches the user only at launch time
   as a 503 — after the operator has already composed the mission.

### Recommendation

- **W7 (quick win):** Extend the preflight panel with two static rows rendered from the
  W1 chip: "Backbone: provider · model (verified ✓ / unverified)" and "Targets in scope:
  N (M without explicit authorization receipts)". Link the local-model failure text
  (already produced by `verifyLocalLLMServed`) into this panel instead of only the launch
  error.

---

## Journey 4 — Active mission control (pause / resume / stop / unexpected stop)

### As-is

- Header buttons: `#cmdPauseBtn` (hidden unless running; label is the `⏸` glyph; title
  "Pause mission") and `#cmdAbortBtn` (`✕`, title "Abort mission (Esc)") —
  `docs/index.html` ~3804–3805. Esc also aborts (~9539); the button flips between
  pause/resume handlers (~7858, ~20795, ~21015).
- Transport failures: transport-guard keeps last-known status on poll failure, and a
  `warGangStallBanner` (~4594) renders `stallReason` with Resume/Re-poll for stalled
  runs (shipped 2026-08-28; see docs/MISSION_RECOVERY.md).
- State feedback: `#cmdMissionStatus` text ("Awaiting orders" etc.).

### Friction

1. **Icon-only controls.** 275 `<button>`s in `docs/index.html` carry 5 `aria-label`s
   total. `⏸` / `✕` have `title` tooltips only: no accessible name (WCAG 4.1.2
   Name, Role, Value), no text label, and glyph-only buttons under ~24×24 px violate
   WCAG 2.5.8 Target Size (Minimum) — heuristically flagged; pixel sizes not measured.
2. **Pause↔resume is a hidden state machine.** The same button swaps onclick handlers;
   there is no `aria-pressed`/`aria-expanded` state, and a paused mission looks identical
   to a queued one in the header (Status text is the only signal).
3. **Destructive affordance.** `✕` aborts with an Esc shortcut and no confirm step;
   `[hypothesis]` accidental aborts are cheap, and "abort" vs "pause" vs "stall" states
   are hard to distinguish post-hoc in the event feed.
4. Unexpected-stop recovery exists (stall banner + MISSION_RECOVERY docs) but entry
   points are split between the banner and the event log.

### Recommendation

- **W8 (quick win):** Text+icon buttons — "⏸ Pause" / "▶ Resume" / "■ Stop" — with
  `aria-label`s, and a disabled (not hidden) paused state; add `aria-live="polite"` to
  `#cmdMissionStatus`.
- **W9 (quick win):** Make Esc-abort require a double-press or an undo toast ("Mission
  aborted — Undo (5s)") where the mission state still allows it.
- **W10 (structural):** A single mission-control state machine (idle → launching →
  running → paused → stalled → stopped → failed) rendered from one source (the SSE
  status event), so the header, stall banner, and event log can't disagree. This
  refactor is only worth it with W3, since both consume the same record.

---

## Accessibility audit (heuristic, markup-level)

- **Accessible names:** 5 `aria-label`s vs 275 buttons (`docs/index.html`); icon-only
  buttons rely on `title`, which is not reliably announced → WCAG 4.1.2.
- **Labels:** `docs/settings.html` uses styled `<label>`s for main inputs (38 present)
  but the pattern is not consistent in card grids.
- **Target size:** command-header buttons use compact padding; measure against 2.5.8
  (24×24 CSS px minimum).
- **Contrast:** `#666`-on-dark metadata text and `rgba(255,...,0.15)` borders were not
  measured; check 1.4.3 for the muted header fields.
- **Focus:** default browser focus is relied on; no visible focus-visible styling found
  in the sampled controls → 2.4.7.
- **Narrow layouts:** the command header is a single flex row with fixed-width
  separators; at mobile widths it wraps awkwardly (`[hypothesis]` — needs a real
  390px-viewport pass).

## Implementation sequence

1. W1, W2, W4, W5, W8 — pure UI, no contract changes.
2. W7, W9 — small server state reuse (status + verify payload already exist).
3. W3 (+W6, W10) — introduce the server-backed active-config record and unify the
   selectors; largest test surface (Settings ↔ War Room ↔ launch contract).

## Acceptance criteria (testable)

- After any config save, the command header shows the provider/model the server will
  actually use within one refresh cycle (W1/W3).
- A model Fetch against an unreachable host produces a visible, cause-specific message
  in the panel (W2), and selecting a static placeholder for `local`/`ollama` is either
  blocked or clearly badged as a placeholder (W2).
- Importing a file with 0 valid lines shows a toast naming skip reasons (W4).
- Every mission-control button has a text label or `aria-label` and meets 24×24 px
  target size (W8).
- A paused mission is distinguishable from a running one without hover (W8).
- All states from the spike checklist — empty, loading, success, invalid-input,
  unavailable-provider, paused, stopped, failed, narrow — have a designed rendering
  before W3 implementation starts.

## Open questions for maintainers

1. Should the War Room `#modelSelector` survive W3 as a scoped quick-switcher, or be
   removed in favor of the Settings record + header chip?
2. Is localStorage `state.settings` required for offline operation, or can the active
   config become server-authoritative now that `/ui` is loopback-only?
3. For W9, is there a mission state where abort is genuinely irreversible (operator
   spawns already dispatched) — and should Undo be withheld there?
