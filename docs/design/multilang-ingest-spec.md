# Multi-language white-box ingest for T3MP3ST

**Status:** Draft design (for an upstream PR to `elder-plinius/T3MP3ST`)
**Date:** 2026-07-10
**Scope:** Replace the Python-only ingest parser with a portable multi-language parser, reusing T3MP3ST's existing security-ranking pipeline unchanged.

---

## 1. Problem

T3MP3ST markets white-box source hunting as a proven strength ("Code: ✅ Proven — CVE-Zero 8/10 across 7 languages"), but the ingest **engine** only reads Python. `src/recon/code-ingest.ts:6` says so itself:

> "This is a PYTHON-ONLY, regex-based 'AST-lite' PROTOTYPE … The real version is tree-sitter (or a language server) + multi-language."

The README status table flags it: **Code → ⚠️ Python-only ingest**. Point the white-box flow at a Go/Java/C/TS repo and `crawl` keeps only `.py`; every non-Python file is invisible to the hunt.

## 2. Goal / Non-goals

**Goal.** White-box ingest parses many languages, feeding T3MP3ST's *existing* security-ranking so multi-language repos get the same attack-surface-ordered analysis Python repos get today.

**Non-goals.**
- Not changing the security model (`classify`/`prioritize`/`reachability`/`context-pack`) — it is reused verbatim.
- Not adding an external binary, native-compiled dependency, or new API key.
- Not building cross-language taint/call-graph analysis in this PR (see §9, phase 2).

## 3. Key insight — the seam is one stage

The ingest is a pipeline (`whitebox.ts`): `code-ingest (SELECT) → context-pack (BUDGET) → orchestrator (REASON)`. Within SELECT, only **one** stage is language-bound:

- `parseFile()` (`code-ingest.ts:409`) — Python `def`/`class` regex → `CodeBlock[]`. **Language-bound.**
- Everything downstream operates on `CodeBlock {name, params, body, line, …}` via text regexes over the block body/name/params:
  - `buildCallGraph`, `findEntryPoints`, `reachability` — walk `CodeBlock` names. Language-agnostic.
  - `classify` (per-block `Exposure`) and `prioritize` (score) — run `DANGEROUS_SINK_RE`, `RISKY_PARAM_RE`, `OUTBOUND_REQUEST_RE`, `SECURITY_CONTROL_NAME_RE` over the block **body/params**. Mechanism is language-agnostic.

So the change is surgical: **replace `parseFile` with a multi-language block extractor that emits the same `CodeBlock` shape.** No downstream code changes.

## 4. Decision record — how to parse (embedded ADR; T3MP3ST has no ADR dir)

**Decision: `web-tree-sitter` (WASM), as the default on every platform.**

Options considered:

| Option | Nature | Rejected because |
|---|---|---|
| Extend regex per language | fragile per-language regex | The exact trap the file header warns against; unmaintainable across 40 grammars. |
| `tree-sitter` (node-tree-sitter) | **native** N-API C++ addon; fastest | Compiles native code at install (node-gyp/toolchain) or needs per-OS/ABI prebuilds. T3MP3ST has **zero** native deps today and ships via `npx tempest` / `npm install` onto arbitrary machines, **fully offline**, cross-platform (open Windows bug #18). Native compile is the #1 install-failure mode in exactly that scenario. |
| Per-language JS parsers (`@babel/parser`…) | pure JS, one language each | Cannot cover many languages. |
| Shell out to cxpak (external Rust tool) | multi-language, but external | Adds a binary install (brew/cargo/docker); and cxpak exposes **no** `{name, params, body, span}` symbol interface (CLI = markdown prose; `serve` = analyses, not a symbol table; `lsp` = MCP-over-stdio, no `documentSymbol`) — verified. Cannot cheaply supply `CodeBlock`s. |
| **`web-tree-sitter` (WASM)** | official WASM build of tree-sitter | **Chosen.** |

**Rationale.** web-tree-sitter is the WASM sibling of the native binding — same grammars, same parse quality — with **zero compile step**, running identically on any OS/Node/offline. It preserves T3MP3ST's pure-JS, portable, keyless character. The native binding's ~2–5× parse-speed edge is worthless here: ingest parses a repo **once per mission**, dwarfed by LLM latency. Grammar `.wasm` files are sourced from a prebuilt collection (e.g. `tree-sitter-wasms`; exact package/coverage confirmed at implementation time), not built locally.

**Consequence / accepted cost.** Async grammar init; a few MB of bundled wasm for the top languages (lazy-loaded by extension); slightly more setup code than a `require()` grammar.

## 5. Architecture

```
crawl (broadened includeExts)
  → parseFileMultiLang(path, content)          ← NEW: web-tree-sitter → CodeBlock[]
      ├─ grammar for ext loaded?  → tree-sitter query → CodeBlock[]
      └─ no grammar / init fails  → parseFile() (existing Python regex)   ← fail-open
  → buildCallGraph → findEntryPoints → reachability → classify → prioritize   (UNCHANGED)
  → context-pack (BUDGET) → orchestrator (REASON)                             (UNCHANGED)
```

**SYNC architecture (revised — grammar init hoisted to bootstrap so the ingest path stays synchronous).** web-tree-sitter's `Parser.init()`/`Language.load()` are async (one-time); `parser.parse()` is sync. So init runs once at bootstrap and the per-file parse is sync — `ingestRepository` keeps its sync signature and there is no async ripple.

**New units:**
- `src/recon/ts-grammars.ts` — `initGrammars(exts): Promise<void>` (one-time, cached, `try/catch` → empty registry on failure = fail-open); `getParser(ext): Parser | undefined` (sync accessor); the ext→{query, captures, wasm} registry.
- `src/recon/ts-parse.ts` — `parseFileMultiLang(path, content, ext): CodeBlock[]` (**sync**): `getParser(ext)` present → `parser.parse()` (with a **bounded parse time** via `setTimeoutMicros`/parse-limit — a hostile input must not spin) → query → `nodeToCodeBlock`; timeout/absent/error → `parseFile(...)`. `nodeToCodeBlock` fills the full `CodeBlock` shape (`name` from `@name`, `body`/`lineStart`/`lineEnd` from node position, `params` via `splitParamList(text, lang)`, `decorators []`, `kind`).
- Per-language query table (top ~8: `py, js, ts, tsx, go, java, c, cpp`). cxpak's grammar queries are a reference for the capture patterns.

**Wiring.** (1) Bootstrap: `await initGrammars(...)` once at **`server.ts` startup** (the only ingest entrypoint — `server.ts:6060/6126`; the CLI never ingests, so `cli.ts` is not wired). (2) `ingestRepository()` (`code-ingest.ts:749`, **stays sync**) dispatches each file through `parseFileMultiLang(...)` with `parseFile` fallback. (3) **Production caller swap (required):** both `whitebox.ts` callers of `ingestRepository` — `ingestRepoToSourceContext` (L125) and `runWhiteboxAnalysis` (L205) — move from `createPythonIngestConfig` to `createMultiLangIngestConfig`; without this the extractor only sees `.py` in production.

## 6. Security-ranking reuse & cross-language sinks

`classify`/`prioritize` are reused unchanged. Their regexes (`DANGEROUS_SINK_RE`, etc.) are Python-tuned; cross-language sinks that already overlap (`eval(`, `exec(`, `system(`) still fire, so ranking **degrades gracefully**, never breaks. This PR **additively** broadens the sink/param patterns with a few cross-language entries (`Runtime.exec`, `ProcessBuilder`, `exec.Command`, `os/exec`, `system(`, `popen(`, `child_process`), each with a test. Deeper per-language tuning is out of scope (incremental follow-up).

## 7. Fail-open

- Grammar missing/unsupported ext → that file falls back to `parseFile` (Python files unaffected; unknown languages simply parse as before / are skipped as today).
- web-tree-sitter init throws in a hostile env → whole extractor falls back to the Python path. **Ingest never crashes a mission; worst case is today's behavior.**

## 8. Test plan (vitest — matches their suite; deterministic, no model calls)

1. **Multi-language extraction (headline regression).** Temp repo (`mkdtempSync`, mirroring `code-ingest.test.ts`) with `.py` + `.go` + `.ts` files, each holding a function with a known sink. Assert non-`.py` functions are extracted as `CodeBlock`s **and** land as `attack_surface`/high-priority after `classify`/`prioritize`. This test *is* the proof the limitation is fixed.
2. **CodeBlock fidelity.** For a known TS/Go function, assert `name`, `params`, `line`, and `body` (contains the sink line) are correct.
3. **Fail-open — unsupported ext.** A `.zig` (or grammar-absent) file routes to fallback / is handled, no throw.
4. **Fail-open — grammar init failure.** Force `initGrammars` to fail (bad wasm path) → registry stays empty, `getParser` returns undefined, every file routes to `parseFile`; `ingestRepository` resolves normally, mission-safe.
5. **Cross-language sink patterns.** Unit-test each added regex against a positive and negative snippet.
6. *(optional, `--ignored` like `spine-live.test.ts`)* real wasm load against a fixture repo — live smoke.

**Acceptance:** `npm test` green, `npm run typecheck` clean; test 1 proves multi-language, tests 3–4 prove fail-open.

## 9. PR scope

**In:** `ts-grammars.ts` (registry + `initGrammars`/`getParser`) + `ts-parse.ts` (`parseFileMultiLang`/`nodeToCodeBlock`) + `param-split.ts`; `web-tree-sitter` dep + grammar wasm assets (top ~8 langs); bootstrap `initGrammars` call (server/CLI); `ingestRepository`/`crawl` wiring (**sync**, broadened exts) + `createMultiLangIngestConfig`; **`whitebox.ts` caller swap (both call sites)**; additive cross-language sink patterns; tests; README status flip (both "Python-only" rows).

**Out (name in PR as deliberate):** cxpak integration (phase 2); deep per-language sink tuning; the `serve`-backed cross-language call-graph/taint upgrade; node-tree-sitter fast path.

**Size target:** 3 new source files (`param-split`, `ts-grammars`, `ts-parse`) + edits to 4 (`code-ingest`, `whitebox`, `server`, `cli`) + coverage config + test suites (unit, headline regression, production-path, adversarial). Larger than a trivial PR because of the mandated quality gates (§12), but still one cohesive feature — deliberately not a mega-diff (cf. #61/#17, closed for sprawl).

## 10. Phase 2 (noted, not this PR) — cxpak as an optional ranking upgrade

When installed, cxpak's `serve` endpoints supply genuinely better multi-language facts than T3MP3ST's regex heuristics: `/call_graph` (cross-language edges), `/api_surface` (entry points with file+line), `/data_flow` (taint paths). A later, fail-open, opt-in PR can let cxpak *upgrade* the ranking inputs (entry points, reachability, sinks) while the web-tree-sitter parser from phase 1 remains the universal default. Not required for the headline win.

## 11. Risks

- **Grammar wasm sourcing/versioning** — confirm the collection package and language coverage at implementation time; pin versions.
- **production caller swap** — the multilang config must be repointed at BOTH `whitebox.ts` `ingestRepository` callers (L125, L205); a regression test drives `ingestRepoToSourceContext` end-to-end so the feature can't silently no-op in production. *(The async ripple is designed out by the sync + bootstrap-init architecture.)*
- **bootstrap race** — a mission firing before `initGrammars` resolves fail-opens to Python for that call; entrypoints `await` init before serving.
- **Param extraction variance** across grammars — mitigated by falling back to slicing the signature line when the parameters node is absent.
- **Bundle size** — mitigated by lazy-loading grammars per encountered extension rather than eager-loading all.

## 12. Quality gates (mandatory — all three block merge)

1. **100% coverage of our code.** vitest coverage (`@vitest/coverage-v8`, `vitest.config.ts` with a coverage-only block) with per-file thresholds = 100% (statements/branches/functions/lines) on every NEW file (`param-split.ts`, `ts-grammars.ts`, `ts-parse.ts`), and 100% of every new branch/function added to edited files (`code-ingest.ts`, `whitebox.ts`). Sole carve-out: the single `await initGrammars(...)` wiring line at `server.ts` bootstrap (`initGrammars` itself is 100% unit-tested; the line is `npm run smoke`-covered). Coverage is necessary-not-sufficient — gate 3 verifies the covering assertions are meaningful (no line-touching / cheater tests).

2. **Adversarial local testing.** Because ingest parses **untrusted target source**, a crafted hostile-input suite (`ts-parse-adversarial.test.ts`) drives the full wired path against malformed/mixed-language/binary/oversized inputs, a **pathological input that would make tree-sitter spin** (asserting the `ts-parse` parse-timeout fail-opens — not aspirational), and **symlink/loop entries** (crawl must not escape the contained root or hang); asserts fail-open + CodeBlock invariants + bounded wall-time/bytes. Then a `security-test-engineer` subagent actively attempts to break the built code (parser hangs, resource exhaustion, mission crash) against a hostile-repo corpus. All defects fixed before review.

3. **Strict subagent code review.** The `/code-review-pr-strict` methodology on the full diff: parallel specialist subagents with **security-critical detection first**, false-positive elimination, and the mandatory verification protocol. Every confirmed finding resolved; re-review until clean. This is the merge gate.

Gate order at rollout: build → coverage → adversarial → strict review → ship; any gate can bounce back to build.
