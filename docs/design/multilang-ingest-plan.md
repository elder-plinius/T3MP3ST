# Plan: T3MP3ST-MLINGEST — Multi-language white-box ingest (web-tree-sitter)

## Executive Summary
- **Goal:** Replace the Python-only `parseFile` stage with a portable `web-tree-sitter` extractor emitting the existing `CodeBlock` shape; reuse the security-ranking pipeline verbatim; language-scoped fail-open (`.py` keeps the Python regex; other languages return `[]` on a grammar miss / parse error — never the Python regex).
- **Complexity:** Medium-low (no async ripple — see Arch). **Risk:** Low-Medium. **Diff:** 3 new source files (`param-split`, `ts-grammars`, `ts-parse`) + edits to 3 (`code-ingest`, `whitebox`, `server`) + coverage config + test suites.
- **Spec:** `2026-07-10-multilang-ingest-design.md`. **Reviews folded:** architect-review (async→sync pivot + 5 defects), test-automator (RED discrimination + granularity).

## 🚨 Critical Implementation Standards
- Fail-open mandatory (language-scoped): `.py` → `parseFile`; a non-`.py` grammar init/parse failure → `[]` (never the Python regex). Ingest never crashes a mission.
- Security ranking reused, not rewritten (`classify`/`prioritize`/`reachability`/`context-pack` untouched).
- vitest green, `tsc --noEmit` clean, `eslint` clean. No TODO/HACK/dead code; every failure path handled.
- **100% coverage of our code (hard gate).** Statements/branches/functions/lines = 100% on every NEW file (`param-split.ts`, `ts-grammars.ts`, `ts-parse.ts`) and 100% of every new branch/function added to edited files (`code-ingest.ts`, `whitebox.ts`). Sole carve-out: the **single** `await initGrammars(...)` wiring line at `server.ts` bootstrap — `initGrammars` itself is 100% unit-tested in `grammar-registry`; the wiring line is exercised by `npm run smoke` at the ship gate. (`cli.ts` is NOT wired — the CLI never ingests; ingest is reached only via `server.ts:6060/6126`.) Coverage is necessary-not-sufficient — the review gate confirms assertions are meaningful, not line-touching.
- **Adversarial phase mandatory (this parses untrusted target source).** A crafted hostile-input suite + a `security-test-engineer` subagent actively trying to break the built code; all defects fixed before review.
- **Strict subagent review is the merge gate.** `/code-review-pr-strict` methodology (parallel specialists, security-critical detection FIRST, false-positive elimination) on the full diff; every confirmed finding resolved; re-review until clean.

## Architecture — SYNC ingest + bootstrap init (revised per architect §2)
web-tree-sitter: only `Parser.init()`/`Language.load(wasm)` are async (one-time); `parser.parse()` is **sync**. So we hoist init to bootstrap and keep the ingest path synchronous — **`ingestRepository` stays sync**, eliminating the entire async ripple through `whitebox.ts`/`server.ts`/tests.

```
bootstrap (server start / CLI main):  await initGrammars(exts)   // load all grammars once into a module singleton; try/catch → empty registry on failure (fail-open)
─────────────────────────────────────
crawl (multi-lang includeExts)
  → ingestRepository (SYNC, unchanged signature) — per file:
       parseFileMultiLang(path, content, ext)              // SYNC
         ├─ ext == .py                                    → parseFile(...)   // Python regex, unchanged
         ├─ non-.py, getGrammar(ext) loaded?              → parser.parse() → query → nodeToCodeBlock[] → CodeBlock[]
         └─ non-.py, no grammar / not-yet-loaded / timeout / error → []   // FAIL-OPEN (never the Python regex)
  → buildCallGraph → findEntryPoints → reachability → classify → prioritize   (UNCHANGED)
  → context-pack → orchestrator                                                (UNCHANGED)
```
Race: a mission firing before init resolves simply fail-opens for that call (`.py` → Python regex, other languages → `[]`) — degrade, never crash. Grammars eager-loaded at bootstrap (~few MB, one-time) — the cost of a sync hot path.

**Killed by the sync pivot:** the async signature change on `ingestRepository`; the `ingest-limits.test.ts` await churn (D1); the unguarded-init mission crash (D5, now a bootstrap try/catch).
**NOT killed — still required (validator BLOCKER):** `whitebox.ts` must still be edited to repoint BOTH production callers (`ingestRepoToSourceContext` L125, `runWhiteboxAnalysis` L205) from `createPythonIngestConfig` → `createMultiLangIngestConfig`. This config-swap is independent of sync/async; without it the multilang extractor only ever sees `.py` in production and the PR is a no-op. Node `whitebox-wiring` below.

## Current State (grounded in /tmp/T3MP3ST)
- `CodeBlock = {id, path, name, kind, lineStart, lineEnd, params, decorators, body}` (`id=\`${path}::${name}@${lineStart}\``; `decorators=[]` for non-Python).
- `parseFile` (code-ingest.ts:409, stays as the `.py` path only); `parseParams` (decl L328, Python-only).
- `ingestRepository` (L749, **stays sync**); sink regexes L169–201; `crawl` L238.
- **Two** production `ingestRepository` callers, both in `whitebox.ts`: `ingestRepoToSourceContext` (L125) and `runWhiteboxAnalysis` (L205) — both pass `createPythonIngestConfig`. (`server.ts:6060` calls `ingestRepoToSourceContext`, not `ingestRepository` directly.) Both must be repointed — see `whitebox-wiring`.

## Node ownership split (execution-offload datapoint)
- **Owned (local:false — specialized / cross-cutting / verification):** `deps-assets`, `coverage-setup`, `grammar-registry` (+`initGrammars`), `server-init-wiring`, `ts-parse`, `ingest-wiring`, `whitebox-wiring`, `adversarial-tests`. (8)
- **Offloaded (local:true — mechanical single-region, committed RED test):** `param-split`, `sink-patterns`, `multilang-config`, `readme-status`. (4)
- 12 manifest nodes; the Adversarial-exploration and Strict-review **phases** below are subagent-driven gates, not manifest nodes.
- **Retained-`local:false`, deliberate:** `nodeToCodeBlock` (pure map inside `ts-parse`) is offload-able in principle, but a discriminating RED test for it needs a real tree-sitter Node (no deterministic offline parse without the loaded grammar), so its natural RED test *is* the `ts-parse` integration test — extracting it would create a node whose test can't be cleanly pre-committed. Conscious retention per validator finding 5.

**Execution prerequisite:** every `local:true` node's `accept` runs a pre-committed RED test file that **no node creates** — the orchestrator commits all RED baselines to the repo *before* running the manifest (Promise-Theory: the local model never authors its own test). Running the manifest cold without this step makes those accepts fail with "no test files found."

## RED baselines (committed before impl; local model sees only the test)

**`param-split`** — `src/__tests__/param-split.test.ts` (＋discriminating same-raw case per tester)
```ts
import { describe, it, expect } from 'vitest';
import { splitParamList } from '../recon/param-split.js';
describe('splitParamList', () => {
  it('python: drops self, strips annotations/defaults/*args', () =>
    expect(splitParamList('self, url: str, timeout=5, *args', 'py')).toEqual(['url','timeout']));
  it('go name-first', () => expect(splitParamList('ctx context.Context, id string', 'go')).toEqual(['ctx','id']));
  it('java type-first', () => expect(splitParamList('String url, int max', 'java')).toEqual(['url','max']));
  it('ts name: type', () => expect(splitParamList('url: string, opts?: Opts', 'ts')).toEqual(['url','opts']));
  it('empty', () => expect(splitParamList('', 'ts')).toEqual([]));
  it('SAME raw, different lang → forces real dispatch', () => {   // ← tester fix
    expect(splitParamList('a b', 'go')).toEqual(['a']);    // name-first
    expect(splitParamList('a b', 'java')).toEqual(['b']);  // type-first
  });
});
```

**`sink-patterns`** — `src/__tests__/sink-patterns.test.ts` (scoped to 2 contiguous regexes; ＋false-positive guards)
```ts
import { describe, it, expect } from 'vitest';
import { DANGEROUS_SINK_RE, OUTBOUND_REQUEST_RE } from '../recon/code-ingest.js';
describe('cross-language sinks', () => {
  it('matches new sinks', () => {
    for (const s of ['Runtime.getRuntime().exec(cmd)','exec.Command("sh")','child_process.exec(x)','system(buf)','popen(cmd)'])
      expect(DANGEROUS_SINK_RE.test(s)).toBe(true);
  });
  it('regression: python sinks still match', () => expect(DANGEROUS_SINK_RE.test('os.system(x)')).toBe(true));
  it('no FP on benign / System.out / filesystem ids', () => {           // ← tester fix
    expect(DANGEROUS_SINK_RE.test('const total = sum(a, b)')).toBe(false);
    expect(DANGEROUS_SINK_RE.test('System.out.println("debug")')).toBe(false);
    expect(DANGEROUS_SINK_RE.test('fileSystem.readFile(x)')).toBe(false);
  });
  it('outbound covers go/js http', () => {
    for (const s of ['http.Get(u)','fetch(u)','axios.get(u)']) expect(OUTBOUND_REQUEST_RE.test(s)).toBe(true);
  });
});
```

**`multilang-config`** — `src/__tests__/multilang-config.test.ts` (all exts ＋negative per tester)
```ts
import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path'; import { tmpdir } from 'node:os';
import { crawl, createMultiLangIngestConfig } from '../recon/code-ingest.js';
describe('createMultiLangIngestConfig', () => {
  const EXTS = ['py','js','ts','tsx','go','java','c','cpp'];
  it('crawls every supported ext, excludes non-source', () => {
    const root = mkdtempSync(join(tmpdir(), 'mling-'));
    for (const e of EXTS) writeFileSync(join(root, `f.${e}`), '\n');
    writeFileSync(join(root, 'd.md'), '# ignore');
    const files = crawl(createMultiLangIngestConfig(root));
    for (const e of EXTS) expect(files.some(f => f.endsWith(`f.${e}`))).toBe(true); // no degenerate hardcode
    expect(files.some(f => f.endsWith('d.md'))).toBe(false);                        // no wildcard/drop-filter
  });
});
```

**`readme-status`** — accept grep (corrected; all three rows, "regex" word — per tester finding 2).

## Owned-node acceptance tests (real assertions committed up front — tester finding 5)
- **`grammar-registry`** — `ts-grammars.test.ts`: registry has entries for all 8 exts with non-empty query + `@name`/`@def` captures; **`initGrammars` fail-open**: forcing a bad wasm path leaves the registry empty and `getParser` returns undefined, **no throw** (covers D5).
- **`ts-parse`** — `ts-parse.test.ts`: parse a TS and a Go function → assert `name/params/lineStart/body`; unsupported non-`.py` `.zzz` → returns `[]`, no throw; `.py` → byte-identical to `parseFile`.
- **`server-init-wiring`** — `tsc --noEmit` clean; the single bootstrap line covered by `npm run smoke` at the ship gate (`initGrammars` itself is 100% unit-tested in `grammar-registry`).
- **`ingest-wiring`** (headline regression) — `ts-parse-multilang-rank.test.ts`: temp repo `.py`+`.go`+`.ts`+`.java`, each a sink-bearing function; `ingestRepository(createMultiLangIngestConfig(root))` (sync) → non-`.py` blocks present, classified `attack_surface`, priority > a neutral block; **PLUS a cross-language reachability case** (Go/TS entry-point → reachable callee gets the reach bonus) to guard `buildCallGraph` name-matching on non-Python ids (tester finding 5). Existing `code-ingest.test.ts` unchanged (sync preserved).
- **`whitebox-wiring`** (production-path regression) — `whitebox-multilang.test.ts`: temp Go+TS repo through `ingestRepoToSourceContext(root)` → asserts non-`.py` source in the returned `sourceContext` (the real server/CLI entry, not the config directly); `tsc --noEmit` + `eslint` green; `whitebox-containment` tests still green.

## Execution Manifest
```json
{
  "execution-manifest": [
    {
      "id": "deps-assets",
      "files": ["package.json"],
      "change": "Add web-tree-sitter dependency and bundle prebuilt grammar .wasm assets for py/js/ts/tsx/go/java/c/cpp (pinned versions), ensuring they ship to dist. package.json + build/copy only — no source parser code here. Environmental — author yourself.",
      "accept": "npm ci >/dev/null 2>&1 && node -e \"require('web-tree-sitter')\" && test -d node_modules/web-tree-sitter",
      "local": false
    },
    {
      "id": "coverage-setup",
      "files": ["package.json", "vitest.config.ts"],
      "change": "Add @vitest/coverage-v8 devDependency and create vitest.config.ts containing ONLY a coverage block (provider v8; include the new files src/recon/param-split.ts, ts-grammars.ts, ts-parse.ts; per-file thresholds statements/branches/functions/lines = 100). Do NOT add test.include/root/environment keys — the existing zero-config `vitest run src` behavior must be byte-preserved. Owned (config).",
      "accept": "npx vitest run src >/dev/null 2>&1 && npx vitest run --coverage src/__tests__/redact.test.ts 2>&1 | grep -qiE 'coverage|% ' && test -f vitest.config.ts",
      "local": false
    },
    {
      "id": "grammar-registry",
      "files": ["src/recon/ts-grammars.ts", "src/__tests__/ts-grammars.test.ts"],
      "change": "Create ts-grammars.ts: extension->{languageId, wasmFile, query (tree-sitter S-expr with @name/@def), captures}; a wasm-path resolver; initGrammars(exts) (async, one-time, cached, try/catch -> empty registry on failure); getParser(ext) sync accessor. Specialized queries + fail-open init — author yourself. Author ts-grammars.test.ts as the RED baseline.",
      "accept": "npx vitest run src/__tests__/ts-grammars.test.ts",
      "local": false
    },
    {
      "id": "param-split",
      "files": ["src/recon/param-split.ts"],
      "change": "Create param-split.ts exporting splitParamList(raw, lang): bare param identifiers per test_param-split. Python drops self/cls, strips *args and ':'-annotations and '='-defaults; Go/TS name-first (name before ':' or space); Java type-first (name is last token of each comma part). Must branch on lang (the 'a b' case proves it). Empty -> [].",
      "accept": "npx vitest run src/__tests__/param-split.test.ts",
      "forbid": ["new_deps"],
      "kind": "create",
      "local": true
    },
    {
      "id": "ts-parse",
      "files": ["src/recon/ts-parse.ts", "src/__tests__/ts-parse.test.ts"],
      "change": "Create ts-parse.ts: nodeToCodeBlock(node, source, path) -> full CodeBlock (id, kind, lineStart/lineEnd from node position, params via splitParamList on the parameters-node text, decorators [], body via node text); parseFileMultiLang(path, content, ext): CodeBlock[] — SYNC — `.py` → parseFile; non-.py via getGrammar(ext), returning [] on no-grammar/unsupported/any error (never the Python regex). MUST bound parse time (wall-clock via progressCallback) so a pathological input cannot spin — on timeout, treat as parse failure and return []. Integration crux — author yourself.",
      "accept": "npx vitest run src/__tests__/ts-parse.test.ts",
      "local": false
    },
    {
      "id": "sink-patterns",
      "files": ["src/recon/code-ingest.ts"],
      "change": "Additively extend ONLY the two contiguous consts DANGEROUS_SINK_RE and OUTBOUND_REQUEST_RE (L173-179) with cross-language sinks (Java Runtime.exec/ProcessBuilder, Go exec.Command/http.Get, C system(/popen(, JS child_process/fetch/axios) per test_sink-patterns, WITHOUT dropping existing Python patterns and WITHOUT matching benign ids like System.out/fileSystem. Export both consts for the test. (SINK_EVIDENCE_RES enrichment deferred to a follow-up — keeps this a single region.)",
      "accept": "npx vitest run src/__tests__/sink-patterns.test.ts",
      "forbid": ["new_deps"],
      "local": true
    },
    {
      "id": "multilang-config",
      "files": ["src/recon/code-ingest.ts"],
      "change": "Add createMultiLangIngestConfig(repoRoot): IngestConfig mirroring createPythonIngestConfig with includeExts covering exactly py/js/ts/tsx/go/java/c/cpp (leading dots), per test_multilang-config (all included, .md excluded).",
      "accept": "npx vitest run src/__tests__/multilang-config.test.ts",
      "forbid": ["new_deps"],
      "local": true
    },
    {
      "id": "server-init-wiring",
      "files": ["src/server.ts"],
      "change": "Invoke `await initGrammars(SUPPORTED_EXTS)` ONCE at server bootstrap (before app.listen) so grammars are loaded before any ingest request; on init failure log and continue (registry empty -> .py via parseFile, other languages -> []). server.ts is the ONLY ingest entrypoint (6060/6126); do NOT wire cli.ts (the CLI never ingests). Cross-cutting entrypoint — author yourself.",
      "accept": "npx tsc --noEmit",
      "local": false
    },
    {
      "id": "ingest-wiring",
      "files": ["src/recon/code-ingest.ts", "src/__tests__/ts-parse-multilang-rank.test.ts"],
      "change": "In ingestRepository (KEEP SYNC), dispatch each file through parseFileMultiLang(path, content, ext) (language-scoped fail-open: .py -> parseFile, other languages -> []), preserving byte/file ceilings. Author the headline multilang-rank regression test (non-.py blocks extracted + attack_surface ranked + cross-language reachability). Do NOT change ingestRepository's signature or any caller. Author yourself.",
      "accept": "npx vitest run src/__tests__/ts-parse-multilang-rank.test.ts src/__tests__/code-ingest.test.ts",
      "local": false
    },
    {
      "id": "whitebox-wiring",
      "files": ["src/recon/whitebox.ts", "src/__tests__/whitebox-multilang.test.ts"],
      "change": "BLOCKING production wiring: in whitebox.ts repoint BOTH ingestRepository calls (ingestRepoToSourceContext L125 [sync], runWhiteboxAnalysis L205 [already async — leave async]) from createPythonIngestConfig to createMultiLangIngestConfig — a pure argument swap, no signature change. Author the regression test whitebox-multilang.test.ts driving a temp Go+TS repo through ingestRepoToSourceContext and asserting non-.py source appears in the returned sourceContext (proves the feature reaches production, not just tests). Verify existing whitebox-containment tests stay green. Author yourself.",
      "accept": "npx vitest run src/__tests__/whitebox-multilang.test.ts src/__tests__/whitebox-containment.test.ts && npx tsc --noEmit && npm run lint",
      "local": false
    },
    {
      "id": "adversarial-tests",
      "files": ["src/__tests__/ts-parse-adversarial.test.ts"],
      "change": "Author a hostile-input suite exercising the FULL wired path (parseFileMultiLang + ingestRepository): malformed/syntactically-broken source per language; a .go file containing Python (and vice-versa); binary/non-UTF8 bytes; a multi-MB generated file and a deeply-nested/very-long-line file (byte/file ceilings hold); a PATHOLOGICAL input that would make tree-sitter spin (asserts parse returns within the timeout and fail-opens — proves the ts-parse timeout is real, not aspirational); a symlink and a symlink-loop under the repo root (crawl must not escape the contained root or hang); empty file; unicode identifiers; a file that makes tree-sitter error. Assert: never throws (non-.py fail-opens to [], .py to parseFile), bounded wall-time, CodeBlock invariants hold (lineStart<=lineEnd, body non-empty when name present, params is string[]), ingest resolves. Owned (crafted adversarial inputs).",
      "accept": "npx vitest run src/__tests__/ts-parse-adversarial.test.ts",
      "local": false
    },
    {
      "id": "readme-status",
      "files": ["README.md"],
      "change": "Flip the two rows that literally say 'Python-only' to multi-language (web-tree-sitter), Python-regex fail-open noted: the 'What it hunts' row (⚠️ Python-only ingest, ~L56) and the 'What ships today' row (Python-only regex ingest, ~L115). Leave the 'Coverage by domain' Code row (~L130, 'experimental') alone — it is a maturity axis, not the Python-only axis, and stays honest until the PR proves out. (Multi-region doc edit — the single-region rule is waived for docs.)",
      "accept": "grep -qi 'web-tree-sitter' README.md && ! grep -qi 'Python-only regex ingest' README.md && ! grep -qi 'Python-only ingest' README.md",
      "forbid": ["new_deps"],
      "local": true
    }
  ]
}
```

## Risk Assessment (post-review)
- ~~[High] async ripple~~ → **eliminated** by the sync + bootstrap-init architecture.
- **[Med] grammar wasm sourcing/version** — owned `deps-assets`; pin versions; the fail-open init means a bad bundle preserves Python ingest while non-Python files yield `[]`, not a crash.
- **[Med] cross-language call-graph** — `buildCallGraph` name-matching may mis-handle non-Python ids; guarded by the reachability assertion in the headline test.
- **[Low] sink-regex FP** — guarded by `System.out`/`fileSystem` negatives.
- **[Low] bootstrap race** — pre-init-completion ingest preserves Python parsing while non-Python files yield `[]`.

## Rollout — gated phases (each can bounce back)
1. **Build.** Branch `feat/multilang-ingest`; land the 12 nodes in manifest order (fleet: `start-fleet.sh`). I implement the 8 owned; cascade fills the 4 local.
2. **Coverage gate (hard).** `npx vitest run --coverage` → **100%** on the new files (thresholds fail the run otherwise); manually confirm every new branch/function in `code-ingest.ts`/`whitebox.ts` is hit (diff-coverage), carve-out only the `server.ts`/`cli.ts` bootstrap lines (smoke-covered). Gap → add tests, re-run.
3. **Adversarial phase.** `ts-parse-adversarial.test.ts` green, then dispatch a **`security-test-engineer`** subagent to actively break the built code against a hostile-repo corpus (malformed/mixed-language/binary/pathological inputs, resource-exhaustion, parser hangs). Every defect fixed; re-run coverage.
4. **Strict review gate.** Apply the **`/code-review-pr-strict`** methodology via parallel specialist subagents on the FULL diff — **security-critical detection runs first**, then correctness/perf/maintainability, with false-positive elimination and the mandatory verification protocol. Confirm coverage is meaningful assertions (no line-touching). Resolve every confirmed finding; **re-review until clean**.
5. **Ship.** `npm test` + `tsc --noEmit` + `eslint` + `npm run smoke` (covers the server bootstrap init line) + coverage all green → open PR; body carries spec §4 decision record, the node split, coverage report, adversarial summary, and review sign-off.
- Follow-ups (own issues): SINK_EVIDENCE_RES cross-language enrichment; cxpak `serve` phase-2 ranking upgrade.

## Success Criteria
- [ ] Non-`.py` functions extracted + security-ranked (headline regression green, incl. cross-lang reachability).
- [ ] **Feature reaches production** — `whitebox-multilang.test.ts` drives multilang through `ingestRepoToSourceContext` (not just `createMultiLangIngestConfig` directly).
- [ ] Fail-open verified at BOTH boundaries: init failure (empty registry) and per-file unsupported ext.
- [ ] Python behavior byte-unchanged (existing suite green, no test edits).
- [ ] Both README "Python-only" rows flipped. `tsc`/`eslint`/`vitest` all green (eslint gated in `whitebox-wiring`).
- [ ] **100% coverage** on new files + all new branches in edited files (carve-out: bootstrap lines) — coverage gate green.
- [ ] **Adversarial phase** passed: crafted-input suite green AND `security-test-engineer` subagent found no unfixed break.
- [ ] **Strict review** (`/code-review-pr-strict`, security-first) clean — all confirmed findings resolved, assertions verified meaningful.

---
**Status:** Draft — pending human sign-off
**Date:** 2026-07-10
