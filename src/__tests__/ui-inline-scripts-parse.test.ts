/**
 * Regression guard for issue #111 — "APP doesn't initialize / unresponsive".
 *
 * The SPA is a single classic <script> in docs/index.html. A duplicate `response`
 * declaration in `_safeLLMCallOnce` made the whole script fail to PARSE
 * (`SyntaxError: Identifier 'response' has already been declared`), so nothing ran:
 * the UI stuck on "Initializing…", every handler unwired, only a pre-registered
 * poller still firing. A parse error in one inline script breaks that entire script
 * tag, so we compile every classic inline <script> the way a browser would (a
 * `vm.Script` is parsed as a classic script — no module/CORS/DOM needed) and require
 * each to compile. This catches the whole class of "the app won't boot because the
 * script won't parse" regressions with no browser and no new dependency.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { Linter } from 'eslint';

const html = readFileSync(new URL('../../docs/index.html', import.meta.url), 'utf8');

/**
 * Extract the bodies of bare inline `<script>` blocks (the app's own scripts). We
 * deliberately match only `<script>` with no attributes: external libs are
 * `<script src=…>` and never inline code, and the app never uses `type="module"`.
 * In-string occurrences (`'<script'`, the escaped `<\/script>` inside a regex
 * literal) can't false-match: they aren't a bare `<script>` open, and the real
 * close tag is `</script>` while the in-string one is written `<\/script>`.
 */
function inlineScripts(source: string): string[] {
  const blocks: string[] = [];
  const re = /<script>([\s\S]*?)<\/script>/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(source)) !== null) blocks.push(m[1]);
  return blocks;
}

describe('docs/index.html inline scripts (issue #111 regression)', () => {
  const blocks = inlineScripts(html);

  it('extracts the app inline scripts (guard against a vacuous pass)', () => {
    expect(blocks.length).toBeGreaterThanOrEqual(5);
  });

  it('every classic inline <script> compiles without a SyntaxError', () => {
    const failures: string[] = [];
    blocks.forEach((src, i) => {
      try {
        new vm.Script(src, { filename: `docs/index.html#inline-${i}` });
      } catch (e) {
        failures.push(`inline #${i}: ${(e as Error).message}`);
      }
    });
    expect(failures, failures.join('\n')).toEqual([]);
  });
});

/**
 * Second layer — semantic defect gate (#111 hardening).
 *
 * The vm.Script check above catches outright *parse* failures. This catches the
 * shapes a conflict-concatenating auto-merge leaves behind that still PARSE but are
 * always bugs — duplicate declarations, code after a `return`, duplicate object
 * keys — using ESLint's high-precision "possible problem" rules run programmatically.
 * No new dependency (`eslint` is already a devDependency) and no eslint.config / CI
 * change: this rides the existing `npm test`. #111 shipped 8 such scars past a CI
 * that only ever looked at `src/`; this closes that blind spot for the UI too.
 *
 * The rule set is deliberately a tight, always-a-bug set, and each `<script>` is
 * linted in isolation, so it is false-positive-free on the real file. Notably
 * EXCLUDED, by design:
 *   - `no-undef` / `no-unused-vars` — the SPA relies on hundreds of cross-<script>
 *     and browser globals a per-block lint can't see; enabling them would flood.
 *   - `no-func-assign` — the app legitimately monkey-patches `navigateTo` (wraps it
 *     to add CTF-range init), a pattern that rule flags.
 */
const SCAR_RULES: Linter.RulesRecord = {
  'no-redeclare': 'error',
  'no-unreachable': 'error',
  'no-dupe-keys': 'error',
  'no-dupe-args': 'error',
  'no-dupe-else-if': 'error',
  'no-duplicate-case': 'error',
  'no-const-assign': 'error',
  'no-import-assign': 'error',
  'no-class-assign': 'error',
};

describe('docs/index.html inline scripts — semantic defect gate (#111 hardening)', () => {
  it('no duplicate declarations, unreachable code, or duplicate keys in any inline <script>', () => {
    const linter = new Linter();
    const config: Linter.Config = {
      languageOptions: { ecmaVersion: 'latest', sourceType: 'script' },
      rules: SCAR_RULES,
    };
    const findings: string[] = [];
    inlineScripts(html).forEach((src, i) => {
      for (const m of linter.verify(src, config)) {
        findings.push(`inline #${i} L${m.line}:${m.column} [${m.ruleId ?? 'parse'}] ${m.message}`);
      }
    });
    expect(findings, findings.join('\n')).toEqual([]);
  });
});
