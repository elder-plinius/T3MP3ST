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
        // eslint-disable-next-line no-new
        new vm.Script(src, { filename: `docs/index.html#inline-${i}` });
      } catch (e) {
        failures.push(`inline #${i}: ${(e as Error).message}`);
      }
    });
    expect(failures, failures.join('\n')).toEqual([]);
  });
});
