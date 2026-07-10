/**
 * Language-scoped fail-open: the Python regex parser must ONLY ever run on `.py`.
 * This file deliberately never calls initGrammars(), so the registry is empty and
 * every getGrammar() returns undefined — the "grammars failed to load / not yet
 * loaded" production scenario. A brace/`class` language routed to the Python regex
 * in that state would emit a corrupt block (wrong line span, methods lost); the
 * contract is honest absence ([]) instead.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { __resetGrammarsForTest } from '../recon/ts-grammars.js';
import { parseFileMultiLang } from '../recon/ts-parse.js';
import { parseFile } from '../recon/code-ingest.js';

beforeAll(() => __resetGrammarsForTest()); // ensure the registry is empty; do NOT init

describe('parseFileMultiLang — language-scoped fallback (no grammars loaded)', () => {
  it('a Java `class` file returns [] — never a mangled Python-regex block', () => {
    // If this routed to parseFile, the Python CLASS_RE would match `class A` and
    // emit exactly one (wrong) block; assert it does not.
    expect(parseFileMultiLang('A.java', 'class A {\n  void run(String c){}\n}\n', '.java')).toEqual([]);
  });

  it('a JS `class` file returns [] with no grammar (would false-match the Python regex)', () => {
    expect(parseFileMultiLang('a.js', 'class Svc {\n  run(cmd){ exec(cmd); }\n}\n', '.js')).toEqual([]);
  });

  it('.py still routes to the Python regex even with no grammars loaded (byte-identical)', () => {
    const src = 'def fetch(url):\n    return get(url)\n';
    expect(parseFileMultiLang('a.py', src, '.py')).toEqual(parseFile('a.py', src));
  });
});
