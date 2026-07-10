/**
 * Adversarial hardening — ingest parses UNTRUSTED target source. A crafted file
 * must never throw, hang, or crash a mission; worst case is honest absence ([])
 * — a non-.py file is NEVER routed to the Python regex. Drives the full wired
 * path (parseFileMultiLang + ingestRepository/crawl).
 */
import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { mkdtempSync, writeFileSync, mkdirSync, symlinkSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { Tree } from 'web-tree-sitter';
import { initGrammars, __resetGrammarsForTest } from '../recon/ts-grammars.js';
import { parseFileMultiLang } from '../recon/ts-parse.js';
import { ingestRepository, createMultiLangIngestConfig, type CodeBlock } from '../recon/code-ingest.js';

const tmpRoots: string[] = [];

beforeAll(async () => {
  __resetGrammarsForTest();
  await initGrammars();
});

afterAll(() => {
  for (const r of tmpRoots) rmSync(r, { recursive: true, force: true });
});

const invariants = (blocks: CodeBlock[]) => {
  expect(Array.isArray(blocks)).toBe(true);
  for (const b of blocks) {
    expect(b.lineStart).toBeLessThanOrEqual(b.lineEnd);
    expect(Array.isArray(b.params)).toBe(true);
    if (b.name) expect(b.body.length).toBeGreaterThan(0);
  }
};

describe('adversarial parseFileMultiLang', () => {
  it('malformed source per language does not throw', () => {
    for (const [ext, src] of [
      ['.go', 'func ('],
      ['.ts', 'class {{{ function ('],
      ['.java', 'class A { void ('],
      ['.c', 'int f( { { {'],
    ] as const) {
      expect(() => invariants(parseFileMultiLang(`x${ext}`, src, ext))).not.toThrow();
    }
  });

  it('wrong-language content (Python in a .go file) yields structurally valid output', () => {
    expect(() =>
      invariants(parseFileMultiLang('x.go', 'def fetch(url):\n    return get(url)\n', '.go')),
    ).not.toThrow();
  });

  it('binary / non-UTF8 bytes do not throw', () => {
    const bin = Buffer.from([0x00, 0xff, 0xfe, 0x10, 0x80, 0x00, 0x41]).toString('binary');
    expect(() => invariants(parseFileMultiLang('x.go', bin, '.go'))).not.toThrow();
  });

  it('empty file yields no blocks, no throw', () => {
    expect(parseFileMultiLang('e.go', '', '.go')).toEqual([]);
  });

  it('unicode identifiers are extracted correctly', () => {
    const blocks = parseFileMultiLang('u.go', 'package m\nfunc Ünïçødé(x int) int { return x }\n', '.go');
    const fn = blocks.find((b) => b.name === 'Ünïçødé');
    expect(fn, 'unicode function name captured').toBeDefined();
    expect(fn!.params).toEqual(['x']);
  });

  it('large file parses within the wall-clock budget and still extracts', () => {
    let src = 'package m\n';
    for (let i = 0; i < 20000; i++) src += `func F${i}(url string) error { return http.Get(url) }\n`;
    const t0 = Date.now();
    const blocks = parseFileMultiLang('big.go', src, '.go');
    expect(Date.now() - t0).toBeLessThan(10000); // bounded — never spins
    expect(blocks.length).toBeGreaterThan(0);
  });

  it('a real parse tripping the wall-clock budget fails open to [] (not mocked)', () => {
    // Drive the REAL tree-sitter progressCallback path with a 0ms budget: the
    // callback returns true on its first invocation, tree-sitter cancels, parse
    // returns null, and the fail-open returns []. Proves the actual cancellation
    // wiring — not a mock that hard-returns null.
    let src = 'package m\n';
    for (let i = 0; i < 5000; i++) src += `func F${i}(a int) int { return a }\n`;
    const t0 = Date.now();
    const blocks = parseFileMultiLang('slow.go', src, '.go', undefined, 0);
    expect(blocks).toEqual([]); // cancellation path taken
    expect(Date.now() - t0).toBeLessThan(5000); // cancelled early, not run to completion
  });

  it('deeply nested input does not blow the stack, hang, or corrupt output', () => {
    const deep = 'package m\nfunc F() { ' + '{'.repeat(2000) + '}'.repeat(2000) + ' }\n';
    const t0 = Date.now();
    expect(() => invariants(parseFileMultiLang('d.go', deep, '.go'))).not.toThrow();
    expect(Date.now() - t0).toBeLessThan(10000);
  });

  it('frees the parsed tree exactly once per parse that produced one (leak-fix mechanism)', () => {
    // Deterministic, machine-independent guard for the WASM Tree/Parser leak:
    // assert tree.delete() is actually invoked. (A resource-exhaustion repro is
    // hardware/heap-ceiling dependent and green-only on machines with headroom.)
    const del = vi.spyOn(Tree.prototype, 'delete');
    try {
      del.mockClear();
      parseFileMultiLang('ok.go', 'package m\nfunc F(){ return }\n', '.go'); // success path
      expect(del, 'success path frees its tree').toHaveBeenCalledTimes(1);

      del.mockClear();
      parseFileMultiLang('bad.ts', 'class C { m( { { {', '.ts'); // error-recovery still yields a tree
      expect(del, 'error-recovery path frees its tree').toHaveBeenCalledTimes(1);
    } finally {
      del.mockRestore();
    }
  });
});

describe('adversarial crawl / ingest', () => {
  it('symlink loop under the repo root terminates (crawl does not follow symlink dirs)', () => {
    const root = mkdtempSync(join(tmpdir(), 'advcrawl-'));
    tmpRoots.push(root);
    const sub = join(root, 'sub');
    mkdirSync(sub);
    writeFileSync(join(sub, 'a.go'), 'package m\nfunc A() {}\n');
    try {
      symlinkSync(root, join(sub, 'loop'), 'dir'); // self-referential loop
    } catch {
      console.warn('[skip] symlinks unavailable in this environment — loop guard unverified');
      return;
    }
    const t0 = Date.now();
    const result = ingestRepository(createMultiLangIngestConfig(root));
    expect(Date.now() - t0).toBeLessThan(10000); // did not spin on the loop
    expect(result.analysisUnits.some((u) => u.block.name === 'A')).toBe(true);
  });
});
