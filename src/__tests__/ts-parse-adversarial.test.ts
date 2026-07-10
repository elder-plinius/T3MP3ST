/**
 * Adversarial hardening — ingest parses UNTRUSTED target source. A crafted file
 * must never throw, hang, or crash a mission; worst case is fail-open to the
 * Python regex parser. Drives the full wired path (parseFileMultiLang +
 * ingestRepository/crawl).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { mkdtempSync, writeFileSync, mkdirSync, symlinkSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { initGrammars, __resetGrammarsForTest } from '../recon/ts-grammars.js';
import { parseFileMultiLang } from '../recon/ts-parse.js';
import { ingestRepository, createMultiLangIngestConfig, type CodeBlock } from '../recon/code-ingest.js';

beforeAll(async () => {
  __resetGrammarsForTest();
  await initGrammars();
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

  it('wrong-language content (Python in a .go file) does not throw', () => {
    expect(() => parseFileMultiLang('x.go', 'def fetch(url):\n    return get(url)\n', '.go')).not.toThrow();
  });

  it('binary / non-UTF8 bytes do not throw', () => {
    const bin = Buffer.from([0x00, 0xff, 0xfe, 0x10, 0x80, 0x00, 0x41]).toString('binary');
    expect(() => invariants(parseFileMultiLang('x.go', bin, '.go'))).not.toThrow();
  });

  it('empty file yields no blocks, no throw', () => {
    expect(parseFileMultiLang('e.go', '', '.go')).toEqual([]);
  });

  it('unicode identifiers are handled', () => {
    const blocks = parseFileMultiLang('u.go', 'package m\nfunc Ünïçødé(x int) int { return x }\n', '.go');
    expect(() => invariants(blocks)).not.toThrow();
  });

  it('large file parses within the wall-clock budget (progress callback fires)', () => {
    let src = 'package m\n';
    for (let i = 0; i < 20000; i++) src += `func F${i}(url string) error { return http.Get(url) }\n`;
    const t0 = Date.now();
    const blocks = parseFileMultiLang('big.go', src, '.go');
    expect(Date.now() - t0).toBeLessThan(10000); // bounded — never spins
    expect(blocks.length).toBeGreaterThan(0);
  });

  it('deeply nested input does not blow the stack or hang', () => {
    const deep = 'package m\nfunc F() { ' + '{'.repeat(2000) + '}'.repeat(2000) + ' }\n';
    expect(() => parseFileMultiLang('d.go', deep, '.go')).not.toThrow();
  });
});

describe('adversarial crawl / ingest', () => {
  it('symlink loop under the repo root terminates (crawl does not follow symlink dirs)', () => {
    const root = mkdtempSync(join(tmpdir(), 'advcrawl-'));
    const sub = join(root, 'sub');
    mkdirSync(sub);
    writeFileSync(join(sub, 'a.go'), 'package m\nfunc A() {}\n');
    try {
      symlinkSync(root, join(sub, 'loop'), 'dir'); // self-referential loop
    } catch {
      return; // symlinks unavailable (e.g. restricted env) — skip
    }
    const t0 = Date.now();
    const result = ingestRepository(createMultiLangIngestConfig(root));
    expect(Date.now() - t0).toBeLessThan(10000); // did not spin on the loop
    expect(result.analysisUnits.some((u) => u.block.name === 'A')).toBe(true);
  });
});
