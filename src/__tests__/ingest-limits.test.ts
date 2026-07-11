/**
 * ingest ceiling tests — the bounded-ingest hardening must FIRE only on pathological input
 * and leave a normal ingest byte-identical (no truncated flag, no behavior change).
 */

import { describe, it, expect, afterAll } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { ingestRepository, crawl, type IngestConfig } from '../recon/code-ingest.js';

function makeRepo(nFiles: number): string {
  const dir = mkdtempSync(join(tmpdir(), 't3mp3st-ingest-limits-'));
  for (let i = 0; i < nFiles; i++) {
    writeFileSync(join(dir, `mod_${i}.py`), `def f_${i}(x):\n    return x + ${i}\n`);
  }
  return dir;
}

describe('ingest ceilings (bounded ingest, non-regressing)', () => {
  const dirs: string[] = [];
  const cfg = (repoRoot: string, extra: Partial<IngestConfig> = {}): IngestConfig => ({
    repoRoot, includeExts: ['.py'], excludeGlobs: [], ...extra,
  });
  afterAll(() => { for (const d of dirs) { try { rmSync(d, { recursive: true, force: true }); } catch { /* noop */ } } });

  it('crawl caps at maxFiles and ingest flags stats.truncated', () => {
    const dir = makeRepo(20); dirs.push(dir);
    expect(crawl(cfg(dir, { maxFiles: 5 })).length).toBe(5);
    const res = ingestRepository(cfg(dir, { maxFiles: 5 }));
    expect(res.stats.files).toBe(5);
    expect(res.stats.truncated).toBe(true);
  });

  it('ingest caps at maxTotalBytes and flags stats.truncated', () => {
    const dir = makeRepo(20); dirs.push(dir);
    const res = ingestRepository(cfg(dir, { maxTotalBytes: 50 })); // ~30 bytes/file → breaks after ~2
    expect(res.stats.truncated).toBe(true);
    expect(res.stats.files).toBeLessThan(20);
    expect(res.stats.files).toBe(res.stats.blocks); // fixture has one block per processed file
    expect(res.stats.blocks).toBeGreaterThan(0);
  });

  it('a NORMAL ingest under the ceilings is unchanged — no truncated key', () => {
    const dir = makeRepo(10); dirs.push(dir);
    const res = ingestRepository(cfg(dir, { maxFiles: 50000, maxTotalBytes: 1_000_000_000 }));
    expect(res.stats.files).toBe(10);
    expect(res.stats.blocks).toBe(10);
    expect(res.stats.truncated).toBeUndefined(); // shape identical to pre-hardening
  });

  it('no ceilings configured = fully unbounded (back-compat)', () => {
    const dir = makeRepo(8); dirs.push(dir);
    const res = ingestRepository(cfg(dir)); // no maxFiles / maxTotalBytes at all
    expect(res.stats.files).toBe(8);
    expect(res.stats.truncated).toBeUndefined();
  });

  it('an empty / non-Python repo yields 0 files (the ONLY case the whitebox guard throws on)', () => {
    const dir = mkdtempSync(join(tmpdir(), 't3mp3st-ingest-empty-')); dirs.push(dir);
    writeFileSync(join(dir, 'README.md'), '# not python\n');
    const res = ingestRepository(cfg(dir));
    expect(res.stats.files).toBe(0);
    expect(res.analysisUnits.length).toBe(0);
  });

  it('a Python repo with only module-level code has files>0 but 0 blocks (whitebox guard must NOT throw)', () => {
    // A valid script (imports + top-level statements, no def/class) is legitimate input. The
    // whitebox empty-guard gates on stats.files===0, so this files>0 case proceeds — it must
    // NOT regress into a 500 (regression sweep finding #2).
    const dir = mkdtempSync(join(tmpdir(), 't3mp3st-ingest-modlevel-')); dirs.push(dir);
    writeFileSync(join(dir, 'app.py'), 'import os\nx = 1\nprint(os.getcwd(), x)\n');
    const res = ingestRepository(cfg(dir));
    expect(res.stats.files).toBe(1);          // there IS source
    expect(res.analysisUnits.length).toBe(0); // but 0 extractable def/class blocks
  });
});
