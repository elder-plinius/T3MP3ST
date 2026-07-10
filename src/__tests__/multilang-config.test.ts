import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { crawl, createMultiLangIngestConfig } from '../recon/code-ingest.js';

describe('createMultiLangIngestConfig', () => {
  const EXTS = ['py', 'js', 'ts', 'tsx', 'go', 'java', 'c', 'cpp'];

  it('crawls every supported extension and excludes non-source', () => {
    const root = mkdtempSync(join(tmpdir(), 'mling-'));
    for (const e of EXTS) writeFileSync(join(root, `f.${e}`), 'x\n');
    writeFileSync(join(root, 'd.md'), '# ignore');
    writeFileSync(join(root, 'e.txt'), 'ignore');

    const files = crawl(createMultiLangIngestConfig(root));

    for (const e of EXTS) {
      expect(files.some((f) => f.endsWith(`f.${e}`)), `includes .${e}`).toBe(true);
    }
    expect(files.some((f) => f.endsWith('d.md'))).toBe(false);
    expect(files.some((f) => f.endsWith('e.txt'))).toBe(false);
  });
});
