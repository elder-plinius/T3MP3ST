import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, realpathSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { initGrammars, __resetGrammarsForTest } from '../recon/ts-grammars.js';
import { ingestRepoToSourceContext } from '../recon/whitebox.js';

let base: string;
let repo: string;
let prevRoot: string | undefined;

beforeAll(async () => {
  __resetGrammarsForTest();
  await initGrammars();
  base = realpathSync(mkdtempSync(join(tmpdir(), 't3mp3st-wbml-')));
  prevRoot = process.env.T3MP3ST_REPO_ROOT;
  process.env.T3MP3ST_REPO_ROOT = base;
  repo = join(base, 'repo');
  mkdirSync(repo);
  writeFileSync(join(repo, 'svc.go'), 'package m\nfunc Fetch(url string) error {\n\treturn http.Get(url)\n}\n');
  writeFileSync(join(repo, 'run.ts'), 'export function runCmd(cmd: string) {\n\treturn exec(cmd);\n}\n');
  writeFileSync(join(repo, 'p.py'), 'def load(path):\n    return open(path)\n');
});

afterAll(() => {
  if (prevRoot === undefined) delete process.env.T3MP3ST_REPO_ROOT;
  else process.env.T3MP3ST_REPO_ROOT = prevRoot;
});

describe('ingestRepoToSourceContext (production white-box entry) — multi-language', () => {
  it('non-.py source reaches the packed sourceContext (feature is not a no-op in prod)', () => {
    const { sourceContext } = ingestRepoToSourceContext(repo);
    // Go and TS blocks — proof the multilang config swap actually took effect on the
    // real production path, not just via a direct createMultiLangIngestConfig call.
    expect(sourceContext).toContain('Fetch');
    expect(sourceContext).toContain('runCmd');
    // Python still ingested alongside.
    expect(sourceContext).toContain('load');
  });
});
