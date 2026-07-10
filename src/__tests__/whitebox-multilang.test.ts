import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, realpathSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { initGrammars, __resetGrammarsForTest } from '../recon/ts-grammars.js';
import { ingestRepoToSourceContext, runWhiteboxAnalysis } from '../recon/whitebox.js';
import { DecompositionOrchestrator } from '../orchestration/index.js';

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

  it('runWhiteboxAnalysis (2nd production caller) also feeds multilang source to the orchestrator', async () => {
    // Guards the second createMultiLangIngestConfig swap site — a one-token
    // revert to createPythonIngestConfig would drop non-.py content silently.
    // Stub orch.run so no real LLM calls fire; capture the sourceContext it gets.
    const runSpy = vi
      .spyOn(DecompositionOrchestrator.prototype, 'run')
      .mockResolvedValue({} as never);
    try {
      await runWhiteboxAnalysis({ repoPath: repo, objective: 'x' });
      expect(runSpy).toHaveBeenCalledTimes(1);
      const sourceContext = runSpy.mock.calls[0][1] as string;
      expect(sourceContext).toContain('Fetch'); // Go reached the orchestrator
      expect(sourceContext).toContain('runCmd'); // TS reached the orchestrator
    } finally {
      runSpy.mockRestore();
    }
  });
});
