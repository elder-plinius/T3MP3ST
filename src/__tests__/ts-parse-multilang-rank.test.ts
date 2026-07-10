import { describe, it, expect, beforeAll } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { initGrammars, __resetGrammarsForTest } from '../recon/ts-grammars.js';
import { ingestRepository, createMultiLangIngestConfig } from '../recon/code-ingest.js';

beforeAll(async () => {
  __resetGrammarsForTest();
  await initGrammars();
});

describe('multi-language ingest → security ranking (headline regression)', () => {
  function repo(): string {
    const root = mkdtempSync(join(tmpdir(), 'mlrank-'));
    // Go: Handler calls Fetch; Fetch is an SSRF surface (identifier param + outbound).
    writeFileSync(
      join(root, 'svc.go'),
      'package m\n' +
        'func Handler(url string) error {\n\treturn Fetch(url)\n}\n' +
        'func Fetch(url string) error {\n\treturn http.Get(url)\n}\n' +
        'func Add(a int, b int) int {\n\treturn a + b\n}\n',
    );
    // TS: command-exec sink.
    writeFileSync(join(root, 'run.ts'), 'export function runCmd(cmd: string) { return exec(cmd); }\n');
    // Java: Runtime.exec sink.
    writeFileSync(join(root, 'A.java'), 'class A { void run(String cmd){ Runtime.getRuntime().exec(cmd); } }\n');
    // Python still works alongside (regex path).
    writeFileSync(join(root, 'p.py'), 'def load(path):\n    return open(path)\n');
    return root;
  }

  it('extracts non-.py functions and security-ranks them as attack_surface', () => {
    const { analysisUnits } = ingestRepository(createMultiLangIngestConfig(repo()));
    const by = (name: string) => analysisUnits.find((u) => u.block.name === name);

    // multi-language extraction reached the pipeline (Go/TS/Java + Python)
    for (const name of ['Fetch', 'runCmd', 'run', 'load']) {
      expect(by(name), `block ${name} extracted`).toBeDefined();
    }

    // sink-bearing functions are attack_surface, out-ranking a neutral block
    for (const name of ['Fetch', 'runCmd', 'run']) {
      expect(by(name)!.exposure, `${name} exposure`).toBe('attack_surface');
    }
    expect(by('Fetch')!.priority).toBeGreaterThan(by('Add')!.priority);
    expect(by('Add')!.exposure).toBe('neutral');
  });

  it('call graph links non-Python identifiers (cross-language reachability guard)', () => {
    const { analysisUnits } = ingestRepository(createMultiLangIngestConfig(repo()));
    const handler = analysisUnits.find((u) => u.block.name === 'Handler')!;
    const fetch = analysisUnits.find((u) => u.block.name === 'Fetch')!;
    // buildCallGraph matched the Go call "Fetch(url)" inside Handler by name.
    expect(handler.callees).toContain(fetch.block.id);
    expect(fetch.callers).toContain(handler.block.id);
  });
});
