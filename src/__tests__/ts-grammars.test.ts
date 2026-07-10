import { describe, it, expect, beforeEach } from 'vitest';
import { Parser } from 'web-tree-sitter';
import {
  initGrammars,
  getGrammar,
  supportedExts,
  __resetGrammarsForTest,
} from '../recon/ts-grammars.js';

describe('ts-grammars registry', () => {
  beforeEach(() => __resetGrammarsForTest());

  it('advertises the multi-language extension set', () => {
    expect(supportedExts()).toEqual(
      expect.arrayContaining(['.py', '.js', '.ts', '.tsx', '.go', '.java', '.c', '.cpp']),
    );
  });

  it('loads every grammar with a working def-query (multi-language, real parse)', async () => {
    await initGrammars();
    const samples: Record<string, string> = {
      '.py': 'def fetch(url):\n    return get(url)\n',
      '.js': 'function fetch(url){return get(url)}\n',
      '.ts': 'export function fetch(url: string){return get(url)}\n',
      '.tsx': 'export function F(p: {a:number}){ return null; }\n',
      '.go': 'package m\nfunc Fetch(url string) error { return nil }\n',
      '.java': 'class A { void run(String u){} }\n',
      '.c': 'int fetch(char *url){ return 0; }\n',
      '.cpp': 'int fetch(char *url){ return 0; }\n',
    };
    for (const ext of supportedExts()) {
      const g = getGrammar(ext);
      expect(g, `grammar for ${ext}`).toBeDefined();
      const p = new Parser();
      p.setLanguage(g!.language);
      const tree = p.parse(samples[ext]);
      const names = g!.query
        .matches(tree!.rootNode)
        .flatMap((m) => m.captures.filter((c) => c.name === 'name').map((c) => c.node.text));
      expect(names.length, `captures for ${ext}`).toBeGreaterThan(0);
    }
  });

  it('is idempotent — a second init keeps the loaded registry', async () => {
    await initGrammars(['.go']);
    await initGrammars(['.py']); // second call is a no-op (already initialized)
    expect(getGrammar('.go')).toBeDefined();
    expect(getGrammar('.py')).toBeUndefined();
  });

  it('fail-open: per-grammar load failure skips that ext, no throw', async () => {
    await expect(
      initGrammars(['.go'], () => { throw new Error('bad wasm path'); }),
    ).resolves.toBeUndefined();
    expect(getGrammar('.go')).toBeUndefined();
  });

  it('fail-open: global init failure leaves the registry empty, no throw', async () => {
    await expect(
      initGrammars(supportedExts(), (n) => n, () => Promise.reject(new Error('runtime init failed'))),
    ).resolves.toBeUndefined();
    for (const ext of supportedExts()) expect(getGrammar(ext)).toBeUndefined();
  });

  it('ignores unknown extensions', async () => {
    await initGrammars(['.zzz']);
    expect(getGrammar('.zzz')).toBeUndefined();
  });
});
