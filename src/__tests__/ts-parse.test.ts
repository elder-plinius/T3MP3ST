import { describe, it, expect, beforeAll } from 'vitest';
import type { Parser } from 'web-tree-sitter';
import { initGrammars, __resetGrammarsForTest } from '../recon/ts-grammars.js';
import { parseFileMultiLang, nodeToCodeBlock } from '../recon/ts-parse.js';
import { parseFile } from '../recon/code-ingest.js';

beforeAll(async () => {
  __resetGrammarsForTest(); // clear any singleton state leaked from another test file
  await initGrammars();
});

describe('parseFileMultiLang', () => {
  it('extracts a Go function as a CodeBlock', () => {
    const src = 'package m\nfunc Fetch(url string) error {\n  return http.Get(url)\n}\n';
    const fn = parseFileMultiLang('a.go', src, '.go').find((b) => b.name === 'Fetch');
    expect(fn).toBeDefined();
    expect(fn!.params).toEqual(['url']);
    expect(fn!.kind).toBe('function');
    expect(fn!.lineStart).toBe(2);
    expect(fn!.body).toContain('http.Get(url)');
    expect(fn!.id).toBe('a.go::Fetch@2');
    expect(fn!.decorators).toEqual([]);
  });

  it('extracts a TS class + method', () => {
    const src = 'class Svc {\n  run(cmd: string) { exec(cmd); }\n}\n';
    const blocks = parseFileMultiLang('s.ts', src, '.ts');
    expect(blocks.find((b) => b.name === 'Svc')?.kind).toBe('class');
    const m = blocks.find((b) => b.name === 'run');
    expect(m?.kind).toBe('method');
    expect(m?.params).toEqual(['cmd']);
  });

  it('extracts a Java constructor as a method', () => {
    const blocks = parseFileMultiLang('A.java', 'class A {\n  A(int x){}\n}\n', '.java');
    expect(blocks.find((b) => b.name === 'A' && b.kind === 'method')).toBeDefined();
    expect(blocks.find((b) => b.name === 'A' && b.kind === 'class')).toBeDefined();
  });

  it('.py routes to the regex parser (byte-identical)', () => {
    const src = 'def fetch(url):\n    return get(url)\n';
    expect(parseFileMultiLang('a.py', src, '.py')).toEqual(parseFile('a.py', src));
  });

  it('unsupported ext fail-opens to parseFile (no throw)', () => {
    const src = 'func F(){}';
    expect(parseFileMultiLang('a.zzz', src, '.zzz')).toEqual(parseFile('a.zzz', src));
  });

  it('fail-open on parse timeout (parse returns null)', () => {
    const src = 'package m\nfunc F(){}\n';
    const nullParser = () =>
      ({ setLanguage() {}, setTimeoutMicros() {}, parse: () => null }) as unknown as Parser;
    expect(parseFileMultiLang('a.go', src, '.go', nullParser)).toEqual(parseFile('a.go', src));
  });

  it('fail-open on parser error (parse throws)', () => {
    const src = 'package m\nfunc F(){}\n';
    const throwParser = () =>
      ({
        setLanguage() {},
        setTimeoutMicros() {},
        parse() {
          throw new Error('boom');
        },
      }) as unknown as Parser;
    expect(parseFileMultiLang('a.go', src, '.go', throwParser)).toEqual(parseFile('a.go', src));
  });
});

describe('nodeToCodeBlock', () => {
  it('maps a class node (no params) to kind=class with empty params', () => {
    const fake = {
      type: 'class_declaration',
      startPosition: { row: 4 },
      endPosition: { row: 9 },
      text: 'class C {}',
    } as never;
    const name = { text: 'C' } as never;
    const cb = nodeToCodeBlock(fake, name, undefined, 'x.ts', 'ts');
    expect(cb).toMatchObject({ name: 'C', kind: 'class', lineStart: 5, lineEnd: 10, params: [], id: 'x.ts::C@5' });
  });
});
