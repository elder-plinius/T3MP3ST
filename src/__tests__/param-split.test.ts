import { describe, it, expect } from 'vitest';
import { splitParamList } from '../recon/param-split.js';

describe('splitParamList', () => {
  it('python: drops self, strips annotations/defaults, drops *args', () =>
    expect(splitParamList('self, url: str, timeout=5, *args', 'py')).toEqual(['url', 'timeout']));
  it('go name-first, drops types', () =>
    expect(splitParamList('ctx context.Context, id string', 'go')).toEqual(['ctx', 'id']));
  it('java type-first, keeps trailing name', () =>
    expect(splitParamList('String url, int max', 'java')).toEqual(['url', 'max']));
  it('ts name: type, strips optional marker', () =>
    expect(splitParamList('url: string, opts?: Opts', 'ts')).toEqual(['url', 'opts']));
  it('empty', () => expect(splitParamList('', 'ts')).toEqual([]));
  it('SAME raw, different lang → forces real dispatch', () => {
    expect(splitParamList('a b', 'go')).toEqual(['a']); // name-first
    expect(splitParamList('a b', 'java')).toEqual(['b']); // type-first
  });
  it('strips surrounding parens (tree-sitter params node text)', () =>
    expect(splitParamList('(url string)', 'go')).toEqual(['url']));
  it('c pointers: type-first, strips *', () =>
    expect(splitParamList('char *url, int n', 'c')).toEqual(['url', 'n']));
  it('generics do not split params', () =>
    expect(splitParamList('m Map<int, string>, n int', 'go')).toEqual(['m', 'n']));
  it('python drops bare * and / markers', () =>
    expect(splitParamList('a, *, b, /', 'py')).toEqual(['a', 'b']));
  it('python drops cls', () =>
    expect(splitParamList('cls, x', 'py')).toEqual(['x']));
  it('ts rest param + array type', () =>
    expect(splitParamList('...args: number[]', 'ts')).toEqual(['args']));
  it('cpp references and pointers stripped', () =>
    expect(splitParamList('const std::string &ref, int* p', 'cpp')).toEqual(['ref', 'p']));
  it('c array-suffix name stripped', () =>
    expect(splitParamList('char buf[]', 'c')).toEqual(['buf']));
  it('bracket + brace nesting does not split', () => {
    expect(splitParamList('a int[2], b T{}', 'go')).toEqual(['a', 'b']);
  });
  it('unbalanced close bracket is tolerated', () =>
    expect(splitParamList('a)x, b', 'go')).toEqual(['a', 'b']));
  it('non-identifier params are dropped', () =>
    expect(splitParamList('*, ---', 'go')).toEqual([]));
  it('trailing comma tolerated', () =>
    expect(splitParamList('a,', 'go')).toEqual(['a']));
  it('empty segment (double comma) dropped', () =>
    expect(splitParamList('a,,b', 'go')).toEqual(['a', 'b']));
  it('ts name-less param dropped', () =>
    expect(splitParamList(': int, x: str', 'ts')).toEqual(['x']));
  it('java name-less param dropped', () =>
    expect(splitParamList('=v, int x', 'java')).toEqual(['x']));
});
