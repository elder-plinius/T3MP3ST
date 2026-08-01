/**
 * Regression guard for issue #141 — JS/TS arrow functions and function
 * expressions were never extracted by white-box ingest.
 *
 * The def-queries in `ts-grammars.ts` bound only *declarations*
 * (`function_declaration` / `method_definition` / `class_declaration`), so every
 * definition bound to a value — `const f = (a) => …`, `module.exports.handler =
 * async (e) => …`, `{ upload: (p) => … }`, `class K { f = (z) => … }` — produced
 * no CodeBlock at all. Nothing downstream (classify → prioritize →
 * findEntryPoints → reachability → context pack) ever saw those bodies, so their
 * sinks went unranked and arrow-bound handlers could never become entry points.
 * The file parsed fine; it just yielded nothing, so the hole was silent.
 *
 * These tests pin BOTH directions: every named-value form is extracted with the
 * right name/params/span, and the shapes that carry no name-to-function binding
 * (IIFEs, destructured bindings, HOC-wrapped definitions) stay unmatched rather
 * than being guessed at.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { initGrammars, __resetGrammarsForTest } from '../recon/ts-grammars.js';
import { parseFileMultiLang } from '../recon/ts-parse.js';
import { ingestRepository, createMultiLangIngestConfig } from '../recon/code-ingest.js';

beforeAll(async () => {
  __resetGrammarsForTest(); // clear any singleton state leaked from another test file
  await initGrammars();
});

/**
 * One fixture, valid in all three dialects. Lines 2-13 must each yield exactly
 * one block; lines 14-18 must yield none. Line numbers are asserted, so keep the
 * leading newline and do not reorder.
 */
const FIXTURE = `
const arrowBlock = (req, res) => { eval(req.body); };
const arrowExpr = url => fetch(url);
const arrowAsync = async (a, b) => { await run(a); };
const funcExpr = function (cmd) { exec(cmd); };
const namedFuncExpr = function inner(cmd) { exec(cmd); };
obj.assigned = (u) => http.get(u);
module.exports.handler = async (event) => { exec(event.cmd); };
onmessage = e => eval(e.data);
const routes = { upload: (p) => open(p), legacy: function (q) { open(q); } };
class K { field = (z) => exec(z); m(a) { z(a); } }
export const exported = (s) => exec(s);
function plain(a) { a; }
const notAFn = 42;
const iife = (() => 1)();
const [d1, d2] = [() => 1, () => 2];
export const wrapped = mw(async (req) => exec(req));
let noInit;
`;

/**
 * Exactly the blocks the fixture must produce — nothing more. Asserting the full
 * set (not just presence) is what catches BOTH a missed form and a pattern that
 * double-extracts an existing declaration or matches a non-function initializer.
 */
const EXPECTED = [
  'K',
  'arrowAsync',
  'arrowBlock',
  'arrowExpr',
  'assigned',
  'exported',
  'field',
  'funcExpr',
  'handler',
  'legacy',
  'm',
  'namedFuncExpr',
  'onmessage',
  'plain',
  'upload',
];

describe.each([
  ['.js', 'a.js'],
  ['.ts', 'a.ts'],
  ['.tsx', 'a.tsx'],
])('named-value function extraction (%s)', (ext, path) => {
  const blocks = () => parseFileMultiLang(path, FIXTURE, ext);
  const byName = (name: string) => blocks().filter((b) => b.name === name);
  const one = (name: string) => {
    const hits = byName(name);
    expect(hits, `exactly one block named ${name}`).toHaveLength(1);
    return hits[0];
  };

  it('extracts exactly the named-value and declaration forms, no duplicates', () => {
    expect(blocks().map((b) => b.name).sort()).toEqual(EXPECTED);
  });

  it('extracts a const-bound arrow with its parameters and span', () => {
    const b = one('arrowBlock');
    expect(b.kind).toBe('function');
    expect(b.params).toEqual(['req', 'res']);
    expect(b.lineStart).toBe(2);
    expect(b.body).toContain('eval(req.body)');
  });

  it('extracts an un-parenthesized single-parameter arrow (param name preserved)', () => {
    // `url` is what the risky-parameter heuristic keys on — dropping it would
    // silently downgrade the block's exposure.
    expect(one('arrowExpr').params).toEqual(['url']);
  });

  it('extracts async arrows and function expressions, named or not', () => {
    expect(one('arrowAsync').params).toEqual(['a', 'b']);
    expect(one('funcExpr').params).toEqual(['cmd']);
    expect(one('namedFuncExpr').params).toEqual(['cmd']);
  });

  it('extracts property-assigned functions under the property name', () => {
    // Named by the property, consistent with how `method_definition` is named —
    // it is the name the call graph and the entry-point heuristic match on.
    expect(one('assigned').params).toEqual(['u']);
    expect(one('handler').params).toEqual(['event']);
  });

  it('extracts a bare-identifier assignment (worker/global handler shape)', () => {
    expect(one('onmessage').params).toEqual(['e']);
    expect(one('onmessage').body).toContain('eval(e.data)');
  });

  it('extracts object-literal properties and class fields', () => {
    expect(one('upload').params).toEqual(['p']);
    expect(one('legacy').params).toEqual(['q']);
    expect(one('field').params).toEqual(['z']);
  });

  it('leaves existing declaration forms extracted exactly once', () => {
    expect(one('plain').kind).toBe('function');
    expect(one('m').kind).toBe('method');
    expect(one('K').kind).toBe('class');
  });

  it('does not match shapes with no name-to-function binding', () => {
    // Non-function initializers, IIFEs, destructured bindings and HOC-wrapped
    // definitions have no direct name→function edge; guessing at one would be
    // worse than the honest absence. Tracked as out of scope in #141.
    for (const absent of ['notAFn', 'iife', 'd1', 'd2', 'wrapped', 'noInit']) {
      expect(byName(absent), `${absent} must not be extracted`).toEqual([]);
    }
  });
});

describe('typed parameters (TS dialects)', () => {
  it('strips type annotations from arrow parameters', () => {
    const src = 'export const runCmd = (cmd: string, opts?: Opts): void => { exec(cmd); };\n';
    for (const [ext, path] of [
      ['.ts', 'a.ts'],
      ['.tsx', 'a.tsx'],
    ] as const) {
      const b = parseFileMultiLang(path, src, ext).find((x) => x.name === 'runCmd');
      expect(b, `runCmd in ${ext}`).toBeDefined();
      expect(b!.params).toEqual(['cmd', 'opts']);
    }
  });
});

describe('private class fields', () => {
  it('extracts a #private field arrow (a sink there is as dangerous as a public one)', () => {
    const src = 'class C { #handler = (x) => eval(x); pub = (y) => y; }\n';
    for (const [ext, path] of [
      ['.js', 'c.js'],
      ['.ts', 'c.ts'],
      ['.tsx', 'c.tsx'],
    ] as const) {
      const names = parseFileMultiLang(path, src, ext).map((b) => b.name).sort();
      expect(names, `blocks in ${ext}`).toEqual(['#handler', 'C', 'pub']);
    }
  });
});

describe('same-line duplicate names get distinct ids', () => {
  it('disambiguates two same-named definitions on one line (minified-bundle shape)', () => {
    // `path::name@line` alone collides here, and a colliding id silently merges
    // the two blocks' call-graph entries — one carrying a sink, one not.
    const src = 'const a = { send: (u) => fetch(u) }; const b = { send: (u) => log(u) };\n';
    const blocks = parseFileMultiLang('bundle.min.js', src, '.js').filter((x) => x.name === 'send');
    expect(blocks).toHaveLength(2);
    expect(new Set(blocks.map((x) => x.id)).size).toBe(2);
    expect(blocks[0].id).toBe('bundle.min.js::send@1'); // first keeps the plain id
  });
});

describe('JSX (.tsx)', () => {
  it('extracts an arrow-bound React component and its handler', () => {
    const src =
      'const Panel = ({ url }: Props) => {\n' +
      '  const onSubmit = (e) => fetch(url);\n' +
      '  return <form onSubmit={onSubmit} />;\n' +
      '};\n';
    const blocks = parseFileMultiLang('p.tsx', src, '.tsx');
    expect(blocks.map((b) => b.name).sort()).toEqual(['Panel', 'onSubmit']);
    expect(blocks.find((b) => b.name === 'onSubmit')!.params).toEqual(['e']);
  });
});

describe('arrow-bound definitions reach the security pipeline (#141 headline)', () => {
  function repo(): string {
    const root = mkdtempSync(join(tmpdir(), 'arrowfn-'));
    // Every function here is arrow-bound: before the fix this whole repo
    // ingested as zero blocks from these two files.
    writeFileSync(
      join(root, 'svc.ts'),
      'export const runCmd = (cmd: string) => exec(cmd);\n' +
        'export const addUp = (a: number, b: number) => a + b;\n',
    );
    writeFileSync(
      join(root, 'lambda.js'),
      'module.exports.handler = async (event) => {\n  return runCmd(event.cmd);\n};\n',
    );
    return root;
  }

  it('ranks an arrow-bound sink as attack_surface and elevates an arrow-bound handler to an entry point', () => {
    const { analysisUnits, entryPoints } = ingestRepository(createMultiLangIngestConfig(repo()));
    const by = (name: string) => analysisUnits.find((u) => u.block.name === name);

    for (const name of ['runCmd', 'addUp', 'handler']) {
      expect(by(name), `block ${name} extracted`).toBeDefined();
    }
    expect(by('runCmd')!.exposure).toBe('attack_surface');
    expect(by('addUp')!.exposure).toBe('neutral');
    expect(by('runCmd')!.priority).toBeGreaterThan(by('addUp')!.priority);

    // `handler` matches the entry-point name heuristic — unreachable before the
    // fix because the block did not exist.
    expect(entryPoints).toContain(by('handler')!.block.id);
  });

  it('links the arrow-bound handler to the sink it calls (reachability)', () => {
    const { analysisUnits } = ingestRepository(createMultiLangIngestConfig(repo()));
    const handler = analysisUnits.find((u) => u.block.name === 'handler')!;
    const runCmd = analysisUnits.find((u) => u.block.name === 'runCmd')!;
    expect(handler.callees).toContain(runCmd.block.id);
    expect(runCmd.reachable).toBe(true);
  });
});
