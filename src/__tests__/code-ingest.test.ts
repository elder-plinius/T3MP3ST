/**
 * code-ingest tests
 *
 * Builds a tiny temp Python repo with mkdtempSync, runs the full
 * ingestRepository pipeline over it, and asserts the SELECTION behavior:
 *   - blocks extracted with correct names + plausible line ranges
 *   - entry points detected from @app.route decorators
 *   - call graph resolves an intra-repo call (handler -> helper)
 *   - classification precedence: route -> exposed_externally,
 *     fetch_url -> attack_surface, validate_token -> security_control,
 *     format_name -> neutral
 *   - priority: the exposed handler outranks the neutral util
 *   - packAnalysisUnits preserves priority order and respects a small budget
 *
 * Reminder: code-ingest is a PYTHON-ONLY regex "AST-lite" prototype (see the
 * module header) — these tests exercise the constructs it is designed to handle.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import {
  ingestRepository,
  createPythonIngestConfig,
  parseFile,
  buildCallGraph,
  findEntryPoints,
  packAnalysisUnits,
  formatUnitForLLM,
  crawl,
  type IngestResult,
  type AnalysisUnit,
} from '../recon/code-ingest.js';
import { estimateTokens } from '../orchestration/context-pack.js';

// ---------------------------------------------------------------------------
// Temp repo fixture
// ---------------------------------------------------------------------------

const APP_PY = `from flask import Flask, request
from util import fetch_url, validate_token, format_name

app = Flask(__name__)


@app.route("/proxy")
def proxy_view():
    token = request.args.get("token")
    if not validate_token(token):
        return "no", 403
    data = fetch_url(request.args.get("target"))
    return data


@app.route("/health")
def health_view():
    return "ok"
`;

const UTIL_PY = `import requests


def fetch_url(url):
    resp = requests.get(url)
    return resp.text


def validate_token(tok):
    return tok == "secret"


def format_name(x):
    return str(x).strip().title()
`;

// A file that must be skipped because it lives in a test dir.
const TEST_PY = `def test_something():
    assert True
`;

let repoRoot: string;
let result: IngestResult;

beforeAll(() => {
  repoRoot = mkdtempSync(join(tmpdir(), 'code-ingest-'));
  writeFileSync(join(repoRoot, 'app.py'), APP_PY);
  writeFileSync(join(repoRoot, 'util.py'), UTIL_PY);

  // a dir that must be excluded by default
  mkdirSync(join(repoRoot, 'tests'));
  writeFileSync(join(repoRoot, 'tests', 'test_app.py'), TEST_PY);

  // a non-python file that must be ignored by includeExts
  writeFileSync(join(repoRoot, 'README.md'), '# not python\n');

  const config = createPythonIngestConfig(repoRoot);
  result = ingestRepository(config);
});

afterAll(() => {
  rmSync(repoRoot, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function unitByName(name: string): AnalysisUnit {
  const u = result.analysisUnits.find((au) => au.block.name === name);
  if (!u) throw new Error(`no analysis unit for ${name}`);
  return u;
}

// ---------------------------------------------------------------------------
// crawl
// ---------------------------------------------------------------------------

describe('crawl', () => {
  it('keeps .py files and skips test dirs + non-python files', () => {
    const files = crawl(createPythonIngestConfig(repoRoot));
    const names = files.map((f) => f.split(/[\\/]/).pop());
    expect(names).toContain('app.py');
    expect(names).toContain('util.py');
    // excluded by default test-dir rule
    expect(names).not.toContain('test_app.py');
    // excluded by includeExts (.py only)
    expect(names).not.toContain('README.md');
  });
});

// ---------------------------------------------------------------------------
// parseFile
// ---------------------------------------------------------------------------

describe('parseFile', () => {
  it('extracts function blocks with names, params, and plausible line ranges', () => {
    const blocks = parseFile('util.py', UTIL_PY);
    const names = blocks.map((b) => b.name);
    expect(names).toContain('fetch_url');
    expect(names).toContain('validate_token');
    expect(names).toContain('format_name');

    const fetch = blocks.find((b) => b.name === 'fetch_url')!;
    expect(fetch.kind).toBe('function');
    expect(fetch.params).toEqual(['url']);
    // def is on line 4 of UTIL_PY (1-indexed), body spans a couple lines
    expect(fetch.lineStart).toBe(4);
    expect(fetch.lineEnd).toBeGreaterThanOrEqual(fetch.lineStart);
    expect(fetch.lineEnd).toBeLessThan(fetch.lineStart + 4);
    expect(fetch.body).toContain('requests.get(url)');
    // stable id shape
    expect(fetch.id).toBe(`util.py::fetch_url@${fetch.lineStart}`);
  });

  it('captures decorators immediately preceding a def', () => {
    const blocks = parseFile('app.py', APP_PY);
    const proxy = blocks.find((b) => b.name === 'proxy_view')!;
    expect(proxy.decorators.join('\n')).toContain('@app.route("/proxy")');
  });

  it('labels methods nested under a class as "method"', () => {
    const src = [
      'class Service:',
      '    def handle(self, req):',
      '        return req',
      '',
      'def free_function(a):',
      '    return a',
    ].join('\n');
    const blocks = parseFile('svc.py', src);
    const cls = blocks.find((b) => b.name === 'Service')!;
    const method = blocks.find((b) => b.name === 'handle')!;
    const fn = blocks.find((b) => b.name === 'free_function')!;
    expect(cls.kind).toBe('class');
    expect(method.kind).toBe('method');
    // self dropped from params
    expect(method.params).toEqual(['req']);
    expect(fn.kind).toBe('function');
  });

  it('recovers a multiline def signature instead of dropping the function', () => {
    // A security-relevant function whose params span lines must NOT vanish.
    const src = [
      'def transfer(',
      '    src_account,',
      '    dst_account,',
      '    amount=compute_fee(0),',
      '):',
      '    do_wire(src_account, dst_account, amount)',
      '    return True',
      '',
      'def after(x):',
      '    return x',
    ].join('\n');
    const blocks = parseFile('bank.py', src);
    const transfer = blocks.find((b) => b.name === 'transfer');
    expect(transfer, 'transfer() must be captured, not dropped').toBeTruthy();
    // params gathered across lines, defaults/nested-call stripped to bare names
    expect(transfer!.params).toEqual(['src_account', 'dst_account', 'amount']);
    expect(transfer!.lineStart).toBe(1);
    // body reaches past the ")" line to the real statements
    expect(transfer!.body).toContain('do_wire(');
    // the following def is still parsed (signature lines were skipped, not eaten)
    expect(blocks.find((b) => b.name === 'after')).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// entry points + call graph
// ---------------------------------------------------------------------------

describe('findEntryPoints', () => {
  it('detects @app.route handlers as entry points', () => {
    const blocks = parseFile('app.py', APP_PY);
    const eps = findEntryPoints(blocks);
    const proxy = blocks.find((b) => b.name === 'proxy_view')!;
    const health = blocks.find((b) => b.name === 'health_view')!;
    expect(eps).toContain(proxy.id);
    expect(eps).toContain(health.id);
  });
});

describe('buildCallGraph', () => {
  it('resolves an intra-repo call from a handler to a helper', () => {
    const blocks = [
      ...parseFile('app.py', APP_PY),
      ...parseFile('util.py', UTIL_PY),
    ];
    const graph = buildCallGraph(blocks);
    const proxy = blocks.find((b) => b.name === 'proxy_view')!;
    const fetch = blocks.find((b) => b.name === 'fetch_url')!;

    // handler -> helper edge
    expect(graph[proxy.id].callees).toContain(fetch.id);
    // inverse: helper knows its caller
    expect(graph[fetch.id].callers).toContain(proxy.id);
  });
});

// ---------------------------------------------------------------------------
// full pipeline: classification, reachability, priority
// ---------------------------------------------------------------------------

describe('ingestRepository classification', () => {
  it('classifies a @route handler as exposed_externally', () => {
    expect(unitByName('proxy_view').exposure).toBe('exposed_externally');
    expect(result.entryPoints).toContain(unitByName('proxy_view').block.id);
  });

  it('classifies fetch_url (outbound request sink) as attack_surface', () => {
    const fetch = unitByName('fetch_url');
    expect(fetch.exposure).toBe('attack_surface');
    // evidence recorded
    expect(fetch.riskSignals.some((s) => s.includes('requests.get'))).toBe(true);
    // SSRF/IDOR shape: url param + outbound request
    expect(fetch.riskSignals.some((s) => s.startsWith('ssrf-idor:'))).toBe(true);
  });

  it('classifies validate_token as security_control (by name)', () => {
    expect(unitByName('validate_token').exposure).toBe('security_control');
  });

  it('classifies format_name as neutral', () => {
    expect(unitByName('format_name').exposure).toBe('neutral');
  });

  it('reaches fetch_url from the proxy_view entry point', () => {
    const fetch = unitByName('fetch_url');
    expect(fetch.reachable).toBe(true);
    expect(fetch.reachDepth).toBe(1);
    // representative reachability path starts at the handler
    expect(fetch.reachabilityPaths[0][0]).toBe(unitByName('proxy_view').block.id);
  });

  it('stats account for every block and every exposure class', () => {
    const { stats } = result;
    expect(stats.files).toBe(2); // app.py + util.py (tests dir excluded)
    expect(stats.blocks).toBe(result.analysisUnits.length);
    const sum =
      stats.exposed_externally +
      stats.exposed_internally +
      stats.attack_surface +
      stats.security_control +
      stats.neutral;
    expect(sum).toBe(stats.blocks);
  });
});

describe('ingestRepository priority ordering', () => {
  it('ranks the exposed handler above the neutral util', () => {
    const handler = unitByName('proxy_view');
    const neutral = unitByName('format_name');
    expect(handler.priority).toBeGreaterThan(neutral.priority);
  });

  it('emits analysisUnits sorted by priority descending', () => {
    const priorities = result.analysisUnits.map((u) => u.priority);
    const sorted = [...priorities].sort((a, b) => b - a);
    expect(priorities).toEqual(sorted);
  });

  it('never assigns a negative priority (unreachable just misses the bonus)', () => {
    for (const u of result.analysisUnits) {
      expect(u.priority).toBeGreaterThanOrEqual(0);
    }
  });
});

// ---------------------------------------------------------------------------
// composition with context-pack
// ---------------------------------------------------------------------------

describe('packAnalysisUnits', () => {
  it('respects a small token budget and drops the lowest-priority units', () => {
    const units = result.analysisUnits;
    // Budget large enough for the top unit but not all of them.
    const topCost = estimateTokens(formatUnitForLLM(units[0]));
    const budget = topCost + 5;

    const packed = packAnalysisUnits(units, budget);

    expect(packed.tokensUsed).toBeLessThanOrEqual(budget);
    expect(packed.includedUnits.length).toBeGreaterThan(0);
    expect(packed.droppedUnits.length).toBeGreaterThan(0);
    // nothing vanishes off the books
    expect(packed.includedUnits.length + packed.droppedUnits.length).toBe(
      units.length,
    );
    // the highest-priority unit is included, a lower one is dropped
    expect(packed.includedUnits[0].block.name).toBe(units[0].block.name);
  });

  it('preserves the incoming (security) priority order among included units', () => {
    const units = result.analysisUnits;
    const packed = packAnalysisUnits(units, 100_000); // everything fits
    const includedNames = packed.includedUnits.map((u) => u.block.name);
    const originalNames = units.map((u) => u.block.name);
    // same order, all included
    expect(includedNames).toEqual(originalNames);
    expect(packed.droppedUnits).toHaveLength(0);
  });

  it('formatUnitForLLM renders path:lines, exposure, risk signals, and body', () => {
    const fetch = unitByName('fetch_url');
    const text = formatUnitForLLM(fetch);
    expect(text).toContain(`util.py:${fetch.block.lineStart}-${fetch.block.lineEnd}`);
    expect(text).toContain('exposure: attack_surface');
    expect(text).toContain('risk signals:');
    expect(text).toContain('requests.get(url)'); // body included
  });

  it('redacts source secrets before producing LLM-facing context', () => {
    const blocks = parseFile('secrets.py', `def leak():\n    api_key = "sk-ant-api03-ABCDEFGHIJKLMNOP"\n    return "Authorization: Bearer abcdefghijklmnop"\n`);
    const block = blocks[0];
    if (!block) throw new Error('expected parseFile to return a block');
    const unit: AnalysisUnit = {
      block,
      exposure: 'neutral',
      callers: [],
      callees: [],
      reachable: false,
      reachDepth: Infinity,
      reachabilityPaths: [],
      riskSignals: [],
      priority: 0,
    };

    const formatted = formatUnitForLLM(unit);
    const packed = packAnalysisUnits([unit], 100_000).text;

    for (const text of [formatted, packed]) {
      expect(text).not.toContain('sk-ant-api03-ABCDEFGHIJKLMNOP');
      expect(text).not.toContain('Bearer abcdefghijklmnop');
      expect(text).toContain('[redacted]');
    }
  });
});
