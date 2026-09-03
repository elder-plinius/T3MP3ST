/**
 * Regression guard for issue #165 — cross-language sink EVIDENCE.
 *
 * `DANGEROUS_SINK_RE` classifies Go/Java/JS/C sinks as attack_surface, but
 * `SINK_EVIDENCE_RES` (which produces the `sink:<label>` entries in riskSignals)
 * was Python-only. So a non-Python function shelled out via `exec.Command(...)`
 * ranked attack_surface with a BLANK reason — the operator triage list and the
 * reasoning-layer context pack both saw a flagged block with no evidence, and
 * `prioritize()` (`+10 * riskSignals.length`) under-ranked it vs a Python peer.
 *
 * The invariant this pins: a block that is attack_surface BY SINK always carries
 * at least one `sink:` evidence label, in every supported language.
 */
import { describe, it, expect } from 'vitest';
import { classify, DANGEROUS_SINK_RE, type CodeBlock } from '../recon/code-ingest.js';

/** Minimal attack-surface-eligible block: neutral name (not a security control),
 * no params (so the only signals are sinks, not the ssrf-idor combo). */
function block(body: string): CodeBlock {
  return {
    id: 'x::sinkFn@1',
    path: 'x',
    name: 'sinkFn',
    kind: 'function',
    lineStart: 1,
    lineEnd: 3,
    params: [],
    decorators: [],
    body,
  };
}

const NEUTRAL_CTX = { isEntryPoint: false, reachable: false };

/** The `sink:`-prefixed signals for a body, sorted (order is not semantically
 * meaningful downstream — priority weighs `riskSignals.length`). */
function sinkLabelsOf(body: string): string[] {
  return classify(block(body), NEUTRAL_CTX)
    .riskSignals.filter((s) => s.startsWith('sink:'))
    .sort();
}

// (language, body, exact sink label expected). Each body is a real cross-language
// sink that classified attack_surface but had no evidence label. The label is
// asserted EXACTLY and as the ONLY sink signal, so a double-count (which would
// inflate priority via +10*riskSignals.length) fails the test. Covers all 11
// new SINK_EVIDENCE_RES entries; `popen`/`Runtime.getRuntime` are the two that
// textually overlap a generic Python label and must be de-duplicated to one.
const CROSS_LANG_SINKS: Array<[string, string, string]> = [
  ['go/exec.Command', 'func run(u string) error {\n  return exec.Command("sh", "-c", u).Run()\n}', 'sink:exec.Command'],
  ['java/Runtime', 'void run(String cmd) {\n  Runtime.getRuntime().exec(cmd);\n}', 'sink:Runtime.getRuntime'],
  ['java/ProcessBuilder', 'void run(String cmd) {\n  new ProcessBuilder(cmd).start();\n}', 'sink:ProcessBuilder'],
  ['go/http.Get', 'func fetchIt(u string) {\n  http.Get(u)\n}', 'sink:http.Get/Post/NewRequest'],
  ['node/http.request', 'function send(opts) {\n  return https.request(opts)\n}', 'sink:http.request'],
  ['go/client.Do', 'func send(req *Request) {\n  client.Do(req)\n}', 'sink:client.Do/Get/Post'],
  ['js/fetch', 'async function load(u) {\n  return fetch(u)\n}', 'sink:fetch()'],
  ['js/axios', 'function load(u) {\n  return axios.get(u)\n}', 'sink:axios'],
  ['c/system', 'void run(char *cmd) {\n  system(cmd);\n}', 'sink:system()'],
  ['c/popen', 'void run(char *cmd) {\n  popen(cmd, "r");\n}', 'sink:popen()'],
  ['c/execl', 'void run(char *p) {\n  execl(p, p, 0);\n}', 'sink:execl/execv'],
];

describe('cross-language sink evidence (#165)', () => {
  it.each(CROSS_LANG_SINKS)('%s → attack_surface with exactly one sink label', (_lang, body, label) => {
    const { exposure, riskSignals } = classify(block(body), NEUTRAL_CTX);
    expect(exposure).toBe('attack_surface');
    const sinks = riskSignals.filter((s) => s.startsWith('sink:'));
    // exactly one — a double-count (e.g. popen also matching open()) would inflate
    // priority and is the bug this asserts against
    expect(sinks, `${_lang}: expected exactly [${label}], got ${JSON.stringify(riskSignals)}`).toEqual([label]);
  });

  it('invariant: every attack_surface-by-sink body carries at least one sink: label', () => {
    // If DANGEROUS_SINK_RE flags a body, evidence must explain it — no blank reason.
    for (const [lang, body] of CROSS_LANG_SINKS) {
      expect(DANGEROUS_SINK_RE.test(body), `${lang} should be a dangerous sink`).toBe(true);
      const { riskSignals } = classify(block(body), NEUTRAL_CTX);
      expect(
        riskSignals.some((s) => s.startsWith('sink:')),
        `${lang}: attack_surface with no sink evidence`,
      ).toBe(true);
    }
  });

  it('keeps a separate generic sink that co-occurs with an overlapping specific one', () => {
    // The specific sink's text is a superset of a generic one (`popen(`⊃`open(`;
    // `…exec(`⊃`exec(`). Suppression is per-occurrence, not existence-based: when a
    // body has BOTH the overlapping specific call AND a distinct real generic call,
    // the generic must still report — dropping it would hide a real sink.
    const cBody = 'void run(char *cmd, char *path) {\n  popen(cmd, "r");\n  int fd = open(path, 0);\n}';
    expect(classify(block(cBody), NEUTRAL_CTX).exposure).toBe('attack_surface');
    expect(sinkLabelsOf(cBody), 'C popen+open').toEqual(['sink:open()', 'sink:popen()']);

    const jBody = 'void run(String cmd, String code) {\n  Runtime.getRuntime().exec(cmd);\n  engine.exec(code);\n}';
    expect(classify(block(jBody), NEUTRAL_CTX).exposure).toBe('attack_surface');
    expect(sinkLabelsOf(jBody), 'Java Runtime+exec').toEqual(['sink:Runtime.getRuntime', 'sink:exec()']);
  });

  it('does not drop a detached exec() when its count coincidentally equals Runtime.getRuntime', () => {
    // Regression: `Runtime.getRuntime` and `exec(` are NOT textually nested, so a
    // bare equal-count test would wrongly suppress the real `other.exec(code)`
    // here (one `Runtime.getRuntime`, one `exec(` → equal). The `.exec(` is
    // detached from `getRuntime()` (a `.gc()` sits between), so it must survive.
    const body = 'void run(String code) {\n  Runtime.getRuntime().gc();\n  other.exec(code);\n}';
    expect(classify(block(body), NEUTRAL_CTX).exposure).toBe('attack_surface');
    expect(sinkLabelsOf(body), 'detached exec must not be suppressed').toEqual([
      'sink:Runtime.getRuntime',
      'sink:exec()',
    ]);
  });

  it('collapses the Runtime.getRuntime().exec() idiom to a single signal', () => {
    // The common inline shell-out is ONE logical sink — the chained `.exec(` is
    // covered by `getRuntime()`, so only the specific label reports (no +10 double).
    expect(sinkLabelsOf('void r(String c) {\n  Runtime.getRuntime().exec(c);\n}')).toEqual(['sink:Runtime.getRuntime']);
  });

  it('does not trip a bare cross-language pattern on a qualified receiver call', () => {
    // The `(?<![\w.])` guard is load-bearing for corpus stability: a qualified
    // `obj.system(` must NOT match the bare C `system()` pattern, else the new
    // sinks would double-flag unrelated Python/JS method calls across the corpus.
    // (`system(` is the clean case — unlike `obj.popen(`, it carries no other
    // sink substring; `popen`⊃`open(` trips the separate, pre-existing `open()`.)
    const body = 'function run(cmd) {\n  obj.system(cmd);\n}';
    expect(sinkLabelsOf(body)).toEqual([]);
    expect(classify(block(body), NEUTRAL_CTX).exposure).not.toBe('attack_surface');
  });

  it('does not mistake a db/cache accessor for an outbound HTTP client call', () => {
    // The `[Cc]lient\.` receiver guard: a mundane `db.Get(id)` is not a client.Do/
    // Get/Post outbound request and must stay un-flagged (no sink, no ssrf-idor).
    const b: CodeBlock = { ...block('function load(id) {\n  return db.Get(id);\n}'), params: ['id'] };
    const { exposure, riskSignals } = classify(b, NEUTRAL_CTX);
    expect(riskSignals.some((s) => s.startsWith('sink:client'))).toBe(false);
    expect(riskSignals.some((s) => s.startsWith('ssrf-idor:'))).toBe(false);
    expect(exposure).not.toBe('attack_surface');
  });

  it('Python evidence is unchanged (control)', () => {
    // Exact single label: a regression that made `os.system(x)` also match the new
    // bare `system()` pattern would double-count (highest-blast-radius: the legacy
    // corpus). `toContain` would miss that — assert the sink set exactly.
    expect(classify(block('def f(x):\n  os.system(x)'), NEUTRAL_CTX).exposure).toBe('attack_surface');
    expect(sinkLabelsOf('def f(x):\n  os.system(x)')).toEqual(['sink:os.system']);
  });
});
