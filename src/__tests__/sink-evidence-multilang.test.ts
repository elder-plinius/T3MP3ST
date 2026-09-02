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

// (language, body, substring the sink label must contain). Each body is a real
// cross-language sink that classifies attack_surface but had no evidence label.
const CROSS_LANG_SINKS: Array<[string, string, string]> = [
  ['go/exec', 'func run(u string) error {\n  return exec.Command("sh", "-c", u).Run()\n}', 'exec.Command'],
  ['java/ProcessBuilder', 'void run(String cmd) {\n  new ProcessBuilder(cmd).start();\n}', 'ProcessBuilder'],
  ['go/http.Get', 'func fetchIt(u string) {\n  http.Get(u)\n}', 'http.Get'],
  ['go/client.Do', 'func send(req *Request) {\n  client.Do(req)\n}', 'client.Do'],
  ['js/fetch', 'async function load(u) {\n  return fetch(u)\n}', 'fetch'],
  ['js/axios', 'function load(u) {\n  return axios.get(u)\n}', 'axios'],
  ['c/system', 'void run(char *cmd) {\n  system(cmd);\n}', 'system'],
  ['c/execl', 'void run(char *p) {\n  execl(p, p, 0);\n}', 'exec'],
];

describe('cross-language sink evidence (#165)', () => {
  it.each(CROSS_LANG_SINKS)('%s classifies attack_surface WITH a sink label', (_lang, body, needle) => {
    const { exposure, riskSignals } = classify(block(body), NEUTRAL_CTX);
    expect(exposure).toBe('attack_surface');
    const sinks = riskSignals.filter((s) => s.startsWith('sink:'));
    expect(sinks, `expected a sink: label for ${_lang}, got ${JSON.stringify(riskSignals)}`).not.toHaveLength(0);
    expect(sinks.join(' ')).toContain(needle);
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

  it('Python evidence is unchanged (control)', () => {
    const { exposure, riskSignals } = classify(block('def f(x):\n  os.system(x)'), NEUTRAL_CTX);
    expect(exposure).toBe('attack_surface');
    expect(riskSignals).toContain('sink:os.system');
  });
});
