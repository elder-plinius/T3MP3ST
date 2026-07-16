import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { parseToolOutput, hasParser, PARSED_TOOL_IDS } from '../arsenal/parsers.js';
import { gateLiveFinding } from '../evidence/gate.js';
import { adapterToCustomTool, type AdapterToolDeps } from '../arsenal/adapter-tools.js';
import { TOOL_ADAPTERS } from '../arsenal/catalog.js';
import { KillChainPhase } from '../types/index.js';
import type { CustomTool, Finding, ToolFinding } from '../types/index.js';

// ─────────────────────────────────────────────────────────────────────────────
// STRUCTURED PARSERS — turn real scanner stdout into ToolFinding[], honestly.
//
// Two things are pinned here:
//  1) each JSON-emitting scanner's output maps to the right structured fields, and
//  2) the honesty contract holds: empty / garbled / unknown input yields [] (never a
//     fabricated finding), and a parsed finding — carried through the SAME shape the
//     agent loop + operator build — PASSES the live provenance gate. That last check
//     is the point of the whole layer: structured output that the honesty spine accepts.
// ─────────────────────────────────────────────────────────────────────────────

const fixture = (name: string): string =>
  readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8');

describe('parseToolOutput — field mapping per scanner', () => {
  it('nuclei: one finding per JSONL match; skips non-JSON lines; maps cve/cwe/cvss/severity', () => {
    const f = parseToolOutput('nuclei', fixture('nuclei.jsonl'));
    expect(f).toHaveLength(2); // banner line skipped
    const log4j = f[0];
    expect(log4j.title).toBe('Apache Log4j RCE');
    expect(log4j.severity).toBe('critical');
    expect(log4j.cve).toEqual(['CVE-2021-44228']);
    expect(log4j.cwe).toEqual(['CWE-502']);
    expect(log4j.cvss).toBe(10.0);
    expect(log4j.remediation).toMatch(/2\.17\.0/);
    expect(log4j.details).toContain('target.example.com');
    expect(f[1].severity).toBe('info'); // nginx version disclosure
  });

  it('httpx: one info finding per live host with url/status/tech in details', () => {
    const f = parseToolOutput('httpx', fixture('httpx.jsonl'));
    expect(f).toHaveLength(2);
    expect(f[0].severity).toBe('info');
    expect(f[0].title).toContain('target.example.com');
    expect(f[0].details).toContain('status: 200');
    expect(f[0].details).toContain('Nginx');
  });

  it('dalfox: one finding per XSS probe with severity + CWE', () => {
    const f = parseToolOutput('dalfox', fixture('dalfox.json'));
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('high');
    expect(f[0].cwe).toEqual(['CWE-79']);
    expect(f[0].title).toContain('q'); // the param
    expect(f[0].details).toContain('poc');
  });

  it('ffuf: a single aggregate finding counting discovered paths (no per-path flood)', () => {
    const f = parseToolOutput('ffuf', fixture('ffuf.json'));
    expect(f).toHaveLength(1);
    expect(f[0].title).toBe('ffuf: 2 path(s) discovered');
    expect(f[0].severity).toBe('info');
    expect(f[0].details).toContain('admin');
    expect(f[0].details).toContain('login');
  });

  it('katana: a single aggregate finding counting discovered endpoints', () => {
    const f = parseToolOutput('katana', fixture('katana.jsonl'));
    expect(f).toHaveLength(1);
    expect(f[0].title).toBe('katana: 3 endpoint(s) discovered');
    expect(f[0].details).toContain('/about');
  });
});

describe('parseToolOutput — honesty contract (never fabricate, never throw)', () => {
  it('returns [] for empty, whitespace, and unparseable output', () => {
    for (const raw of ['', '   ', '\n\n', 'not json at all', '{bad json', '<html>error</html>']) {
      expect(parseToolOutput('nuclei', raw)).toEqual([]);
      expect(parseToolOutput('ffuf', raw)).toEqual([]);
      expect(parseToolOutput('dalfox', raw)).toEqual([]);
    }
  });

  it('returns [] for a tool with no parser wired', () => {
    expect(parseToolOutput('sqlmap', fixture('nuclei.jsonl'))).toEqual([]);
    expect(parseToolOutput('metasploit', 'anything')).toEqual([]);
    expect(hasParser('sqlmap')).toBe(false);
  });

  it('never throws on adversarial / deeply-nested / wrong-shape input', () => {
    const evil = [
      JSON.stringify({ results: 'not-an-array' }),
      '[1,2,3]',
      '{"info":null}\n{"info":{"classification":"nope"}}',
      '['.repeat(500),
      JSON.stringify({ results: [{ input: null, status: {} }] }),
    ];
    for (const id of PARSED_TOOL_IDS) {
      for (const raw of evil) {
        expect(() => parseToolOutput(id, raw)).not.toThrow();
        expect(Array.isArray(parseToolOutput(id, raw))).toBe(true);
      }
    }
  });

  it('exposes exactly the wired parser ids', () => {
    expect([...PARSED_TOOL_IDS].sort()).toEqual(
      ['dalfox', 'ffuf', 'gitleaks', 'grype', 'httpx', 'katana', 'nuclei', 'semgrep', 'trivy'],
    );
  });
});

describe('parseToolOutput — source / supply-chain scanners', () => {
  it('semgrep: one finding per rule match with mapped severity + CWE token', () => {
    const f = parseToolOutput('semgrep', fixture('semgrep.json'));
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('high'); // ERROR → high
    expect(f[0].cwe).toEqual(['CWE-78']); // extracted from "CWE-78: OS Command Injection"
    expect(f[0].details).toContain('app/run.py:42');
  });

  it('trivy: one finding per package vuln with CVE, CWE, and an upgrade remediation', () => {
    const f = parseToolOutput('trivy', fixture('trivy.json'));
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('high');
    expect(f[0].cve).toEqual(['CVE-2021-3749']);
    expect(f[0].cwe).toEqual(['CWE-400']);
    expect(f[0].remediation).toContain('0.21.2');
    expect(f[0].details).toContain('axios');
  });

  it('grype: one finding per match with CVE + package coordinates', () => {
    const f = parseToolOutput('grype', fixture('grype.json'));
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('high'); // "High" → high
    expect(f[0].cve).toEqual(['CVE-2022-23529']);
    expect(f[0].details).toContain('jsonwebtoken');
  });

  it('gitleaks: one high finding per secret, and the raw secret is REDACTED from details', () => {
    const f = parseToolOutput('gitleaks', fixture('gitleaks.json'));
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('high');
    expect(f[0].details).toContain('config/prod.env:12');
    // Defense in depth: the AWS key present in the raw report must never survive into the finding.
    expect(f[0].details).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(f[0].details).toContain('[redacted]');
  });
});

describe('end-to-end: a parsed finding passes the live provenance gate', () => {
  // Mirror how the agent loop stamps provenance (src/agent/index.ts) and how the operator
  // materialises a ToolFinding into a Finding with output-evidence (src/operators/index.ts),
  // then run the real gate. This proves parsed output is accepted by the honesty spine.
  const materialise = (tf: ToolFinding, rawOutput: string, toolName: string): Finding => {
    const stamped = { ...tf, provenance: 'tool' as const, toolName, toolOutput: rawOutput.slice(0, 4000) };
    return {
      id: 'finding-test',
      title: stamped.title,
      description: stamped.details,
      severity: stamped.severity,
      targetId: 'target-1',
      operatorId: 'op-1',
      phase: KillChainPhase.RECON,
      cvss: stamped.cvss,
      cve: stamped.cve,
      cwe: stamped.cwe,
      evidence: stamped.provenance === 'tool'
        ? [{ type: 'output', content: stamped.toolOutput || stamped.details || '', timestamp: 1, metadata: { tool: stamped.toolName } }]
        : [],
      remediation: stamped.remediation,
      discoveredAt: 1,
    };
  };

  it('a parsed nuclei critical finding is gated PASS with provenance=tool', () => {
    const raw = fixture('nuclei.jsonl');
    const tf = parseToolOutput('nuclei', raw)[0];
    const gate = gateLiveFinding(materialise(tf, raw, 'nuclei_tool'));
    expect(gate.passed).toBe(true);
    expect(gate.provenance).toBe('tool');
  });

  it('every parsed finding across all scanners is gate-passable (real tool evidence)', () => {
    for (const [id, file] of [
      ['nuclei', 'nuclei.jsonl'], ['httpx', 'httpx.jsonl'], ['dalfox', 'dalfox.json'],
      ['ffuf', 'ffuf.json'], ['katana', 'katana.jsonl'],
      ['semgrep', 'semgrep.json'], ['gitleaks', 'gitleaks.json'],
      ['trivy', 'trivy.json'], ['grype', 'grype.json'],
    ] as const) {
      const raw = fixture(file);
      for (const tf of parseToolOutput(id, raw)) {
        const gate = gateLiveFinding(materialise(tf, raw, `${id}_tool`));
        expect(gate.passed, `${id} finding "${tf.title}" should pass the gate`).toBe(true);
        expect(gate.provenance).toBe('tool');
      }
    }
  });
});

describe('factory wiring: a minted adapter returns structured findings from real stdout', () => {
  // Proves the actual code path (adapter-tools.ts success return) populates ToolResult.findings —
  // not just that the pure parser works. Deps are fakes; runSubprocess replays a fixture as stdout.
  const depsReturning = (stdout: string): AdapterToolDeps => ({
    isToolAvailable: async () => true,
    runSubprocess: async () => ({ stdout, stderr: '', exitCode: 0 }),
  });
  const mint = (id: string, deps: AdapterToolDeps): CustomTool => {
    const adapter = TOOL_ADAPTERS.find((a) => a.id === id);
    if (!adapter) throw new Error(`fixture: adapter '${id}' not found`);
    const tool = adapterToCustomTool(adapter, deps);
    if (!tool) throw new Error(`fixture: adapter '${id}' is not mintable`);
    return tool;
  };

  it('nuclei_tool surfaces parsed findings (with cwe/cve) AND keeps the raw stdout as evidence', async () => {
    const raw = fixture('nuclei.jsonl');
    const res = await mint('nuclei', depsReturning(raw)).handler({ parameters: { url: 'https://target.example.com' } });
    expect(res.success).toBe(true);
    expect(res.output).toBe(raw); // raw stdout preserved as the evidence of record
    expect(res.findings).toHaveLength(2);
    expect(res.findings?.[0].cwe).toEqual(['CWE-502']);
  });

  it('a tool whose scan yields no parseable output leaves findings unset (no fabrication)', async () => {
    const res = await mint('nuclei', depsReturning('no findings here\n')).handler({ parameters: { url: 'https://target.example.com' } });
    expect(res.success).toBe(true);
    expect(res.findings).toBeUndefined();
  });
});
