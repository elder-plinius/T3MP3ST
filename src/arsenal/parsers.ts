/**
 * T3MP3ST Arsenal — tool-output → structured evidence parsers.
 *
 * Turns the raw stdout of the JSON-emitting scanners into `ToolFinding[]` so the generic
 * adapter factory (src/arsenal/adapter-tools.ts) can return STRUCTURED findings, not just
 * text. Downstream the pipe already exists and is honest-by-construction: the agent loop
 * stamps `provenance:'tool'` + the raw output onto each finding, the operator materialises
 * it into a `Finding` with output-evidence, and the live gate (src/evidence/gate.ts) can
 * then mark it verified. Until now these adapters (parserStatus:'planned') returned raw
 * stdout only — the structured channel (`ToolResult.findings`) was never populated.
 *
 * HONESTY CONTRACT (same discipline as stub-honesty / no-phantom-tools):
 *  - Pure, dependency-free, and NEVER throws. Empty / garbled output → `[]`, never a
 *    fabricated finding. The caller keeps the raw stdout as the evidence of record; a
 *    parser SUMMARISES real output, it does not invent it.
 *  - Parsers do NOT set provenance/toolName/toolOutput — the agent loop stamps those from
 *    the real subprocess result, so a parser can never forge provenance.
 */

import type { Severity, ToolFinding } from '../types/index.js';

// ── small, defensive helpers ────────────────────────────────────────────────
const SEVERITIES = new Set<Severity>(['critical', 'high', 'medium', 'low', 'info']);
const sev = (v: unknown, fallback: Severity = 'info'): Severity => {
  const s = String(v ?? '').trim().toLowerCase();
  return SEVERITIES.has(s as Severity) ? (s as Severity) : fallback;
};
const asObj = (v: unknown): Record<string, unknown> =>
  v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
const asStrArray = (v: unknown): string[] =>
  Array.isArray(v)
    ? v.map((x) => String(x)).filter((s) => s.trim().length > 0)
    : v !== null && v !== undefined && v !== '' ? [String(v)] : [];
const num = (v: unknown): number | undefined => {
  const n = typeof v === 'number' ? v : Number(v);
  return Number.isFinite(n) ? n : undefined;
};
const truncate = (s: string, n = 400): string => (s.length > n ? `${s.slice(0, n)}…` : s);

/** Parse JSONL defensively: one object per non-empty line; any non-JSON line is skipped. */
function jsonl(raw: string): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = [];
  for (const line of String(raw).split('\n')) {
    const t = line.trim();
    if (!t) continue;
    try {
      const parsed: unknown = JSON.parse(t);
      if (parsed && typeof parsed === 'object') out.push(parsed as Record<string, unknown>);
    } catch {
      /* not a JSON line (banner, log, truncated tail) — skip */
    }
  }
  return out;
}

/** Parse a single JSON document defensively; returns undefined on any error. */
function jsonDoc(raw: string): unknown {
  try {
    return JSON.parse(String(raw));
  } catch {
    return undefined;
  }
}

// ── nuclei -jsonl : one finding per template match ───────────────────────────
function parseNuclei(raw: string): ToolFinding[] {
  const out: ToolFinding[] = [];
  for (const e of jsonl(raw)) {
    const info = asObj(e.info);
    const cls = asObj(info.classification);
    const templateId = String(e['template-id'] ?? e.templateID ?? '');
    const title = String(info.name || templateId || 'nuclei match');
    const bits = [
      e.host && `host: ${String(e.host)}`,
      e['matched-at'] && `matched-at: ${String(e['matched-at'])}`,
      info.description && `desc: ${truncate(String(info.description))}`,
    ].filter(Boolean) as string[];
    const f: ToolFinding = { title, severity: sev(info.severity), details: bits.join(' | ') || title };
    const cvss = num(cls['cvss-score']);
    if (cvss !== undefined) f.cvss = cvss;
    const cve = asStrArray(cls['cve-id']);
    if (cve.length) f.cve = cve;
    const cwe = asStrArray(cls['cwe-id']);
    if (cwe.length) f.cwe = cwe;
    if (info.remediation) f.remediation = String(info.remediation);
    out.push(f);
  }
  return out;
}

// ── httpx -json : one info finding per live host (technology fingerprint) ─────
function parseHttpx(raw: string): ToolFinding[] {
  const out: ToolFinding[] = [];
  for (const e of jsonl(raw)) {
    const url = String(e.url ?? e.input ?? e.host ?? '');
    if (!url) continue;
    const status = e.status_code ?? e['status-code'];
    const title = String(e.title ?? '');
    const tech = asStrArray(e.tech ?? e.technologies);
    const server = String(e.webserver ?? e.server ?? '');
    const bits = [
      `url: ${url}`,
      status !== null && status !== undefined && `status: ${String(status)}`,
      title && `title: ${truncate(title, 120)}`,
      server && `server: ${server}`,
      tech.length && `tech: ${tech.join(', ')}`,
    ].filter(Boolean) as string[];
    out.push({ title: `HTTP service ${url}`, severity: 'info', details: bits.join(' | ') });
  }
  return out;
}

// ── dalfox --format json : one finding per XSS probe ─────────────────────────
function parseDalfox(raw: string): ToolFinding[] {
  const doc = jsonDoc(raw);
  const arr: unknown[] = Array.isArray(doc)
    ? doc
    : Array.isArray(asObj(doc).pocs) ? (asObj(doc).pocs as unknown[]) : [];
  const out: ToolFinding[] = [];
  for (const item of arr) {
    const e = asObj(item);
    const param = String(e.param ?? '');
    const kind = String(e.type ?? e.inject_type ?? 'XSS');
    const bits = [
      e.method && `method: ${String(e.method)}`,
      param && `param: ${param}`,
      e.data && `data: ${truncate(String(e.data), 200)}`,
      e.evidence && `evidence: ${truncate(String(e.evidence), 200)}`,
      e.poc && `poc: ${truncate(String(e.poc), 300)}`,
    ].filter(Boolean) as string[];
    const f: ToolFinding = {
      title: `dalfox ${kind}${param ? ` @ ${param}` : ''}`,
      severity: sev(e.severity, 'medium'),
      details: bits.join(' | ') || String(e.message_str ?? e.message ?? 'XSS probe'),
    };
    const cwe = asStrArray(e.cwe).map((c) => (/^CWE-/i.test(c) ? c.toUpperCase() : `CWE-${c}`));
    if (cwe.length) f.cwe = cwe;
    out.push(f);
  }
  return out;
}

// ── ffuf -of json : one aggregate info finding (N paths) ─────────────────────
function parseFfuf(raw: string): ToolFinding[] {
  const results = ((): unknown[] => {
    const r = asObj(jsonDoc(raw)).results;
    return Array.isArray(r) ? r : [];
  })();
  if (!results.length) return [];
  const lines = results.slice(0, 50).map((r) => {
    const e = asObj(r);
    const path = String(asObj(e.input).FUZZ ?? e.input ?? e.url ?? '');
    return `${path} (status ${String(e.status ?? '?')}, len ${String(e.length ?? '?')})`;
  });
  const more = results.length > 50 ? `\n… +${results.length - 50} more` : '';
  return [{
    title: `ffuf: ${results.length} path(s) discovered`,
    severity: 'info',
    details: lines.join('\n') + more,
  }];
}

// ── katana -jsonl : one aggregate info finding (N endpoints) ──────────────────
function parseKatana(raw: string): ToolFinding[] {
  const endpoints: string[] = [];
  for (const e of jsonl(raw)) {
    const ep = String(asObj(e.request).endpoint ?? e.endpoint ?? e.url ?? '');
    if (ep) endpoints.push(ep);
  }
  if (!endpoints.length) return [];
  const more = endpoints.length > 50 ? `\n… +${endpoints.length - 50} more` : '';
  return [{
    title: `katana: ${endpoints.length} endpoint(s) discovered`,
    severity: 'info',
    details: endpoints.slice(0, 50).join('\n') + more,
  }];
}

const PARSERS: Record<string, (raw: string) => ToolFinding[]> = {
  nuclei: parseNuclei,
  httpx: parseHttpx,
  dalfox: parseDalfox,
  ffuf: parseFfuf,
  katana: parseKatana,
};

/** Adapter ids that have a structured output parser wired here. */
export const PARSED_TOOL_IDS: readonly string[] = Object.keys(PARSERS);

/** True iff a structured parser is wired for this adapter id. */
export function hasParser(toolId: string): boolean {
  return Object.prototype.hasOwnProperty.call(PARSERS, toolId);
}

/**
 * Parse a tool's raw stdout into structured `ToolFinding[]`.
 *
 * Returns `[]` for any tool with no parser, for empty output, and for output a parser cannot
 * make sense of. NEVER throws — an unexpected parser failure degrades to `[]` so a malformed
 * scan can never crash the agent loop or fabricate a finding.
 */
export function parseToolOutput(toolId: string, rawOutput: string): ToolFinding[] {
  const parser = PARSERS[toolId];
  if (!parser || !rawOutput || !String(rawOutput).trim()) return [];
  try {
    return parser(rawOutput);
  } catch {
    return [];
  }
}
