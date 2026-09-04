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
import { redactString } from '../redact.js';

// ── small, defensive helpers ────────────────────────────────────────────────
const SEVERITIES = new Set<Severity>(['critical', 'high', 'medium', 'low', 'info']);
// Map the many scanner severity vocabularies (semgrep ERROR/WARNING/INFO, trivy/grype
// CRITICAL…NEGLIGIBLE, npm-audit "moderate", …) onto the five canonical levels.
const SEVERITY_ALIAS: Record<string, Severity> = {
  error: 'high', warning: 'medium', warn: 'medium', inventory: 'info', experiment: 'info',
  moderate: 'medium', negligible: 'info', unknown: 'info', none: 'info', informational: 'info',
};
const sev = (v: unknown, fallback: Severity = 'info'): Severity => {
  const s = String(v ?? '').trim().toLowerCase();
  if (SEVERITIES.has(s as Severity)) return s as Severity;
  return SEVERITY_ALIAS[s] ?? fallback;
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

// ── semgrep scan --json : one finding per rule match (SAST) ──────────────────
function parseSemgrep(raw: string): ToolFinding[] {
  const results = ((): unknown[] => {
    const r = asObj(jsonDoc(raw)).results;
    return Array.isArray(r) ? r : [];
  })();
  const out: ToolFinding[] = [];
  for (const item of results) {
    const e = asObj(item);
    const extra = asObj(e.extra);
    const meta = asObj(extra.metadata);
    const checkId = String(e.check_id ?? e.checkId ?? 'semgrep rule');
    const path = String(e.path ?? '');
    const line = num(asObj(e.start).line);
    const where = path ? `${path}${line !== undefined ? `:${line}` : ''}` : '';
    const f: ToolFinding = {
      title: checkId,
      severity: sev(extra.severity),
      details: [where && `at ${where}`, extra.message && truncate(String(extra.message))].filter(Boolean).join(' | ') || checkId,
    };
    // semgrep CWE metadata is like ["CWE-89: SQL Injection"] — keep the CWE-NNN token.
    const cwe = asStrArray(meta.cwe).map((c) => c.match(/CWE-\d+/i)?.[0] ?? '').filter(Boolean);
    if (cwe.length) f.cwe = cwe.map((c) => c.toUpperCase());
    const refs = asStrArray(meta.references);
    if (refs.length) f.remediation = `refs: ${refs.slice(0, 3).join(', ')}`;
    out.push(f);
  }
  return out;
}

// ── gitleaks detect --report-format json --redact : one finding per secret ────
function parseGitleaks(raw: string): ToolFinding[] {
  const arr: unknown[] = Array.isArray(jsonDoc(raw)) ? (jsonDoc(raw) as unknown[]) : [];
  const out: ToolFinding[] = [];
  for (const item of arr) {
    const e = asObj(item);
    const rule = String(e.RuleID ?? e.Description ?? 'secret');
    const file = String(e.File ?? '');
    const line = num(e.StartLine);
    const where = file ? `${file}${line !== undefined ? `:${line}` : ''}` : '';
    // Defense in depth: the adapter already runs gitleaks with --redact, but scrub the details
    // through redactString anyway so a raw secret can NEVER reach a finding or the evidence vault.
    const details = redactString([where && `at ${where}`, String(e.Description ?? '')].filter(Boolean).join(' | '));
    out.push({ title: `secret: ${rule}`, severity: 'high', details: details || `secret: ${rule}` });
  }
  return out;
}

// ── trivy fs --format json : one finding per package vulnerability ────────────
function parseTrivy(raw: string): ToolFinding[] {
  const results = ((): unknown[] => {
    const r = asObj(jsonDoc(raw)).Results;
    return Array.isArray(r) ? r : [];
  })();
  const out: ToolFinding[] = [];
  for (const res of results) {
    const target = String(asObj(res).Target ?? '');
    const vulns = asObj(res).Vulnerabilities;
    if (!Array.isArray(vulns)) continue;
    for (const item of vulns) {
      const v = asObj(item);
      const id = String(v.VulnerabilityID ?? '');
      const pkg = String(v.PkgName ?? '');
      const installed = String(v.InstalledVersion ?? '');
      const fixed = String(v.FixedVersion ?? '');
      const f: ToolFinding = {
        title: String(v.Title || id || 'vulnerability'),
        severity: sev(v.Severity),
        details: [target && `target: ${target}`, pkg && `pkg: ${pkg}${installed ? ` ${installed}` : ''}`,
          v.Description && truncate(String(v.Description), 200)].filter(Boolean).join(' | ') || id,
      };
      if (/^CVE-/i.test(id)) f.cve = [id];
      const cwe = asStrArray(v.CweIDs);
      if (cwe.length) f.cwe = cwe;
      if (fixed) f.remediation = `upgrade ${pkg || 'package'} to ${fixed}`;
      out.push(f);
    }
  }
  return out;
}

// ── grype dir:. -o json : one finding per matched vulnerability ───────────────
function parseGrype(raw: string): ToolFinding[] {
  const matches = ((): unknown[] => {
    const m = asObj(jsonDoc(raw)).matches;
    return Array.isArray(m) ? m : [];
  })();
  const out: ToolFinding[] = [];
  for (const item of matches) {
    const m = asObj(item);
    const vuln = asObj(m.vulnerability);
    const art = asObj(m.artifact);
    const id = String(vuln.id ?? '');
    const name = String(art.name ?? '');
    const version = String(art.version ?? '');
    const f: ToolFinding = {
      title: id || 'vulnerability',
      severity: sev(vuln.severity),
      details: [name && `pkg: ${name}${version ? ` ${version}` : ''}`,
        vuln.description && truncate(String(vuln.description), 200)].filter(Boolean).join(' | ') || id,
    };
    if (/^CVE-/i.test(id)) f.cve = [id];
    out.push(f);
  }
  return out;
}

// ── garak : LLM/agent red-team probes (report.jsonl) ─────────────────────────
// garak writes one JSON object per line. We roll the run up into ONE finding per
// (probe × detector) that registered at least one attack success, reporting the
// attack-success-rate. We faithfully summarise garak's OWN detector verdicts — a
// parser summarises, it does not re-judge (detector false-positives are a downstream
// concern, called out in the finding details so the operator transcript-verifies).
// Only probe/detector names + counts are surfaced — never prompt/response text — so
// no probe transcript leaks through the structured channel.
const garakSev = (asr: number): Severity =>
  asr >= 50 ? 'critical' : asr >= 20 ? 'high' : asr >= 5 ? 'medium' : 'low';

function parseGarak(raw: string): ToolFinding[] {
  const agg = new Map<string, { probe: string; detector: string; broken: number; total: number }>();
  const evals: Record<string, unknown>[] = [];

  for (const e of jsonl(raw)) {
    const entryType = String(e.entry_type ?? '');
    if (entryType === 'eval') { evals.push(e); continue; }
    if (entryType !== 'attempt') continue;
    if (num(e.status) !== 2) continue; // only completed attempts
    const probe = String(e.probe_classname ?? e.probe ?? 'unknown');
    for (const [detector, scoresRaw] of Object.entries(asObj(e.detector_results))) {
      const scores = Array.isArray(scoresRaw) ? scoresRaw : [];
      const key = `${probe}|${detector}`;
      let a = agg.get(key);
      if (!a) { a = { probe, detector, broken: 0, total: 0 }; agg.set(key, a); }
      for (const s of scores) {
        a.total += 1;
        const n = num(s);
        if (n !== undefined && n >= 0.5) a.broken += 1;
      }
    }
  }

  const out: ToolFinding[] = [];
  const emit = (probe: string, detector: string, broken: number, total: number): void => {
    if (broken <= 0 || total <= 0) return;
    const asr = (100 * broken) / total;
    out.push({
      title: `garak: ${probe} broke via ${detector} (${broken}/${total}, ${asr.toFixed(1)}% ASR)`,
      severity: garakSev(asr),
      details:
        `LLM/agent red-team probe. Attack-success-rate ${asr.toFixed(1)}% ` +
        `(${broken}/${total} outputs flagged by detector '${detector}'; probe '${probe}'). ` +
        `ASR reflects garak's automated detector verdict — verify transcripts before ` +
        `acting; keyword-style detectors over-report on small/aligned models.`,
    });
  };

  for (const { probe, detector, broken, total } of agg.values()) emit(probe, detector, broken, total);

  // Fallback: some garak builds emit only aggregated 'eval' rollups (no per-attempt scores).
  if (out.length === 0) {
    for (const e of evals) {
      const passed = num(e.passed);
      const total = num(e.total ?? e.instances);
      if (passed === undefined || total === undefined) continue;
      emit(String(e.probe ?? 'unknown'), String(e.detector ?? 'detector'), total - passed, total);
    }
  }

  return out;
}

// ── sqlmap : text stdout → one finding per vulnerable parameter ──────────────
// sqlmap has no JSON stdout; its console log carries the verdict in a stable
// shape: "Parameter: <name> (<where>)" sections with "Type:" lines and
// "Payload:" evidence, plus a "back-end DBMS is <dbms>" banner. We summarise
// that — never invent a parameter the log doesn't name.
function parseSqlmap(raw: string): ToolFinding[] {
  const text = String(raw);
  if (!/vulnerable|Parameter:|back-end DBMS/i.test(text)) return [];

  const dbms = (text.match(/back-end DBMS is ([^\n]+)/i)?.[1] ?? '').trim();
  const vulnParams = new Set<string>();
  for (const m of text.matchAll(/parameter\s+['"]?([\w.-]+)['"]?\s+is\s+vulnerable/gi)) {
    vulnParams.add(m[1]);
  }

  // "Parameter: id (GET)" section headers
  const blocks: { param: string; where: string; body: string[] }[] = [];
  let current: { param: string; where: string; body: string[] } | null = null;
  const lines = text.split('\n');
  for (const line of lines) {
    const pm = /Parameter:\s+([\w.-]+)\s*\(([^)]+)\)/i.exec(line);
    if (pm) {
      current = { param: pm[1], where: pm[2].trim(), body: [] };
      blocks.push(current);
      continue;
    }
    if (current) current.body.push(line.trim());
  }
  // include standalone "X is vulnerable" params without a section
  for (const p of vulnParams) {
    if (!blocks.some((b) => b.param === p)) blocks.push({ param: p, where: '?', body: [] });
  }
  const sections: { param: string; where: string; types: string[]; payloads: string[] }[] = [];
  for (const b of blocks) {
    const types: string[] = [];
    const payloads: string[] = [];
    for (const line of b.body) {
      const t = /Type:\s*(.+)$/i.exec(line);
      if (t) types.push(t[1].trim());
      const p = /Payload:\s*(.+)$/i.exec(line);
      if (p) payloads.push(truncate(p[1].trim(), 220));
    }
    if (types.length === 0 && !vulnParams.has(b.param)) continue;
    sections.push({ param: b.param, where: b.where, types, payloads });
  }

  return sections.map((s) => ({
    title: `SQL Injection in '${s.param}' (${s.where})`,
    severity: 'high' as const,
    details: [
      `sqlmap confirmed injection in parameter '${s.param}' (${s.where}).`,
      dbms && `DBMS: ${dbms}`,
      s.types.length && `Types: ${s.types.join('; ')}`,
      s.payloads.length && `Payload(s): ${s.payloads.join(' || ')}`,
    ].filter(Boolean).join(' | '),
    cwe: ['CWE-89'],
  }));
}

// ── feroxbuster --json : one aggregate info finding (N reachable paths) ──────
function parseFeroxbuster(raw: string): ToolFinding[] {
  const entries: { url: string; status: number; length?: number }[] = [];
  for (const e of jsonl(raw)) {
    const u = String(e.url ?? e['url'] ?? '');
    if (!u) continue;
    const status = num(e.status) ?? 0;
    if (status >= 200 && status < 400) {
      entries.push({ url: u, status, length: num(e.content_length) ?? num(e.length) });
    }
  }
  if (!entries.length) return [];
  const lines = entries.slice(0, 50).map((e) => `${e.url} (status ${e.status}${e.length !== undefined ? `, len ${e.length}` : ''})`);
  const more = entries.length > 50 ? `\n… +${entries.length - 50} more` : '';
  return [{
    title: `feroxbuster: ${entries.length} reachable path(s) discovered`,
    severity: 'info',
    details: lines.join('\n') + more,
  }];
}

// ── wafw00f : text output → WAF detection finding ───────────────────────────
function parseWafw00f(raw: string): ToolFinding[] {
  const text = String(raw);
  const out: ToolFinding[] = [];
  // "[+] The site https://x is behind Cloudflare (Cloudflare)" / "...is behind a WAF named ..."
  const re = /is behind(?:\s+a\s+WAF)?\s+([^(]+?)\s*\(([^)]+)\)/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const name = m[1].trim();
    const id = m[2].trim();
    out.push({
      title: `WAF Detected: ${name}`,
      severity: 'info',
      details: `wafw00f identified ${name} (${id}). WAF responses (403/503) must not be interpreted as origin behavior — e.g. blocked HTTP methods or rate-limit errors are the WAF, not the application.`,
    });
  }
  if (out.length === 0 && /no waf|not behind|no firewall/i.test(text)) {
    out.push({
      title: 'No WAF Detected',
      severity: 'info',
      details: 'wafw00f found no known WAF in front of the target — HTTP status codes likely reflect the origin.',
    });
  }
  return out;
}

// ── trufflehog --json : one finding per leaked secret ────────────────────────
function parseTrufflehog(raw: string): ToolFinding[] {
  const out: ToolFinding[] = [];
  for (const e of jsonl(raw)) {
    const meta = asObj(e.SourceMetadata);
    const data = asObj(meta.Data);
    const file = String(data.File ?? meta.Filename ?? meta.Path ?? '');
    const secret = String(e.Raw ?? e.Secret ?? '');
    const detector = String(e.DetectorName ?? e.decoder_type ?? 'secret');
    const line = num(data.Line) ?? undefined;
    const verified = e.Verified === true || e.verified === true;
    if (!secret || secret.length < 4) continue;
    out.push({
      title: `trufflehog: ${detector}${file ? ` in ${file.split(/[\\/]/).pop()}` : ''}`,
      severity: verified ? 'high' : 'medium',
      details: [
        `Detector: ${detector}`,
        file && `File: ${file}${line !== undefined ? `:${line}` : ''}`,
        verified ? 'Verified credential' : 'Unverified secret (verify manually)',
        `Secret: ${secret.slice(0, 60)}${secret.length > 60 ? '…' : ''}`,
      ].filter(Boolean).join(' | '),
      cwe: ['CWE-798'],
    });
  }
  return out;
}

// ── arjun -oJ / text : found hidden parameters per endpoint ──────────────────
function parseArjun(raw: string): ToolFinding[] {
  const doc = jsonDoc(raw);
  const out: ToolFinding[] = [];
  if (doc && typeof doc === 'object') {
    for (const [url, paramsRaw] of Object.entries(doc as Record<string, unknown>)) {
      const params = paramsRaw && typeof paramsRaw === 'object' ? Object.keys(paramsRaw as Record<string, unknown>) : [];
      if (!params.length) continue;
      out.push({
        title: `arjun: ${params.length} hidden parameter(s) on ${url}`,
        severity: 'info',
        details: `Discovered parameters: ${params.join(', ')}. Hidden parameters often unlock undocumented functionality — probe each for injection/auth issues.`,
      });
    }
    return out;
  }
  // Text mode: "Found 2 parameters: token, debug" or an indented parameter block.
  const text = String(raw);
  const found = text.match(/Found\s+(\d+)\s+param(?:eter)?s?\s*:?\s*(.+)/i);
  if (found) {
    const params = found[2].split(/[\s,]+/).filter(Boolean);
    out.push({
      title: `arjun: ${params.length} hidden parameter(s)`,
      severity: 'info',
      details: `Discovered parameters: ${params.join(', ')}. Hidden parameters often unlock undocumented functionality — probe each for injection/auth issues.`,
    });
    return out;
  }
  const line = text.split('\n').map((l) => l.trim()).find((l) => /^https?:\/\/\S+\s*[:]\s*\S+/.test(l));
  if (line) {
    const [url, ...rest] = line.split(':');
    const params = rest.join(':').split(/[\s,]+/).filter(Boolean);
    if (params.length) {
      out.push({
        title: `arjun: ${params.length} hidden parameter(s) on ${url.trim()}`,
        severity: 'info',
        details: `Discovered parameters: ${params.join(', ')}. Hidden parameters often unlock undocumented functionality.`,
      });
    }
  }
  return out;
}

// ── wpscan --format json : WP core/plugin/theme vulns + interesting findings ──────────────
// WPScan emits ONE JSON document: { version, main_theme, plugins{}, themes{},
// interesting_findings[], users{}, … } with vulns as { title, fixed_in, references:
// { cve: ['2020-11516'], url: [...], wpvulndb: [...] } } — CVE refs arrive WITHOUT the
// 'CVE-' prefix. WPScan never scores severity, so this mapping is documented, not invented:
// core vulns on a core WPScan itself labels 'insecure' → high; other confirmed component
// vulns → medium; enumeration / interesting findings → info.
function parseWpscan(raw: string): ToolFinding[] {
  const doc = asObj(jsonDoc(raw));
  if (Object.keys(doc).length === 0) return [];
  const out: ToolFinding[] = [];
  const pushVulns = (component: string, node: unknown, severity: Severity) => {
    const vulns = asObj(node).vulnerabilities;
    if (!Array.isArray(vulns)) return;
    for (const item of vulns) {
      const v = asObj(item);
      const title = redactString(String(v.title ?? ''));
      if (!title) continue;
      const refs = asObj(v.references);
      const f: ToolFinding = {
        title: redactString(`${component}: ${title}`),
        severity,
        details: truncate(redactString(asStrArray(refs.url).join(' ') || title)),
      };
      const cves = asStrArray(refs.cve)
        .map((c) => c.trim().toUpperCase())
        .map((c) => (c.startsWith('CVE-') ? c : `CVE-${c}`))
        .filter((c) => /^CVE-\d{4}-\d{4,}$/.test(c));
      if (cves.length) f.cve = cves;
      const fixed = String(v.fixed_in ?? '');
      if (fixed) f.remediation = `update ${component} to ${fixed}`;
      out.push(f);
    }
  };
  const version = asObj(doc.version);
  const coreNum = String(version.number ?? '');
  if (coreNum) {
    pushVulns(`WordPress core ${coreNum}`, version, String(version.status ?? '') === 'insecure' ? 'high' : 'medium');
  }
  for (const [slug, node] of Object.entries(asObj(doc.plugins))) pushVulns(`plugin ${slug}`, node, 'medium');
  for (const [slug, node] of Object.entries(asObj(doc.themes))) pushVulns(`theme ${slug}`, node, 'medium');
  const mainTheme = asObj(doc.main_theme);
  if (mainTheme.slug) pushVulns(`theme ${String(mainTheme.slug)}`, mainTheme, 'medium');
  const interesting = doc.interesting_findings;
  if (Array.isArray(interesting)) {
    for (const item of interesting) {
      const o = asObj(item);
      const label = redactString(String(o.to_s ?? o.url ?? ''));
      if (!label) continue;
      out.push({
        title: `wpscan: ${truncate(label, 80)}`,
        severity: 'info',
        details: [
          o.url && `url: ${redactString(String(o.url))}`,
          o.found_by && `found_by: ${redactString(String(o.found_by))}`,
          o.confidence !== undefined && `confidence: ${String(o.confidence)}`,
        ].filter(Boolean).join(' | '),
      });
    }
  }
  const users = Object.keys(asObj(doc.users));
  if (users.length) {
    out.push({
      title: `wpscan: ${users.length} user(s) enumerated`,
      severity: 'info',
      details: `Usernames: ${redactString(users.join(', '))} — valid account names for password-policy review, not proof of compromise.`,
    });
  }
  return out;
}

const PARSERS: Record<string, (raw: string) => ToolFinding[]> = {
  nuclei: parseNuclei,
  httpx: parseHttpx,
  dalfox: parseDalfox,
  ffuf: parseFfuf,
  katana: parseKatana,
  semgrep: parseSemgrep,
  gitleaks: parseGitleaks,
  trivy: parseTrivy,
  grype: parseGrype,
  garak: parseGarak,
  sqlmap: parseSqlmap,
  feroxbuster: parseFeroxbuster,
  wafw00f: parseWafw00f,
  trufflehog: parseTrufflehog,
  arjun: parseArjun,
  wpscan: parseWpscan,
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
