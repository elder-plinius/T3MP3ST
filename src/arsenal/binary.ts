/**
 * T3MP3ST binary_sink_scan — dangerous-sink detection in binaries/scripts.
 *
 * Reads a LOCAL file (binary or source), extracts printable strings, and runs
 * the project's decompiled-vuln ruleset (same RULES as scripts/binary-vuln-bench.mjs):
 * gets/strcpy/sprintf (unbounded copies), printf(var) format strings,
 * system()/popen() command injection, malloc/calloc multiplication
 * (integer-overflow alloc). Pure JS — no external binaries needed; works on
 * DLLs, EXEs, .so, Python/JS/C sources alike (strings survive in binaries).
 *
 * Safety: local file read only; bounded size (10MB); every hit is a REAL
 * substring found in the file's strings — never fabricated.
 */

import { readFileSync, statSync } from 'fs';
import type { CustomTool, ToolFinding } from '../types/index.js';

// Same ruleset as scripts/binary-vuln-bench.mjs (kept in sync manually) +
// extended sink classes beyond the bench corpus.
const SINK_RULES: { id: string; desc: string; severity: 'high' | 'medium'; re: RegExp }[] = [
  { id: 'B-GETS', desc: 'gets() - unbounded stdin read (always unsafe)', severity: 'medium', re: /\bgets\s*\(/ },
  { id: 'B-STRCPY', desc: 'strcpy() - unbounded copy into a fixed buffer', severity: 'medium', re: /\bstrcpy\s*\(/ },
  { id: 'B-SPRINTF', desc: 'sprintf() - unbounded formatted write', severity: 'medium', re: /\bsprintf\s*\(/ },
  { id: 'B-FORMAT-STRING', desc: 'printf(var) - user-controlled format string', severity: 'medium', re: /\bf?printf\s*\(\s*[a-zA-Z_]\w*\s*\)/ },
  { id: 'B-CMD-INJECTION', desc: 'system()/popen() on a variable - command injection', severity: 'high', re: /\b(system|popen)\s*\(\s*[a-zA-Z_]\w*/ },
  { id: 'B-INT-OVERFLOW', desc: 'malloc/calloc with multiplication - integer-overflow alloc size', severity: 'high', re: /\b(malloc|calloc|alloca|realloc)\s*\([^)]*\*/ },
  { id: 'B-STRCAT', desc: 'strcat() - unbounded append into a buffer', severity: 'medium', re: /\bstrcat\s*\(/ },
  { id: 'B-VSPRINTF', desc: 'vsprintf() - unbounded formatted write with va_list', severity: 'medium', re: /\bvsprintf\s*\(/ },
  { id: 'B-MEMCPY-SIZE', desc: 'memcpy with a variable/derived size — potential overflow if size is unchecked', severity: 'medium', re: /\bmemcpy\s*\([^)]*,\s*[^)]*,\s*[a-zA-Z_]/ },
  { id: 'B-ALLOCA', desc: 'alloca() with variable size — stack overflow risk', severity: 'medium', re: /\balloca\s*\(\s*[a-zA-Z_]/ },
  { id: 'B-CREATEPROCESS', desc: 'CreateProcess/ShellExecute on a variable — possible injection/path abuse', severity: 'high', re: /\b(CreateProcess|ShellExecute|WinExec)\w*\s*\([^)]*[a-zA-Z_]\w*\s*[),]/ },
  { id: 'B-DLLIMPORT', desc: 'DllImport with dynamic library name — DLL search-order hijack risk', severity: 'medium', re: /DllImport\s*\(\s*["\x27][a-zA-Z_]/ },
  { id: 'B-STRTOK', desc: 'strtok/strsep — fragile parsing, often leads to OOB when input is malformed', severity: 'low', re: /\b(strtok|strsep)\s*\(/ },
];

// Hardcoded secret / sensitive-data patterns found in extracted strings.
const SECRET_RULES: { id: string; desc: string; severity: 'high' | 'medium'; re: RegExp }[] = [
  { id: 'B-HARDCODED-PASS', desc: 'Hardcoded password-like literal', severity: 'high', re: /(password|passwd|pwd)\s*[=:]\s*["\x27][^"\x27]{4,}["\x27]/i },
  { id: 'B-HARDCODED-KEY', desc: 'Hardcoded API key / token-like literal', severity: 'high', re: /(api[_-]?key|secret|token|apikey)\s*[=:]\s*["\x27][A-Za-z0-9_\-]{12,}["\x27]/i },
  { id: 'B-HARDCODED-CRED', desc: 'Hardcoded user:password / connection string', severity: 'high', re: /(user(id)?|login)\s*[=:]\s*["\x27][^"\x27]+["\x27]\s*[,;]\s*(pass|passwd|pwd)\s*[=:]\s*["\x27][^"\x27]+["\x27]/i },
  { id: 'B-HARDCODED-URL-CRED', desc: 'Credentials embedded in a URL (scheme://user:pass@host)', severity: 'medium', re: /[a-z][a-z0-9+.-]*:\/\/[^\/\s:]+:[^\/\s@]+@/i },
  { id: 'B-ENCRYPTION-KEY', desc: 'Hardcoded encryption key/IV literal', severity: 'medium', re: /(encryption[_-]?key|aes[_-]?key|iv|salt|init[_-]?vector)\s*[=:]\s*["\x27][^"\x27]{4,}["\x27]/i },
];

const MAX_BYTES = 10 * 1024 * 1024;

/** Extract printable strings (ASCII runs >= 4) from raw bytes. */
function extractStrings(buf: Buffer): string[] {
  const out: string[] = [];
  let cur = '';
  for (const b of buf) {
    if (b >= 0x20 && b <= 0x7e) {
      cur += String.fromCharCode(b);
    } else {
      if (cur.length >= 4) out.push(cur);
      cur = '';
    }
  }
  if (cur.length >= 4) out.push(cur);
  return out;
}

export const binarySinkScanTool: CustomTool = {
  name: 'binary_sink_scan',
  description: 'Scan a local binary/DLL/script file for dangerous sinks (gets, strcpy, sprintf, printf(var), system/popen, malloc*mult) — pure-JS string extraction, no external tools',
  category: 're',
  parameters: [
    { name: 'path', type: 'string', description: 'Absolute path to the file (binary, DLL, source)', required: true },
  ],
  handler: async (context) => {
    const filePath = String(context.parameters.path || '').trim();
    if (!filePath) return { success: false, error: 'binary_sink_scan: path required' };
    let size = 0;
    try { size = statSync(filePath).size; } catch {
      return { success: false, error: `binary_sink_scan: cannot stat ${filePath}` };
    }
    if (size > MAX_BYTES) {
      return { success: false, error: `binary_sink_scan: file too large (${size} bytes, max ${MAX_BYTES})` };
    }
    let buf: Buffer;
    try { buf = readFileSync(filePath); } catch (e) {
      return { success: false, error: `binary_sink_scan: read failed: ${e instanceof Error ? e.message.slice(0, 120) : 'unknown'}` };
    }
    const strings = extractStrings(buf);
    const joined = '\n' + strings.join('\n') + '\n';

    const hits: { rule: typeof SINK_RULES[number]; count: number; examples: string[] }[] = [];
    for (const rule of SINK_RULES) {
      const matches = strings.filter((s) => rule.re.test(s));
      if (matches.length) {
        hits.push({ rule, count: matches.length, examples: matches.slice(0, 4).map((s) => s.slice(0, 80)) });
      }
    }
    const secretHits: { rule: typeof SECRET_RULES[number]; count: number; examples: string[] }[] = [];
    for (const rule of SECRET_RULES) {
      const matches = strings.filter((s) => rule.re.test(s));
      if (matches.length) {
        secretHits.push({ rule, count: matches.length, examples: matches.slice(0, 4).map((s) => s.slice(0, 80)) });
      }
    }

    const output = [
      `binary_sink_scan ${filePath} (${size} bytes, ${strings.length} strings extracted):`,
      hits.length === 0 ? 'No dangerous sinks found.' : `Found ${hits.length} sink class(es):`,
      ...hits.map((h) => `  [${h.rule.id}] ${h.rule.desc} — ${h.count} match(es)` +
        (h.examples.length ? `\n    e.g. ${h.examples.join(' | ')}` : '')),
      secretHits.length ? `\nFound ${secretHits.length} hardcoded-secret class(es):` : '',
      ...secretHits.map((h) => `  [${h.rule.id}] ${h.rule.desc} — ${h.count} match(es)` +
        (h.examples.length ? `\n    e.g. ${h.examples.join(' | ')}` : '')),
      '',
      'Sinks are heuristic matches on extracted strings — verify in a disassembler (radare2/ghidra) before reporting.',
    ].join('\n');
    void joined;

    const findings: ToolFinding[] | undefined = hits.length || secretHits.length
      ? [{
          title: `Dangerous Sinks${secretHits.length ? ' and Hardcoded Secrets' : ''} in ${filePath.split(/[\\/]/).pop()}`,
          severity: hits.some((h) => h.rule.severity === 'high') || secretHits.some((h) => h.rule.severity === 'high') ? 'high' : 'medium',
          details: [
            hits.map((h) => `${h.rule.id}: ${h.rule.desc} (${h.count})`).join('; '),
            secretHits.map((h) => `${h.rule.id}: ${h.rule.desc} (${h.count})`).join('; '),
          ].filter(Boolean).join(' | '),
          cwe: ['CWE-120', 'CWE-78', 'CWE-134', 'CWE-190', 'CWE-798'],
        }]
      : undefined;

    return { success: true, output, findings };
  },
};
