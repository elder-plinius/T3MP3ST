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

// Same ruleset as scripts/binary-vuln-bench.mjs (kept in sync manually).
const SINK_RULES: { id: string; desc: string; severity: 'high' | 'medium'; re: RegExp }[] = [
  { id: 'B-GETS', desc: 'gets() - unbounded stdin read (always unsafe)', severity: 'medium', re: /\bgets\s*\(/ },
  { id: 'B-STRCPY', desc: 'strcpy() - unbounded copy into a fixed buffer', severity: 'medium', re: /\bstrcpy\s*\(/ },
  { id: 'B-SPRINTF', desc: 'sprintf() - unbounded formatted write', severity: 'medium', re: /\bsprintf\s*\(/ },
  { id: 'B-FORMAT-STRING', desc: 'printf(var) - user-controlled format string', severity: 'medium', re: /\bf?printf\s*\(\s*[a-zA-Z_]\w*\s*\)/ },
  { id: 'B-CMD-INJECTION', desc: 'system()/popen() on a variable - command injection', severity: 'high', re: /\b(system|popen)\s*\(\s*[a-zA-Z_]\w*/ },
  { id: 'B-INT-OVERFLOW', desc: 'malloc/calloc with multiplication - integer-overflow alloc size', severity: 'high', re: /\b(malloc|calloc|alloca|realloc)\s*\([^)]*\*/ },
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

    const output = [
      `binary_sink_scan ${filePath} (${size} bytes, ${strings.length} strings extracted):`,
      hits.length === 0 ? 'No dangerous sinks found.' : `Found ${hits.length} sink class(es):`,
      ...hits.map((h) => `  [${h.rule.id}] ${h.rule.desc} — ${h.count} match(es)` +
        (h.examples.length ? `\n    e.g. ${h.examples.join(' | ')}` : '')),
      '',
      'Sinks are heuristic matches on extracted strings — verify in a disassembler (radare2/ghidra) before reporting.',
    ].join('\n');
    void joined;

    const findings: ToolFinding[] | undefined = hits.length
      ? [{
          title: `Dangerous Sinks in ${filePath.split(/[\\/]/).pop()}`,
          severity: hits.some((h) => h.rule.severity === 'high') ? 'high' : 'medium',
          details: hits.map((h) => `${h.rule.id}: ${h.rule.desc} (${h.count})`).join('; '),
          cwe: ['CWE-120', 'CWE-78', 'CWE-134', 'CWE-190'],
        }]
      : undefined;

    return { success: true, output, findings };
  },
};
