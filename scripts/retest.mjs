#!/usr/bin/env node
/**
 * T3MP3ST retest runner — re-verify previously reported findings against a
 * live target using the real agent loop (LLM + arsenal tools), then write a
 * retest report.
 *
 * Usage:
 *   node scripts/retest.mjs --target https://example.com --findings findings.json
 *
 * findings.json: array of { title, details?, severity?, url? } — the old report's
 * findings. The agent re-probes each (headers, endpoints, DNS, TLS) and returns a
 * verdict per finding: fixed | still_vulnerable | unverifiable, with tool-backed
 * evidence. Output: reports/retest-<target>-<ts>.md
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
const imp = (p) => import(pathToFileURL(join(ROOT, p)).href);
const { createTestTempest } = await imp('src/index.ts');
const { LLMBackbone } = await imp('src/llm/index.ts');
const { Arsenal, BUILTIN_TOOLS } = await imp('src/arsenal/index.ts');
const { buildAdapterTools } = await imp('src/arsenal/adapter-tools.ts');
const { TOOL_ADAPTERS } = await imp('src/arsenal/catalog.ts');
const { createPrivateReportWorkspace, readPrivateToolReport } = await imp('src/arsenal/report-workspace.ts');
const { AgentLoop } = await imp('src/agent/index.ts');

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--target' || a === '--findings') out[a.slice(2)] = argv[++i];
  }
  return out;
}

const { target, findings: findingsPath } = parseArgs(process.argv.slice(2));
if (!target || !findingsPath) {
  console.error('Usage: node scripts/retest.mjs --target <url> --findings <json>');
  process.exit(1);
}
const findings = JSON.parse(readFileSync(findingsPath, 'utf8'));
if (!Array.isArray(findings) || findings.length === 0) {
  console.error('findings file must be a non-empty array');
  process.exit(1);
}

// Brain + hands, same as a mission. Use the REAL configured LLM (createTestTempest
// ships a mock backbone — fine for unit tests, useless for an actual retest).
const { config } = await imp('src/config/index.ts');
const llm = new LLMBackbone(config.getLLMConfig());
const arsenal = new Arsenal();
arsenal.registerMany(BUILTIN_TOOLS);
if (/^(1|true|on)$/i.test(process.env.T3MP3ST_FULL_ARSENAL ?? '')) {
  const existing = new Set(arsenal.getToolDefinitions().map((t) => t.name));
  arsenal.registerMany(buildAdapterTools(TOOL_ADAPTERS, {
    runSubprocess: async () => ({ stdout: '', stderr: '', exitCode: 0 }),
    isToolAvailable: async () => true,
    scopeOk: () => true,
    createReportWorkspace,
    readToolReport: readPrivateToolReport,
  }, existing));
}
arsenal.setScope({ allowedHosts: [target.replace(/^https?:\/\//, '').split('/')[0]], allowLoopback: true, allowPrivate: true });

const list = findings.map((f, i) => `${i + 1}. [${f.severity ?? '?'}] ${f.title}${f.url ? ` (${f.url})` : ''}${f.details ? ` — ${String(f.details).slice(0, 200)}` : ''}`).join('\n');

const systemPrompt = `You are a RETEST analyst. Your ONLY job: re-verify a list of previously reported findings against the live target, using the available tools (HTTP requests, header checks, TLS checks, DNS). Do NOT perform new attacks beyond confirming/denying the listed checks.

For each finding decide:
- "fixed" — the issue is no longer present (e.g., header now set, endpoint now 404/closed, cert now valid)
- "still_vulnerable" — the issue is still present, with a tool result as evidence
- "unverifiable" — you could not determine the state

FINISH with a single fenced \`\`\`json block:
{"retests":[{"title":"<exact title>","status":"fixed|still_vulnerable|unverifiable","evidence":"<short tool-backed note>"}]}
List ALL findings in the same order. Do not fabricate tool results.`;

const task = {
  id: 'retest-1',
  missionId: 'retest',
  name: `Retest ${findings.length} findings against ${target}`,
  description: `Re-verify each listed finding against ${target}. Findings:\n${list}`,
  phase: 'actions_on_objectives',
  operatorType: 'analyst',
  status: 'in_progress',
  priority: 5,
  dependencies: [],
  createdAt: Date.now(),
};

const loop = new AgentLoop(llm, arsenal, { maxIterations: Math.min(40, findings.length * 6 + 4), maxTokens: 60000 });
const result = await loop.run(task, systemPrompt, { address: target, type: 'web_application' });

// Verdicts arrive in the structured findings channel (the agent re-probes with
// tools; a re-found issue comes back as a finding with tool-backed details).
// Fall back to JSON in the final text when present.
const STOP = new Set(['the','a','an','in','of','on','at','with','for','from','via','and','or','to','exposed','discovered','detected','found','present','available','missing','enabled','disabled','vulnerable','issues','issue','problem','warning','disclosure','disclosed','leak','leaked','revealed','identified','located']);
const norm = (t) => String(t || '').toLowerCase().replace(/[()]/g, ' ').replace(/\s+/g, ' ').trim()
  .split(' ').filter((w) => w && !STOP.has(w)).map((w) => (w.length > 4 && /s$/.test(w) && !/(ss|us|is|as|os)$/.test(w) ? w.slice(0, -1) : w)).join(' ');

const newFindings = result.findings ?? [];
const matched = new Map();
for (const f of newFindings) {
  const key = norm(f.title);
  if (key) matched.set(key, f);
}

function structuredRetests(text) {
  const source = String(text || '');
  const fenced = [...source.matchAll(/```json\s*([\s\S]*?)```/gi)].at(-1)?.[1];
  if (!fenced) return new Map();
  try {
    const parsed = JSON.parse(fenced);
    if (!Array.isArray(parsed?.retests)) return new Map();
    return new Map(parsed.retests
      .filter((v) => v && typeof v.title === 'string' && ['fixed', 'still_vulnerable', 'unverifiable'].includes(v.status))
      .map((v) => [norm(v.title), { status: v.status, evidence: String(v.evidence || '').slice(0, 200) }]));
  } catch { return new Map(); }
}

const declared = structuredRetests(result.output ?? result.content ?? '');

const verdicts = findings.map((old) => {
  const key = norm(old.title);
  const hit = key && (matched.get(key) ?? [...matched.entries()].find(([k]) => k.includes(key.slice(0, 12)) || key.includes(k.slice(0, 12)))?.[1]);
  const explicit = declared.get(key);
  if (explicit?.status === 'still_vulnerable' && hit) {
    return { title: old.title, status: 'still_vulnerable', evidence: String(hit.details ?? hit.title ?? '').slice(0, 200) };
  }
  if (explicit?.status === 'fixed') return { title: old.title, ...explicit };
  return { title: old.title, status: 'unverifiable', evidence: explicit?.evidence || 'No valid structured verdict with corroborating tool evidence.' };
});

const md = [
  `# Retest report: ${target}`,
  '',
  `- **Date**: ${new Date().toISOString()}`,
  `- **Findings re-checked**: ${findings.length}`,
  `- **Verdicts parsed**: ${verdicts.length}`,
  '',
  '| # | Finding | Verdict | Evidence |',
  '|---|---------|---------|----------|',
  ...findings.map((f, i) => {
    const v = verdicts[i] ?? { status: 'unverifiable', evidence: 'no verdict' };
    return `| ${i + 1} | ${String(f.title).replace(/\|/g, '\\|')} | ${v.status ?? 'unverifiable'} | ${String(v.evidence ?? '').replace(/\|/g, '\\|').slice(0, 120)} |`;
  }),
  '',
  '---',
  '*Generated by T3MP3ST retest runner.*',
].join('\n');

const outDir = join(ROOT, 'reports');
mkdirSync(outDir, { recursive: true });
const file = join(outDir, `retest-${target.replace(/[^a-zA-Z0-9.-]/g, '_')}-${Date.now()}.md`);
writeFileSync(file, md, 'utf8');

console.log(md);
console.log(`\nОтчёт сохранён: ${file}`);
const open = verdicts.filter((v) => v.status === 'still_vulnerable').length;
const fixed = verdicts.filter((v) => v.status === 'fixed').length;
const unverifiable = verdicts.filter((v) => v.status === 'unverifiable').length;
console.log(`Итого: still_vulnerable=${open}, fixed=${fixed}, unverifiable=${unverifiable}`);
