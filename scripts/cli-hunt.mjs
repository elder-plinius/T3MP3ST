#!/usr/bin/env node
/**
 * cli-hunt — BYO-SUBSCRIPTION zero-day hunter.  ⚡ MAXIMUM POWAAAH, $0 marginal cost.
 *
 * The subscription-agent FINDS; T3MP3ST VERIFIES. Instead of burning metered API
 * tokens, this drives the autonomous coding agent behind your flat-rate plan —
 * Codex (ChatGPT/Codex sub) or Claude Code (Claude Max sub) — to do a read-only
 * coordinated-disclosure source audit of a target repo. The finding it returns is
 * emitted in T3MP3ST's standard schema and flows straight into the existing
 * verify → refute → disclose pipeline (the part that makes a finding real).
 *
 *   FINDER (cheap, your subscription)  →  VERIFIER (T3MP3ST's integrity pipeline)
 *
 * The agent runs READ-ONLY (no writes, no network) over the target. "Clean" is a
 * valid, respected result — the prompt is built to fight fabrication, not invite it.
 *
 * Usage:
 *   node scripts/cli-hunt.mjs --backend codex  --repo /path/to/clone [--commit <sha>]
 *   node scripts/cli-hunt.mjs --backend claude --repo /path/to/clone --verify
 *   node scripts/cli-hunt.mjs --backend codex  --repo . --dry-run      # print plan, no spend
 *   node scripts/cli-hunt.mjs --self-test                              # offline
 *
 * Exit 0 = ran (finding or clean) · 2 = bad input · 3 = backend error.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function parseArgs(argv) {
  const a = { backend: 'codex' };
  for (let i = 0; i < argv.length; i++) {
    const t = argv[i];
    if (t.startsWith('--')) { const k = t.slice(2); const v = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : 'true'; a[k] = v; }
  }
  return a;
}

// ── the anti-fabrication hunt prompt (mirrors wild-hunt's doctrine) ──
function huntPrompt(commit) {
  return `You are a meticulous vulnerability researcher doing a READ-ONLY coordinated-disclosure source audit of the code in the current directory${commit ? ` (pinned at commit ${commit})` : ''}. Read and grep the source; do NOT modify any file.

Find AT MOST ONE genuinely exploitable, high-confidence security vulnerability.

HARD RULES — fabrication is the enemy:
1. "The code is clean — I found nothing exploitable" is a VALID and respected result. Do NOT invent a bug. A false finding is worse than none.
2. For any finding you MUST quote the EXACT vulnerable code (file + line) and trace untrusted input from its source to the dangerous sink.
3. REFUTE YOURSELF FIRST: actively hunt for the bound/guard/validation/auth that would make it NOT exploitable. Report ONLY if you genuinely cannot find one — and say what you looked for.
4. Real sinks only: memory corruption (OOB/overflow), command/code injection, path traversal, SSRF, unsafe deserialization, auth bypass, unchecked length handling.

When done, output your result as a SINGLE JSON array on the LAST line — no prose after it:
[{"title":"short","file":"rel/path","line":123,"cwe":"CWE-###","vuln_class":"...","severity":"critical|high|medium|low","confidence":"high|medium|low","summary":"root cause in one sentence","reachability":"untrusted source → … → sink","exact_code":"the quoted vulnerable line(s)","refutation_attempted":"the guard you looked for and why it does not save it"}]
If clean, output exactly: []`;
}

// ── backend runners — each returns the agent's final text (on YOUR subscription) ──
function runCodex(repo, prompt, model) {
  const outFile = path.join(os.tmpdir(), `cli-hunt-codex-${process.pid}.txt`);
  const args = ['exec', '--skip-git-repo-check', '-c', 'approval_policy="never"', '--sandbox', 'read-only', '--color', 'never', '--output-last-message', outFile];
  if (model) args.push('-m', model);
  args.push(prompt);
  const r = spawnSync('codex', args, { cwd: repo, encoding: 'utf8', timeout: 20 * 60 * 1000, maxBuffer: 64 * 1024 * 1024 });
  if (r.error) throw new Error(`codex spawn failed: ${r.error.message}`);
  const last = fs.existsSync(outFile) ? fs.readFileSync(outFile, 'utf8') : '';
  try { fs.unlinkSync(outFile); } catch {}
  return last || r.stdout || '';
}

function runClaude(repo, prompt, model) {
  // -p = headless; uses your logged-in Claude Code (Max) session. Read-only tools only.
  const args = ['-p', prompt, '--output-format', 'json', '--allowedTools', 'Read,Grep,Glob'];
  if (model) args.push('--model', model);
  // Force the SUBSCRIPTION (OAuth), not a metered API key — that's the whole point.
  const cenv = { ...process.env }; delete cenv.ANTHROPIC_API_KEY;
  const r = spawnSync('claude', args, { cwd: repo, encoding: 'utf8', timeout: 20 * 60 * 1000, maxBuffer: 64 * 1024 * 1024, env: cenv });
  if (r.error) throw new Error(`claude spawn failed: ${r.error.message}`);
  const out = r.stdout || '';
  if (/Failed to authenticate|Not logged in|401|Invalid authentication/i.test(out)) {
    throw new Error('claude is not authenticated for a standalone run. Run `claude login` (your Claude Max subscription) first. Note: --backend claude cannot run nested inside another Claude Code session — the parent session\'s auth does not pass through to a child `claude -p`. Use --backend codex, or run cli-hunt from a plain terminal.');
  }
  // --output-format json → envelope {type:"result", result:"<text>", ...}
  try { const env = JSON.parse(out); if (env && typeof env.result === 'string') return env.result; } catch {}
  return out;
}

// ── robust extraction of the findings array (last valid balanced [...]) ──
function extractFindings(text) {
  const s = String(text).replace(/```(?:json)?/gi, '');
  const spans = []; let depth = 0, start = -1;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '[') { if (depth === 0) start = i; depth++; }
    else if (c === ']') { if (depth > 0 && --depth === 0 && start >= 0) { spans.push(s.slice(start, i + 1)); start = -1; } }
  }
  for (let i = spans.length - 1; i >= 0; i--) {
    try { const d = JSON.parse(spans[i]); if (Array.isArray(d)) return d; } catch { /* keep scanning */ }
  }
  return null;
}

function normalizeFinding(raw, project, commit, backend) {
  const f = raw || {};
  return {
    project, commit: commit || null, found_by: `cli-hunt/${backend}`,
    title: f.title || 'untitled',
    file: f.file || '', line: typeof f.line === 'number' ? f.line : null,
    cwe: f.cwe || '', vuln_class: f.vuln_class || '',
    severity: f.severity || 'unknown', confidence: f.confidence || 'unknown',
    summary: f.summary || '', reachability: f.reachability || '',
    sink: f.file ? { file: f.file, line: f.line ?? null } : undefined,
    exact_code: f.exact_code || '', refutation_attempted: f.refutation_attempted || '',
  };
}

function slugify(project, backend) {
  return `cli-hunt-${backend}-${String(project).replace(/[^a-z0-9]+/gi, '-').toLowerCase().slice(0, 40)}`;
}

function selfTest() {
  let pass = 0, fail = 0;
  const ok = (l, c) => (c ? (pass++, console.log(`  ✅ ${l}`)) : (fail++, console.log(`  ❌ ${l}`)));
  ok('prompt forbids fabrication ("clean … VALID")', /VALID and respected result/.test(huntPrompt()));
  ok('prompt demands self-refutation', /REFUTE YOURSELF/.test(huntPrompt()));
  ok('prompt threads the pinned commit', /commit abc123/.test(huntPrompt('abc123')));
  ok('extract: clean [] → empty array', JSON.stringify(extractFindings('analysis… []')) === '[]');
  ok('extract: finding array (ignores prose + fences)', extractFindings('reasoning [nota] ```json\n[{"title":"x","file":"a.c","line":5}]\n```')?.[0]?.title === 'x');
  ok('extract: prose-only → null', extractFindings('no json here at all') === null);
  const n = normalizeFinding({ title: 't', file: 'a.c', line: 9, cwe: 'CWE-787', severity: 'critical' }, 'proj', 'sha1', 'codex');
  ok('normalize: schema shape + provenance', n.found_by === 'cli-hunt/codex' && n.sink.file === 'a.c' && n.project === 'proj');
  ok('slugify is filesystem-safe', /^cli-hunt-codex-[a-z0-9-]+$/.test(slugify('My Repo!', 'codex')));
  console.log(`\n${fail === 0 ? '✅ ALL PASS' : `❌ ${fail} FAILED`} — ${pass}/${pass + fail}\n`);
  process.exit(fail === 0 ? 0 : 1);
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args['self-test']) return selfTest();

  const backend = args.backend === 'claude' ? 'claude' : 'codex';
  if (!args.repo || args.repo === 'true') {
    console.error('usage: node scripts/cli-hunt.mjs --backend codex|claude --repo <path> [--commit <sha>] [--model <m>] [--verify] [--dry-run] [--self-test]');
    process.exit(2);
  }
  const repo = path.resolve(args.repo);
  if (!fs.existsSync(repo)) { console.error(`repo not found: ${repo}`); process.exit(2); }
  const project = path.basename(repo);
  const prompt = huntPrompt(args.commit && args.commit !== 'true' ? args.commit : null);
  const bin = backend === 'claude' ? 'claude' : 'codex';

  console.log(`\n${'═'.repeat(70)}`);
  console.log(`  ⚡ CLI-HUNT — BYO-subscription zero-day hunt`);
  console.log(`  backend:  ${bin}  (your subscription — $0 marginal API cost)`);
  console.log(`  target:   ${repo}${args.commit && args.commit !== 'true' ? ` @ ${args.commit}` : ''}`);
  console.log(`  mode:     READ-ONLY source audit · anti-fabrication · self-refuting`);
  console.log(`${'═'.repeat(70)}\n`);

  if (args['dry-run']) {
    console.log(`[dry-run] would run: ${bin} ${backend === 'claude' ? "-p <prompt> --output-format json --allowedTools Read,Grep,Glob" : "exec --sandbox read-only --output-last-message <tmp> <prompt>"}  (cwd=${repo})`);
    console.log(`\n[dry-run] hunt prompt:\n${prompt}\n\n[dry-run] no agent run, no spend.`);
    process.exit(0);
  }

  console.log(`  running ${bin} … (autonomous read-only hunt; this can take a few minutes)`);
  let text = '';
  try { text = backend === 'claude' ? runClaude(repo, prompt, args.model) : runCodex(repo, prompt, args.model); }
  catch (e) { console.error(`  backend error: ${e.message}`); process.exit(3); }

  const findings = extractFindings(text);
  if (findings === null) {
    console.log(`  ⚠ could not parse a findings array from the agent output. Raw tail:\n${text.slice(-600)}`);
    process.exit(3);
  }
  if (findings.length === 0) {
    console.log(`  ✅ CLEAN — the agent reported no exploitable vulnerability (a respected result).`);
    process.exit(0);
  }

  const top = normalizeFinding(findings[0], project, args.commit && args.commit !== 'true' ? args.commit : null, backend);
  const slug = slugify(project, backend);
  const outDir = path.join(REPO_ROOT, 'bench', 'wild-hunt', 'findings');
  fs.mkdirSync(outDir, { recursive: true });
  const outPath = path.join(outDir, `${slug}.json`);
  fs.writeFileSync(outPath, JSON.stringify({ slug, ...top, all_findings: findings }, null, 2));

  console.log(`  🎯 FINDING: [${top.severity}/${top.confidence}] ${top.cwe} ${top.file}:${top.line ?? '?'} — ${top.title}`);
  console.log(`     ${top.summary}`);
  console.log(`     written: ${path.relative(REPO_ROOT, outPath)}  (gitignored — held for verification)`);

  if (args.verify) {
    console.log(`\n  → adversarial refute pass (refute-finding.mjs)…`);
    const r = spawnSync('node', ['scripts/refute-finding.mjs', '--finding', path.relative(REPO_ROOT, outPath)], { cwd: REPO_ROOT, stdio: 'inherit' });
    process.exit(r.status === 0 ? 0 : 3); // 0=SURVIVED, 3=REFUTED/needs-review
  }
  console.log(`\n  next: node scripts/refute-finding.mjs --finding ${path.relative(REPO_ROOT, outPath)}   (adversarial reachability)`);
  console.log(`        then verify-finding → executed PoC → disclosure-gen. The finder is cheap; the VERIFIER is what makes it real.\n`);
}

// reusable primitives for the swarm orchestrator (cli-swarm.mjs)
export { huntPrompt, runCodex, runClaude, extractFindings, normalizeFinding, slugify, parseArgs };

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) main();
