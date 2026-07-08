#!/usr/bin/env node
/**
 * cli-swarm — BYO-SUBSCRIPTION collaborative zero-day SWARM.  ⚡ MAXIMUM POWAAAH.
 *
 * cli-hunt is the finder primitive: ONE agent, ONE read-only pass. This is the
 * swarm behind it — a coordinating team of specialist agents that hunt the target
 * for as long as it deserves, share what they learn, and adversarially refute each
 * other before anything is called real.
 *
 *   N SPECIALISTS (parallel, your subscription, $0)  ×  R COLLABORATIVE ROUNDS
 *        →  pool + dedupe leads  →  SKEPTIC refutes each finding  →  survivors
 *        →  loop until DRY (or budget)  →  synthesis + full audit transcript
 *
 * Each specialist owns a vuln class (injection, path-traversal, prototype-pollution,
 * ReDoS, SSRF/redirect, authz-bypass, deserialization, crypto/secrets). Round N+1
 * sees the whole swarm's round-N lead-board: confirm/refute open leads, don't
 * re-tread cleared ground, chase where the swarm found smoke. Surviving findings
 * flow to the existing executed-PoC verifier — the part that makes a finding real.
 *
 * Usage:
 *   node scripts/cli-swarm.mjs --repo /path/to/clone [--rounds 3] [--concurrency 4]
 *        [--budget-min 240] [--lenses injection,path-traversal,...] [--commit <sha>]
 *   node scripts/cli-swarm.mjs --self-test                              # offline
 *
 * READ-ONLY over the target. "Clean" after a deep swarm is a STRONG, respected
 * result. The prompts fight fabrication; a false finding is worse than none.
 * Exit 0 = ran (findings or clean) · 2 = bad input · 3 = backend error.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { extractFindings, normalizeFinding, parseArgs } from './cli-hunt.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const now = () => new Date().toISOString().slice(11, 19);

// ── the specialist lenses: a division of labor across vuln classes ──
const LENSES = [
  { key: 'injection',         name: 'Injection',            focus: 'command / code / eval / template / SQL injection — any untrusted input reaching an interpreter, shell, child_process, eval/Function, or query.' },
  { key: 'path-traversal',    name: 'Path traversal',       focus: 'arbitrary file read/write/include via user-influenced paths — sendFile/static, fs.* sinks, require(), view/template resolution, archive extraction, the classic startsWith/normalize prefix bugs.' },
  { key: 'prototype-pollution', name: 'Prototype pollution', focus: 'recursive merge/extend/clone/defaults and query/body/cookie/header parsing that writes attacker keys (__proto__, constructor, prototype) into objects, and the gadget that turns it into impact.' },
  { key: 'redos-dos',         name: 'ReDoS / resource DoS',  focus: 'regexes with catastrophic backtracking run on untrusted input; unbounded loops, recursion, allocations, or quadratic parsing reachable from a request.' },
  { key: 'ssrf-redirect',     name: 'SSRF / open-redirect',  focus: 'URL / host / Location / proxy / redirect parsing — server-side request forgery, open redirect, host-header trust, and parser-differential confusion.' },
  { key: 'authz-bypass',      name: 'Authz / auth bypass',   focus: 'authentication, session, signature/HMAC verify, CSRF, and access-control checks — and the input that bypasses or skips them (timing, type confusion, missing-check paths).' },
  { key: 'deserialization',   name: 'Deserialization / parse', focus: 'cookie / JSON / multipart / content-type / config parsing, unsafe deserialization, type confusion, and length/bounds handling on parsed data.' },
  { key: 'crypto-secrets',    name: 'Crypto / secrets',      focus: 'weak or predictable randomness for security tokens, non-constant-time comparison of secrets, signature-verification flaws, and hardcoded or leaked credentials.' },
  { key: 'memory-safety',     name: 'Memory safety',         focus: 'out-of-bounds read/write, heap/stack buffer overflow, integer overflow leading to undersized allocation, use-after-free, unchecked length/offset/count/size fields, and missing bounds checks when parsing UNTRUSTED binary input (C/C++/native/unsafe) — the classic malicious-file -> memory-corruption -> RCE surface. Trace attacker-controlled record sizes/offsets to memcpy/resize/indexing sinks.' },
];

// ── a rate-limited / quota-exhausted / errored backend must NEVER read as "clean" ──
function isRateLimited(text) {
  return /you'?ve hit your usage limit|usage limit|rate.?limit|\b429\b|too many requests|quota exceeded|insufficient_quota/i.test(String(text || ''));
}

// ── scope discipline: a bug in demo/test/benchmark code is NOT a library vuln ──
// The shipped attack surface is the package's own source, not examples nobody deploys.
// Reporting an open-redirect in examples/ as "an Express vuln" is exactly the overclaim
// this project exists to kill. Drop out-of-scope paths both in the prompt and post-hoc.
const OUT_OF_SCOPE = /(^|\/)(examples?|samples?|demos?|tests?|__tests__|spec|specs|benchmarks?|bench|docs?|fixtures?|mocks?|\.github|node_modules|coverage|dist|build|vendor|third[_-]?party)(\/|$)/i;
function inScope(file) { return !!file && !OUT_OF_SCOPE.test(String(file)); }

// ── anti-fabrication doctrine shared by every specialist ──
const DOCTRINE = `HARD RULES — fabrication is the enemy:
1. "Clean — nothing exploitable in my specialty" is a VALID, respected result. A false finding is worse than none. Never invent a bug to look productive.
2. For any finding, quote the EXACT vulnerable code (file + line) and trace untrusted input from its real source to the dangerous sink.
3. REFUTE YOURSELF FIRST: hunt for the guard/bound/validation/auth that would make it NOT exploitable; report only if you genuinely cannot find one, and say what you looked for.`;

function specialistPrompt(lens, board, round, commit) {
  return `You are vulnerability-research specialist "${lens.name}" on a coordinating SWARM doing a READ-ONLY coordinated-disclosure audit of the code in the current directory${commit ? ` (pinned at ${commit})` : ''}. This is round ${round}. Read and grep the source; do NOT modify any file.

YOUR SPECIALTY — concentrate here: ${lens.focus}
(If you stumble on something exploitable outside your specialty, still report it.)

SCOPE — this is critical: report ONLY vulnerabilities in the SHIPPED LIBRARY's own source (e.g. lib/, src/, index.js — the code in the package's "main"/"files"). Code under examples/, samples/, demos/, test/, tests/, spec/, benchmarks/, docs/, fixtures/ is OUT OF SCOPE — a bug in demo or test code is NOT a vulnerability in the published package, and reporting it is a false positive. Do not report findings there.

${DOCTRINE}

SWARM STATE so far (the whole team's shared knowledge — DO NOT re-tread cleared ground; DO confirm or refute open leads in your specialty and dig where the swarm found smoke):
${board || '(round 1 — no prior state. Map your specialty\'s attack surface across the whole repo and surface both confirmed findings and promising leads.)'}

Output a SINGLE JSON array on the LAST line, no prose after it. Include BOTH confirmed findings AND promising leads worth a deeper look:
[{"title":"short","file":"rel/path","line":123,"cwe":"CWE-###","vuln_class":"...","severity":"critical|high|medium|low","confidence":"high|medium|low","summary":"root cause in one sentence","reachability":"untrusted source → … → sink","exact_code":"the quoted line(s)","refutation_attempted":"the guard you looked for and why it doesn't save it","status":"confirmed|lead"}]
A "lead" is a real suspicion you couldn't fully prove yet (confidence low/medium) — say what still needs proving in reachability. If your specialty is genuinely clean and you have no leads, output exactly: []`;
}

function skepticPrompt(finding, commit) {
  return `You are a SKEPTICAL senior security reviewer. A teammate claims this vulnerability in the code in the current directory${commit ? ` (pinned at ${commit})` : ''}:

${JSON.stringify({ title: finding.title, file: finding.file, line: finding.line, cwe: finding.cwe, summary: finding.summary, reachability: finding.reachability, exact_code: finding.exact_code }, null, 2)}

Your job is to REFUTE it. Read the ACTUAL code at that location and everything around it. Find the validation, bound, sanitization, auth check, type guard, or unreachability that makes it NOT exploitable in practice. Be adversarial — assume the finder was sloppy. Only if you genuinely cannot refute it after a real attempt do you concede it SURVIVES.

Output a SINGLE JSON object on the LAST line, no prose after:
{"verdict":"REFUTED"|"SURVIVES","reason":"what you found (the guard, or why it truly holds)","guard_found":"file:line of the guard, or null"}`;
}

// ── precision triage: cluster survivors by ROOT CAUSE + classify novel vs by-design/known/dup ──
// This is the layer the rosbridge run lacked: 32 skeptic-survivors were really ~1-2 root causes
// reported across many sites, the bulk by-design (unauth bridge) — the gate that refuses overclaim.
function triagePrompt(project, confirmed, commit) {
  const list = confirmed.map((f, i) => `${i + 1}. [${f.severity}/${f.cwe}] ${f.file}:${f.line ?? '?'} — ${f.title} :: ${(f.summary || '').slice(0, 160)}`).join('\n');
  return `You are a principal security engineer doing FINAL TRIAGE on a hunting swarm's surviving findings for "${project}"${commit ? ` @ ${commit}` : ''}. The swarm has HIGH RECALL but LOW PRECISION — your job is to cut to the TRUE signal and REFUSE to overclaim. Read the actual code in the current directory as needed to judge.

SURVIVING FINDINGS (${confirmed.length}):
${list}

Do three things:
1. CLUSTER by ROOT CAUSE — many of these are the SAME underlying bug reported at different call sites; collapse those into ONE cluster.
2. CLASSIFY each cluster as exactly one of:
   - NOVEL_REAL  — a genuine, disclosable, NOT-by-design vulnerability with real impact
   - BY_DESIGN   — the documented/intended posture (e.g. "do not expose unauthenticated", an opt-in security feature disabled by default, auth removed on purpose)
   - KNOWN       — almost certainly already documented / CVE'd / a well-known design caveat
   - LOW_VALUE   — technically real but operator-responsibility / hardening (e.g. resource exhaustion reachable only on a service that is unauthenticated by design)
   - DUPLICATE   — same root cause as another cluster
3. Give each cluster an HONEST severity (critical/high/medium/low/info) and a one-line "why" for the classification.

Be RUTHLESS. A by-design DoS on a service documented as needing network isolation is NOT a vulnerability. Only NOVEL_REAL clusters with real, non-by-design impact are signal. Concluding that ZERO are NOVEL_REAL is a correct and valuable outcome.

Output a SINGLE JSON object on the LAST line, no prose after:
{"clusters":[{"root_cause":"...","members":["file:line",...],"classification":"NOVEL_REAL|BY_DESIGN|KNOWN|LOW_VALUE|DUPLICATE","severity":"...","why":"..."}],"novel_real":N,"summary":"one honest sentence"}`;
}

async function triagePass(repo, project, confirmed, commit) {
  const r = await runCodexAsync(repo, triagePrompt(project, confirmed, commit), { label: 'triage', timeoutMs: 12 * 60 * 1000 });
  if (!r.ok) return null;
  const objs = extractObjects(r.text);
  return objs.length ? objs[objs.length - 1] : null;
}

// ── async codex runner (parallel-safe: unique out-file per call) ──
let _runSeq = 0;
function runCodexAsync(repo, prompt, { model, label, timeoutMs = 10 * 60 * 1000 } = {}) {
  return new Promise((resolve) => {
    const outFile = path.join(os.tmpdir(), `cli-swarm-${process.pid}-${++_runSeq}.txt`);
    const args = ['exec', '--skip-git-repo-check', '-c', 'approval_policy="never"', '--sandbox', 'read-only', '--color', 'never', '--output-last-message', outFile];
    if (model) args.push('-m', model);
    args.push(prompt);
    // stdin:'ignore' is critical — an open stdin pipe makes `codex exec` wait on an
    // EOF that never arrives and hang to the timeout. spawnSync closes stdin for us;
    // async spawn does not, so we must.
    const child = spawn('codex', args, { cwd: repo, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    let killed = false;
    const timer = setTimeout(() => { killed = true; try { child.kill('SIGKILL'); } catch {} }, timeoutMs);
    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    child.on('error', (e) => { clearTimeout(timer); resolve({ ok: false, text: '', error: e.message, label }); });
    child.on('close', () => {
      clearTimeout(timer);
      let last = '';
      try { if (fs.existsSync(outFile)) { last = fs.readFileSync(outFile, 'utf8'); fs.unlinkSync(outFile); } } catch {}
      if (killed) return resolve({ ok: false, text: last || stdout, error: 'timeout', stderr: stderr.slice(-400), label });
      const out = last || stdout || '';
      // a rate-limited / quota-exhausted backend returns an error string, not findings.
      // surface it explicitly so the run is flagged INVALID, never mistaken for "clean".
      if (isRateLimited(out))
        return resolve({ ok: false, text: out, error: 'BACKEND rate-limited (usage limit)', rateLimited: true, label });
      resolve({ ok: true, text: out, label });
    });
  });
}

// run thunks with bounded concurrency
async function pool(items, concurrency, fn) {
  const results = new Array(items.length);
  let i = 0;
  async function worker() {
    while (i < items.length) { const idx = i++; results[idx] = await fn(items[idx], idx); }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, worker));
  return results;
}

// ── dedup + lead-board ──
const dedupKey = (f) => `${(f.file || '').toLowerCase()}::${(f.cwe || '').toUpperCase()}::${Math.round((f.line || 0) / 15)}`;
const titleSeen = (board, f) => board.some((b) => dedupKey(b) === dedupKey(f));

function renderBoard(state) {
  const lines = [];
  if (state.confirmed.length) {
    lines.push('CONFIRMED (survived skeptic — do not re-find, help strengthen the PoC):');
    for (const f of state.confirmed) lines.push(`  ✓ [${f.cwe}] ${f.file}:${f.line ?? '?'} — ${f.title}`);
  }
  if (state.leads.length) {
    lines.push('OPEN LEADS (confirm or refute these — this is where to dig):');
    for (const f of state.leads.slice(0, 16)) lines.push(`  ? [${f.confidence}/${f.cwe}] ${f.file}:${f.line ?? '?'} — ${f.title} :: still needs: ${(f.reachability || '').slice(0, 120)}`);
  }
  if (state.refuted.length) {
    lines.push('REFUTED / CLEARED (the swarm killed these — do NOT resurface them):');
    for (const f of state.refuted.slice(0, 16)) lines.push(`  ✗ [${f.cwe}] ${f.file}:${f.line ?? '?'} — ${f.title} (guard: ${(f.guard_found || f.reason || 'n/a').slice(0, 80)})`);
  }
  if (state.cleanLenses.length) lines.push(`SPECIALTIES REPORTED CLEAN: ${state.cleanLenses.join(', ')}`);
  return lines.join('\n');
}

function selfTest() {
  let pass = 0, fail = 0;
  const ok = (l, c) => (c ? (pass++, console.log(`  ✅ ${l}`)) : (fail++, console.log(`  ❌ ${l}`)));
  ok('9 specialist lenses defined (incl. memory-safety)', LENSES.length === 9 && LENSES.every((l) => l.key && l.focus) && LENSES.some((l) => l.key === 'memory-safety'));
  ok('specialist prompt carries anti-fab doctrine', /VALID, respected result/.test(specialistPrompt(LENSES[0], '', 1)));
  ok('specialist prompt demands self-refutation', /REFUTE YOURSELF FIRST/.test(specialistPrompt(LENSES[0], '', 1)));
  ok('specialist prompt threads the swarm board', specialistPrompt(LENSES[0], 'OPEN LEADS: foo', 2).includes('OPEN LEADS: foo'));
  ok('specialist prompt threads commit', specialistPrompt(LENSES[0], '', 1, 'abc123').includes('abc123'));
  ok('skeptic prompt is adversarial (REFUTE)', /REFUTE it/.test(skepticPrompt({ title: 't' })));
  ok('skeptic prompt forces REFUTED|SURVIVES verdict', /"REFUTED"\|"SURVIVES"/.test(skepticPrompt({ title: 't' })));
  ok('scope: lib/src/index.js in-scope', inScope('lib/response.js') && inScope('src/router.js') && inScope('index.js'));
  ok('scope: examples/test/bench/docs OUT', !inScope('examples/auth/index.js') && !inScope('test/app.js') && !inScope('benchmarks/run.js') && !inScope('docs/api.md') && !inScope('lib/__tests__/x.js'));
  ok('scope: tricky non-matches stay in-scope', inScope('lib/examplesHelper.js') && inScope('lib/contest.js'));
  ok('specialist prompt carries scope discipline', /OUT OF SCOPE/.test(specialistPrompt(LENSES[0], '', 1)));
  const a = { file: 'lib/x.js', cwe: 'CWE-22', line: 100 }, b = { file: 'lib/x.js', cwe: 'CWE-22', line: 103 }, c = { file: 'lib/x.js', cwe: 'CWE-22', line: 580 };
  ok('dedup: near lines collapse', dedupKey(a) === dedupKey(b));
  ok('dedup: far lines distinct', dedupKey(a) !== dedupKey(c));
  ok('titleSeen flags a known finding', titleSeen([a], b) && !titleSeen([a], c));
  const board = renderBoard({ confirmed: [{ cwe: 'CWE-77', file: 'a.js', line: 5, title: 'cmd inj' }], leads: [{ confidence: 'medium', cwe: 'CWE-22', file: 'b.js', line: 9, title: 'lead', reachability: 'src→sink' }], refuted: [{ cwe: 'CWE-918', file: 'c.js', line: 3, title: 'ssrf', guard_found: 'allowlist@c.js:1' }], cleanLenses: ['Crypto / secrets'] });
  ok('board renders confirmed/leads/refuted/clean sections', /CONFIRMED/.test(board) && /OPEN LEADS/.test(board) && /REFUTED/.test(board) && /CLEAN/.test(board));
  const tp = triagePrompt('proj', [{ severity: 'high', cwe: 'CWE-1', file: 'a.py', line: 1, title: 't', summary: 's' }]);
  ok('triage prompt has all 5 classifications', ['NOVEL_REAL', 'BY_DESIGN', 'KNOWN', 'LOW_VALUE', 'DUPLICATE'].every((c) => tp.includes(c)));
  ok('triage prompt clusters by root cause + is ruthless', /CLUSTER by ROOT CAUSE/.test(tp) && /RUTHLESS/.test(tp));
  ok('triage prompt lists the finding to classify', tp.includes('CWE-1') && tp.includes('a.py'));
  ok('rate-limit detector catches usage-limit / 429 / quota', isRateLimited("ERROR: You've hit your usage limit. try again at 12:10 PM") && isRateLimited('429 Too Many Requests') && isRateLimited('quota exceeded'));
  ok('rate-limit detector ignores normal findings output', !isRateLimited('[{"title":"x","file":"a.py","line":5,"cwe":"CWE-22"}]'));
  console.log(`\n${fail === 0 ? '✅ ALL PASS' : `❌ ${fail} FAILED`} — ${pass}/${pass + fail}\n`);
  process.exit(fail === 0 ? 0 : 1);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args['self-test']) return selfTest();

  if (!args.repo || args.repo === 'true') {
    console.error('usage: node scripts/cli-swarm.mjs --repo <path> [--rounds 3] [--concurrency 4] [--budget-min 240] [--lenses k1,k2] [--commit <sha>] [--model <m>]');
    process.exit(2);
  }
  const repo = path.resolve(args.repo);
  if (!fs.existsSync(repo)) { console.error(`repo not found: ${repo}`); process.exit(2); }
  const project = path.basename(repo);
  const commit = args.commit && args.commit !== 'true' ? args.commit : null;
  const maxRounds = Math.max(1, parseInt(args.rounds, 10) || 3);
  const concurrency = Math.max(1, parseInt(args.concurrency, 10) || 4);
  const budgetMs = (parseFloat(args['budget-min']) || 240) * 60 * 1000;
  const lenses = args.lenses && args.lenses !== 'true'
    ? LENSES.filter((l) => String(args.lenses).split(',').map((s) => s.trim()).includes(l.key))
    : LENSES;
  const startedAt = Date.now();
  const overBudget = () => Date.now() - startedAt > budgetMs;

  console.log(`\n${'═'.repeat(72)}`);
  console.log(`  ⚡ CLI-SWARM — BYO-subscription collaborative zero-day swarm`);
  console.log(`  target:      ${repo}${commit ? ` @ ${commit}` : ''}`);
  console.log(`  specialists: ${lenses.length} (${lenses.map((l) => l.key).join(', ')})`);
  console.log(`  plan:        up to ${maxRounds} collaborative rounds · ${concurrency} parallel · budget ${(budgetMs / 60000) | 0}min`);
  console.log(`  mode:        READ-ONLY · anti-fabrication · adversarially self-refuting · $0 marginal (codex sub)`);
  console.log(`${'═'.repeat(72)}\n`);

  const state = { confirmed: [], leads: [], refuted: [], cleanLenses: [] };
  const transcript = { project, commit, started: new Date().toISOString(), rounds: [] };
  let dryRounds = 0;
  let backendCalls = 0, backendFails = 0, rateLimited = false; // distinguish a real clean from a degraded/rate-limited non-run

  for (let round = 1; round <= maxRounds; round++) {
    if (overBudget()) { console.log(`  ⏱  budget reached — stopping before round ${round}.`); break; }
    console.log(`\n──────── ROUND ${round}/${maxRounds}  (${now()}) ────────`);
    const board = renderBoard(state);
    const roundRec = { round, started: new Date().toISOString(), specialists: [], newConfirmed: [], newLeads: [], refuted: [], outOfScope: 0 };

    // fan out the specialists in parallel
    const runs = await pool(lenses, concurrency, async (lens) => {
      const t0 = Date.now();
      const r = await runCodexAsync(repo, specialistPrompt(lens, board, round, commit), { label: lens.key });
      const secs = ((Date.now() - t0) / 1000).toFixed(0);
      backendCalls++;
      if (r.rateLimited) rateLimited = true;
      if (!r.ok) { backendFails++; console.log(`  ⚠ ${lens.name.padEnd(22)} ${r.error} (${secs}s)`); return { lens, items: [] }; }
      const items = extractFindings(r.text);
      if (items === null) { backendFails++; console.log(`  ⚠ ${lens.name.padEnd(22)} unparseable output (${secs}s)`); return { lens, items: [] }; }
      const conf = items.filter((x) => x.status === 'confirmed' || x.confidence === 'high').length;
      console.log(`  • ${lens.name.padEnd(22)} ${items.length} item(s) (${conf} confirmed/high) (${secs}s)`);
      roundRec.specialists.push({ lens: lens.key, n: items.length, secs: +secs });
      return { lens, items };
    });

    // pool + dedupe
    const fresh = [];
    for (const { lens, items } of runs) {
      if (!items.length) { if (!state.cleanLenses.includes(lens.name)) state.cleanLenses.push(lens.name); continue; }
      state.cleanLenses = state.cleanLenses.filter((n) => n !== lens.name); // it found something now
      for (const raw of items) {
        const f = normalizeFinding(raw, project, commit, 'swarm');
        f.confidence = raw.confidence || 'medium'; f.status = raw.status || (raw.confidence === 'high' ? 'confirmed' : 'lead'); f.lens = lens.key;
        if (!inScope(f.file)) { roundRec.outOfScope++; continue; } // demo/test/bench code ≠ library vuln
        if (titleSeen(state.confirmed, f) || titleSeen(state.refuted, f) || titleSeen(fresh, f)) continue;
        fresh.push(f);
      }
    }

    // skeptic refutation for the high-confidence / confirmed fresh items (parallel)
    const toVet = fresh.filter((f) => f.status === 'confirmed' || f.confidence === 'high');
    const leadsOnly = fresh.filter((f) => !(f.status === 'confirmed' || f.confidence === 'high'));
    if (toVet.length) console.log(`  ⚔ skeptic refuting ${toVet.length} candidate finding(s)…`);
    const vetted = await pool(toVet, concurrency, async (f) => {
      const r = await runCodexAsync(repo, skepticPrompt(f, commit), { label: `skeptic:${f.lens}` });
      let verdict = { verdict: 'SURVIVES', reason: 'skeptic produced no parseable verdict (kept for human review)', guard_found: null };
      if (r.ok) { const objs = extractObjects(r.text); if (objs.length) verdict = objs[objs.length - 1]; }
      return { f, verdict };
    });

    for (const { f, verdict } of vetted) {
      if (String(verdict.verdict).toUpperCase() === 'REFUTED') {
        f.reason = verdict.reason; f.guard_found = verdict.guard_found;
        state.refuted.push(f); roundRec.refuted.push(f);
        console.log(`    ✗ REFUTED  ${f.cwe} ${f.file}:${f.line ?? '?'} — ${verdict.guard_found || verdict.reason?.slice(0, 60) || ''}`);
      } else {
        state.confirmed.push(f); roundRec.newConfirmed.push(f);
        console.log(`    ✓ SURVIVES ${f.cwe} ${f.file}:${f.line ?? '?'} — ${f.title}`);
      }
    }
    // merge leads (dedupe vs existing leads too)
    for (const f of leadsOnly) { if (!titleSeen(state.leads, f)) { state.leads.push(f); roundRec.newLeads.push(f); } }
    // promote-resolved leads: drop leads that a confirmed/refuted now covers
    state.leads = state.leads.filter((l) => !titleSeen(state.confirmed, l) && !titleSeen(state.refuted, l));

    transcript.rounds.push(roundRec);
    const newSignal = roundRec.newConfirmed.length + roundRec.newLeads.length;
    console.log(`  round ${round} summary: +${roundRec.newConfirmed.length} confirmed, +${roundRec.newLeads.length} leads, ${roundRec.refuted.length} refuted${roundRec.outOfScope ? `, ${roundRec.outOfScope} out-of-scope dropped` : ''} · totals: ${state.confirmed.length} confirmed / ${state.leads.length} open leads / ${state.refuted.length} refuted`);
    if (newSignal === 0) { dryRounds++; if (dryRounds >= 2) { console.log(`  ◇ two dry rounds — the surface is exhausted. Stopping early.`); break; } }
    else dryRounds = 0;
  }

  // ── precision triage: cluster by root cause + classify (the overclaim gate) ──
  let triage = null;
  if (state.confirmed.length && args.triage !== 'false') {
    console.log(`\n──────── TRIAGE (${now()}) — clustering ${state.confirmed.length} survivors by root cause + classifying ────────`);
    triage = await triagePass(repo, project, state.confirmed, commit);
    if (triage) {
      transcript.triage = triage;
      for (const c of (triage.clusters || [])) console.log(`  [${c.classification}/${c.severity}] ${c.root_cause} (${(c.members || []).length} site(s)) — ${c.why}`);
      console.log(`  → ${triage.novel_real ?? 0} NOVEL_REAL of ${(triage.clusters || []).length} root-cause cluster(s) from ${state.confirmed.length} raw survivors`);
    } else {
      console.log(`  ⚠ triage produced no parseable verdict (keeping raw survivors)`);
    }
  }

  // ── synthesis ──
  transcript.finished = new Date().toISOString();
  transcript.elapsed_min = +(((Date.now() - startedAt) / 60000).toFixed(1));
  transcript.confirmed = state.confirmed; transcript.open_leads = state.leads; transcript.refuted = state.refuted;
  // a run where the backend rate-limited or errored on >=half the specialist calls is a
  // DEGRADED NON-RUN, not a clean assessment. Never let infra failure read as "secure".
  // INVALID only when failures DOMINATE (the assessment didn't meaningfully run). A few
  // rate-limited calls in an otherwise-complete run = partial coverage, NOT invalid —
  // over-flagging a substantially-complete run as "didn't execute" is its own false signal.
  const degraded = backendCalls > 0 && backendFails / backendCalls >= 0.5;
  const partial = rateLimited && !degraded;
  transcript.backend = { calls: backendCalls, fails: backendFails, rateLimited };
  transcript.verdict = degraded ? 'INVALID_DEGRADED' : (state.confirmed.length ? 'FINDINGS' : 'CLEAN');
  const outDir = path.join(REPO_ROOT, 'bench', 'wild-hunt', 'swarm');
  fs.mkdirSync(outDir, { recursive: true });
  const outPath = path.join(outDir, `swarm-${project.replace(/[^a-z0-9]+/gi, '-').toLowerCase()}-${startedAt}.json`);
  fs.writeFileSync(outPath, JSON.stringify(transcript, null, 2));

  console.log(`\n${'═'.repeat(72)}`);
  console.log(`  🐝 SWARM COMPLETE — ${transcript.elapsed_min}min · ${transcript.rounds.length} round(s)`);
  console.log(`${'═'.repeat(72)}`);
  if (degraded) {
    console.log(`  ⛔ INVALID RUN — backend ${rateLimited ? 'RATE-LIMITED (usage limit)' : 'errored'} on ${backendFails}/${backendCalls} specialist calls.`);
    console.log(`     This is NOT a clean assessment — the hunt did not actually execute. Re-run when the backend is available (e.g. after the quota resets).`);
  } else if (state.confirmed.length === 0) {
    console.log(`  ✅ CLEAN — ${lenses.length} specialists across ${transcript.rounds.length} round(s) found no surviving exploitable vulnerability.`);
    console.log(`     A deep, adversarially-refuted clean is a STRONG result on a hardened target.`);
  } else if (triage && triage.clusters) {
    const novel = triage.clusters.filter((c) => c.classification === 'NOVEL_REAL');
    const downgraded = triage.clusters.filter((c) => c.classification !== 'NOVEL_REAL');
    if (novel.length === 0) {
      console.log(`  ✅ ZERO NOVEL findings — ${state.confirmed.length} raw survivors triaged down to ${triage.clusters.length} root cause(s), ALL by-design / known / low-value / duplicate.`);
      console.log(`     The swarm has high recall; the triage gate refused the overclaim. That honesty IS the result.`);
    } else {
      console.log(`  🎯 ${novel.length} NOVEL_REAL finding(s) (from ${state.confirmed.length} raw survivors → ${triage.clusters.length} clusters). NEXT: executed PoC — the gate that makes them real:`);
      for (const c of novel) console.log(`     • [${c.severity}] ${c.root_cause} — sites: ${(c.members || []).slice(0, 4).join(', ')}`);
    }
    if (downgraded.length) console.log(`  ↓ ${downgraded.length} cluster(s) downgraded: ${downgraded.map((c) => `${c.classification}×${(c.members || []).length}`).join(', ')}`);
  } else {
    console.log(`  🎯 ${state.confirmed.length} SURVIVING finding(s) — each cleared the adversarial skeptic. NEXT: executed PoC (the gate that makes them real):`);
    for (const f of state.confirmed) console.log(`     • [${f.severity}/${f.confidence}] ${f.cwe} ${f.file}:${f.line ?? '?'} — ${f.title}`);
  }
  if (partial) console.log(`  ⚠ PARTIAL COVERAGE — ${backendFails}/${backendCalls} specialist call(s) lost to rate-limiting; findings stand but coverage is incomplete (re-run for full sweep).`);
  if (state.leads.length) console.log(`  ◷ ${state.leads.length} open lead(s) held for follow-up (unproven — NOT findings).`);
  if (state.refuted.length) console.log(`  ✗ ${state.refuted.length} candidate(s) adversarially refuted and dropped (anti-fabrication working).`);
  console.log(`  📄 full audit transcript: ${path.relative(REPO_ROOT, outPath)}\n`);
  process.exit(degraded ? 4 : 0);
}

// extract trailing JSON object(s) (for the skeptic verdict)
function extractObjects(text) {
  const s = String(text).replace(/```(?:json)?/gi, '');
  const out = []; let depth = 0, start = -1;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '{') { if (depth === 0) start = i; depth++; }
    else if (c === '}') { if (depth > 0 && --depth === 0 && start >= 0) { try { out.push(JSON.parse(s.slice(start, i + 1))); } catch {} start = -1; } }
  }
  return out;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) main();

export { LENSES, specialistPrompt, skepticPrompt, triagePrompt, triagePass, renderBoard, dedupKey, extractObjects, inScope, isRateLimited };
