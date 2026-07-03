#!/usr/bin/env node
/**
 * refute-finding — the ADVERSARIAL REACHABILITY stage. Complements the deterministic
 * same-function dominating-guard scan in verify-finding.mjs by catching the guards it
 * CAN'T see: a bound/normalize/cap in a DIFFERENT function or file, a config invariant,
 * an auth/CA binding — the things that turned ~10 agent "criticals" into false positives
 * (a normalize/clamp pre-pass in another file, a top-level size cap in a separate
 * function, a cert-is-CA-bound identity invariant, an alloc sized to the same length as
 * the copy). The job of each refuter is NOT to confirm the bug — it is to KILL it.
 *
 * Design:
 *   - Spawn N refuters (default 3). Each is told: "find the dominating check between the
 *     untrusted source and the sink that makes this unreachable/safe; default to REFUTED
 *     if you find one; cite its file:line." Skeptic-by-construction.
 *   - Majority REFUTED -> verdict REFUTED (the finding is likely a false positive; do NOT
 *     claim it until the cited guard is shown not to dominate).
 *   - Otherwise -> SURVIVED (no killing guard found; reachability holds for now).
 *   - Writes <finding-dir>/refutation_report.json for verify-finding / the runbook.
 *
 * Inference runs through the harness's own LLMBackbone (same as wild-hunt.mjs), so it
 * uses whatever provider is configured (openrouter/anthropic/codex/...). It NEVER edits
 * code or runs active probes — read-only reasoning over the cited source.
 *
 * Usage:
 *   node scripts/refute-finding.mjs --finding <file.json> [--refuters 3] [--provider <p>] [--model <m>]
 *   node scripts/refute-finding.mjs --finding <file.json> --dry-run     # print prompts, no inference
 *   node scripts/refute-finding.mjs --self-test                         # offline test of adjudicate()
 *
 * Exit 0 = SURVIVED · 3 = REFUTED / NEEDS-REVIEW · 2 = bad input.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function parseArgs(argv) {
  const a = {};
  for (let i = 0; i < argv.length; i++) {
    const t = argv[i];
    if (t.startsWith('--')) { const k = t.slice(2); const v = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : 'true'; a[k] = v; }
  }
  return a;
}

// ── the refuter prompt: a skeptic whose only job is to find the killing guard ──
function buildRefuterPrompt(f, n) {
  return [
    'You are an adversarial vulnerability REFUTER on a coordinated-disclosure team. A teammate claims the vulnerability below. Most such claims are FALSE POSITIVES because a guard the claimant missed makes the sink unreachable or safe. YOUR ONLY JOB is to find that guard and REFUTE the claim. Do not try to confirm it.',
    '',
    `CLAIM #${n}:`,
    `  project: ${f.project}`,
    `  class:   ${f.cwe || ''} ${f.vuln_class || ''}`,
    `  sink:    ${f.sink ? `${f.sink.file}:${f.sink.line} (length operand: ${f.sink.length_var})` : f.component}`,
    `  summary: ${f.summary || ''}`,
    `  reachability claimed: ${f.reachability || '(none stated)'}`,
    '',
    'Look HARD — especially OUTSIDE the sink\'s own function — for any of these that DOMINATES the path from untrusted input to the sink:',
    '  - a bounds / length / capacity check (possibly in a caller, a wrapper, or a pre-pass like a "normalize"/"validate" step in another file)',
    '  - an integer/size invariant that means the bad value cannot actually occur at real input sizes (e.g. a value bounded by a <=64KB datagram can never reach a 2^32 wrap)',
    '  - an allocation sized to the same attacker length (grow-to-fit) so the "overflow" stays in-bounds',
    '  - a config/default invariant that makes the vulnerable configuration non-default (raise attack complexity)',
    '  - an authentication / signature / certificate / CA binding that the claim ignored',
    '',
    'Default to REFUTED if you find a plausible dominating guard. Only return SURVIVED if you genuinely cannot find one after looking in the callers and related files.',
    '',
    'You may reason first, but your reply MUST END with a single JSON object on its own line — no markdown fences, nothing after it. Use exactly one of these two shapes:',
    '  if you found a guard:   {"verdict":"REFUTED","killing_guard":{"file":"path","line":0,"quote":"the guard source"},"why":"one sentence"}',
    '  if you did not:         {"verdict":"SURVIVED","killing_guard":null,"why":"one sentence"}',
  ].join('\n');
}

// ── deterministic adjudication (pure; unit-tested via --self-test) ──
function adjudicate(verdicts) {
  const valid = verdicts.filter((v) => v && (v.verdict === 'REFUTED' || v.verdict === 'SURVIVED'));
  const refuted = valid.filter((v) => v.verdict === 'REFUTED');
  const n = valid.length;
  const majorityRefuted = n > 0 && refuted.length * 2 > n; // strict majority
  return {
    verdict: n === 0 ? 'INCONCLUSIVE' : majorityRefuted ? 'REFUTED' : 'SURVIVED',
    refutedCount: refuted.length,
    total: n,
    killing_guards: refuted.map((v) => v.killing_guard).filter(Boolean),
  };
}

// Reasoning models often emit chain-of-thought prose (which can contain stray
// braces) and/or wrap the answer in ``` fences, then put the real verdict object
// LAST. So: strip fences, scan for every balanced {...} block, and return the
// LAST one that parses to a valid verdict — the model's final answer.
function parseVerdict(text) {
  const s = String(text).replace(/```(?:json)?/gi, '');
  const objects = [];
  let depth = 0, start = -1;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '{') { if (depth === 0) start = i; depth++; }
    else if (c === '}') {
      if (depth > 0 && --depth === 0 && start >= 0) { objects.push(s.slice(start, i + 1)); start = -1; }
    }
  }
  for (let i = objects.length - 1; i >= 0; i--) {
    try {
      const o = JSON.parse(objects[i]);
      if (o && (o.verdict === 'REFUTED' || o.verdict === 'SURVIVED')) return o;
    } catch { /* keep scanning earlier objects */ }
  }
  return null;
}

// GUARD CITE-CHECK (deterministic): an LLM refuter can hallucinate a plausible-looking
// killing guard (e.g. "if (m_id >= ls.w) continue;") that ISN'T in the code, falsely
// refuting a REAL finding. Before counting a REFUTED vote, confirm the cited guard's
// comparison actually appears in the cited source file. Catches the exact failure observed
// on the held wild-hunt targets: real findings refuted via invented or paraphrased-irrelevant guards.
function guardExistsInSource(g, repoRoot) {
  if (!g || !g.file || !g.quote) return 'no-quote';
  let src;
  try { src = fs.readFileSync(path.join(repoRoot, g.file), 'utf8'); } catch { return 'file-missing'; }
  const norm = (s) => String(s).replace(/\s+/g, '').toLowerCase();
  if (norm(g.quote).length >= 6 && norm(src).includes(norm(g.quote))) return 'verified';
  const cmp = String(g.quote).match(/([\w.()>_-]+)\s*(>=|<=|==|!=|>|<)\s*([\w.()>_-]+)/);
  if (cmp) {
    const a = norm(cmp[1]), b = norm(cmp[3]);
    for (const line of src.split('\n')) { const nl = norm(line); if (a && b && nl.includes(a) && nl.includes(b)) return 'verified'; }
  }
  return 'hallucinated';
}

function selfTest() {
  let pass = 0, fail = 0;
  const ok = (l, c) => (c ? (pass++, console.log(`  ✅ ${l}`)) : (fail++, console.log(`  ❌ ${l}`)));
  ok('2 of 3 REFUTED → REFUTED', adjudicate([{ verdict: 'REFUTED' }, { verdict: 'REFUTED' }, { verdict: 'SURVIVED' }]).verdict === 'REFUTED');
  ok('1 of 3 REFUTED → SURVIVED', adjudicate([{ verdict: 'REFUTED' }, { verdict: 'SURVIVED' }, { verdict: 'SURVIVED' }]).verdict === 'SURVIVED');
  ok('0 valid → INCONCLUSIVE', adjudicate([null, { verdict: 'junk' }]).verdict === 'INCONCLUSIVE');
  ok('collects killing guards', adjudicate([{ verdict: 'REFUTED', killing_guard: { file: 'x', line: 9 } }, { verdict: 'REFUTED', killing_guard: { file: 'x', line: 9 } }]).killing_guards.length === 2);
  ok('parseVerdict extracts JSON', parseVerdict('blah {"verdict":"SURVIVED","killing_guard":null,"why":"none"} tail')?.verdict === 'SURVIVED');
  ok('parseVerdict ignores prose braces, takes last verdict', parseVerdict('I see memcpy(&info, x) {note} reasoning...\n```json\n{"verdict":"REFUTED","killing_guard":{"file":"a.c","line":5,"quote":"if(n>cap)return"},"why":"bounded"}\n```')?.verdict === 'REFUTED');
  ok('parseVerdict returns null on reasoning-only (no JSON)', parseVerdict('Let me trace the path: 1. UDP reception 2. routing — truncated') === null);
  console.log(`\n${fail === 0 ? '✅ ALL PASS' : `❌ ${fail} FAILED`} — ${pass}/${pass + fail}\n`);
  process.exit(fail === 0 ? 0 : 1);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args['self-test']) return selfTest();
  if (!args.finding || args.finding === 'true') { console.error('usage: node scripts/refute-finding.mjs --finding <file.json> [--refuters 3] [--dry-run] [--self-test]'); process.exit(2); }
  const fp = path.isAbsolute(args.finding) ? args.finding : path.join(REPO, args.finding);
  if (!fs.existsSync(fp)) { console.error(`finding not found: ${fp}`); process.exit(2); }
  const f = JSON.parse(fs.readFileSync(fp, 'utf8'));
  const refuters = Number(args.refuters) || 3;

  console.log(`\n════════ refute-finding — ${f.slug || f.project} (${refuters} refuters) ════════\n`);

  if (args['dry-run']) {
    console.log(buildRefuterPrompt(f, 1));
    console.log('\n[dry-run] no inference performed. Drop --dry-run (and configure a provider) to run the refuters.');
    process.exit(0);
  }

  // real run: route through the harness's LLMBackbone (same backend wild-hunt uses).
  // Build the config via ConfigManager.getLLMConfig so the API key (from .env / env),
  // a default model, and the fallback chain are all resolved — a bare
  // { provider, model } object carries no apiKey and would fail auth.
  let LLMBackbone, config;
  try {
    ({ LLMBackbone } = await import('../dist/llm/index.js'));
    ({ config } = await import('../dist/config/index.js'));
  }
  catch (e) { console.error(`could not load harness from dist (build first: npm run build). ${e.message}`); process.exit(2); }
  const llmConfig = config.getLLMConfig(args.provider || 'openrouter', args.model);
  // codex/local/mock are command-based (subscription CLI or local) — no API key needed.
  const KEYLESS_PROVIDERS = ['codex', 'local', 'mock'];
  if (!llmConfig.apiKey && !KEYLESS_PROVIDERS.includes(llmConfig.provider)) {
    console.error(`no API key for provider "${llmConfig.provider}" — set ${llmConfig.provider.toUpperCase()}_API_KEY in .env or the environment.`);
    process.exit(2);
  }
  const backbone = new LLMBackbone(llmConfig);

  const verdicts = [];
  // DIVERSITY: spread the refuters across a temperature ladder (low→high) so the panel
  // explores genuinely different reasoning paths instead of returning N verbatim-identical
  // votes. A single backbone at one temperature is an echo, not a panel — the low-temp
  // refuters drill the cited path precisely, the high-temp ones probe unconventional killing
  // guards. (Next step for full independence: rotate the model per refuter too.)
  const refuterTemp = (i) => (refuters > 1 ? +(0.2 + 0.8 * (i - 1) / (refuters - 1)).toFixed(2) : 0.5);
  for (let i = 1; i <= refuters; i++) {
    const temp = refuterTemp(i);
    try {
      // generous budget: reasoning models burn tokens thinking before they emit
      // the final JSON verdict — too small a cap truncates mid-reasoning (no JSON).
      const res = await backbone.chat([{ role: 'user', content: buildRefuterPrompt(f, i) }], { maxTokens: 2000, temperature: temp });
      let raw = res?.content ?? res;
      let v = parseVerdict(raw);
      // a verbose reasoner can exhaust even 2000 tokens before landing the JSON.
      // one terse, reasoning-free retry guarantees a verdict rather than silently
      // dropping this refuter (which would weaken the majority on a real finding).
      if (!v) {
        if (process.env.REFUTE_DEBUG) { const r = String(raw); console.log(`    ↳ refuter ${i} unparseable [${r.length}ch], retrying json-only; tail: ${JSON.stringify(r.slice(-200))}`); }
        const retryPrompt = `${buildRefuterPrompt(f, i)}\n\nOutput ONLY the single JSON object now. No reasoning, no prose, no markdown — just the object.`;
        const res2 = await backbone.chat([{ role: 'user', content: retryPrompt }], { maxTokens: 600, temperature: temp });
        raw = res2?.content ?? res2;
        v = parseVerdict(raw);
      }
      if (v) v.temp = temp;
      verdicts.push(v);
      console.log(`  refuter ${i} (t=${temp}): ${v ? v.verdict : 'unparseable'}${v?.killing_guard ? ` — guard @ ${v.killing_guard.file}:${v.killing_guard.line}` : ''}`);
      if (!v && process.env.REFUTE_DEBUG) { const r = String(raw); console.log(`    ↳ raw[${r.length}ch] tail: ${JSON.stringify(r.slice(-300))}`); }
    } catch (e) { console.log(`  refuter ${i} (t=${temp}): error — ${e.message}`); verdicts.push(null); }
  }

  // CITE-CHECK: a REFUTED vote must cite a guard that ACTUALLY EXISTS in source. An
  // unverifiable (hallucinated/paraphrased-absent) guard cannot refute a real finding —
  // downgrade it to SURVIVED (recording the original claim for transparency). Needs --repo.
  if (args.repo) {
    for (const v of verdicts) {
      if (v && v.verdict === 'REFUTED' && v.killing_guard) {
        const gc = guardExistsInSource(v.killing_guard, args.repo);
        v.guard_check = gc;
        if (gc === 'hallucinated' || gc === 'file-missing') {
          console.log(`    ⚠ killing-guard NOT in source (${gc}) — REFUTED vote rejected: ${v.killing_guard.file}:${v.killing_guard.line} "${String(v.killing_guard.quote).slice(0, 48)}"`);
          v.original_verdict = 'REFUTED'; v.verdict = 'SURVIVED';
        }
      }
    }
  }
  const adj = adjudicate(verdicts);
  const outPath = path.join(path.dirname(fp), `${f.slug || 'finding'}.refutation_report.json`);
  fs.writeFileSync(outPath, JSON.stringify({ slug: f.slug, ...adj, verdicts, at: f.commit ? `commit ${f.commit}` : undefined }, null, 2));

  console.log(`\n  ${adj.verdict === 'SURVIVED' ? '✅' : '⚠'} ${adj.verdict} — ${adj.refutedCount}/${adj.total} refuters found a killing guard`);
  for (const g of adj.killing_guards) if (g) console.log(`     - ${g.file}:${g.line} ${g.quote ? `(${g.quote})` : ''}`);
  console.log(`  report: ${path.relative(REPO, outPath)}\n`);
  process.exit(adj.verdict === 'SURVIVED' ? 0 : 3);
}

export { adjudicate, parseVerdict, buildRefuterPrompt, guardExistsInSource };
const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) main();
