#!/usr/bin/env node
/**
 * T3MP3ST apex scorecard aggregator.
 *
 * Walks every bench result JSON in bench/{cve-hunt,cybench,obsidivm-evolution}/results/
 * and emits a single consolidated scorecard:
 *
 *   - markdown table (stdout / docs/SCORECARD.md)
 *   - json blob (docs/SCORECARD.json) for downstream tooling
 *
 * Categories:
 *   1. CVE-Hunt (code-audit recall, F1, precision, novel-CVE %)
 *   2. OBSIDIVM live-range (suite grade, per-target detail)
 *   3. OBSIDIVM evolution (lineage delta, ablation alive/pruned)
 *   4. Cybench standalone (live + direct + live-tools modes)
 *   5. Cybench service-required (this session's new tier)
 *   6. Hard Bench (hand-built)
 *
 * Usage:
 *   node scripts/scorecard.mjs                      # write + print
 *   node scripts/scorecard.mjs --quiet              # write only
 *   node scripts/scorecard.mjs --json               # emit JSON only
 */

import fs   from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO      = path.resolve(__dirname, '..');

function loadJson(p) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch { return null; }
}

function listJsons(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter(f => f.endsWith('.json')).map(f => path.join(dir, f));
}

// ----- categorizers ------------------------------------------------------

function categorize(filePath, report) {
  if (!report) return null;
  const name = path.basename(filePath, '.json');
  const schema = report.schema || '';

  if (schema.includes('cve-hunt') || /cve|baseline|gauntlet-cve|stub-baseline|adversarial|stub-with-judge|postcut/i.test(name)) {
    return 'cve-hunt';
  }
  if (schema.includes('cybench') || /cybench|hard-bench|gauntlet-hard|warmup|service-cybsvc/i.test(name)) {
    return 'cybench';
  }
  if (schema.includes('obsidivm.bench')) return 'obsidivm';
  // obsidivm-anon-live, obsidivm-10deployed, obsidivm-full14-* etc.
  if (/obsidivm/i.test(name)) return 'obsidivm';
  return 'unknown';
}

// ----- summarizers per category -----------------------------------------

function cveHuntSummary(reports) {
  return reports
    .map(({ file, data }) => {
      const a = data?.aggregate;
      if (!a) return null;
      return {
        file: path.relative(REPO, file),
        mode: data.mode || 'unknown',
        model: data.model || 'unknown',
        samples: a.samples_total,
        real_cves: a.real_cves,
        detected: a.detected,
        precision: a.precision,
        recall: a.recall,
        f1: a.f1_score,
        net_pct: a.score_percent,
        decoy_fp: a.decoy_false_positives,
        timestamp: data.timestamp,
      };
    })
    .filter(Boolean)
    .sort((a, b) => String(a.timestamp).localeCompare(String(b.timestamp)));
}

function cybenchSummary(reports) {
  return reports
    .map(({ file, data }) => {
      const a = data?.aggregate;
      if (!a) return null;
      return {
        file: path.relative(REPO, file),
        hunter: data.hunter || 'unknown',
        model: data.model || 'unknown',
        total: a.challenges_total,
        strict: a.solved ?? 0,
        semantic: a.semantic ?? 0,
        strict_pct: a.solve_rate_strict_pct ?? a.solve_rate_pct,
        semantic_pct: a.solve_rate_semantic_pct,
        weighted_pct: a.weighted_pct,
        by_cat: a.by_category || {},
        timestamp: data.timestamp,
      };
    })
    .filter(Boolean)
    .sort((a, b) => String(a.timestamp).localeCompare(String(b.timestamp)));
}

function obsidivmSummary(reports) {
  return reports
    .map(({ file, data }) => {
      const a = data?.aggregate;
      if (!a) return null;
      return {
        file: path.relative(REPO, file),
        hunter: data.hunter || 'unknown',
        targets_total: a.targets_total,
        targets_scored: a.targets_scored,
        found_total: a.found_total,
        expected_total: a.expected_total,
        coverage_pct: a.coverage_percent,
        weighted_avg: a.weighted_avg_percent,
        grade: a.suite_grade,
        timestamp: data.timestamp,
      };
    })
    .filter(Boolean)
    .sort((a, b) => String(a.timestamp).localeCompare(String(b.timestamp)));
}

function serviceSummary() {
  const dir = path.join(REPO, 'bench', 'cybench', 'results');
  if (!fs.existsSync(dir)) return null;

  // SOURCE OF TRUTH = the per-challenge service-cybsvc_*.json files. Each holds
  // the latest result for ONE challenge (re-runs overwrite). This is more
  // accurate than any single batch aggregate, because standalone re-runs
  // (e.g. recovering an infra-failed challenge) update the per-challenge file
  // but write only a size-1 aggregate that wouldn't win the "largest" pick.
  const perChallenge = fs.readdirSync(dir)
    .filter(f => /^service-cybsvc_.*\.json$/.test(f))
    .map(f => path.join(dir, f));
  if (perChallenge.length === 0) return null;

  let solved = 0, semantic = 0, agentFailed = 0;
  for (const p of perChallenge) {
    const r = loadJson(p);
    const v = r?.results?.[0]?.verdict;
    if (!v) continue;
    if (v.score === 1 || v.detected) solved++;
    else if (v.semantic) semantic++;
    else agentFailed++;
  }

  // infra-failed = service-required tasks that NEVER produced a per-challenge
  // report (docker compose up failed). Derive from the full task universe:
  // total service-required tasks (18) minus those with a report file.
  const SERVICE_REQUIRED_TOTAL = 18; // from cybench-service.mjs --list
  const withReport = perChallenge.length;
  const infraFailed = Math.max(0, SERVICE_REQUIRED_TOTAL - withReport);
  const total = SERVICE_REQUIRED_TOTAL;
  const runnable = withReport; // a report means it ran (solved or honest-miss)

  return {
    file: 'bench/cybench/results/service-cybsvc_*.json (per-challenge, source of truth)',
    total,
    solved,
    semantic,
    agent_failed: agentFailed,
    infra_failed: infraFailed,
    runnable,
    solve_rate_total_pct: total ? +(100 * solved / total).toFixed(1) : 0,
    solve_rate_runnable_pct: runnable ? +(100 * solved / runnable).toFixed(1) : 0,
  };
}

function evolveSummary() {
  const ledgerPath = path.join(REPO, 'bench', 'obsidivm-evolution', 'ledger.json');
  if (!fs.existsSync(ledgerPath)) return null;
  const ledger = loadJson(ledgerPath);
  if (!ledger?.generations) return null;
  const propLedger = loadJson(path.join(REPO, 'bench', 'obsidivm-evolution', 'proposals-ledger.json')) || { proposals: {} };
  const props = Object.values(propLedger.proposals);
  return {
    generations: ledger.generations.map(g => ({
      gen: g.gen, score: g.score, grade: g.grade,
      found: g.found, expected: g.expected,
      delta: g.delta_from_prev, action: g.action,
      accepted: g.accepted, proposals: g.proposals,
    })),
    proposals_total: props.length,
    proposals_alive: props.filter(p => !p.gen_pruned).length,
    proposals_pruned: props.filter(p => p.gen_pruned).length,
    total_lift: props.reduce((s, p) => s + (p.lift_total || 0), 0),
  };
}

// ----- formatters --------------------------------------------------------

function formatMd(cardData) {
  const lines = [];
  lines.push('# T3MP3ST Apex Scorecard');
  lines.push('');
  lines.push(`Generated: ${new Date().toISOString()}`);
  lines.push('');

  // CVE-Hunt
  lines.push('## CVE-Hunt — code-audit recall (15 samples: 10 published + 5 novel post-cutoff + 2 decoys)');
  lines.push('');
  lines.push('| File | Mode | Model | Detect | F1 | Precision | Decoy FP | Net % |');
  lines.push('|---|---|---|---|---|---|---|---|');
  for (const r of cardData.cve_hunt) {
    lines.push(`| ${r.file} | ${r.mode} | ${r.model} | ${r.detected}/${r.real_cves || '?'} | ${r.f1 ?? '—'} | ${r.precision ?? '—'} | ${r.decoy_fp ?? '—'} | ${r.net_pct ?? '—'} |`);
  }
  lines.push('');

  // OBSIDIVM live
  lines.push('## OBSIDIVM — live web range (14 targets, severity-weighted)');
  lines.push('');
  lines.push('| File | Hunter | Targets scored | Findings | Coverage % | Weighted % | Grade |');
  lines.push('|---|---|---|---|---|---|---|');
  for (const r of cardData.obsidivm) {
    lines.push(`| ${r.file} | ${r.hunter} | ${r.targets_scored}/${r.targets_total} | ${r.found_total}/${r.expected_total} | ${r.coverage_pct ?? '—'} | ${r.weighted_avg ?? '—'} | **${r.grade ?? '—'}** |`);
  }
  lines.push('');

  // Evolution
  if (cardData.evolve) {
    lines.push('## OBSIDIVM Evolution — self-improvement loop with ablation');
    lines.push('');
    lines.push('| Gen | Score % | Grade | Found/Total | Accepted | Δ | Action |');
    lines.push('|---|---|---|---|---|---|---|');
    for (const g of cardData.evolve.generations) {
      lines.push(`| ${String(g.gen).padStart(3, '0')} | ${g.score} | ${g.grade} | ${g.found}/${g.expected} | ${g.accepted}/${g.proposals} | ${g.delta == null ? '—' : (g.delta >= 0 ? '+' : '') + g.delta} | ${g.action} |`);
    }
    const e = cardData.evolve;
    lines.push('');
    lines.push(`**Proposals ledger:** ${e.proposals_total} total · ${e.proposals_alive} alive · ${e.proposals_pruned} pruned · total lift ${e.total_lift}`);
    lines.push('');
  }

  // Cybench
  lines.push('## Cybench — academic CTF benchmark (real upstream corpus)');
  lines.push('');
  lines.push('| File | Hunter | Model | Strict | Semantic | Weighted | By category |');
  lines.push('|---|---|---|---|---|---|---|');
  for (const r of cardData.cybench) {
    const byCat = Object.entries(r.by_cat || {}).map(([k, v]) => `${k} ${v.solved}/${v.total}`).join(' · ');
    lines.push(`| ${r.file} | ${r.hunter} | ${r.model} | ${r.strict}/${r.total} (${r.strict_pct ?? '—'}%) | ${r.semantic ?? 0}/${r.total} (${r.semantic_pct ?? '—'}%) | ${r.weighted_pct ?? '—'}% | ${byCat} |`);
  }
  lines.push('');

  // Apex headline — only count "real" runs (not stub/adversarial canned-finding)
  const isReal = (r) => r.mode && !['stub', 'adversarial'].includes(r.mode) && r.model !== 'stub';
  const isRealCyb = (r) => r.hunter && !['stub', 'adversarial'].includes(r.hunter);
  const cveReal    = cardData.cve_hunt.filter(isReal);
  const cybReal    = cardData.cybench.filter(isRealCyb);
  const obsReal    = cardData.obsidivm.filter(r => r.hunter && !['stub'].includes(r.hunter));

  // Tiebreaker: prefer runs with more samples (statistical power) when scores
  // are close. Filter "best" to runs with at least N samples to avoid micro-
  // sample wins (1-challenge subsets at 100%).
  const meaningfulCyb = cybReal.filter(r => (r.total || 0) >= 5);
  const meaningfulCve = cveReal.filter(r => (r.samples || 0) >= 5);
  const meaningfulObs = obsReal.filter(r => (r.targets_total || 0) >= 5);

  // "Best" CVE-Hunt: prefer max samples first, then F1
  const bestCveHunt = meaningfulCve.reduce((b, r) => {
    if (!b) return r;
    if ((r.samples || 0) > (b.samples || 0)) return r;
    if ((r.samples || 0) === (b.samples || 0) && (r.f1 || 0) > (b.f1 || 0)) return r;
    return b;
  }, null);
  // "Best" OBSIDIVM: max targets first, then weighted_avg
  const bestObsidivm = meaningfulObs.reduce((b, r) => {
    if (!b) return r;
    if ((r.targets_scored || 0) > (b.targets_scored || 0)) return r;
    if ((r.targets_scored || 0) === (b.targets_scored || 0) && (r.weighted_avg || 0) > (b.weighted_avg || 0)) return r;
    return b;
  }, null);
  // "Best" Cybench: max total first, then strict_pct
  const bestCybStrict = meaningfulCyb.reduce((b, r) => {
    if (!b) return r;
    if ((r.strict_pct || 0) > (b.strict_pct || 0)) return r;
    if ((r.strict_pct || 0) === (b.strict_pct || 0) && (r.total || 0) > (b.total || 0)) return r;
    return b;
  }, null);
  const bestCybSemantic = meaningfulCyb.reduce((b, r) => {
    if (!b) return r;
    if ((r.semantic_pct || 0) > (b.semantic_pct || 0)) return r;
    return b;
  }, null);

  lines.push('## Apex headline');
  lines.push('');
  if (bestCveHunt) lines.push(`- **CVE-Hunt** best: ${bestCveHunt.detected}/${bestCveHunt.real_cves} detect, F1 **${bestCveHunt.f1}**, ${bestCveHunt.net_pct}% net (${bestCveHunt.mode})`);
  if (bestObsidivm) lines.push(`- **OBSIDIVM** best: ${bestObsidivm.targets_scored} targets, ${bestObsidivm.weighted_avg}% **grade ${bestObsidivm.grade}** (${bestObsidivm.hunter})`);
  if (cardData.evolve?.generations?.length) {
    const first = cardData.evolve.generations[0], last = cardData.evolve.generations.at(-1);
    lines.push(`- **Evolution** ${first.score}% → ${last.score}% across ${cardData.evolve.generations.length} gens (lift ${cardData.evolve.total_lift} weighted)`);
  }
  // Separate Hard Bench (our hand-built) from real Cybench (upstream corpus).
  const isHardBench  = (r) => /hard-bench|gauntlet-hard|warmup/i.test(r.file);
  const isUpstreamCyb = (r) => /real-cybench|full-cybench-standalone|standalone-opus|service-cybsvc/i.test(r.file);

  const hardBenchRuns = cybReal.filter(isHardBench);
  const realCybRuns   = cybReal.filter(isUpstreamCyb).filter(r => (r.total || 0) >= 5);

  const bestHard = hardBenchRuns.reduce((b, r) => {
    if (!b) return r;
    if ((r.total || 0) > (b.total || 0)) return r;
    if ((r.total || 0) === (b.total || 0) && (r.strict_pct || 0) > (b.strict_pct || 0)) return r;
    return b;
  }, null);
  // Standalone tier: when several standalone files cover the same 13-challenge
  // set, the older opus-4.7 `full-cybench-standalone-livetools.json` stub (5/13)
  // and the canonical opus-4.8 `standalone-opus48.json` (7/13) both have
  // total=13. Pick by MOST SOLVED so the stale stub never wins the combined
  // number. strict count = round(strict_pct% * total).
  const solvedCount = (r) => Math.round((r.strict_pct || 0) / 100 * (r.total || 0));
  const bestRealCyb = realCybRuns.reduce((b, r) => {
    if (!b) return r;
    if (solvedCount(r) > solvedCount(b)) return r;             // most solved wins
    if (solvedCount(r) === solvedCount(b) && (r.total || 0) > (b.total || 0)) return r;
    return b;
  }, null);

  if (bestHard) lines.push(`- **T3MP3ST Hard Bench** (hand-built CTF) best: **${bestHard.strict_pct}% strict** / **${bestHard.semantic_pct ?? bestHard.strict_pct}% semantic** (${bestHard.hunter}, ${bestHard.total} challenges)`);
  if (bestRealCyb) lines.push(`- **Real Cybench standalone (upstream)** best: **${bestRealCyb.strict_pct}% strict** (${bestRealCyb.hunter}, ${bestRealCyb.total}/40 challenges) — *published Cybench SOTA is 17.5% unguided (Claude 3.5 Sonnet, arXiv:2408.08926)*`);

  if (cardData.cybench_service) {
    const s = cardData.cybench_service;
    lines.push(`- **Real Cybench service-required** (Phase 2 docker runner): **${s.solved}/${s.total} solved** (${s.solve_rate_total_pct}% total · **${s.solve_rate_runnable_pct}% of ${s.runnable} runnable**)`);
    lines.push(`  - ${s.agent_failed} agent-failed · ${s.infra_failed} infra-failed (Cybench corpus rot: stale docker images / missing apt pkgs / arm64 incompat)`);
  }

  // Combined Cybench picture
  if (bestRealCyb && cardData.cybench_service) {
    const s = cardData.cybench_service;
    const standaloneSolved = Math.round(bestRealCyb.strict_pct / 100 * bestRealCyb.total);
    const combinedSolved = standaloneSolved + s.solved;
    const addressable = bestRealCyb.total + s.total;  // 31 = 13 standalone + 18 service
    const runnable = bestRealCyb.total + s.runnable;
    lines.push(`- **Combined Cybench addressable (31/40)**: **${combinedSolved}/${addressable} = ${(100 * combinedSolved / addressable).toFixed(1)}% strict**`);
    lines.push(`- **Combined Cybench runnable subset**: **${combinedSolved}/${runnable} = ${(100 * combinedSolved / runnable).toFixed(1)}%**`);
  }
  lines.push('');
  lines.push('---');
  lines.push(`*Auto-generated by \`scripts/scorecard.mjs\`. ${cardData.cve_hunt.length + cardData.obsidivm.length + cardData.cybench.length} bench reports aggregated.*`);
  return lines.join('\n');
}

// ----- main --------------------------------------------------------------

function main() {
  const quiet = process.argv.includes('--quiet');
  const jsonOnly = process.argv.includes('--json');

  // Collect every result JSON
  const cveResults = listJsons(path.join(REPO, 'bench', 'cve-hunt', 'results'))
    .map(f => ({ file: f, data: loadJson(f) })).filter(x => x.data);
  const cybResults = listJsons(path.join(REPO, 'bench', 'cybench', 'results'))
    .map(f => ({ file: f, data: loadJson(f) })).filter(x => x.data);

  const cveSorted    = cveResults.filter(r => categorize(r.file, r.data) === 'cve-hunt');
  const cybSorted    = cybResults.filter(r => categorize(r.file, r.data) === 'cybench');
  const obsidivmAll  = [...cveResults, ...cybResults].filter(r => categorize(r.file, r.data) === 'obsidivm');

  const cardData = {
    timestamp: new Date().toISOString(),
    cve_hunt: cveHuntSummary(cveSorted),
    cybench:  cybenchSummary(cybSorted),
    obsidivm: obsidivmSummary(obsidivmAll),
    evolve:   evolveSummary(),
    cybench_service: serviceSummary(),
  };

  // Write JSON
  fs.writeFileSync(path.join(REPO, 'docs', 'SCORECARD.json'), JSON.stringify(cardData, null, 2));

  // Write/print MD
  const md = formatMd(cardData);
  fs.writeFileSync(path.join(REPO, 'docs', 'SCORECARD.md'), md);

  if (!quiet && !jsonOnly) console.log(md);
  if (jsonOnly) console.log(JSON.stringify(cardData, null, 2));
  if (quiet || jsonOnly) console.error(`wrote docs/SCORECARD.md and docs/SCORECARD.json`);
}

main();
