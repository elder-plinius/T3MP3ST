#!/usr/bin/env node
// cloud-misconfig-bench.mjs — the Cloud loadout's IaC-misconfig detection benchmark.
//
// Scores an IaC scanner (checkov) against a committed corpus of Terraform fixtures with KNOWN
// misconfigurations + a locked-down control. Two axes:
//   • detection    — fraction of misconfigured fixtures where the expected check fired
//   • discrimination — the control fixture must NOT trip any target misconfig check (no false-positive)
//
// HONEST SCOPE: this measures static-IaC misconfig DETECTION, not live cloud exploitation. The number
// is directional (small corpus). `--self-test` validates the parser+scorer offline on committed data
// (no checkov needed); `--live` runs real checkov for the actual number (needs `checkov` installed).
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CORPUS = path.join(HERE, '..', 'bench', 'cloud-misconfig', 'corpus.json');
const SAMPLE = path.join(HERE, '..', 'bench', 'cloud-misconfig', 'sample-checkov-output.json');

export function loadCorpus() {
  return JSON.parse(readFileSync(CORPUS, 'utf8'));
}

// Parse a `checkov -o json` result into { <fixture-id>: Set<check_id> }. Tolerant of checkov's shapes:
// a single {results:{failed_checks}} object, or an array of them (multi-framework runs).
export function parseCheckov(json) {
  const blocks = Array.isArray(json) ? json : [json];
  const byFixture = {};
  for (const b of blocks) {
    for (const fc of b?.results?.failed_checks ?? []) {
      const id = path.basename(String(fc.file_path || ''), '.tf');
      if (!id) continue;
      (byFixture[id] ??= new Set()).add(fc.check_id);
    }
  }
  return byFixture;
}

// Score a parsed detection map against the corpus ground truth.
export function scoreCorpus(corpus, byFixture) {
  const targets = new Set(corpus.target_checks || []);
  const bad = corpus.fixtures.filter((f) => !f.clean);
  const controls = corpus.fixtures.filter((f) => f.clean);
  const perFixture = corpus.fixtures.map((f) => {
    const detected = byFixture[f.id] || new Set();
    if (f.clean) {
      const falsePos = [...detected].filter((c) => targets.has(c));
      return { id: f.id, clean: true, ok: falsePos.length === 0, falsePos };
    }
    const hit = (f.expect || []).some((e) => detected.has(e));
    return { id: f.id, clean: false, ok: hit, expected: f.expect, detected: [...detected] };
  });
  const hits = perFixture.filter((r) => !r.clean && r.ok).length;
  const fpControls = perFixture.filter((r) => r.clean && !r.ok).length;
  return {
    detection: { hits, total: bad.length, rate: bad.length ? hits / bad.length : 0 },
    discrimination: { clean: controls.length, falsePositives: fpControls },
    perFixture,
  };
}

function report(score) {
  const d = score.detection, g = score.discrimination;
  console.log(`\n  detection:      ${d.hits}/${d.total} misconfigs caught (${(100 * d.rate).toFixed(1)}%)`);
  console.log(`  discrimination: ${g.clean - g.falsePositives}/${g.clean} controls clean (${g.falsePositives} false-positive)`);
  for (const r of score.perFixture) {
    const mark = r.ok ? '✅' : '❌';
    const detail = r.clean ? (r.ok ? 'control clean' : `FALSE-POSITIVE: ${r.falsePos.join(',')}`)
      : (r.ok ? `caught ${r.expected.join('/')}` : `MISSED ${r.expected.join('/')} (got: ${r.detected.join(',') || 'nothing'})`);
    console.log(`    ${mark} ${r.id.padEnd(20)} ${detail}`);
  }
}

function runLive() {
  const corpus = loadCorpus();
  const dir = mkdtempSync(path.join(tmpdir(), 'cloud-bench-'));
  try {
    for (const f of corpus.fixtures) writeFileSync(path.join(dir, `${f.id}.tf`), f.hcl);
    let out;
    try {
      out = execFileSync('checkov', ['-d', dir, '-o', 'json', '--compact', '--quiet'], { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
    } catch (e) {
      // checkov exits non-zero when it finds failures — that's expected; use its stdout.
      out = e.stdout?.toString() || '';
      if (!out) { console.error('  ❌ could not run checkov — is it installed? (pipx install checkov)'); process.exitCode = 2; return; }
    }
    const score = scoreCorpus(corpus, parseCheckov(JSON.parse(out)));
    console.log('=== Cloud IaC-misconfig benchmark — LIVE (checkov) ===');
    report(score);
    console.log('\n  (directional; static-IaC detection only — not live cloud exploitation)');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function runSelfTest() {
  const corpus = loadCorpus();
  const sample = JSON.parse(readFileSync(SAMPLE, 'utf8'));
  const score = scoreCorpus(corpus, parseCheckov(sample));
  let pass = 0, fail = 0;
  const ok = (l, c) => (c ? (pass++, console.log('  ✅ ' + l)) : (fail++, console.log('  ❌ ' + l)));
  console.log('=== Cloud IaC-misconfig benchmark — SELF-TEST (offline, committed sample) ===');
  ok('parser extracts a per-fixture detection for every corpus fixture with a failed check',
    Object.keys(parseCheckov(sample)).length >= corpus.fixtures.filter((f) => !f.clean).length);
  ok('every misconfigured fixture is detected (its expected check fired)', score.detection.hits === score.detection.total);
  ok('the locked-down control produces ZERO misconfig false-positives', score.discrimination.falsePositives === 0);
  ok('target_checks are non-empty and every fixture declares expect/clean',
    (corpus.target_checks || []).length > 0 && corpus.fixtures.every((f) => f.clean || (f.expect || []).length > 0));
  report(score);
  console.log('\n  NOTE: the self-test validates the parser/scorer on committed sample data — run `--live` (real checkov) for an actual detection number.');
  console.log(`\n${fail === 0 ? '✅ ALL PASS' : '❌ ' + fail + ' FAILED'} — ${pass}/${pass + fail}\n`);
  process.exitCode = fail === 0 ? 0 : 1;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  if (process.argv.includes('--live')) runLive();
  else runSelfTest();
}
