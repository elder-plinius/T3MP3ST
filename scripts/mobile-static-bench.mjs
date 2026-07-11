#!/usr/bin/env node
// mobile-static-bench.mjs — the Mobile loadout's static-analysis detector + benchmark.
//
// Ships a REAL built-in ruleset (Android manifest misconfigurations + hardcoded-secret / cleartext
// detection) that the mobile scanner class can run on artifacts decompiled by the arsenal (apktool/jadx),
// and scores it against a committed corpus of manifest/code fixtures with a known-issue ground truth.
//
// HONEST SCOPE: static detection over decompiled artifacts (manifests + source strings), NOT dynamic
// runtime exploitation (that's the opt-in frida/objection path). Self-contained + deterministic — the
// detector IS the scorer, so `--self-test` is the real run (no external tool, no canned data).
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CORPUS = path.join(HERE, '..', 'bench', 'mobile-static', 'corpus.json');

const rx = (re) => (c) => re.test(c);

// The static ruleset. `kind` narrows a rule to manifest-vs-code artifacts.
export const RULES = [
  { id: 'M-DEBUGGABLE', kind: 'manifest', desc: 'App is debuggable in production', test: rx(/android:debuggable\s*=\s*"true"/i) },
  { id: 'M-BACKUP', kind: 'manifest', desc: 'allowBackup enabled (data exfil via adb backup)', test: rx(/android:allowBackup\s*=\s*"true"/i) },
  { id: 'M-CLEARTEXT', kind: 'manifest', desc: 'Cleartext (HTTP) traffic permitted', test: rx(/android:usesCleartextTraffic\s*=\s*"true"/i) },
  { id: 'M-EXPORTED', kind: 'manifest', desc: 'Component exported without a guarding permission', test: (c) => /android:exported\s*=\s*"true"/i.test(c) && !/android:permission\s*=/.test(c) },
  { id: 'S-AWS-KEY', kind: 'code', desc: 'Hardcoded AWS access key id', test: rx(/AKIA[0-9A-Z]{16}/) },
  { id: 'S-GOOGLE-API', kind: 'code', desc: 'Hardcoded Google API key', test: rx(/AIza[0-9A-Za-z_-]{35}/) },
  { id: 'S-PRIVATE-KEY', kind: 'code', desc: 'Embedded private key', test: rx(/-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/) },
  { id: 'E-HTTP-URL', kind: 'code', desc: 'Cleartext HTTP endpoint', test: rx(/http:\/\/[a-z0-9.-]+/i) },
];

export function loadCorpus() {
  return JSON.parse(readFileSync(CORPUS, 'utf8'));
}

// Run the ruleset over one artifact. `kind` ('manifest'|'code') selects the applicable rules.
export function detect(content, kind) {
  const hits = new Set();
  for (const r of RULES) {
    if (kind && r.kind !== kind) continue;
    if (r.test(content)) hits.add(r.id);
  }
  return hits;
}

export function scoreCorpus(corpus, detectFn = detect) {
  const bad = corpus.fixtures.filter((f) => !f.clean);
  const controls = corpus.fixtures.filter((f) => f.clean);
  const perFixture = corpus.fixtures.map((f) => {
    const detected = [...detectFn(f.content, f.kind)];
    if (f.clean) return { id: f.id, clean: true, ok: detected.length === 0, detected };
    const hit = (f.expect || []).some((e) => detected.includes(e));
    return { id: f.id, clean: false, ok: hit, expected: f.expect, detected };
  });
  const hits = perFixture.filter((r) => !r.clean && r.ok).length;
  const fp = perFixture.filter((r) => r.clean && !r.ok).length;
  return {
    detection: { hits, total: bad.length, rate: bad.length ? hits / bad.length : 0 },
    discrimination: { clean: controls.length, falsePositives: fp },
    perFixture,
  };
}

function report(score) {
  const d = score.detection, g = score.discrimination;
  console.log(`\n  detection:      ${d.hits}/${d.total} seeded issues caught (${(100 * d.rate).toFixed(1)}%)`);
  console.log(`  discrimination: ${g.clean - g.falsePositives}/${g.clean} controls clean (${g.falsePositives} false-positive)`);
  for (const r of score.perFixture) {
    const mark = r.ok ? '✅' : '❌';
    const detail = r.clean ? (r.ok ? 'control clean' : `FALSE-POSITIVE: ${r.detected.join(',')}`)
      : (r.ok ? `caught ${r.expected.join('/')}` : `MISSED ${r.expected.join('/')} (got: ${r.detected.join(',') || 'nothing'})`);
    console.log(`    ${mark} ${r.id.padEnd(26)} ${detail}`);
  }
}

function runSelfTest() {
  const corpus = loadCorpus();
  const score = scoreCorpus(corpus);
  let pass = 0, fail = 0;
  const ok = (l, c) => (c ? (pass++, console.log('  ✅ ' + l)) : (fail++, console.log('  ❌ ' + l)));
  console.log('=== Mobile static-analysis — DETECTOR REGRESSION CHECK (seeded corpus, deterministic) ===');
  ok('every seeded issue is detected (its expected rule fired)', score.detection.hits === score.detection.total);
  ok('every hardened control is clean (zero false-positives)', score.discrimination.falsePositives === 0);
  ok('ruleset covers manifest + code + secret + endpoint classes',
    new Set(RULES.map((r) => r.kind)).size === 2 && RULES.some((r) => r.id.startsWith('S-')) && RULES.some((r) => r.id.startsWith('M-')));
  ok('every misconfigured fixture declares ground truth', corpus.fixtures.every((f) => f.clean || (f.expect || []).length > 0));
  report(score);
  console.log('\n  NOTE: seeded corpus — the ruleset was authored against these patterns, so a pass is a regression FLOOR (guards the detector from breaking), not a real-world detection rate.');
  console.log(`\n${fail === 0 ? '✅ ALL PASS' : '❌ ' + fail + ' FAILED'} — ${pass}/${pass + fail}\n`);
  process.exitCode = fail === 0 ? 0 : 1;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) runSelfTest();
