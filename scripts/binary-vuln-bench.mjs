#!/usr/bin/env node
// binary-vuln-bench.mjs — the Binary/RE loadout's decompiled-output vulnerability detector + benchmark.
//
// Ships a built-in ruleset for dangerous patterns in DECOMPILED / disassembled output (the pseudocode
// ghidra/radare2/objdump produce), and scores it against a committed corpus of decompiled-C fixtures
// with a known-vuln ground truth + safe controls.
//
// HONEST SCOPE: pattern detection over decompiled artifacts — surfaces *candidate* memory-safety /
// injection sinks. It is NOT full reverse-engineering (understanding/solving a binary) and NOT a pwn/
// exploit — those are the live ghidra/gdb path + the Cybench reversing track. Self-contained +
// deterministic: `--self-test` is the real run (no external tool, no binaries).
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CORPUS = path.join(HERE, '..', 'bench', 'binary-vulns', 'corpus.json');

const rx = (re) => (c) => re.test(c);

// Dangerous-pattern ruleset over decompiled/disassembled C-like pseudocode.
export const RULES = [
  { id: 'B-GETS', desc: 'gets() — unbounded stdin read (always unsafe)', test: rx(/\bgets\s*\(/) },
  { id: 'B-STRCPY', desc: 'strcpy() — unbounded copy into a fixed buffer', test: rx(/\bstrcpy\s*\(/) },
  { id: 'B-SPRINTF', desc: 'sprintf() — unbounded formatted write', test: rx(/\bsprintf\s*\(/) },
  { id: 'B-FORMAT-STRING', desc: 'printf(var) — user-controlled format string', test: rx(/\bf?printf\s*\(\s*[a-zA-Z_]\w*\s*\)/) },
  { id: 'B-CMD-INJECTION', desc: 'system()/popen() on a variable — command injection', test: rx(/\b(system|popen)\s*\(\s*[a-zA-Z_]\w*/) },
  { id: 'B-INT-OVERFLOW', desc: 'malloc/calloc with multiplication — integer-overflow alloc size', test: rx(/\b(malloc|calloc|alloca|realloc)\s*\([^)]*\*/) },
  // Inspects the length (3rd) arg: fires when it begins with a variable / field /
  // deref / decoded value (`len`, `hdr->len`, `ntohl(hdr->len)`) and stays silent
  // when it begins with a `sizeof` expression or a numeric literal. Two subtleties:
  // the `[^)\s]` after the lookahead is load-bearing — without it `\s*` backtracks
  // onto whitespace and bounded forms leak through; and args 1-2 are matched with a
  // single level of BALANCED parens `(?:[^,()]|\([^()]*\))+` so a cast `(void *)dst`
  // and a comma-bearing call `get(a,b)` are each consumed as ONE arg — neither
  // mis-splits the list (the original naive `[^,]+` split on the comma inside a
  // call and false-fired on a bounded length). Directional static pre-filter, not
  // taint analysis — disclosed misses (silently NOT flagged): a computed length
  // that starts with a digit (`8*count`) or with `sizeof` plus a term
  // (`sizeof(x)+n`), and a 1st/2nd arg with a DOUBLY-nested paren
  // (`wrap(get(a,b))`). The `__memcpy_chk`/`memcpy_s`/`wmemcpy` variants are out of
  // scope (the `\b...\(` shape); the `_chk` form is usually the bounded, safe one.
  // Comments aren't stripped: a mid-argument `/* ... */` obscuring a sizeof/literal
  // length would false-fire, but decompiled output does not emit inline comments.
  // Decompiled output inlines constants, so a named-macro length does not arise.
  { id: 'B-MEMCPY', desc: 'memcpy()/memmove() with a non-constant length — candidate overflow from an unchecked/wire-controlled size', test: rx(/\b(?:memcpy|memmove)\s*\((?:[^,()]|\([^()]*\))+,\s*(?:[^,()]|\([^()]*\))+,\s*(?!\d|sizeof\b)[^)\s][^)]*\)/) },
];

export function loadCorpus() {
  return JSON.parse(readFileSync(CORPUS, 'utf8'));
}

// Run the ruleset over one decompiled artifact → Set<rule-id>.
export function detect(content) {
  const hits = new Set();
  for (const r of RULES) if (r.test(content)) hits.add(r.id);
  return hits;
}

export function scoreCorpus(corpus, detectFn = detect) {
  const bad = corpus.fixtures.filter((f) => !f.clean);
  const controls = corpus.fixtures.filter((f) => f.clean);
  const perFixture = corpus.fixtures.map((f) => {
    const detected = [...detectFn(f.content)];
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
  console.log(`\n  detection:      ${d.hits}/${d.total} seeded sinks caught (${(100 * d.rate).toFixed(1)}%)`);
  console.log(`  discrimination: ${g.clean - g.falsePositives}/${g.clean} safe controls clean (${g.falsePositives} false-positive)`);
  for (const r of score.perFixture) {
    const mark = r.ok ? '✅' : '❌';
    const detail = r.clean ? (r.ok ? 'control clean' : `FALSE-POSITIVE: ${r.detected.join(',')}`)
      : (r.ok ? `caught ${r.expected.join('/')}` : `MISSED ${r.expected.join('/')} (got: ${r.detected.join(',') || 'nothing'})`);
    console.log(`    ${mark} ${r.id.padEnd(22)} ${detail}`);
  }
}

function runSelfTest() {
  const corpus = loadCorpus();
  const score = scoreCorpus(corpus);
  let pass = 0, fail = 0;
  const ok = (l, c) => (c ? (pass++, console.log('  ✅ ' + l)) : (fail++, console.log('  ❌ ' + l)));
  console.log('=== Binary/RE decompiled-vuln — DETECTOR REGRESSION CHECK (seeded corpus, deterministic) ===');
  ok('every seeded sink is detected (its expected rule fired)', score.detection.hits === score.detection.total);
  ok('every safe control is clean (zero false-positives — snprintf/strncpy/fgets not flagged)', score.discrimination.falsePositives === 0);
  ok('ruleset covers memory-safety + injection + integer-overflow classes', RULES.length >= 6);
  ok('every seeded fixture declares ground truth', corpus.fixtures.every((f) => f.clean || (f.expect || []).length > 0));
  report(score);
  console.log('\n  NOTE: seeded corpus — the ruleset was authored against these patterns, so a pass is a regression FLOOR (guards the detector from breaking), not a real-world detection rate.');
  console.log(`\n${fail === 0 ? '✅ ALL PASS' : '❌ ' + fail + ' FAILED'} — ${pass}/${pass + fail}\n`);
  process.exitCode = fail === 0 ? 0 : 1;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) runSelfTest();
