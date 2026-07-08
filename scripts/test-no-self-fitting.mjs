#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// test-no-self-fitting.mjs — the contamination wall for the immune memory.
//
// Sibling to test-no-fitting.mjs. The organism (lessons.mjs / docs/lessons.jsonl)
// is allowed to learn METHODOLOGY and INTEGRITY, never ANSWERS. This build-failing
// guard proves that:
//   1. every stored antibody is general methodology (0 answer-leaks), and
//   2. the prime-directive guard actually REJECTS a planted answer-lesson (canary),
//      a flag-shaped secret, and a challenge-id+answer pair — while still ACCEPTING
//      a general lesson.
// If a memorized answer ever sneaks into the lessons store, this fails the build —
// exactly as a self-fitting hackerbot must be stopped from learning to cheat.
// ─────────────────────────────────────────────────────────────────────────────
import { loadAllLessons, isAnswerLeak, recordFailure } from './lessons.mjs';

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.log('  ❌', name); } };

// (1) every stored antibody (curated seed + runtime auto-captured) must be general methodology
const store = loadAllLessons();
let leaks = 0;
for (const l of store) {
  const a = isAnswerLeak(`${l.signature || ''} ${l.lesson || ''} ${l.guard || ''}`);
  if (a.leak) { leaks++; console.log(`  ❌ ANSWER-LEAK in ${l.id}: ${a.why}`); }
}
ok(`all ${store.length} stored antibodies are general methodology (0 answer-leaks)`, leaks === 0);
ok('lessons store is non-empty (seeded from the integrity ledger)', store.length > 0);

// (2) the prime-directive guard must REJECT answers at write time
const c1 = []; const r1 = recordFailure(c1, { class: 'fitting', signature: 'planted canary', lesson: 'XBEN-018 the flag is CANARY_SELF_FIT_d34db33f' });
ok('canary answer-lesson is REJECTED at write time (no store mutation)', r1.rejected === true && c1.length === 0);

const c2 = []; const r2 = recordFailure(c2, { class: 'x', signature: 'wrapped secret', lesson: 'the recovered value is key{sup3r_s3cr3t_inner}' });
ok('flag-shaped secret is REJECTED', r2.rejected === true && c2.length === 0);

const c3 = []; const r3 = recordFailure(c3, { class: 'fitting', signature: 'per-challenge solution', lesson: 'XBEN-053 solution is: payload = "{{7*7}}"' });
ok('challenge-id + concrete answer is REJECTED', r3.rejected === true && c3.length === 0);

// (3) ...while a general methodological lesson is ACCEPTED
const c4 = []; const r4 = recordFailure(c4, { class: 'overclaim', signature: 'severity stated maximal narrow trigger', lesson: 're-verify reachability against the real source and current master before claiming severity' });
ok('a general methodology lesson is ACCEPTED', r4.ok === true && c4.length === 1 && !r4.rejected);

console.log(`\n${fail === 0 ? '✅ CLEAN — the immune memory holds only general methodology, no answers' : '❌ ' + fail + ' FAILED — possible self-fitting / answer-leak in the lessons store'}`);
process.exit(fail === 0 ? 0 : 1);
