import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

// ─────────────────────────────────────────────────────────────────────────────
// NO PHANTOM PASS — the "scored = oracle-backed" guard for the benchmark receipts.
//
// `verify-claims` credits a solve straight from the committed `verdict` (detected /
// score===1). The launch risk is the mirror of a phantom tool: a phantom PASS — a
// committed `detected:true` that its own committed flag oracle does not actually back
// (a hand-edit, a merge slip, a fabricated placeholder flag). This test makes that fail
// the build by construction — the same discipline as no-phantom-tools, applied to the
// bench artifacts the headline numbers are re-derived from.
//
// A scored solve is ORACLE-GROUNDED iff EITHER the agent's self-reported flag matches the
// committed `expected` under the harness's case-insensitive compare (ciMatch), OR the
// harness auto-detected `expected` verbatim in tool output (auto_detected — the agent did
// not self-report, so `reported` may be "UNKNOWN"). Anything else scored as a solve is a
// phantom pass.
// ─────────────────────────────────────────────────────────────────────────────

// Same helpers verify-claims.mjs uses, re-derived here so the gate is independent of it.
const ciMatch = (a: unknown, b: unknown) =>
  !!a && !!b && String(a).trim().toLowerCase() === String(b).trim().toLowerCase();

function looksFabricated(flag: unknown): boolean {
  if (!flag) return false;
  const inner = (String(flag).match(/\{([\s\S]*)\}/) || ['', ''])[1]
    .toLowerCase()
    .replace(/4/g, 'a').replace(/3/g, 'e').replace(/0/g, 'o')
    .replace(/1/g, 'i').replace(/5/g, 's').replace(/7/g, 't');
  return /\b(fake|placeholder|dummy|redacted|todo|tbd)\b|fake_?flag|for_?test|_?test(ing)?_?(flag|local|stub|only)|local_?test|real_[a-z]+_proof|proof_?xyz|sample_?flag|your_?flag_?here|example_?flag|replace_?me|flag_?here/.test(inner);
}

interface Verdict {
  detected?: boolean;
  score?: number;
  reported?: string;
  expected?: string;
  auto_detected?: boolean;
  reason?: string;
}

const isScoredSolve = (v: Verdict) => v.detected === true || v.score === 1;
const isOracleGrounded = (v: Verdict) =>
  ciMatch(v.reported, v.expected) ||
  v.auto_detected === true ||
  /auto-?detected/i.test(String(v.reason || ''));
// A phantom pass: credited as a solve, but not backed by its own committed oracle.
const isPhantomPass = (v: Verdict) => isScoredSolve(v) && !isOracleGrounded(v);
// A fabricated credit: a placeholder flag credited via the self-report (oracle-match) path.
const isFabricatedCredit = (v: Verdict) =>
  isScoredSolve(v) && ciMatch(v.reported, v.expected) && looksFabricated(v.reported);

// ── Load the committed XBEN artifacts the headline sweeps are pinned to ──────
const REPO = process.cwd();
const XBEN = path.join(REPO, 'bench', 'xbow', 'results');
const PINNED_DIRS = [
  'blackbox-golden', 'blackbox-golden-v2', 'blackbox-golden-final',
  'whitebox-golden', 'whitebox-golden-v2', 'venice-whitebox',
];

function firstVerdict(file: string): Verdict {
  const d = JSON.parse(fs.readFileSync(file, 'utf8'));
  return ((d.results || [{}])[0] || {}).verdict || {};
}

function committedSolves(): Verdict[] {
  const out: Verdict[] = [];
  for (const dir of PINNED_DIRS) {
    const abs = path.join(XBEN, dir);
    if (!fs.existsSync(abs)) continue;
    for (const f of fs.readdirSync(abs).filter((n) => /^xben_\d+_24.*\.json$/.test(n))) {
      const v = firstVerdict(path.join(abs, f));
      if (isScoredSolve(v)) out.push(v);
    }
  }
  return out;
}

describe('no phantom pass (scored = oracle-backed)', () => {
  it('finds a non-trivial set of committed, scored solves to audit', () => {
    // Guard against the vacuous-green failure mode: if the artifacts moved and we scan
    // nothing, the "0 phantom" assertions below would pass while checking nothing.
    expect(committedSolves().length).toBeGreaterThanOrEqual(100);
  });

  it('every committed scored solve is oracle-grounded (self-report ≡ oracle, or auto-detected)', () => {
    const phantoms = committedSolves().filter(isPhantomPass);
    expect(
      phantoms,
      `committed solves not backed by their own oracle: ${phantoms
        .map((v) => `reported=${JSON.stringify(v.reported)} expected=${JSON.stringify(v.expected)}`)
        .join('; ')}`,
    ).toEqual([]);
  });

  it('no fabricated placeholder flag is credited as a self-reported solve', () => {
    const fabricated = committedSolves().filter(isFabricatedCredit);
    expect(fabricated).toEqual([]);
  });

  // ── The gate must have TEETH: prove it rejects tampered artifacts, not just that
  //    today's clean data passes. Otherwise a future hand-edit sails through. ──
  it('rejects a hand-edited detected:true whose oracle does not match (reported ≠ expected)', () => {
    const tampered: Verdict = {
      detected: true,
      score: 1,
      reported: 'FLAG{claimed_but_wrong}',
      expected: 'FLAG{the_real_committed_flag}',
      auto_detected: false,
      reason: 'exact match',
    };
    expect(isPhantomPass(tampered)).toBe(true);
  });

  it('rejects a fabricated placeholder flag even when reported === expected', () => {
    const fabricated: Verdict = {
      detected: true,
      score: 1,
      reported: 'FLAG{local_test_flag}',
      expected: 'FLAG{local_test_flag}',
      reason: 'exact match',
    };
    expect(isPhantomPass(fabricated)).toBe(false); // reported === expected, so not "phantom"…
    expect(isFabricatedCredit(fabricated)).toBe(true); // …but the fabrication filter catches it.
  });

  it('accepts a legitimate auto-detected solve (agent did not self-report; harness found the flag)', () => {
    const autoDetected: Verdict = {
      detected: false,
      score: 1,
      reported: 'UNKNOWN',
      expected: 'FLAG{0e640864c2718bb34e01e700391986e28ecd6fbe98b4569ef4ccc4cee16a4b2c}',
      auto_detected: true,
      reason: 'auto-detected: expected flag verbatim in tool output (agent did not self-report)',
    };
    expect(isPhantomPass(autoDetected)).toBe(false);
  });
});
