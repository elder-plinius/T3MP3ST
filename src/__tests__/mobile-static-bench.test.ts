/**
 * Locks the Mobile loadout's static-analysis detector + benchmark into CI: the built-in ruleset must
 * catch every seeded manifest-misconfig / hardcoded-secret in the corpus and stay clean on the hardened
 * controls. Deterministic + self-contained (no external tool).
 */
import { describe, it, expect } from 'vitest';
import { loadCorpus, detect, scoreCorpus, RULES } from '../../scripts/mobile-static-bench.mjs';

describe('mobile static-analysis benchmark', () => {
  const corpus = loadCorpus();
  const score = scoreCorpus(corpus);

  it('corpus has seeded fixtures + hardened controls with ground truth', () => {
    expect(corpus.fixtures.length).toBeGreaterThanOrEqual(6);
    expect(corpus.fixtures.some((f) => f.clean)).toBe(true);
    expect(corpus.fixtures.every((f) => f.clean || f.expect.length > 0)).toBe(true);
  });

  it('detects every seeded manifest/secret issue', () => {
    expect(score.detection.hits).toBe(score.detection.total);
    expect(score.detection.total).toBeGreaterThanOrEqual(6);
  });

  it('does not false-positive on hardened controls', () => {
    expect(score.discrimination.falsePositives).toBe(0);
  });

  it('ruleset spans manifest misconfig + hardcoded secrets, kind-scoped', () => {
    expect(detect('android:debuggable="true"', 'manifest').has('M-DEBUGGABLE')).toBe(true);
    expect(detect('String k = "AKIAIOSFODNN7EXAMPLE";', 'code').has('S-AWS-KEY')).toBe(true);
    // a manifest xmlns http:// must NOT trip the code-only cleartext-endpoint rule
    expect(detect('xmlns:android="http://schemas.android.com/apk/res/android"', 'manifest').has('E-HTTP-URL')).toBe(false);
    expect(RULES.length).toBeGreaterThanOrEqual(6);
  });
});
