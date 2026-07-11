/**
 * Locks the Cloud loadout's IaC-misconfig benchmark scorer into CI: the parser must map checkov
 * findings to fixtures, every seeded misconfig must be detected, and the locked-down control must
 * produce zero misconfig false-positives — validated against the committed sample (no checkov needed).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
// The benchmark logic is authored in the bench script (ESM .mjs); import its pure functions directly.
import { loadCorpus, parseCheckov, scoreCorpus } from '../../scripts/cloud-misconfig-bench.mjs';

const sample = JSON.parse(readFileSync(join(process.cwd(), 'bench/cloud-misconfig/sample-checkov-output.json'), 'utf8'));

describe('cloud IaC-misconfig benchmark scorer', () => {
  const corpus = loadCorpus();
  const score = scoreCorpus(corpus, parseCheckov(sample));

  it('the corpus has misconfigured fixtures + a clean control, all with ground truth', () => {
    expect(corpus.fixtures.length).toBeGreaterThanOrEqual(5);
    expect(corpus.fixtures.some((f: { clean?: boolean }) => f.clean)).toBe(true);
    expect((corpus.target_checks || []).length).toBeGreaterThan(0);
  });

  it('detects every seeded misconfiguration on the committed sample', () => {
    expect(score.detection.hits).toBe(score.detection.total);
    expect(score.detection.total).toBeGreaterThanOrEqual(5);
  });

  it('does not false-positive on the locked-down control', () => {
    expect(score.discrimination.falsePositives).toBe(0);
  });

  it('parser is tolerant of checkov multi-framework (array) output', () => {
    const asArray = parseCheckov([sample]);
    expect(Object.keys(asArray).length).toBe(Object.keys(parseCheckov(sample)).length);
  });
});
