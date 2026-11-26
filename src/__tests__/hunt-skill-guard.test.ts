import { describe, expect, it } from 'vitest';
import { assessExternalSkill, huntClassCoverage } from '../detection/hunt-skill-guard.js';

describe('hunt-skill guard', () => {
  it('refuses hunt-ssrf and marks the class covered', () => {
    expect(assessExternalSkill('hunt-ssrf')).toMatchObject({
      allowed: false,
      coveredByExistingSignatures: true,
      className: 'ssrf',
    });
  });

  it('refuses a hunt-oauth path and marks the class uncovered', () => {
    const result = assessExternalSkill('skills/hunt-oauth/SKILL.md');
    expect(result.allowed).toBe(false);
    expect(result.coveredByExistingSignatures).toBe(false);
    expect(result.className).toBe('oauth');
  });

  it('refuses the bughunter bundle even when the class is covered', () => {
    expect(assessExternalSkill('claude-bughunter:hunt-xss')).toMatchObject({
      allowed: false,
      coveredByExistingSignatures: true,
      className: 'xss',
    });
  });

  it('allows an ordinary skill id', () => {
    expect(assessExternalSkill('web-recon')).toEqual({
      allowed: true,
      coveredByExistingSignatures: false,
    });
  });

  it('reports class coverage without loading a skill', () => {
    expect(huntClassCoverage('xss')).toBe(true);
    expect(huntClassCoverage('not-a-class')).toBe(false);
  });
});
