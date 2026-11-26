/**
 * Refuse hunt-skill identifiers and say which of those classes the existing
 * signature engine already covers. This module does not load skill text.
 */

const COVERED_CLASSES = new Set(['xss', 'sqli', 'ssrf', 'lfi', 'ssti', 'xxe', 'cmdi']);
const HUNT_SLUG = /(?:^|[/\\:])hunt-([a-z0-9][a-z0-9-]*)/i;
const BUNDLE = /claude-bughunter/i;

export interface SkillAssessment {
  allowed: boolean;
  reason?: string;
  coveredByExistingSignatures: boolean;
  className?: string;
}

export function assessExternalSkill(identifier: string): SkillAssessment {
  const bundle = BUNDLE.exec(identifier);
  const hunt = HUNT_SLUG.exec(identifier);
  const className = hunt?.[1]?.toLowerCase();
  const covered = className ? COVERED_CLASSES.has(className) : false;
  if (bundle || hunt) {
    const token = hunt?.[0] ?? bundle?.[0] ?? identifier;
    return {
      allowed: false,
      reason: `refused external skill identifier ${token}`,
      coveredByExistingSignatures: covered,
      className,
    };
  }
  return { allowed: true, coveredByExistingSignatures: false };
}

export function huntClassCoverage(className: string): boolean {
  return COVERED_CLASSES.has(className.trim().toLowerCase());
}
