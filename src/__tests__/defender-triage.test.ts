import { describe, expect, it } from 'vitest';
import { defenderTriage } from '../governance/defender-triage.js';
import type { Evidence } from '../types/index.js';

function output(content: string): Evidence {
  return { type: 'output', content, timestamp: 1 };
}

const good = {
  evidence: [output('hello marker-alpha world')],
  quote: 'marker-alpha',
  scope: ['app.example'],
  targetName: 'app.example',
  impactAccepted: true,
};

describe('defender triage', () => {
  it('passes all five questions when the claim is in scope and quoted', () => {
    const result = defenderTriage(good);
    expect(result.passed).toBe(true);
    expect(result.questions).toHaveLength(5);
    expect(result.questions.every((question) => question.passed)).toBe(true);
  });

  it('fails scope for a target outside the scope list and still returns five questions', () => {
    const result = defenderTriage({ ...good, targetName: 'evil.example' });
    expect(result.passed).toBe(false);
    expect(result.questions.find((question) => question.id === 'scope')?.passed).toBe(false);
    expect(result.questions).toHaveLength(5);
  });

  it('fails PII when authorization text is in tool evidence', () => {
    const result = defenderTriage({ ...good, evidence: [output('Authorization: secret marker-alpha')] });
    expect(result.questions.find((question) => question.id === 'pii')?.passed).toBe(false);
  });

  it('fails PII when only a second tool item carries a cookie marker', () => {
    const result = defenderTriage({
      ...good,
      evidence: [output('hello marker-alpha world'), output('cookie: session')],
    });
    expect(result.questions.find((question) => question.id === 'pii')?.passed).toBe(false);
  });

  it('fails the evidence question when there is no tool evidence and runs no tool', () => {
    const result = defenderTriage({ ...good, evidence: [], quote: 'marker-alpha' });
    expect(result.questions.find((question) => question.id === 'evidence')?.passed).toBe(false);
    expect(result.passed).toBe(false);
  });
});
