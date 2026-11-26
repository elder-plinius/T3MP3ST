import { describe, expect, it } from 'vitest';
import { quoteMatches } from '../evidence/quote-gate.js';
import type { Evidence } from '../types/index.js';

function evidence(type: Evidence['type'], content: string): Evidence {
  return { type, content, timestamp: 1 };
}

describe('quote gate', () => {
  const body = [evidence('output', 'hello marker-alpha world')];

  it('passes when the quote sits in tool evidence', () => {
    expect(quoteMatches(body, 'marker-alpha').passed).toBe(true);
  });

  it('fails when the quote is absent', () => {
    const result = quoteMatches(body, 'marker-beta');
    expect(result.passed).toBe(false);
  });

  it('fails a quote shorter than 8 characters', () => {
    expect(quoteMatches([evidence('output', 'shortly')], 'short').passed).toBe(false);
  });

  it('ignores a screenshot that contains the quote', () => {
    expect(quoteMatches([evidence('screenshot', 'marker-alpha lives here')], 'marker-alpha').passed).toBe(false);
  });

  it('fails an empty quote', () => {
    expect(quoteMatches(body, '').reasons.join(' ')).toMatch(/missing verbatim quote/);
  });
});
