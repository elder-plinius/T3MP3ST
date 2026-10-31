import { describe, it, expect } from 'vitest';
import { OpGeneral } from '../general/index.js';
import { createMockBackbone } from '../llm/index.js';

// Access to the private salvage helper — tested directly, it is a pure string->JSON function.
function salvage(raw: string): unknown | null {
  const g = new OpGeneral(createMockBackbone()) as unknown as {
    salvageTruncatedJson(raw: string): unknown | null;
  };
  return g.salvageTruncatedJson(raw);
}

describe('plan JSON truncation salvage', () => {
  it('salvages a plan cut off mid-array at maxTokens', () => {
    const truncated = '{"codename":"OPERATION NIGHT","summary":"cut off","targets":[{"address":"127.0.0.1","priority":1},{"address":"local-lab","pri';
    const json = salvage(truncated) as { codename?: string; targets?: unknown[] } | null;
    expect(json).not.toBeNull();
    expect(json?.codename).toBe('OPERATION NIGHT');
    expect(Array.isArray(json?.targets)).toBe(true);
    // the cut second entry survives as a partial-but-valid object (address kept, optional fields dropped)
    expect((json?.targets as unknown[]).length).toBe(2);
  });

  it('salvages a plan cut mid-string by dropping the dangling key', () => {
    const truncated = '{"codename":"OP X","summary":"done","rationale": "partial thought';
    const json = salvage(truncated) as { codename?: string; rationale?: unknown } | null;
    expect(json).not.toBeNull();
    expect(json?.codename).toBe('OP X');
    expect(json?.rationale).toBeUndefined();
  });

  it('respects string escapes while walking (no false cut inside \\" … )', () => {
    const raw = '{"codename":"OP \\"QUOTE\\"","summary":"kept","extra":"trunc';
    const json = salvage(raw) as { codename?: string } | null;
    expect(json?.codename).toBe('OP "QUOTE"');
  });

  it('returns null for prose with no JSON object at all', () => {
    expect(salvage('The plan is great, no object here.')).toBeNull();
  });

  it('never fires when a complete object parses (caller parses first anyway)', () => {
    const complete = '{"codename":"OP FULL","summary":"s"}';
    expect((salvage(complete) as { codename?: string }).codename).toBe('OP FULL');
  });
});
