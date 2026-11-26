import { describe, it, expect } from 'vitest';
import { createOperator } from '../operators/index.js';
import type { Finding } from '../types/index.js';

// ─────────────────────────────────────────────────────────────────────────────
// HONESTY SPINE — LOAD-BEARING IN THE LIVE PATH.
//
// The provenance gate (gateLiveFinding) must run where findings are CREATED, not as
// an opt-in verifyFinding(id) call nothing invokes. This test pins that invariant to
// the operator's recordFinding chokepoint — the same path executeTask() uses to record
// every agent finding. A model-asserted finding (no tool evidence) must be recorded
// UNVERIFIED; a tool-backed finding must verify. If this regresses, a model can assert a
// "critical" into the record for free again — the exact failure the whole project prevents.
// ─────────────────────────────────────────────────────────────────────────────

function baseFinding(over: Partial<Finding>): Finding {
  return {
    id: '',
    title: 'x',
    description: 'x',
    severity: 'high',
    targetId: 't',
    operatorId: 'o',
    phase: 'exploitation',
    evidence: [],
    discoveredAt: Date.now(),
    ...over,
  } as Finding;
}

describe('honesty spine is load-bearing at finding creation (operator.recordFinding)', () => {
  it('a model-asserted finding (no tool evidence) is recorded UNVERIFIED with gate reasons', () => {
    const op = createOperator('test-recon', 'recon');
    let blocked: { reasons: string[] } | undefined;
    op.on('finding:gate-blocked', (e) => { blocked = e; });

    const f = baseFinding({ title: 'model says critical', severity: 'critical', evidence: [] });
    op.recordFinding(f, '');

    expect(f.verifyGate?.passed).toBe(false);
    expect(f.verifiedAt).toBeUndefined();
    expect(f.verifyGate?.provenance).toBe('none');
    expect(blocked, 'a gate-blocked event must fire for an unbacked finding').toBeDefined();
    if (!blocked) {
      throw new Error('expected gate-blocked event');
    }
    expect(blocked.reasons.join(' ')).toMatch(/provenance|evidence/i);
  });

  it('a tool-backed finding (real tool-output evidence) verifies', () => {
    const op = createOperator('test-recon2', 'recon');
    const f = baseFinding({
      title: 'nmap found open port',
      severity: 'high',
      evidence: [{ type: 'output', content: 'PORT 22/tcp open ssh\n...real nmap output...', timestamp: Date.now() }],
    });
    op.recordFinding(f, 'PORT 22/tcp open ssh');

    expect(f.verifyGate?.passed).toBe(true);
    expect(f.verifyGate?.provenance).toBe('tool');
    expect(f.verifiedAt).toBeTypeOf('number');
  });

  it('getVerified-style filter only surfaces gate-passed findings', () => {
    const op = createOperator('test-recon3', 'recon');
    op.recordFinding(baseFinding({ title: 'prose claim', evidence: [] }), '');
    const toolOut = 'x'.repeat(20);
    op.recordFinding(baseFinding({ title: 'tool claim', evidence: [{ type: 'output', content: toolOut, timestamp: Date.now() }] }), toolOut);
    const verified = op.getFindings().filter((f) => f.verifyGate?.passed);
    expect(verified.map((f) => f.title)).toEqual(['tool claim']);
  });
});
