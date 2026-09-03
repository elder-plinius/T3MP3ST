import { describe, expect, it, vi } from 'vitest';
import { Arsenal } from '../arsenal/index.js';
import { ArsenalRetestProbe, FindingRetestWorkflow, type ProbeObservation, type RetestRequest } from '../evidence/retest.js';
import type { Evidence, Finding, Target } from '../types/index.js';

const finding = { id: 'finding-1', title: 'Example CVE', description: 'candidate', severity: 'high', targetId: 'target-1', operatorId: 'op-1', phase: 'exploitation', cve: ['CVE-2026-1234'], evidence: [], discoveredAt: 1 } as Finding;
const target = { id: 'target-1', name: 'lab', type: 'web_application', address: 'lab.example' } as Target;
const request = (overrides: Partial<RetestRequest> = {}): RetestRequest => ({ requestId: 'request-1', finding, target, toolName: 'probe', arguments: { url: 'https://lab.example' }, timeoutMs: 200, maxAttempts: 2, ...overrides });
const evidence = (content = 'HTTP 200 with vulnerable marker'): Evidence[] => [{ type: 'response', content, timestamp: 10, metadata: { source: 'probe' } }];
const observation = (disposition: ProbeObservation['disposition'], withEvidence = true): ProbeObservation => ({ disposition, evidence: withEvidence ? evidence() : [], result: { success: true, output: 'probe complete' } });

describe('evidence-honest finding retest', () => {
  it.each([
    ['present', true, 'still_vulnerable'],
    ['absent', true, 'fixed'],
    ['inconclusive', true, 'unverifiable'],
    ['present', false, 'unverifiable'],
    ['absent', false, 'unverifiable'],
  ] as const)('maps %s with evidence=%s to %s', async (disposition, backed, status) => {
    const workflow = new FindingRetestWorkflow({ run: vi.fn().mockResolvedValue(observation(disposition, backed)) }, () => 100);
    await expect(workflow.run(request())).resolves.toMatchObject({ status, findingId: finding.id, cve: ['CVE-2026-1234'], provenance: { source: 'authorized-tool-retest' } });
  });

  it('never interprets an empty successful scan as fixed', async () => {
    const workflow = new FindingRetestWorkflow({ run: vi.fn().mockResolvedValue({ disposition: 'inconclusive', evidence: [], result: { success: true, findings: [] } }) });
    await expect(workflow.run(request())).resolves.toHaveProperty('status', 'unverifiable');
  });

  it('rejects target substitution and non-CVE findings before probing', async () => {
    const run = vi.fn();
    const workflow = new FindingRetestWorkflow({ run });
    await expect(workflow.run(request({ target: { ...target, id: 'other' } }))).rejects.toThrow('must match');
    await expect(workflow.run(request({ requestId: 'no-cve', finding: { ...finding, cve: [] } }))).rejects.toThrow('valid CVE');
    expect(run).not.toHaveBeenCalled();
  });

  it('retries explicit partial failures and preserves every attempt', async () => {
    const run = vi.fn()
      .mockResolvedValueOnce({ ...observation('inconclusive'), retryable: true, result: { success: false, error: 'partial response' } })
      .mockResolvedValueOnce(observation('present'));
    const result = await new FindingRetestWorkflow({ run }, () => 100).run(request());
    expect(run).toHaveBeenCalledTimes(2);
    expect(result).toMatchObject({ status: 'still_vulnerable', attempts: [{ disposition: 'inconclusive', error: 'partial response' }, { disposition: 'present' }] });
  });

  it('returns the same promise/result for an idempotent request and rejects key reuse', async () => {
    const run = vi.fn().mockResolvedValue(observation('present'));
    const workflow = new FindingRetestWorkflow({ run });
    const first = workflow.run(request());
    const second = workflow.run(request());
    expect(second).toBe(first);
    expect((await second).id).toBe((await first).id);
    expect(run).toHaveBeenCalledTimes(1);
    await expect(workflow.run(request({ toolName: 'different' }))).rejects.toThrow('different retest');
  });

  it('times out, exhausts retries, and remains unverifiable', async () => {
    vi.useFakeTimers();
    const run = vi.fn((_request: RetestRequest, signal: AbortSignal) => new Promise<ProbeObservation>((_resolve, reject) => signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true })));
    const promise = new FindingRetestWorkflow({ run }).run(request({ timeoutMs: 100, maxAttempts: 2 }));
    await vi.advanceTimersByTimeAsync(250);
    const result = await promise;
    expect(run).toHaveBeenCalledTimes(2);
    expect(result.status).toBe('unverifiable');
    expect(result.attempts.every((attempt) => attempt.error === 'Retest timed out')).toBe(true);
    vi.useRealTimers();
  });

  it('honors cancellation without retrying or changing finding state', async () => {
    const controller = new AbortController();
    controller.abort();
    const run = vi.fn();
    const result = await new FindingRetestWorkflow({ run }).run(request({ signal: controller.signal, maxAttempts: 5 }));
    expect(run).not.toHaveBeenCalled();
    expect(result).toMatchObject({ status: 'unverifiable', attempts: [{ error: 'Retest cancelled' }] });
    expect(finding).not.toHaveProperty('retestStatus');
  });

  it('isolates sweep failures through unverifiable records', async () => {
    const probe = { run: vi.fn().mockRejectedValueOnce(new Error('network down')).mockResolvedValueOnce(observation('present')) };
    const results = await new FindingRetestWorkflow(probe).sweep([request({ requestId: 'a', maxAttempts: 1 }), request({ requestId: 'b' })]);
    expect(results.map(({ status }) => status)).toEqual(['unverifiable', 'still_vulnerable']);
  });
});

describe('Arsenal retest adapter', () => {
  it('refuses execution without an explicit scope', async () => {
    const arsenal = new Arsenal();
    const probe = new ArsenalRetestProbe(arsenal, () => observation('present'));
    await expect(probe.run(request(), new AbortController().signal)).rejects.toThrow('explicit Arsenal scope');
  });

  it('delegates to Arsenal so out-of-scope probes fail before the handler', async () => {
    const arsenal = new Arsenal();
    const handler = vi.fn().mockResolvedValue({ success: true, output: 'hit' });
    arsenal.register({ name: 'probe', description: 'probe', category: 'web', parameters: [], handler });
    arsenal.setScope({ allowedHosts: ['lab.example'], allowLoopback: false, allowPrivate: false });
    const probe = new ArsenalRetestProbe(arsenal, (result) => ({ disposition: 'inconclusive', evidence: [], result }));
    const result = await probe.run(request({ arguments: { url: 'https://outside.example' } }), new AbortController().signal);
    expect(result.result.error).toContain('SCOPE DENIED');
    expect(handler).not.toHaveBeenCalled();
  });

  it('refuses a cancelled request before Arsenal execution', async () => {
    const arsenal = new Arsenal();
    arsenal.setScope({ allowedHosts: ['lab.example'], allowLoopback: false, allowPrivate: false });
    const controller = new AbortController();
    controller.abort();
    const probe = new ArsenalRetestProbe(arsenal, () => observation('present'));
    await expect(probe.run(request(), controller.signal)).rejects.toMatchObject({ name: 'AbortError' });
  });
});
