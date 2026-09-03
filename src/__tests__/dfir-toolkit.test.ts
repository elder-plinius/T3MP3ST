import { describe, expect, it, vi } from 'vitest';
import { createContainmentPreview, DfirToolkit, supportedDfirPlatforms, type ContainmentApproval, type DfirPlatform, type ReadOnlyCollector } from '../dfir/toolkit.js';

const collector = (platform: DfirPlatform = 'linux', collect = vi.fn(async () => [{ name: 'auth.log', source: '/var/log/auth.log', bytes: new TextEncoder().encode('synthetic log'), collectedAt: 100 }])): ReadOnlyCollector => ({ id: `collector-${platform}`, platform, collect });
const preview = () => createContainmentPreview({ caseId: 'case-1', targetId: 'host-1', actionId: 'isolate-network', summary: 'Remove host from incident VLAN', rollback: 'Restore the prior VLAN assignment', commands: ['inspect-current-vlan', 'apply-quarantine-vlan'] });
const approval = (digest: string, overrides: Partial<ContainmentApproval> = {}): ContainmentApproval => ({ receiptId: 'receipt-1', caseId: 'case-1', targetId: 'host-1', actionId: 'isolate-network', previewDigest: digest, approvedBy: 'operator-1', approvedAt: 90, expiresAt: 200, ...overrides });

describe('read-only evidence acquisition', () => {
  it('hashes evidence and emits complete redacted custody fields', async () => {
    const result = await new DfirToolkit(() => 110).acquire({ caseId: 'case-1', targetId: 'host-1', investigator: 'analyst-1', collector: collector(), metadata: { token: 'private', purpose: 'triage' } });
    expect(result.outcome).toBe('collected');
    expect(result.records[0]).toMatchObject({ caseId: 'case-1', targetId: 'host-1', source: '/var/log/auth.log', collectedAt: 100, receivedAt: 110, sizeBytes: 13, collector: 'collector-linux', transfer: 'in-process', verified: true, redactedMetadata: { token: '[redacted]', purpose: 'triage' } });
    expect(result.records[0].sha256).toMatch(/^[a-f0-9]{64}$/);
  });
  it('reports permission failure without fabricating custody records', async () => {
    const collect = vi.fn().mockRejectedValue(new Error('EACCES secret path'));
    await expect(new DfirToolkit().acquire({ caseId: 'case-1', targetId: 'host-1', investigator: 'analyst-1', collector: collector('linux', collect) })).resolves.toEqual({ outcome: 'permission-denied', records: [], error: 'permission-denied' });
  });
  it('preserves already collected records when cancellation occurs between artifacts', async () => {
    const controller = new AbortController();
    const collect = vi.fn(async () => [{ name: 'one', source: '/one', bytes: new Uint8Array([1]), collectedAt: 1 }, { get name() { controller.abort(); return 'two'; }, source: '/two', bytes: new Uint8Array([2]), collectedAt: 2 }]);
    const result = await new DfirToolkit().acquire({ caseId: 'case-1', targetId: 'host-1', investigator: 'analyst-1', collector: collector('linux', collect), signal: controller.signal });
    expect(result).toMatchObject({ outcome: 'cancelled' });
    expect(result.records).toHaveLength(1);
  });
  it('claims only platforms supplied by tested adapters', () => {
    expect(supportedDfirPlatforms([collector('linux'), collector('darwin'), collector('win32')])).toEqual(['linux', 'darwin', 'win32']);
    expect(supportedDfirPlatforms([collector('linux')])).toEqual(['linux']);
  });
});

describe('authorization-gated containment', () => {
  it('denies absent, expired, mismatched-target, and changed-preview approvals', async () => {
    const action = preview(); const executor = { execute: vi.fn() }; const toolkit = new DfirToolkit(() => 100);
    for (const receipt of [undefined, approval(action.digest, { expiresAt: 100 }), approval(action.digest, { targetId: 'other' }), approval('0'.repeat(64))]) {
      await expect(toolkit.contain(action, receipt, executor)).resolves.toMatchObject({ outcome: 'denied', completedSteps: 0, rollback: action.rollback });
    }
    expect(executor.execute).not.toHaveBeenCalled();
  });
  it('executes an exact approved preview and records success', async () => {
    const action = preview(); const executor = { execute: vi.fn().mockResolvedValue({ completedSteps: 2, totalSteps: 2 }) };
    await expect(new DfirToolkit(() => 100).contain(action, approval(action.digest), executor)).resolves.toMatchObject({ outcome: 'completed', completedSteps: 2, totalSteps: 2, rollback: action.rollback });
    expect(executor.execute).toHaveBeenCalledOnce();
  });
  it('records partial execution and rollback guidance', async () => {
    const action = preview(); const executor = { execute: vi.fn().mockResolvedValue({ completedSteps: 1, totalSteps: 2 }) };
    await expect(new DfirToolkit(() => 100).contain(action, approval(action.digest), executor)).resolves.toMatchObject({ outcome: 'partial', completedSteps: 1, error: 'partial-execution', rollback: 'Restore the prior VLAN assignment' });
  });
  it('does not invoke containment when already cancelled', async () => {
    const action = preview(); const controller = new AbortController(); controller.abort(); const executor = { execute: vi.fn() };
    await expect(new DfirToolkit(() => 100).contain(action, approval(action.digest), executor, controller.signal)).resolves.toMatchObject({ outcome: 'cancelled' });
    expect(executor.execute).not.toHaveBeenCalled();
  });
});
