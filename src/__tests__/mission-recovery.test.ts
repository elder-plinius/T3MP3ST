import { describe, expect, it, vi } from 'vitest';
import { MISSION_RECOVERY_SCHEMA, MissionRecoveryCoordinator, parseRecoverySnapshot, scoreExposure, type MissionRecoverySnapshot, type RecoveryStore } from '../mission/recovery.js';

const snapshot = (overrides: Partial<MissionRecoverySnapshot> = {}): MissionRecoverySnapshot => ({ schemaVersion: MISSION_RECOVERY_SCHEMA, missionId: 'mission-1', revision: 0, state: 'paused', savedAt: 1, actions: [{ id: 'action-1', idempotencyKey: 'mission-1:action-1', kind: 'probe', status: 'pending', attempts: 0, maxAttempts: 2 }], ...overrides });

function memoryStore(initial: unknown) {
  let value = structuredClone(initial);
  const store: RecoveryStore = {
    load: vi.fn(async () => structuredClone(value)),
    compareAndSwap: vi.fn(async (_id, revision, next) => {
      const current = parseRecoverySnapshot(value);
      if (!current || current.revision !== revision) return false;
      value = structuredClone(next); return true;
    }),
  };
  return { store, read: () => structuredClone(value) };
}

describe('mission recovery schema and fail-closed boundaries', () => {
  it('rejects corrupt, duplicate-key, and unknown-version state', async () => {
    expect(parseRecoverySnapshot({ ...snapshot(), schemaVersion: 'v99' })).toBeUndefined();
    expect(parseRecoverySnapshot({ ...snapshot(), actions: [snapshot().actions[0], { ...snapshot().actions[0], id: 'action-2' }] })).toBeUndefined();
    const executor = { execute: vi.fn() };
    await expect(new MissionRecoveryCoordinator(memoryStore('{bad').store).recover('mission-1', executor)).resolves.toEqual({ outcome: 'corrupt', executed: [] });
    expect(executor.execute).not.toHaveBeenCalled();
  });

  it('never replays an action left in progress at a crash boundary', async () => {
    const state = memoryStore(snapshot({ actions: [{ ...snapshot().actions[0], status: 'in_progress', attempts: 1 }] }));
    const executor = { execute: vi.fn() };
    const result = await new MissionRecoveryCoordinator(state.store, () => 2).recover('mission-1', executor);
    expect(result.outcome).toBe('blocked');
    expect(parseRecoverySnapshot(state.read())?.actions[0]).toMatchObject({ status: 'blocked', error: 'ambiguous-after-crash' });
    expect(executor.execute).not.toHaveBeenCalled();
  });

  it('claims with compare-and-swap and executes a pending action once', async () => {
    const state = memoryStore(snapshot());
    const executor = { execute: vi.fn().mockResolvedValue({ receiptId: 'receipt-1' }) };
    const result = await new MissionRecoveryCoordinator(state.store, () => 2).recover('mission-1', executor);
    expect(result).toMatchObject({ outcome: 'recovered', executed: ['action-1'] });
    expect(executor.execute).toHaveBeenCalledOnce();
    expect(parseRecoverySnapshot(state.read())?.actions[0]).toMatchObject({ status: 'completed', attempts: 1, receiptId: 'receipt-1' });
    await new MissionRecoveryCoordinator(state.store).recover('mission-1', executor);
    expect(executor.execute).toHaveBeenCalledOnce();
  });

  it('loses a concurrent claim without executing', async () => {
    const state = memoryStore(snapshot());
    vi.mocked(state.store.compareAndSwap).mockResolvedValueOnce(false);
    const executor = { execute: vi.fn() };
    await expect(new MissionRecoveryCoordinator(state.store).recover('mission-1', executor)).resolves.toEqual({ outcome: 'concurrent', executed: [] });
    expect(executor.execute).not.toHaveBeenCalled();
  });

  it('honors cancellation before execution and terminal states', async () => {
    const controller = new AbortController(); controller.abort();
    const executor = { execute: vi.fn() };
    await expect(new MissionRecoveryCoordinator(memoryStore(snapshot()).store).recover('mission-1', executor, controller.signal)).resolves.toMatchObject({ outcome: 'cancelled' });
    await expect(new MissionRecoveryCoordinator(memoryStore(snapshot({ state: 'completed' })).store).recover('mission-1', executor)).resolves.toMatchObject({ outcome: 'terminal' });
    expect(executor.execute).not.toHaveBeenCalled();
  });

  it('bounds explicit retries and keeps status observational', async () => {
    const failed = snapshot({ actions: [{ ...snapshot().actions[0], status: 'failed', attempts: 1 }] });
    const state = memoryStore(failed);
    const coordinator = new MissionRecoveryCoordinator(state.store);
    const before = state.read();
    await expect(coordinator.status('mission-1')).resolves.toEqual(failed);
    expect(state.read()).toEqual(before);
    await expect(coordinator.retry('mission-1', 'action-1')).resolves.toBe(true);
    expect(parseRecoverySnapshot(state.read())?.actions[0].status).toBe('pending');
  });
});

describe('contextual exposure scoring', () => {
  it('documents weighting through deterministic score, confidence, and unknowns', () => {
    expect(scoreExposure({ internetExposure: { value: 1, confidence: 1 }, exploitableFinding: { value: 0.5, confidence: 0.8 }, credentialExposure: { value: 0, confidence: 1 } })).toEqual({ score: 53, confidence: 0.79, coverage: 0.85, disposition: 'scored', unknown: ['businessCriticality'] });
  });
  it('does not turn insufficient unknown data into a low score', () => {
    expect(scoreExposure({ businessCriticality: { value: 1, confidence: 1 } })).toEqual({ confidence: 0.15, coverage: 0.15, disposition: 'insufficient-data', unknown: ['internetExposure', 'exploitableFinding', 'credentialExposure'] });
  });
});
