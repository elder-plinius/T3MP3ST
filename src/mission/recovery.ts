export const MISSION_RECOVERY_SCHEMA = 't3mp3st_mission_recovery/v1' as const;
export type RecoveryActionStatus = 'pending' | 'in_progress' | 'completed' | 'failed' | 'cancelled' | 'blocked';

export interface RecoveryAction {
  id: string;
  idempotencyKey: string;
  kind: string;
  status: RecoveryActionStatus;
  attempts: number;
  maxAttempts: number;
  receiptId?: string;
  error?: string;
}

export interface MissionRecoverySnapshot {
  schemaVersion: typeof MISSION_RECOVERY_SCHEMA;
  missionId: string;
  revision: number;
  state: 'paused' | 'active' | 'completed' | 'aborted' | 'cancelled';
  savedAt: number;
  actions: RecoveryAction[];
}

export interface RecoveryStore {
  load(missionId: string): Promise<unknown>;
  compareAndSwap(missionId: string, expectedRevision: number, snapshot: MissionRecoverySnapshot): Promise<boolean>;
}

export interface RecoveryExecutor {
  execute(action: Readonly<RecoveryAction>, signal?: AbortSignal): Promise<{ receiptId: string }>;
}

export type RecoveryResult =
  | { outcome: 'recovered'; snapshot: MissionRecoverySnapshot; executed: string[] }
  | { outcome: 'terminal' | 'corrupt' | 'concurrent' | 'cancelled' | 'blocked'; snapshot?: MissionRecoverySnapshot; executed: string[] };

const idPattern = /^[a-zA-Z0-9_.:-]{1,128}$/;
const actionStates = new Set<RecoveryActionStatus>(['pending', 'in_progress', 'completed', 'failed', 'cancelled', 'blocked']);
const missionStates = new Set<MissionRecoverySnapshot['state']>(['paused', 'active', 'completed', 'aborted', 'cancelled']);

export function parseRecoverySnapshot(value: unknown): MissionRecoverySnapshot | undefined {
  if (!value || typeof value !== 'object') return undefined;
  const v = value as Record<string, unknown>;
  if (v.schemaVersion !== MISSION_RECOVERY_SCHEMA || typeof v.missionId !== 'string' || !idPattern.test(v.missionId)
    || !Number.isInteger(v.revision) || Number(v.revision) < 0 || !Number.isFinite(v.savedAt)
    || !missionStates.has(v.state as MissionRecoverySnapshot['state']) || !Array.isArray(v.actions)) return undefined;
  const keys = new Set<string>();
  const actions: RecoveryAction[] = [];
  for (const raw of v.actions) {
    if (!raw || typeof raw !== 'object') return undefined;
    const action = raw as Record<string, unknown>;
    if (typeof action.id !== 'string' || !idPattern.test(action.id) || typeof action.idempotencyKey !== 'string' || !idPattern.test(action.idempotencyKey)
      || keys.has(action.idempotencyKey) || typeof action.kind !== 'string' || !idPattern.test(action.kind)
      || !actionStates.has(action.status as RecoveryActionStatus) || !Number.isInteger(action.attempts) || Number(action.attempts) < 0
      || !Number.isInteger(action.maxAttempts) || Number(action.maxAttempts) < 1 || Number(action.maxAttempts) > 10
      || Number(action.attempts) > Number(action.maxAttempts)) return undefined;
    keys.add(action.idempotencyKey);
    actions.push(structuredClone(raw) as RecoveryAction);
  }
  return { schemaVersion: MISSION_RECOVERY_SCHEMA, missionId: v.missionId, revision: Number(v.revision), state: v.state as MissionRecoverySnapshot['state'], savedAt: Number(v.savedAt), actions };
}

export class MissionRecoveryCoordinator {
  constructor(private readonly store: RecoveryStore, private readonly now: () => number = Date.now) {}

  async status(missionId: string): Promise<MissionRecoverySnapshot | undefined> {
    return parseRecoverySnapshot(await this.store.load(missionId));
  }

  async recover(missionId: string, executor: RecoveryExecutor, signal?: AbortSignal): Promise<RecoveryResult> {
    const snapshot = parseRecoverySnapshot(await this.store.load(missionId));
    if (!snapshot) return { outcome: 'corrupt', executed: [] };
    if (['completed', 'aborted', 'cancelled'].includes(snapshot.state)) return { outcome: 'terminal', snapshot, executed: [] };
    if (snapshot.actions.some(action => action.status === 'in_progress')) {
      const blocked = this.next(snapshot, snapshot.actions.map(action => action.status === 'in_progress' ? { ...action, status: 'blocked' as const, error: 'ambiguous-after-crash' } : action), 'paused');
      if (!await this.store.compareAndSwap(missionId, snapshot.revision, blocked)) return { outcome: 'concurrent', executed: [] };
      return { outcome: 'blocked', snapshot: blocked, executed: [] };
    }
    if (signal?.aborted) return { outcome: 'cancelled', snapshot, executed: [] };
    const pending = snapshot.actions.find(action => action.status === 'pending');
    if (!pending) return { outcome: 'recovered', snapshot, executed: [] };

    const claimed = this.next(snapshot, snapshot.actions.map(action => action.id === pending.id ? { ...action, status: 'in_progress' as const, attempts: action.attempts + 1 } : action), 'paused');
    if (!await this.store.compareAndSwap(missionId, snapshot.revision, claimed)) return { outcome: 'concurrent', executed: [] };
    if (signal?.aborted) {
      const cancelled = this.next(claimed, claimed.actions.map(action => action.id === pending.id ? { ...action, status: 'cancelled' as const } : action), 'cancelled');
      await this.store.compareAndSwap(missionId, claimed.revision, cancelled);
      return { outcome: 'cancelled', snapshot: cancelled, executed: [] };
    }
    try {
      const receipt = await executor.execute(Object.freeze(structuredClone(pending)), signal);
      if (!idPattern.test(receipt.receiptId)) throw new Error('invalid-receipt');
      const completed = this.next(claimed, claimed.actions.map(action => action.id === pending.id ? { ...action, status: 'completed' as const, receiptId: receipt.receiptId, error: undefined } : action), 'paused');
      if (!await this.store.compareAndSwap(missionId, claimed.revision, completed)) return { outcome: 'concurrent', executed: [pending.id] };
      return { outcome: 'recovered', snapshot: completed, executed: [pending.id] };
    } catch {
      const failed = this.next(claimed, claimed.actions.map(action => action.id === pending.id ? { ...action, status: action.attempts >= action.maxAttempts ? 'blocked' as const : 'failed' as const, error: 'execution-failed' } : action), 'paused');
      await this.store.compareAndSwap(missionId, claimed.revision, failed);
      return { outcome: failed.actions.find(action => action.id === pending.id)?.status === 'blocked' ? 'blocked' : 'recovered', snapshot: failed, executed: [pending.id] };
    }
  }

  async retry(missionId: string, actionId: string): Promise<boolean> {
    const snapshot = parseRecoverySnapshot(await this.store.load(missionId));
    if (!snapshot || snapshot.state !== 'paused') return false;
    const action = snapshot.actions.find(item => item.id === actionId);
    if (!action || action.status !== 'failed' || action.attempts >= action.maxAttempts) return false;
    return this.store.compareAndSwap(missionId, snapshot.revision, this.next(snapshot, snapshot.actions.map(item => item.id === actionId ? { ...item, status: 'pending' as const, error: undefined } : item), 'paused'));
  }

  private next(snapshot: MissionRecoverySnapshot, actions: RecoveryAction[], state: MissionRecoverySnapshot['state']): MissionRecoverySnapshot {
    return { ...snapshot, revision: snapshot.revision + 1, savedAt: this.now(), state, actions };
  }
}

export interface ExposureSignal { value?: number; confidence?: number }
export interface ExposureScore {
  score?: number;
  confidence: number;
  coverage: number;
  disposition: 'scored' | 'insufficient-data';
  unknown: string[];
}

const exposureWeights = { internetExposure: 0.3, exploitableFinding: 0.3, credentialExposure: 0.25, businessCriticality: 0.15 } as const;
export function scoreExposure(signals: Partial<Record<keyof typeof exposureWeights, ExposureSignal>>): ExposureScore {
  let weighted = 0; let knownWeight = 0; let confidenceWeight = 0;
  const unknown: string[] = [];
  for (const [name, weight] of Object.entries(exposureWeights) as Array<[keyof typeof exposureWeights, number]>) {
    const signal = signals[name];
    if (signal?.value === undefined || !Number.isFinite(signal.value) || signal.value < 0 || signal.value > 1) { unknown.push(name); continue; }
    const confidence = signal.confidence === undefined ? 0.5 : Math.max(0, Math.min(1, signal.confidence));
    weighted += signal.value * weight; knownWeight += weight; confidenceWeight += confidence * weight;
  }
  const coverage = Number(knownWeight.toFixed(4));
  const confidence = knownWeight ? Number((confidenceWeight / knownWeight * coverage).toFixed(4)) : 0;
  if (knownWeight < 0.5) return { confidence, coverage, disposition: 'insufficient-data', unknown };
  return { score: Math.round(weighted / knownWeight * 100), confidence, coverage, disposition: 'scored', unknown };
}
