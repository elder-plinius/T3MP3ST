import { createHash, randomUUID } from 'node:crypto';
import { redactSecrets } from '../redact.js';

export type DfirPlatform = 'linux' | 'darwin' | 'win32';
export interface EvidenceArtifact { name: string; source: string; bytes: Uint8Array; collectedAt: number }
export interface EvidenceRecord { id: string; caseId: string; targetId: string; name: string; source: string; collectedAt: number; receivedAt: number; sha256: string; sizeBytes: number; collector: string; transfer: 'in-process'; verified: boolean; redactedMetadata: Record<string, unknown> }
export interface ReadOnlyCollector {
  readonly id: string;
  readonly platform: DfirPlatform;
  collect(targetId: string, signal?: AbortSignal): Promise<readonly EvidenceArtifact[]>;
}
export interface AcquisitionRequest { caseId: string; targetId: string; investigator: string; collector: ReadOnlyCollector; signal?: AbortSignal; metadata?: Record<string, unknown> }
export interface AcquisitionResult { outcome: 'collected' | 'cancelled' | 'permission-denied' | 'collection-failed'; records: EvidenceRecord[]; error?: string }

export interface ContainmentPreview { caseId: string; targetId: string; actionId: string; summary: string; rollback: string; commands: readonly string[]; digest: string }
export interface ContainmentApproval { receiptId: string; caseId: string; targetId: string; actionId: string; previewDigest: string; approvedBy: string; approvedAt: number; expiresAt: number }
export interface ContainmentExecutor { execute(preview: ContainmentPreview, signal?: AbortSignal): Promise<{ completedSteps: number; totalSteps: number }> }
export interface ContainmentReceipt { receiptId: string; caseId: string; targetId: string; actionId: string; outcome: 'completed' | 'partial' | 'cancelled' | 'denied' | 'failed'; completedSteps: number; totalSteps: number; startedAt: number; completedAt: number; rollback: string; error?: string }

const idPattern = /^[a-zA-Z0-9_.:-]{1,128}$/;
const sha256 = (value: Uint8Array | string) => createHash('sha256').update(value).digest('hex');
const safeError = (error: unknown): AcquisitionResult['outcome'] => error instanceof Error && /EACCES|EPERM|permission/i.test(error.message) ? 'permission-denied' : 'collection-failed';

export function createContainmentPreview(input: Omit<ContainmentPreview, 'digest'>): ContainmentPreview {
  if (![input.caseId, input.targetId, input.actionId].every(value => idPattern.test(value)) || !input.summary.trim() || !input.rollback.trim() || !input.commands.length) throw new Error('Containment preview is incomplete');
  const canonical = JSON.stringify({ caseId: input.caseId, targetId: input.targetId, actionId: input.actionId, summary: input.summary, rollback: input.rollback, commands: input.commands });
  return { ...structuredClone(input), digest: sha256(canonical) };
}

export class DfirToolkit {
  constructor(private readonly now: () => number = Date.now) {}

  async acquire(request: AcquisitionRequest): Promise<AcquisitionResult> {
    if (![request.caseId, request.targetId, request.investigator, request.collector.id].every(value => idPattern.test(value))) return { outcome: 'collection-failed', records: [], error: 'invalid-request' };
    if (request.signal?.aborted) return { outcome: 'cancelled', records: [] };
    try {
      const artifacts = await request.collector.collect(request.targetId, request.signal);
      const names = new Set<string>();
      const records: EvidenceRecord[] = [];
      for (const artifact of artifacts) {
        if (request.signal?.aborted) return { outcome: 'cancelled', records };
        const name = artifact.name;
        if (request.signal?.aborted) return { outcome: 'cancelled', records };
        if (!name || names.has(name) || !artifact.source || !Number.isFinite(artifact.collectedAt)) return { outcome: 'collection-failed', records, error: 'invalid-artifact' };
        names.add(name);
        const digest = sha256(artifact.bytes);
        records.push({ id: randomUUID(), caseId: request.caseId, targetId: request.targetId, name, source: artifact.source, collectedAt: artifact.collectedAt, receivedAt: this.now(), sha256: digest, sizeBytes: artifact.bytes.byteLength, collector: request.collector.id, transfer: 'in-process', verified: sha256(artifact.bytes) === digest, redactedMetadata: redactSecrets(request.metadata ?? {}) as Record<string, unknown> });
      }
      return { outcome: 'collected', records };
    } catch (error) {
      return { outcome: safeError(error), records: [], error: safeError(error) };
    }
  }

  async contain(preview: ContainmentPreview, approval: ContainmentApproval | undefined, executor: ContainmentExecutor, signal?: AbortSignal): Promise<ContainmentReceipt> {
    const startedAt = this.now();
    const base = { receiptId: approval?.receiptId ?? randomUUID(), caseId: preview.caseId, targetId: preview.targetId, actionId: preview.actionId, startedAt, rollback: preview.rollback };
    const denied = !approval || !idPattern.test(approval.receiptId) || !idPattern.test(approval.approvedBy) || approval.caseId !== preview.caseId || approval.targetId !== preview.targetId || approval.actionId !== preview.actionId || approval.previewDigest !== preview.digest || approval.approvedAt > startedAt || approval.expiresAt <= startedAt;
    if (denied) return { ...base, outcome: 'denied', completedSteps: 0, totalSteps: preview.commands.length, completedAt: this.now(), error: 'authorization-required' };
    if (signal?.aborted) return { ...base, outcome: 'cancelled', completedSteps: 0, totalSteps: preview.commands.length, completedAt: this.now(), error: 'cancelled' };
    try {
      const result = await executor.execute(structuredClone(preview), signal);
      const completedSteps = Math.max(0, Math.min(preview.commands.length, Math.trunc(result.completedSteps)));
      const totalSteps = preview.commands.length;
      return { ...base, outcome: signal?.aborted ? 'cancelled' : completedSteps === totalSteps ? 'completed' : 'partial', completedSteps, totalSteps, completedAt: this.now(), ...(completedSteps === totalSteps ? {} : { error: signal?.aborted ? 'cancelled' : 'partial-execution' }) };
    } catch {
      return { ...base, outcome: signal?.aborted ? 'cancelled' : 'failed', completedSteps: 0, totalSteps: preview.commands.length, completedAt: this.now(), error: signal?.aborted ? 'cancelled' : 'execution-failed' };
    }
  }
}

export function supportedDfirPlatforms(collectors: readonly ReadOnlyCollector[]): DfirPlatform[] {
  return [...new Set(collectors.map(collector => collector.platform))];
}
