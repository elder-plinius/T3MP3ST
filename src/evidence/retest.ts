import { createHash, randomUUID } from 'node:crypto';
import type { Arsenal } from '../arsenal/index.js';
import type { Evidence, Finding, Target, ToolResult } from '../types/index.js';

export type RetestStatus = 'fixed' | 'still_vulnerable' | 'unverifiable';
export type ProbeDisposition = 'present' | 'absent' | 'inconclusive';

export interface ProbeObservation {
  disposition: ProbeDisposition;
  evidence: Evidence[];
  result: ToolResult;
  retryable?: boolean;
}

export interface RetestRequest {
  requestId: string;
  finding: Finding;
  target: Target;
  toolName: string;
  arguments: Record<string, unknown>;
  timeoutMs?: number;
  maxAttempts?: number;
  signal?: AbortSignal;
}

export interface RetestAttempt {
  attempt: number;
  startedAt: number;
  completedAt: number;
  disposition: ProbeDisposition;
  evidence: Evidence[];
  error?: string;
}

export interface RetestRecord {
  id: string;
  requestId: string;
  findingId: string;
  cve: string[];
  targetId: string;
  toolName: string;
  status: RetestStatus;
  attempts: RetestAttempt[];
  provenance: { source: 'authorized-tool-retest'; createdAt: number };
}

export interface RetestProbe {
  run(request: RetestRequest, signal: AbortSignal): Promise<ProbeObservation>;
}

const TOOL_EVIDENCE = new Set<Evidence['type']>(['log', 'request', 'response', 'file', 'command', 'output']);
function copyEvidence(items: readonly Evidence[]): Evidence[] {
  return items.map((item) => ({ ...item, metadata: item.metadata ? { ...item.metadata } : undefined }));
}
function hasToolEvidence(items: readonly Evidence[]): boolean {
  return items.some((item) => TOOL_EVIDENCE.has(item.type) && item.content.trim().length > 0);
}
function fingerprint(request: RetestRequest): string {
  return createHash('sha256').update(JSON.stringify({ findingId: request.finding.id, targetId: request.target.id, toolName: request.toolName, arguments: request.arguments })).digest('hex');
}
function abortError(message = 'Retest cancelled'): Error {
  const error = new Error(message);
  error.name = 'AbortError';
  return error;
}

/** Arsenal adapter: scope must be configured; Arsenal still owns schema, scope, and approval gates. */
export class ArsenalRetestProbe implements RetestProbe {
  constructor(private readonly arsenal: Arsenal, private readonly classify: (result: ToolResult) => ProbeObservation) {}

  async run(request: RetestRequest, signal: AbortSignal): Promise<ProbeObservation> {
    if (!this.arsenal.getScope()) throw new Error('Retest refused: an explicit Arsenal scope is required');
    if (signal.aborted) throw abortError();
    const result = await this.arsenal.execute(request.toolName, { target: request.target, parameters: { ...request.arguments } });
    if (signal.aborted) throw abortError();
    return this.classify(result);
  }
}

export class FindingRetestWorkflow {
  private readonly completed = new Map<string, { fingerprint: string; result: Promise<RetestRecord> }>();

  constructor(private readonly probe: RetestProbe, private readonly now: () => number = Date.now) {}

  run(request: RetestRequest): Promise<RetestRecord> {
    if (!request.requestId.trim()) return Promise.reject(new Error('requestId is required'));
    if (!request.finding.id || !request.target.id || !request.toolName.trim()) return Promise.reject(new Error('finding, target, and toolName are required'));
    if (request.finding.targetId !== request.target.id) return Promise.reject(new Error('retest target must match the finding target'));
    if (!request.finding.cve?.length || request.finding.cve.some((id) => !/^CVE-\d{4}-\d{4,}$/i.test(id))) return Promise.reject(new Error('targeted retest requires valid CVE identifiers'));
    const key = fingerprint(request);
    const prior = this.completed.get(request.requestId);
    if (prior) {
      if (prior.fingerprint !== key) return Promise.reject(new Error('requestId was already used for a different retest'));
      return prior.result;
    }
    const result = this.execute(request);
    this.completed.set(request.requestId, { fingerprint: key, result });
    return result;
  }

  async sweep(requests: readonly RetestRequest[]): Promise<RetestRecord[]> {
    return Promise.all(requests.map((request) => this.run(request)));
  }

  private async execute(request: RetestRequest): Promise<RetestRecord> {
    const maxAttempts = Math.min(5, Math.max(1, request.maxAttempts ?? 2));
    const timeoutMs = Math.min(120_000, Math.max(100, request.timeoutMs ?? 20_000));
    const attempts: RetestAttempt[] = [];
    let final: ProbeObservation | undefined;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      if (request.signal?.aborted) {
        attempts.push({ attempt, startedAt: this.now(), completedAt: this.now(), disposition: 'inconclusive', evidence: [], error: 'Retest cancelled' });
        break;
      }
      const startedAt = this.now();
      const controller = new AbortController();
      const onAbort = () => controller.abort();
      request.signal?.addEventListener('abort', onAbort, { once: true });
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        final = await this.probe.run(request, controller.signal);
        attempts.push({ attempt, startedAt, completedAt: this.now(), disposition: final.disposition, evidence: copyEvidence(final.evidence), ...(final.result.error ? { error: final.result.error } : {}) });
        if (!final.retryable) break;
      } catch (error) {
        const cancelled = request.signal?.aborted;
        attempts.push({ attempt, startedAt, completedAt: this.now(), disposition: 'inconclusive', evidence: [], error: cancelled ? 'Retest cancelled' : controller.signal.aborted ? 'Retest timed out' : error instanceof Error ? error.message : String(error) });
        if (cancelled) break;
      } finally {
        clearTimeout(timer);
        request.signal?.removeEventListener('abort', onAbort);
      }
    }
    const evidenceBacked = Boolean(final && final.result.success && hasToolEvidence(final.evidence));
    const status: RetestStatus = evidenceBacked && final?.disposition === 'present'
      ? 'still_vulnerable'
      : evidenceBacked && final?.disposition === 'absent'
        ? 'fixed'
        : 'unverifiable';
    return {
      id: randomUUID(), requestId: request.requestId, findingId: request.finding.id, cve: [...(request.finding.cve ?? [])],
      targetId: request.target.id, toolName: request.toolName, status, attempts,
      provenance: { source: 'authorized-tool-retest', createdAt: this.now() },
    };
  }
}
