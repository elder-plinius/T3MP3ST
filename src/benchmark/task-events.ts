/**
 * Agent Task Event Log — an ordered, append-only event stream per run.
 *
 * Every observable step of an agent task (start, each tool call with its
 * arguments, each gate denial, notes, finish) becomes one JSON line. Two
 * invariants make runs reviewable and reproducible:
 *
 *   1. ORDER: seq is assigned by the log (1, 2, 3, ...) and never edited.
 *   2. DETERMINISM: ts is a LOGICAL clock — by default ts === seq — so a
 *      scripted run produces byte-identical events.jsonl on any machine,
 *      any timezone, any wall-clock. Real elapsed time lives in each
 *      tool_call's durationMs, not in ordering metadata.
 */

export const AGENT_TASK_EVENT_SCHEMA = 't3mp3st_agent_task_event/v1';

export type TaskEventKind = 'task_started' | 'tool_call' | 'tool_denied' | 'note' | 'task_finished';
export type DenialReason = 'scope' | 'approval' | 'other';

const KINDS: readonly TaskEventKind[] = ['task_started', 'tool_call', 'tool_denied', 'note', 'task_finished'];
const REASONS: readonly DenialReason[] = ['scope', 'approval', 'other'];

/** Fields the caller supplies; the log owns seq/ts/schemaVersion/taskId/backend. */
export type TaskEventInput = Partial<Omit<TaskEvent, 'schemaVersion' | 'seq' | 'ts' | 'taskId' | 'backend'>> & { kind: TaskEventKind };

export interface TaskEvent {
  schemaVersion: string;
  seq: number;
  ts: number;
  kind: TaskEventKind;
  taskId: string;
  backend: string;
  tool?: string;
  parameters?: Record<string, unknown>;
  success?: boolean;
  durationMs?: number;
  /** Capped preview of the tool result (full output belongs to the evidence vault, not the log). */
  resultPreview?: string;
  errorPreview?: string;
  reason?: DenialReason;
  detail?: string;
  text?: string;
  answer?: string;
  abstained?: boolean;
  infrastructureError?: string;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Classify a pre-execution refusal by its canonical prefix (see arsenal execute()). */
export function classifyDenial(message: string): DenialReason {
  if (message.startsWith('SCOPE DENIED:')) return 'scope';
  if (message.startsWith('APPROVAL REQUIRED:')) return 'approval';
  return 'other';
}

export const PREVIEW_LIMIT = 512;

export function preview(text: string | undefined): string | undefined {
  if (text === undefined) return undefined;
  return text.length <= PREVIEW_LIMIT ? text : `${text.slice(0, PREVIEW_LIMIT)}…[truncated ${text.length - PREVIEW_LIMIT} chars]`;
}

/**
 * Validate one parsed event object. Unknown kinds, broken seq/ts invariants, or
 * missing per-kind fields reject the line (fail closed on untrusted logs).
 */
export function parseTaskEvent(value: unknown): TaskEvent | undefined {
  if (!isRecord(value) || value.schemaVersion !== AGENT_TASK_EVENT_SCHEMA) return undefined;
  if (!Number.isInteger(value.seq) || (value.seq as number) < 1) return undefined;
  if (!Number.isInteger(value.ts) || (value.ts as number) < 0) return undefined;
  if (typeof value.taskId !== 'string' || value.taskId.length < 3 || value.taskId.length > 64) return undefined;
  if (typeof value.backend !== 'string' || value.backend.length < 1 || value.backend.length > 64) return undefined;
  if (typeof value.kind !== 'string' || !KINDS.includes(value.kind as TaskEventKind)) return undefined;
  const kind = value.kind as TaskEventKind;
  const evt: TaskEvent = {
    schemaVersion: AGENT_TASK_EVENT_SCHEMA,
    seq: value.seq as number,
    ts: value.ts as number,
    kind,
    taskId: value.taskId,
    backend: value.backend,
  };
  const optStr = (v: unknown, max: number): string | undefined =>
    (typeof v === 'string' && v.length >= 1 && v.length <= max ? v : undefined);
  if (value.tool !== undefined) {
    const tool = optStr(value.tool, 64);
    if (!tool) return undefined;
    evt.tool = tool;
  }
  if (value.parameters !== undefined) {
    if (!isRecord(value.parameters)) return undefined;
    evt.parameters = value.parameters;
  }
  if (value.success !== undefined) {
    if (typeof value.success !== 'boolean') return undefined;
    evt.success = value.success;
  }
  if (value.durationMs !== undefined) {
    if (typeof value.durationMs !== 'number' || !Number.isInteger(value.durationMs) || value.durationMs < 0) return undefined;
    evt.durationMs = value.durationMs;
  }
  for (const key of ['resultPreview', 'errorPreview', 'detail', 'text', 'answer', 'infrastructureError'] as const) {
    const v = value[key];
    if (v !== undefined) {
      const s = optStr(v, 8192);
      if (s === undefined) return undefined;
      evt[key] = s;
    }
  }
  if (value.reason !== undefined) {
    if (!REASONS.includes(value.reason as DenialReason)) return undefined;
    evt.reason = value.reason as DenialReason;
  }
  if (value.abstained !== undefined) {
    if (typeof value.abstained !== 'boolean') return undefined;
    evt.abstained = value.abstained;
  }
  // Per-kind contracts.
  if ((kind === 'tool_call' || kind === 'tool_denied') && evt.tool === undefined) return undefined;
  if (kind === 'tool_denied' && evt.reason === undefined) return undefined;
  if (kind === 'note' && evt.text === undefined) return undefined;
  return evt;
}

/**
 * Append-only event log. `now` is the logical clock (default: seq, i.e. strictly
 * monotonic + deterministic). Events are shallow-frozen after append.
 */
export class TaskEventLog {
  private readonly events: TaskEvent[] = [];

  constructor(
    public readonly taskId: string,
    public readonly backend: string,
    private readonly now: (seq: number) => number = seq => seq,
  ) {}

  get length(): number {
    return this.events.length;
  }

  get all(): readonly TaskEvent[] {
    return this.events;
  }

  append(input: TaskEventInput): TaskEvent {
    const seq = this.events.length + 1;
    const ts = this.now(seq);
    if (!Number.isInteger(ts) || ts < (this.events[this.events.length - 1]?.ts ?? 0)) {
      throw new Error(`task-events: logical clock must be a non-decreasing integer (seq ${seq})`);
    }
    const evt: TaskEvent = Object.freeze({
      schemaVersion: AGENT_TASK_EVENT_SCHEMA,
      seq,
      ts,
      taskId: this.taskId,
      backend: this.backend,
      ...input,
    }) as TaskEvent;
    const reparsed = parseTaskEvent(evt);
    if (!reparsed) throw new Error(`task-events: invalid event input (kind ${input.kind})`);
    this.events.push(Object.freeze(reparsed));
    return reparsed;
  }

  toJsonl(): string {
    return this.events.map(e => JSON.stringify(e)).join('\n') + (this.events.length ? '\n' : '');
  }

  /** Parse a full JSONL stream; rejects unknown lines and non-continuous seq. */
  static fromJsonl(text: string, taskId: string, backend: string): TaskEventLog {
    const log = new TaskEventLog(taskId, backend);
    const lines = text.split('\n').filter(l => l.length > 0);
    lines.forEach((line, i) => {
      let raw: unknown;
      try {
        raw = JSON.parse(line);
      } catch {
        throw new Error(`task-events: line ${i + 1} is not JSON`);
      }
      const evt = parseTaskEvent(raw);
      if (!evt) throw new Error(`task-events: line ${i + 1} failed validation`);
      if (evt.seq !== i + 1) throw new Error(`task-events: line ${i + 1} has seq ${evt.seq}, expected ${i + 1}`);
      if (evt.taskId !== taskId || evt.backend !== backend) throw new Error(`task-events: line ${i + 1} task/backend mismatch`);
      log.events.push(evt);
    });
    return log;
  }
}
