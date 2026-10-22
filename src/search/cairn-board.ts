// =============================================================================
// Cairn board — the blackboard fact-intent graph and its scheduling policies.
//
// Techniques reimplemented from oritera/Cairn (AGPL-3.0): the Fact/Intent/Hint
// blackboard, the three task types (bootstrap / reason / explore) with their
// output contracts, and the situation-checkpoint scheduling rules described in
// the upstream design docs. No upstream code is vendored — this is a native
// TypeScript implementation of the documented behaviour, the same treatment
// this platform gives every AGPL technique source (mxrch/ghunt precedent).
//
// The invariants that make the technique work:
//   * Coordination is STIGMERGIC — tasks see only the board, never each other.
//   * The graph grows origin → goal; every intent names the fact(s) it grew
//     from, so the finished search is a readable path, not a log.
//   * Progress is forced where it is cheap: a Reason with an empty frontier
//     MUST propose at least one intent; an Explore always returns one objective
//     fact even when the exploration found nothing.
//   * Re-reasoning is keyed to NEW SITUATIONS (facts/hints grew, or the frontier
//     emptied) — never to "an intent was just created", which is the previous
//     reason's own output.
// =============================================================================

export interface Fact {
  id: string;
  description: string;
  createdBy: string;
  at: number;
}

export interface Intent {
  id: string;
  description: string;
  /** The fact(s) this exploration direction grew from — the graph's edges. */
  from: string[];
  creator: string;
  state: 'open' | 'concluded';
  claimedBy?: string;
  claimedAt?: number;
  concludedAt?: number;
  /** The fact produced by concluding this intent, if it concluded. */
  factId?: string;
}

export interface Completion {
  from: string[];
  description: string;
  at: number;
}

export interface Hint {
  text: string;
  at: number;
}

export interface BoardConfig {
  /** Upper bound on intents one Reason round may propose (Cairn: {max_intents}). */
  maxIntents: number;
  /** Try the goal directly on a fresh search before any exploration. */
  bootstrapEnabled: boolean;
  /** Concurrent task cap inside one search (Cairn: runtime.max_project_workers). */
  maxProjectWorkers: number;
}

export const DEFAULT_BOARD_CONFIG: BoardConfig = {
  maxIntents: 4,
  bootstrapEnabled: true,
  maxProjectWorkers: 3,
};

export type TaskKind = 'bootstrap' | 'reason' | 'explore';

export type ReasonVerdict =
  | { kind: 'complete'; complete: { from: string[]; description: string } }
  | { kind: 'intents'; intents: Array<{ from: string[]; description: string }> }
  | { kind: 'noop' }
  | { kind: 'rejected'; reason: string }
  | { kind: 'invalid'; error: string };

export type ExploreVerdict =
  | { kind: 'fact'; description: string }
  | { kind: 'rejected'; reason: string }
  | { kind: 'invalid'; error: string };

export type BootstrapVerdict =
  | { kind: 'complete'; factDescription: string; completeDescription: string }
  | { kind: 'fact'; factDescription: string }
  | { kind: 'rejected'; reason: string }
  | { kind: 'invalid'; error: string };

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function asStringArray(v: unknown): string[] | null {
  if (!Array.isArray(v) || v.length === 0) return null;
  const out: string[] = [];
  for (const item of v) {
    if (typeof item !== 'string' || !item.trim()) return null;
    out.push(item.trim());
  }
  return out;
}

function asNonEmptyString(v: unknown): string | null {
  return typeof v === 'string' && v.trim() ? v.trim() : null;
}

/**
 * The Reason output contract (upstream validate_reason_payload): the model
 * returns {accepted, data} where data carries `complete` XOR `intent(s)` XOR
 * nothing. Complete and intents may not coexist. A singular `intent` key is
 * accepted for compatibility. An intents array is capped at maxIntents; an
 * EMPTY proposals array is only tolerable when open intents already exist —
 * an empty frontier forces progress.
 */
export function validateReasonPayload(
  payload: unknown,
  openIntentsEmpty: boolean,
  maxIntents: number,
): ReasonVerdict {
  if (!isPlainObject(payload)) return { kind: 'invalid', error: 'payload is not an object' };
  if (payload.accepted === false) {
    return { kind: 'rejected', reason: asNonEmptyString(payload.reason) ?? 'model declined' };
  }
  if (payload.accepted !== true) {
    // Upstream tolerates a bare data object arriving without the accepted wrapper.
    if (!('complete' in payload) && !('intents' in payload) && !('intent' in payload)) {
      return { kind: 'invalid', error: 'accepted must be true or false' };
    }
  }
  const data = isPlainObject(payload.data) ? payload.data : payload;
  const completeRaw = data.complete;
  let intentsRaw = data.intents;
  if (intentsRaw === undefined || intentsRaw === null) {
    // Backward compat: accept a singular `intent` object from the model.
    const singular = data.intent;
    if (isPlainObject(singular)) intentsRaw = [singular];
  }
  if (completeRaw !== undefined && completeRaw !== null) {
    if (intentsRaw !== undefined && intentsRaw !== null) {
      return { kind: 'invalid', error: 'complete and intents cannot coexist' };
    }
    if (!isPlainObject(completeRaw)) return { kind: 'invalid', error: 'complete must be an object' };
    const from = asStringArray(completeRaw.from);
    const description = asNonEmptyString(completeRaw.description);
    if (!from || !description) return { kind: 'invalid', error: 'complete needs from[] and description' };
    return { kind: 'complete', complete: { from, description } };
  }
  if (intentsRaw !== undefined && intentsRaw !== null) {
    if (!Array.isArray(intentsRaw)) return { kind: 'invalid', error: 'intents must be an array' };
    const parsed: Array<{ from: string[]; description: string }> = [];
    for (const item of intentsRaw) {
      if (!isPlainObject(item)) return { kind: 'invalid', error: 'each intent must be an object' };
      const from = asStringArray(item.from);
      const description = asNonEmptyString(item.description);
      if (!from || !description) return { kind: 'invalid', error: 'each intent needs from[] and description' };
      parsed.push({ from, description });
    }
    if (parsed.length === 0 && openIntentsEmpty) {
      return { kind: 'invalid', error: 'intents must not be empty when no open intents exist' };
    }
    const capped = parsed.slice(0, maxIntents);
    if (capped.length === 0) return { kind: 'noop' };
    return { kind: 'intents', intents: capped };
  }
  if (openIntentsEmpty) {
    return { kind: 'invalid', error: 'intents is required when no open intents exist' };
  }
  return { kind: 'noop' };
}

/** The Explore output contract: exactly one objective fact description. */
export function validateExplorePayload(payload: unknown): ExploreVerdict {
  if (!isPlainObject(payload)) return { kind: 'invalid', error: 'payload is not an object' };
  if (payload.accepted === false) {
    return { kind: 'rejected', reason: asNonEmptyString(payload.reason) ?? 'model declined' };
  }
  const data = isPlainObject(payload.data) ? payload.data : payload;
  const description = asNonEmptyString(data.description);
  if (!description) return { kind: 'invalid', error: 'data.description is required' };
  return { kind: 'fact', description };
}

/**
 * The Bootstrap output contract. Main phase: returns ONLY when the problem is
 * already solved, and then must carry BOTH fact and complete. Conclude phase:
 * summarizes what is known so far — a fact, never a completion.
 */
export function validateBootstrapPayload(payload: unknown, phase: 'execute' | 'conclude'): BootstrapVerdict {
  if (!isPlainObject(payload)) return { kind: 'invalid', error: 'payload is not an object' };
  if (payload.accepted === false) {
    return { kind: 'rejected', reason: asNonEmptyString(payload.reason) ?? 'model declined' };
  }
  const data = isPlainObject(payload.data) ? payload.data : payload;
  const factRaw = isPlainObject(data.fact) ? data.fact : null;
  const factDescription = factRaw ? asNonEmptyString(factRaw.description) : null;
  if (!factDescription) return { kind: 'invalid', error: 'fact.description is required' };
  const completeRaw = isPlainObject(data.complete) ? data.complete : null;
  const completeDescription = completeRaw ? asNonEmptyString(completeRaw.description) : null;
  if (phase === 'execute') {
    // The main phase is not allowed to return only a fact: if it returns at
    // all, the problem is solved and provable.
    if (!completeDescription) return { kind: 'invalid', error: 'complete.description is required in the main phase' };
    return { kind: 'complete', factDescription, completeDescription };
  }
  return { kind: 'fact', factDescription };
}

/** Normalized description key for intent de-duplication. */
export function intentKey(description: string): string {
  return description.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
}

export class CairnBoard {
  readonly facts = new Map<string, Fact>();
  readonly intents = new Map<string, Intent>();
  readonly hints: Hint[] = [];
  completion: Completion | null = null;

  private nextFactSeq = 0;
  private nextIntentSeq = 0;
  private originDescription = '';
  private goalDescription = '';

  /** Situation at the last completed Reason (or the admission baseline). */
  private lastReason: { factCount: number; hintCount: number; hadOpenIntents: boolean } | null = null;
  reasonRunning = false;
  bootstrapAttempted = false;
  bootstrapRunning = false;

  constructor(
    public readonly origin: string,
    public readonly goal: string,
    public readonly config: BoardConfig = DEFAULT_BOARD_CONFIG,
  ) {
    this.originDescription = origin.trim();
    this.goalDescription = goal.trim();
  }

  get isInitial(): boolean {
    // Initial state: only origin and goal exist and no ordinary intent ever has.
    return this.facts.size === 2 && this.intents.size === 0 && this.lastReason === null;
  }

  get openIntents(): Intent[] {
    return [...this.intents.values()].filter((i) => i.state === 'open');
  }

  get openIntentsEmpty(): boolean {
    return this.openIntents.length === 0;
  }

  get claimableIntents(): Intent[] {
    return this.openIntents.filter((i) => !i.claimedBy);
  }

  get hintsSeen(): number {
    return this.hints.length;
  }

  addOriginAndGoal(): void {
    this.addFact(`ORIGIN: ${this.originDescription}`, 'board.origin');
    this.addFact(`GOAL: ${this.goalDescription}`, 'board.goal');
  }

  addFact(description: string, createdBy: string): Fact {
    this.nextFactSeq += 1;
    const fact: Fact = { id: `f${String(this.nextFactSeq).padStart(3, '0')}`, description: description.trim(), createdBy, at: Date.now() };
    this.facts.set(fact.id, fact);
    return fact;
  }

  get factIds(): string[] {
    return [...this.facts.keys()];
  }

  /**
   * Propose an intent. Returns null when the description duplicates an intent
   * that already exists (open or concluded) — re-exploring the same direction
   * is how a search burns its budget while looking busy.
   */
  proposeIntent(description: string, from: string[], creator: string): Intent | null {
    const key = intentKey(description);
    for (const existing of this.intents.values()) {
      if (intentKey(existing.description) === key) return null;
    }
    // Edge targets must be real facts; an intent rooted in nothing is unwritable.
    const validFrom = from.filter((f) => this.facts.has(f));
    this.nextIntentSeq += 1;
    const intent: Intent = {
      id: `i${String(this.nextIntentSeq).padStart(3, '0')}`,
      description: description.trim(),
      from: validFrom.length ? validFrom : [this.goalFactId()],
      creator,
      state: 'open',
    };
    this.intents.set(intent.id, intent);
    return intent;
  }

  private goalFactId(): string {
    for (const f of this.facts.values()) if (f.createdBy === 'board.goal') return f.id;
    return this.factIds[0] ?? 'f001';
  }

  addHint(text: string): Hint {
    const hint: Hint = { text: text.trim(), at: Date.now() };
    this.hints.push(hint);
    return hint;
  }

  claimIntent(id: string, worker: string): boolean {
    const intent = this.intents.get(id);
    if (!intent || intent.state !== 'open' || intent.claimedBy) return false;
    intent.claimedBy = worker;
    intent.claimedAt = Date.now();
    return true;
  }

  releaseIntent(id: string): void {
    const intent = this.intents.get(id);
    if (!intent) return;
    delete intent.claimedBy;
    delete intent.claimedAt;
  }

  /** Conclude an intent: its conclusion becomes a Fact on the board. */
  concludeIntent(id: string, factDescription: string, worker: string): Fact | null {
    const intent = this.intents.get(id);
    if (!intent || intent.state !== 'open') return null;
    const fact = this.addFact(factDescription, worker);
    intent.state = 'concluded';
    intent.concludedAt = Date.now();
    intent.factId = fact.id;
    delete intent.claimedBy;
    delete intent.claimedAt;
    return fact;
  }

  complete(from: string[], description: string): Completion {
    const validFrom = from.filter((f) => this.facts.has(f));
    this.completion = { from: validFrom, description: description.trim(), at: Date.now() };
    return this.completion;
  }

  get runningTaskCount(): number {
    let n = this.claimedCount();
    if (this.bootstrapRunning) n += 1;
    if (this.reasonRunning) n += 1;
    return n;
  }

  private claimedCount(): number {
    return this.openIntents.filter((i) => i.claimedBy).length;
  }

  situation(): { factCount: number; hintCount: number; hadOpenIntents: boolean; openIntentsEmpty: boolean } {
    return { factCount: this.facts.size, hintCount: this.hints.length, hadOpenIntents: !this.openIntentsEmpty, openIntentsEmpty: this.openIntentsEmpty };
  }

  /**
   * Establish the admission baseline: an active search with open intents but no
   * reason checkpoint must record its situation WITHOUT triggering a reason, so
   * the first genuinely new fact/hint after admission is not swallowed.
   */
  establishReasonBaseline(): void {
    if (!this.lastReason) {
      const s = this.situation();
      this.lastReason = { factCount: s.factCount, hintCount: s.hintCount, hadOpenIntents: s.hadOpenIntents };
    }
  }

  /** Drop the checkpoint so the next round re-reasons (engine stall recovery). */
  clearReasonCheckpoint(): void {
    this.lastReason = null;
  }

  /**
   * Is a Reason task due? Upstream rules:
   *  - never while a reason lease is running;
   *  - the FIRST reason fires only when no open intents exist;
   *  - afterwards only on a new situation: facts grew, hints grew, or the
   *    frontier transitioned from open to empty. An intent being created is
   *    NOT a new situation (it is the previous reason's own output), and an
   *    explore failing/releasing is not either.
   */
  reasonDue(): boolean {
    if (this.reasonRunning || this.completion) return false;
    if (!this.lastReason) {
      if (this.openIntentsEmpty) return true;
      this.establishReasonBaseline();
      return false;
    }
    const s = this.situation();
    return s.factCount > this.lastReason.factCount
      || s.hintCount > this.lastReason.hintCount
      || (this.lastReason.hadOpenIntents && s.openIntentsEmpty);
  }

  checkpointReason(): void {
    const s = this.situation();
    this.lastReason = { factCount: s.factCount, hintCount: s.hintCount, hadOpenIntents: s.hadOpenIntents };
  }

  /**
   * The scheduler's per-round priority, upstream order: bootstrap on an initial
   * search, then a due Reason, then any claimable Explore. Null only when the
   * search is finished or every lane is saturated.
   */
  nextTask(): TaskKind | null {
    if (this.completion) return null;
    if (this.isInitial && this.config.bootstrapEnabled && !this.bootstrapAttempted && !this.bootstrapRunning) return 'bootstrap';
    if (this.reasonDue()) return 'reason';
    if (this.claimableIntents.length > 0 && this.runningTaskCount < this.config.maxProjectWorkers) return 'explore';
    return null;
  }

  /** The graph snapshot handed to Reason/Explore prompts (YAML, ids intact). */
  snapshotYaml(): string {
    const lines: string[] = [];
    lines.push('goal:');
    lines.push(`  description: ${this.yamlEscape(this.goalDescription)}`);
    lines.push('facts:');
    for (const fact of this.facts.values()) {
      lines.push(`  - id: ${fact.id}`);
      lines.push(`    description: ${this.yamlEscape(fact.description)}`);
    }
    lines.push('intents:');
    lines.push('  open:');
    const open = this.openIntents;
    if (open.length === 0) lines.push('    []');
    for (const intent of open) {
      lines.push(`    - id: ${intent.id}`);
      lines.push(`      from: [${intent.from.join(', ')}]`);
      lines.push(`      description: ${this.yamlEscape(intent.description)}`);
      if (intent.claimedBy) lines.push(`      claimed: true`);
    }
    lines.push('  concluded:');
    const concluded = [...this.intents.values()].filter((i) => i.state === 'concluded');
    if (concluded.length === 0) lines.push('    []');
    for (const intent of concluded) {
      lines.push(`    - id: ${intent.id}`);
      lines.push(`      from: [${intent.from.join(', ')}]`);
      lines.push(`      description: ${this.yamlEscape(intent.description)}`);
      lines.push(`      produced_fact: ${intent.factId ?? '[]'}`);
    }
    lines.push('hints:');
    if (this.hints.length === 0) lines.push('  []');
    for (const hint of this.hints) lines.push(`  - ${this.yamlEscape(hint.text)}`);
    if (this.completion) {
      lines.push('complete:');
      lines.push(`  from: [${this.completion.from.join(', ')}]`);
      lines.push(`  description: ${this.yamlEscape(this.completion.description)}`);
    }
    return lines.join('\n');
  }

  private yamlEscape(v: string): string {
    return JSON.stringify(v);
  }
}
