import { describe, expect, it } from 'vitest';
import {
  CairnBoard,
  validateBootstrapPayload,
  validateExplorePayload,
  validateReasonPayload,
  DEFAULT_BOARD_CONFIG,
} from '../search/cairn-board.js';
import { extractJsonObject, runCairnSearch, type ChatFn } from '../search/cairn-engine.js';

// ---------------------------------------------------------------------------
// Reason output contract
// ---------------------------------------------------------------------------

describe('cairn reason contract', () => {
  it('accepts a completion citing valid facts', () => {
    const v = validateReasonPayload({ accepted: true, data: { complete: { from: ['f001'], description: 'flag proven' } } }, true, 4);
    expect(v.kind).toBe('complete');
  });

  it('rejects complete and intents coexisting', () => {
    const v = validateReasonPayload({
      accepted: true,
      data: { complete: { from: ['f001'], description: 'x' }, intents: [{ from: ['f001'], description: 'y' }] },
    }, true, 4);
    expect(v.kind).toBe('invalid');
  });

  it('accepts a singular intent object for compatibility', () => {
    const v = validateReasonPayload({ accepted: true, data: { intent: { from: ['f002'], description: 'try sqli' } } }, false, 4);
    expect(v.kind).toBe('intents');
    if (v.kind === 'intents') expect(v.intents).toHaveLength(1);
  });

  it('caps proposals at maxIntents', () => {
    const intents = [1, 2, 3, 4, 5, 6].map((n) => ({ from: ['f001'], description: `direction ${n}` }));
    const v = validateReasonPayload({ accepted: true, data: { intents } }, false, 4);
    expect(v.kind).toBe('intents');
    if (v.kind === 'intents') expect(v.intents).toHaveLength(4);
  });

  it('forbids empty proposals when the frontier is empty — progress is forced', () => {
    const v = validateReasonPayload({ accepted: true, data: { intents: [] } }, true, 4);
    expect(v.kind).toBe('invalid');
    const v2 = validateReasonPayload({ accepted: true, data: {} }, true, 4);
    expect(v2.kind).toBe('invalid');
  });

  it('tolerates empty proposals when open intents already exist (a legal noop)', () => {
    const v = validateReasonPayload({ accepted: true, data: { intents: [] } }, false, 4);
    expect(v.kind).toBe('noop');
    const v2 = validateReasonPayload({ accepted: true, data: {} }, false, 4);
    expect(v2.kind).toBe('noop');
  });

  it('surfaces a policy refusal as rejected, not invalid', () => {
    const v = validateReasonPayload({ accepted: false, reason: 'cannot help' }, false, 4);
    expect(v.kind).toBe('rejected');
  });

  it('tolerates a bare data object without the accepted wrapper', () => {
    const v = validateReasonPayload({ intents: [{ from: ['f001'], description: 'x' }] }, false, 4);
    expect(v.kind).toBe('intents');
  });

  it('rejects malformed payloads with the field named', () => {
    expect(validateReasonPayload({ accepted: true, data: { complete: { from: [], description: 'x' } } }, true, 4).kind).toBe('invalid');
    expect(validateReasonPayload({ accepted: true, data: { intents: 'many' } }, false, 4).kind).toBe('invalid');
    expect(validateReasonPayload({ accepted: true, data: { intents: [{ description: 'no from' }] } }, false, 4).kind).toBe('invalid');
    expect(validateReasonPayload('hello', false, 4).kind).toBe('invalid');
  });
});

// ---------------------------------------------------------------------------
// Explore + Bootstrap contracts
// ---------------------------------------------------------------------------

describe('cairn explore and bootstrap contracts', () => {
  it('explore: a clean negative is still a fact', () => {
    const v = validateExplorePayload({ accepted: true, data: { description: 'tested /search for sqli, none found' } });
    expect(v).toEqual({ kind: 'fact', description: 'tested /search for sqli, none found' });
  });

  it('explore: refusal and malformed are distinct outcomes', () => {
    expect(validateExplorePayload({ accepted: false, reason: 'policy_refusal' }).kind).toBe('rejected');
    expect(validateExplorePayload({ accepted: true, data: {} }).kind).toBe('invalid');
  });

  it('bootstrap main phase requires BOTH fact and complete — no partial credit', () => {
    const both = validateBootstrapPayload({ accepted: true, data: { fact: { description: 'got flag' }, complete: { description: 'goal met' } } }, 'execute');
    expect(both.kind).toBe('complete');
    expect(validateBootstrapPayload({ accepted: true, data: { fact: { description: 'got flag' } } }, 'execute').kind).toBe('invalid');
  });

  it('bootstrap conclude phase banks a fact and never a completion', () => {
    const v = validateBootstrapPayload({ accepted: true, data: { fact: { description: 'attempted ssh, closed port' } } }, 'conclude');
    expect(v.kind).toBe('fact');
  });
});

// ---------------------------------------------------------------------------
// Scheduling policies
// ---------------------------------------------------------------------------

describe('cairn board scheduling', () => {
  function freshBoard(): CairnBoard {
    const b = new CairnBoard('10.0.0.1', 'get a shell', { ...DEFAULT_BOARD_CONFIG });
    b.addOriginAndGoal();
    return b;
  }

  it('an initial search schedules bootstrap first', () => {
    const b = freshBoard();
    expect(b.isInitial).toBe(true);
    expect(b.nextTask()).toBe('bootstrap');
  });

  it('the first reason fires only on an empty frontier; with open intents it baselines silently', () => {
    const b = freshBoard();
    b.bootstrapAttempted = true;
    expect(b.reasonDue()).toBe(true); // no checkpoint, no open intents
    b.checkpointReason();
    expect(b.reasonDue()).toBe(false);

    // Open intents exist but no checkpoint yet → baseline silently, so the
    // first genuinely new fact after admission is not swallowed.
    const b3 = freshBoard();
    b3.bootstrapAttempted = true;
    b3.proposeIntent('enumerate subdomains', [b3.factIds[0]], 'reasoner');
    expect(b3.openIntents.length).toBe(1);
    expect(b3.reasonDue()).toBe(false); // baseline taken, not triggered
    expect(b3.reasonDue()).toBe(false); // still baselined
  });

  it('a new situation re-triggers reason; a mere intent creation does not', () => {
    const b = freshBoard();
    b.bootstrapAttempted = true;
    b.checkpointReason();
    const intent = b.proposeIntent('try ftp anonymous', [b.factIds[0]], 'reasoner');
    expect(intent).not.toBeNull();
    expect(b.reasonDue()).toBe(false); // the reason's own output is not news

    const fact = b.addFact('ftp allows anonymous login', 'explorer');
    expect(b.reasonDue()).toBe(true); // fact count grew — new situation

    b.checkpointReason();
    expect(b.reasonDue()).toBe(false);
    b.addHint('focus on the internal host');
    expect(b.reasonDue()).toBe(true); // hint count grew
    b.checkpointReason();

    // Frontier transition: open → empty.
    const i2 = b.proposeIntent('pivot deeper', [fact.id], 'reasoner');
    b.checkpointReason();
    b.concludeIntent(i2!.id, 'pivot refused: no route', 'explorer');
    expect(b.reasonDue()).toBe(true);
  });

  it('explore failure and release are not new situations', () => {
    const b = freshBoard();
    b.bootstrapAttempted = true;
    b.checkpointReason();
    const intent = b.proposeIntent('scan 445', [b.factIds[0]], 'reasoner')!;
    b.checkpointReason();
    b.claimIntent(intent.id, 'w1');
    expect(b.reasonDue()).toBe(false);
    b.releaseIntent(intent.id);
    expect(b.reasonDue()).toBe(false); // released intent just waits to be re-claimed
  });

  it('priority: bootstrap, then due reason, then explore; done searches schedule nothing', () => {
    const b = freshBoard();
    expect(b.nextTask()).toBe('bootstrap');
    b.bootstrapAttempted = true;
    expect(b.nextTask()).toBe('reason');
    b.checkpointReason();
    b.proposeIntent('enumerate smb', [b.factIds[0]], 'reasoner');
    expect(b.nextTask()).toBe('explore');
    b.complete([b.factIds[0]], 'done');
    expect(b.nextTask()).toBeNull();
  });

  it('claim/conclude lifecycle writes the conclusion as a fact; dedup kills repeat directions', () => {
    const b = freshBoard();
    b.bootstrapAttempted = true;
    const intent = b.proposeIntent('check port 22', [b.factIds[0]], 'reasoner')!;
    expect(b.claimIntent(intent.id, 'w1')).toBe(true);
    expect(b.claimIntent(intent.id, 'w2')).toBe(false); // already claimed
    const fact = b.concludeIntent(intent.id, 'port 22 open, banner OpenSSH', 'w1');
    expect(fact).not.toBeNull();
    expect(intent.state).toBe('concluded');
    expect(intent.factId).toBe(fact!.id);
    expect(b.proposeIntent('check port 22', [b.factIds[0]], 'reasoner')).toBeNull(); // duplicate direction
    expect(b.proposeIntent('Check  Port  22!', [b.factIds[0]], 'reasoner')).toBeNull(); // normalized duplicate
  });

  it('intents rooted in unknown facts are re-rooted rather than dropped', () => {
    const b = freshBoard();
    const intent = b.proposeIntent('try the ghost fact', ['f999'], 'reasoner');
    expect(intent).not.toBeNull();
    expect(intent!.from).toEqual([b.factIds[1]]); // falls back to the GOAL fact
  });

  it('the snapshot carries ids, edges, hints and completion for the prompts', () => {
    const b = freshBoard();
    b.bootstrapAttempted = true;
    b.checkpointReason();
    const intent = b.proposeIntent('enumerate web', [b.factIds[0]], 'reasoner')!;
    b.addHint('the cms is old');
    b.concludeIntent(intent.id, 'cms is wordpress 5.2', 'w1');
    b.complete([b.factIds[1]], 'goal argued');
    const yaml = b.snapshotYaml();
    expect(yaml).toContain('id: f001');
    expect(yaml).toContain('from: [f001]');
    expect(yaml).toContain('wordpress 5.2');
    expect(yaml).toContain('the cms is old');
    expect(yaml).toContain('goal argued');
  });
});

// ---------------------------------------------------------------------------
// JSON extraction from decorated model output
// ---------------------------------------------------------------------------

describe('cairn json extraction', () => {
  it('finds the one balanced object inside prose and fences', () => {
    const decorated = 'Sure! here you go:\n```json\n{"accepted": true, "data": {"description": "a {quoted} \\"thing\\""}}\n```\nhope that helps';
    expect(extractJsonObject(decorated)).toEqual({ accepted: true, data: { description: 'a {quoted} "thing"' } });
  });

  it('returns null on truncation and on non-object roots', () => {
    expect(extractJsonObject('{"accepted": true')).toBeNull();
    expect(extractJsonObject('[1,2,3]')).toBeNull();
    expect(extractJsonObject('')).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Engine runs with a scripted model
// ---------------------------------------------------------------------------

interface Script {
  /** Response per task type, consumed in order; the last one repeats. */
  bootstrap?: string[];
  bootstrapConclude?: string[];
  reason?: string[];
  explore?: string[];
}

function scriptedChat(script: Script): { chat: ChatFn; calls: Array<{ kind: string; user: string }> } {
  const calls: Array<{ kind: string; user: string }> = [];
  const take = (arr: string[] | undefined): string => (arr && arr.length ? (arr.length === 1 ? arr[0] : arr.shift()!) : '{"accepted":false,"reason":"script exhausted"}');
  const chat: ChatFn = async (system, user) => {
    let kind = 'unknown';
    if (system.startsWith('You are the reasoner')) kind = 'reason';
    else if (system.startsWith('You are an explorer')) kind = 'explore';
    else if (system.startsWith('You are opening')) kind = 'bootstrap';
    else if (system.startsWith('The direct attempt is over')) kind = 'bootstrap_conclude';
    calls.push({ kind, user });
    return take(script[kind as keyof Script]);
  };
  return { chat, calls };
}

const J = JSON.stringify;

describe('cairn engine runs', () => {
  it('bootstrap that solves the goal ends the search immediately', async () => {
    const { chat } = scriptedChat({ bootstrap: [J({ accepted: true, data: { fact: { description: 'flag{direct} captured' }, complete: { description: 'flag satisfies goal' } } })] });
    const r = await runCairnSearch({ origin: 'target', goal: 'capture the flag', chat });
    expect(r.state).toBe('complete');
    expect(r.completion).not.toBeNull();
    expect(r.facts).toHaveLength(3); // origin, goal, result
    expect(r.journal[0].task).toBe('bootstrap');
    expect(r.journal[0].outcome).toBe('complete');
  });

  it('the full arc: bootstrap fails → conclude banks a fact → reason proposes → explores run → reason completes', async () => {
    const { chat } = scriptedChat({
      bootstrap: [J({ accepted: true, data: { fact: { description: 'half-done' } } })], // invalid: no complete
      bootstrapConclude: [J({ accepted: true, data: { fact: { description: 'direct attempt ruled out; service is a web app' } } })],
      reason: [
        J({ accepted: true, data: { intents: [{ from: ['f003'], description: 'enumerate the web app' }, { from: ['f003'], description: 'check other ports' }] } }),
        J({ accepted: true, data: { complete: { from: ['f004'], description: 'shell obtained per fact f004' } } }),
      ],
      explore: [
        J({ accepted: true, data: { description: 'found admin panel at /admin with default creds' } }),
        J({ accepted: true, data: { description: 'ports 22/443 also open' } }),
      ],
    });
    const r = await runCairnSearch({ origin: '10.0.0.9', goal: 'root the box', chat });
    expect(r.state).toBe('complete');
    expect(r.facts.some((f) => f.description.includes('admin panel'))).toBe(true);
    expect(r.facts.some((f) => f.description.includes('ports 22/443'))).toBe(true);
    const tasks = r.journal.map((j) => j.task);
    expect(tasks).toContain('bootstrap');
    expect(tasks).toContain('bootstrap_conclude');
    expect(tasks).toContain('reason');
    expect(tasks).toContain('explore');
  });

  it('an explore refusal releases the intent without writing a fact, and the intent stays retryable', async () => {
    const { chat } = scriptedChat({
      bootstrapConclude: [J({ accepted: true, data: { fact: { description: 'web app on 80' } } })],
      reason: [J({ accepted: true, data: { intents: [{ from: ['f003'], description: 'bruteforce the login' }] } })],
      explore: [J({ accepted: false, reason: 'policy_refusal' }), J({ accepted: true, data: { description: 'login form has no lockout' } })],
    });
    const r = await runCairnSearch({ origin: 'host', goal: 'shell', chat, config: { budgetMs: 30_000 } });
    const refused = r.intents.find((i) => i.description.includes('bruteforce'));
    expect(refused).toBeDefined();
    // The refusal released it; the re-reason after frontier transition proposed
    // more work, and the follow-up explore concluded something real.
    expect(r.facts.some((f) => f.description.includes('no lockout'))).toBe(true);
  });

  it('duplicate proposals are dropped and counted, not written', async () => {
    const { chat } = scriptedChat({
      bootstrapConclude: [J({ accepted: true, data: { fact: { description: 'web on 80' } } })],
      reason: [
        J({ accepted: true, data: { intents: [{ from: ['f003'], description: 'enumerate dirs' }] } }),
        J({ accepted: true, data: { intents: [{ from: ['f003'], description: 'Enumerate Dirs!' }, { from: ['f003'], description: 'fuzz dns' }] } }),
        J({ accepted: true, data: { complete: { from: ['f004'], description: 'done per f004' } } }),
      ],
      explore: [J({ accepted: true, data: { description: 'dirs: /backup exposed' } }), J({ accepted: true, data: { description: 'dns has dev host' } })],
    });
    const r = await runCairnSearch({ origin: 'h', goal: 'g', chat });
    const journalReasons = r.journal.filter((j) => j.task === 'reason');
    expect(journalReasons.some((j) => j.detail?.includes('duplicated'))).toBe(true);
    expect(r.intents.filter((i) => i.description.toLowerCase().includes('enumerate dirs'))).toHaveLength(1);
  });

  it('hints injected before the run reach the reason prompt', async () => {
    const { chat, calls } = scriptedChat({
      bootstrapConclude: [J({ accepted: true, data: { fact: { description: 'web on 80' } } })],
      reason: [J({ accepted: true, data: { intents: [{ from: ['f003'], description: 'follow the hint' }] } })],
      explore: [J({ accepted: true, data: { description: 'hint followed' } })],
    });
    await runCairnSearch({ origin: 'h', goal: 'g', hints: ['the app is laravel'], chat });
    const reasonCall = calls.find((c) => c.kind === 'reason');
    expect(reasonCall).toBeDefined();
    expect(reasonCall!.user).toContain('the app is laravel');
  });

  it('exhausted budget ends as budget_exhausted, never as a fake completion', async () => {
    const slowChat: ChatFn = () => new Promise((resolve) => setTimeout(() => resolve('{"accepted":true,"data":{"description":"late"}}'), 1500));
    const r = await runCairnSearch({ origin: 'h', goal: 'g', chat: slowChat, config: { budgetMs: 300 } });
    expect(r.state).toBe('budget_exhausted');
    expect(r.completion).toBeNull();
  });

  it('a reason that keeps returning nothing with an empty frontier stalls the search honestly', async () => {
    const { chat } = scriptedChat({
      bootstrapConclude: [J({ accepted: true, data: { fact: { description: 'web on 80' } } })],
      reason: [J({ accepted: true, data: {} })], // noop with an empty frontier → contract violation, discarded
    });
    const r = await runCairnSearch({ origin: 'h', goal: 'g', chat, config: { budgetMs: 30_000 } });
    expect(r.state).toBe('stalled');
    expect(r.completion).toBeNull();
  });
});
