import { afterEach, describe, expect, it } from 'vitest';
import type { AgentLoop, AgentResult } from '../agent/index.js';
import {
  OperatorCell,
  resetOperatorOverride,
  setOperatorOverride,
} from '../operators/index.js';

const task = {
  id: 'profile-refresh-task',
  missionId: 'profile-refresh-mission',
  name: 'Profile refresh boundary',
  description: 'Exercise the operator profile refresh boundary.',
  phase: 'reconnaissance' as const,
  operatorType: 'recon' as const,
  status: 'pending' as const,
  priority: 1,
  dependencies: [],
  createdAt: Date.now(),
};

const result: AgentResult = {
  success: true,
  summary: 'done',
  steps: [],
  findings: [],
  iterations: 1,
  tokensUsed: 0,
  durationMs: 1,
  hitLimit: false,
};

afterEach(() => {
  resetOperatorOverride('recon');
});

describe('live operator profile refresh', () => {
  it('updates idle matching operators immediately and future spawns inherit the revision', () => {
    resetOperatorOverride('recon');
    const cell = new OperatorCell();
    const existing = cell.spawnOperator('Existing Recon', 'recon');

    setOperatorOverride('recon', { systemPrompt: 'REVISED-RECON-PROFILE' });
    const application = cell.refreshOperatorProfiles('recon');
    const future = cell.spawnOperator('Future Recon', 'recon');

    expect(application).toMatchObject({
      policy: 'idle-now-active-next-task',
      appliedOperatorIds: [existing.id],
      deferredOperatorIds: [],
      futureSpawns: true,
    });
    expect(existing.profile.systemPrompt).toBe('REVISED-RECON-PROFILE');
    expect(future.profile.systemPrompt).toBe('REVISED-RECON-PROFILE');
    expect(existing.getSummary()).toMatchObject({
      profileRevision: application.revision,
      pendingProfileRevision: null,
    });
  });

  it('defers an executing operator until the task boundary without changing its in-flight profile', async () => {
    resetOperatorOverride('recon');
    const cell = new OperatorCell();
    const operator = cell.spawnOperator('Busy Recon', 'recon', { cooldownMs: 0 }, {} as never);
    const originalPrompt = operator.profile.systemPrompt;

    let finishRun!: (value: AgentResult) => void;
    const runningLoop = {
      on: () => runningLoop,
      off: () => runningLoop,
      run: () => new Promise<AgentResult>(resolve => { finishRun = resolve; }),
    } as unknown as AgentLoop;
    operator.attachArsenal({} as never, runningLoop);

    const execution = operator.assignTask(task as never);
    await Promise.resolve();
    expect(operator.status).toBe('executing');

    setOperatorOverride('recon', { systemPrompt: 'NEXT-TASK-RECON-PROFILE' });
    const application = cell.refreshOperatorProfiles('recon');

    expect(application.appliedOperatorIds).toEqual([]);
    expect(application.deferredOperatorIds).toEqual([operator.id]);
    expect(operator.profile.systemPrompt).toBe(originalPrompt);
    expect(operator.getSummary().pendingProfileRevision).toBe(application.revision);

    finishRun(result);
    await execution;

    expect(operator.status).toBe('idle');
    expect(operator.profile.systemPrompt).toBe('NEXT-TASK-RECON-PROFILE');
    expect(operator.getSummary()).toMatchObject({
      profileRevision: application.revision,
      pendingProfileRevision: null,
    });
  });

  it('applies reset through the same immediate/deferred contract', () => {
    setOperatorOverride('recon', { systemPrompt: 'CUSTOM-RECON-PROFILE' });
    const cell = new OperatorCell();
    const operator = cell.spawnOperator('Reset Recon', 'recon');

    resetOperatorOverride('recon');
    const application = cell.refreshOperatorProfiles('recon');

    expect(application.appliedOperatorIds).toEqual([operator.id]);
    expect(operator.profile.systemPrompt).not.toBe('CUSTOM-RECON-PROFILE');
    expect(operator.getSummary().profileRevision).toBe(application.revision);
  });
});
