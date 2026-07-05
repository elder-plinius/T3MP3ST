/**
 * Operator lifecycle races. Two independent defects both stem from a tracked async promise whose late
 * settle mutates shared operator state:
 *  - a cleared cooldown must still settle its awaiting assignTask (no leaked pending promise), and
 *  - a dispatch reaped by the backstop must not, when it finally settles, corrupt the operator that has
 *    since been re-dispatched a new task.
 */
import { describe, it, expect, vi } from 'vitest';
import { createOperator } from '../operators/index.js';
import { LLMBackbone } from '../llm/index.js';
import { Arsenal } from '../arsenal/index.js';
import type { AgentLoop } from '../agent/index.js';
import type { AgentResult } from '../agent/index.js';

const CFG = { maxDetectionRisk: 0.8, cooldownMs: 100_000, maxRetries: 0, preferredTechniques: [], avoidTechniques: [], toolPreferences: [] };
const llm = () => new LLMBackbone({ provider: 'mock', model: 'mock-model' });
const okResult: AgentResult = { success: true, summary: 'ok', steps: [], findings: [], iterations: 1, tokensUsed: 0, durationMs: 0, hitLimit: false };
const fastLoop = () => ({ run: async () => okResult } as unknown as AgentLoop);
const task = (id: string) => ({ id, missionId: 'm', name: 'r', description: 'scan x', phase: 'reconnaissance', operatorType: 'recon', status: 'pending', priority: 1, dependencies: [], createdAt: 1 } as any);

describe('operator cooldown-resolve (no leaked promise)', () => {
  it('abortActiveTask settles a parked cooldown so assignTask resolves instead of hanging', async () => {
    const op = createOperator('Cool-1', 'recon', CFG, llm());
    op.attachArsenal(new Arsenal(), fastLoop());
    const p = op.assignTask(task('A')); // executes fast, then parks on the 100s cooldown timer
    await vi.waitFor(() => expect(op.status).toBe('cooldown'), { timeout: 1000 });
    op.abortActiveTask('interrupt'); // clears the timer — must also settle the awaiting promise
    await expect(p).resolves.toMatchObject({ success: true });
  });
});

describe('operator dispatch-epoch guard (late-settle race)', () => {
  it('a reaped dispatch that settles late does not double-count or corrupt the re-dispatched task', async () => {
    const op = createOperator('Race-1', 'recon', CFG, llm());
    // A slow loop we resolve on demand — simulates a task still running when the backstop reaps it.
    let release!: () => void;
    const slowLoop = { run: () => new Promise<AgentResult>((res) => { release = () => res(okResult); }) } as unknown as AgentLoop;
    op.attachArsenal(new Arsenal(), slowLoop);

    const pA = op.assignTask(task('A'));
    await vi.waitFor(() => expect(op.status).toBe('executing'), { timeout: 1000 });

    op.abortActiveTask('timeout'); // backstop reaps A: operator idle, dispatch epoch bumped
    expect(op.state.completedTasks).toBe(0);

    // Re-dispatch a NEW task B to the now-idle operator, which completes normally.
    op.attachArsenal(new Arsenal(), fastLoop());
    void op.assignTask(task('B'));
    await vi.waitFor(() => expect(op.status).toBe('cooldown'), { timeout: 1000 }); // B did its work
    expect(op.state.completedTasks).toBe(1); // B counted once

    // Now let A's original promise settle LATE. It must skip its shared-state mutations.
    release();
    await pA;
    expect(op.state.completedTasks).toBe(1); // A did NOT double-count
  });
});
