import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { TempestCommand } from '../index.js';

describe('TempestCommand resume behavior on stalled missions', () => {
  let cmd: TempestCommand;

  beforeEach(() => {
    cmd = new TempestCommand({
      name: 'Test Command',
      llm: { provider: 'mock', model: 'mock-model' },
    });
  });

  afterEach(() => {
    if (cmd) cmd.stop();
  });

  it('resets failed tasks in current phase and clears stallReason on resume', async () => {
    cmd.targetEnv.addTarget({
      address: '127.0.0.1:8080',
      name: 'Test Target',
      type: 'web_application',
      zone: 'external',
    });

    // @ts-expect-error accessing private method for test
    cmd.ensureMission();
    // @ts-expect-error accessing private property for test
    cmd.running = true;
    // @ts-expect-error accessing private method for test
    await cmd.tick();

    const mission = cmd.mission.getActiveMission();
    expect(mission).toBeDefined();

    const taskQueue = cmd.mission.getTaskQueue();
    expect(taskQueue).toBeDefined();

    // Mark current phase tasks as failed and clear in-flight dispatch set
    const tasks = taskQueue.getForMission(mission!.id);
    expect(tasks.length).toBeGreaterThan(0);
    for (const t of tasks) {
      taskQueue.fail(t.id, 'Test failure reason');
      // @ts-expect-error accessing private method for test
      cmd.clearDispatch(t.id);
    }

    // Trigger tick which detects all tasks failed and sets stallReason
    // @ts-expect-error accessing private method for test
    await cmd.tick();

    const statusStalled = cmd.getStatus();
    expect(statusStalled.paused).toBe(true);
    expect(statusStalled.stallReason).toContain('stalled in reconnaissance');

    // Operator clicks resume
    cmd.resume();

    const statusResumed = cmd.getStatus();
    expect(statusResumed.paused).toBe(false);
    expect(statusResumed.stallReason).toBeNull();

    // Verify failed tasks were reset to pending so they can be retried
    const pendingTasks = taskQueue.getPending();
    expect(pendingTasks.length).toBeGreaterThan(0);
    for (const t of pendingTasks) {
      expect(t.status).toBe('pending');
      expect(t.result).toBeUndefined();
    }
  });
});
