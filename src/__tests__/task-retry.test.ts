import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { createRequire } from 'node:module';
const ts: typeof import('typescript') = createRequire(import.meta.url)('typescript');
import { describe, expect, it, vi } from 'vitest';
import { MAX_TASK_RETRIES, MissionControl, TaskQueue } from '../mission/index.js';
import { KillChainPhase, type Task } from '../types/index.js';

function makeTask(overrides: Partial<Task> = {}): Task {
  return {
    id: 'task-1',
    missionId: 'mission-1',
    name: 'Recon sweep',
    description: 'recon task',
    phase: KillChainPhase.RECON,
    operatorType: 'recon',
    status: 'pending',
    priority: 5,
    dependencies: [],
    createdAt: 1_000,
    ...overrides,
  };
}

describe('TaskQueue.retry', () => {
  it('resets a failed task to pending and clears its failure state', () => {
    const queue = new TaskQueue();
    const onRetried = vi.fn();
    queue.on('task:retried', onRetried);
    queue.add(makeTask());
    queue.assign('task-1', 'operator-1');
    queue.fail('task-1', 'dispatch timed out after 300s (backstop 300s)');

    const failed = queue.getTask('task-1');
    expect(failed?.status).toBe('failed');
    expect(failed?.result?.error).toContain('timed out');
    expect(failed?.completedAt).toBeTypeOf('number');
    // A failed task is terminal: nothing dispatches it again.
    expect(queue.getNext()).toBeUndefined();
    expect(queue.pendingCount).toBe(0);

    expect(queue.retry('task-1')).toBe(true);

    const retried = queue.getTask('task-1');
    expect(retried?.status).toBe('pending');
    expect(retried?.result).toBeUndefined();
    expect(retried?.assignedTo).toBeUndefined();
    expect(retried?.startedAt).toBeUndefined();
    expect(retried?.completedAt).toBeUndefined();
    expect(retried?.retryCount).toBe(1);
    expect(queue.getNext()?.id).toBe('task-1');
    expect(queue.pendingCount).toBe(1);
    expect(onRetried).toHaveBeenCalledTimes(1);
    expect(onRetried.mock.calls[0][0].id).toBe('task-1');
  });

  it('refuses to retry tasks that are not failed, and unknown ids', () => {
    const queue = new TaskQueue();
    queue.add(makeTask({ id: 'pending-task' }));
    queue.add(makeTask({ id: 'done-task' }));
    queue.complete('done-task', { success: true });

    expect(queue.retry('pending-task')).toBe(false);
    expect(queue.getTask('pending-task')?.status).toBe('pending');
    expect(queue.retry('done-task')).toBe(false);
    expect(queue.getTask('done-task')?.status).toBe('completed');
    expect(queue.retry('no-such-task')).toBe(false);
  });

  it('bounds retries: after MAX_TASK_RETRIES re-queues the task stays failed', () => {
    const queue = new TaskQueue();
    queue.add(makeTask());
    for (let attempt = 1; attempt <= MAX_TASK_RETRIES; attempt++) {
      queue.fail('task-1', `failure ${attempt}`);
      expect(queue.retry('task-1')).toBe(true);
      expect(queue.getTask('task-1')?.retryCount).toBe(attempt);
    }
    queue.fail('task-1', 'one failure too many');
    expect(queue.retry('task-1')).toBe(false);
    expect(queue.getTask('task-1')?.status).toBe('failed');
    expect(queue.pendingCount).toBe(0);
  });
});

describe('MissionControl.retryTask', () => {
  it('re-queues a failed task and forwards the task:retried event', () => {
    const control = new MissionControl();
    const onRetried = vi.fn();
    control.on('task:retried', onRetried);
    const queue = control.getTaskQueue();
    queue.add(makeTask());
    queue.fail('task-1', 'boom');

    expect(control.retryTask('task-1')).toBe(true);
    expect(queue.getTask('task-1')?.status).toBe('pending');
    expect(onRetried).toHaveBeenCalledTimes(1);
    expect(control.retryTask('task-1')).toBe(false);
  });
});

describe('POST /api/tasks/:id/retry', () => {
  function harness(cmd: unknown) {
    const source = readFileSync('src/server.ts', 'utf8');
    const start = source.indexOf("app.post('/api/tasks/:id/retry'");
    expect(start).toBeGreaterThan(-1);
    const route = source.slice(start, source.indexOf('\n});', start) + 4);
    const app = { post: vi.fn() };
    const broadcastEvent = vi.fn();
    vm.runInNewContext(
      ts.transpileModule(route, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText,
      { app, getTempestCommand: () => cmd, broadcastEvent },
    );
    const handler = app.post.mock.calls[0][1] as (req: unknown, res: unknown) => void;
    const call = (id: string) => {
      const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
      handler({ params: { id } }, res);
      return res;
    };
    return { call, broadcastEvent };
  }

  function fakeCommand() {
    const mission = new MissionControl();
    mission.getTaskQueue().add(makeTask());
    return {
      mission,
      retryTask: (taskId: string) => mission.retryTask(taskId),
    };
  }

  it('returns 404 when there is no active mission', () => {
    const { call } = harness(null);
    const res = call('task-1');
    expect(res.status).toHaveBeenCalledWith(404);
    expect(res.json).toHaveBeenCalledWith({ error: 'No active mission' });
  });

  it('returns 404 for an unknown task id', () => {
    const { call } = harness(fakeCommand());
    const res = call('nope');
    expect(res.status).toHaveBeenCalledWith(404);
    expect(res.json).toHaveBeenCalledWith({ error: 'Task not found' });
  });

  it('returns 409 for a task that is not failed', () => {
    const { call } = harness(fakeCommand());
    const res = call('task-1');
    expect(res.status).toHaveBeenCalledWith(409);
  });

  it('re-queues a failed task, broadcasts the retry, and returns the task as pending', () => {
    const cmd = fakeCommand();
    cmd.mission.getTaskQueue().fail('task-1', 'dispatch timed out after 300s (backstop 300s)');
    const { call, broadcastEvent } = harness(cmd);
    const res = call('task-1');
    expect(res.status).not.toHaveBeenCalled();
    expect(res.json).toHaveBeenCalledWith({
      success: true,
      task: expect.objectContaining({ id: 'task-1', status: 'pending', retryCount: 1 }),
    });
    expect(broadcastEvent).toHaveBeenCalledWith('task:retried', expect.objectContaining({ taskId: 'task-1', retryCount: 1 }));
    expect(cmd.mission.getTaskQueue().pendingCount).toBe(1);
  });
});
