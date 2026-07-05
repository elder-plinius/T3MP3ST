/**
 * Tasks are routed to targets by an explicit target address, not by substring-matching the free-text
 * description. Two targets where one address is a prefix of another (10.0.0.1 vs 10.0.0.10 — universal
 * in a /24 sweep) must each be fully seeded and not conflated.
 */
import { describe, it, expect } from 'vitest';
import { MissionControl } from '../mission/index.js';

describe('multi-target task seeding (prefix-collision safety)', () => {
  it('seeds tasks for a target whose address is a prefix of an already-seeded target', () => {
    const mc = new MissionControl();
    const m = mc.createMission({ name: 'Sweep', description: 'x', objectives: ['enumerate'] });
    mc.startMission(m.id);

    mc.generateTasksForTarget('10.0.0.10');
    mc.generateTasksForTarget('10.0.0.1'); // prefix of 10.0.0.10 — must NOT be deduped away

    const tasks = mc.getTaskQueue()!.getForMission(m.id);
    expect(tasks.some(t => t.targetAddress === '10.0.0.10')).toBe(true);
    expect(tasks.some(t => t.targetAddress === '10.0.0.1')).toBe(true);
  });
});
