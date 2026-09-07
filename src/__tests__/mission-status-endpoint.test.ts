import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { createRequire } from 'node:module';
const ts: typeof import('typescript') = createRequire(import.meta.url)('typescript');
import { expect, it, vi } from 'vitest';
import { MissionControl } from '../mission/index.js';

it('returns the requested completed mission after active identity clears, without selecting unrelated history', () => {
  const source = readFileSync('src/server.ts', 'utf8');
  const start = source.indexOf("app.get('/api/mission/status'");
  const route = source.slice(start, source.indexOf('\n});', start) + 4);
  const app = { get: vi.fn() };
  const mission = new MissionControl();
  const previous = mission.createMission({ name: 'previous', description: '', objectives: [] });
  mission.startMission(previous.id);
  mission.completeMission(previous.id);
  const current = mission.createMission({ name: 'current', description: '', objectives: [] });
  mission.startMission(current.id);
  const cmd = { mission, getStatus: () => ({ running: !!mission.getActiveMission() }), vault: { getAllFindings: () => [] }, cell: { getAllOperators: () => [] } };
  vm.runInNewContext(ts.transpileModule(route, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText, { app, getTempestCommand: () => cmd });
  const handler = app.get.mock.calls[0][1];
  const response = { json: vi.fn() };
  handler({ query: { missionId: current.id } }, response);
  expect(response.json).toHaveBeenLastCalledWith(expect.objectContaining({ active: true, mission: expect.objectContaining({ id: current.id, status: 'active' }) }));
  mission.completeMission(current.id);
  handler({ query: { missionId: current.id } }, response);
  expect(response.json).toHaveBeenLastCalledWith(expect.objectContaining({ active: false, mission: expect.objectContaining({ id: current.id, status: 'completed' }) }));
  handler({ query: { missionId: 'unrelated-run' } }, response);
  expect(response.json).toHaveBeenLastCalledWith(expect.objectContaining({ active: false, mission: null }));
  handler({ query: {} }, response);
  expect(response.json).toHaveBeenLastCalledWith(expect.objectContaining({ active: false, mission: null }));
});


it('returns a configuration error before mission mutation when backend resolution throws', async () => {
  const source = readFileSync('src/server.ts', 'utf8');
  const start = source.indexOf("app.post('/api/mission/start'");
  const route = source.slice(start, source.indexOf('  const effectiveKey', start)) + '\n});';
  const app = { post: vi.fn() };
  const resolveGeneralLLMConfig = vi.fn(() => { throw new Error('No configured provider'); });
  vm.runInNewContext(ts.transpileModule(route, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText, { app, resolveGeneralLLMConfig });
  const response = { status: vi.fn().mockReturnThis(), json: vi.fn() };
  await app.post.mock.calls[0][1]({ body: { targets: ['localhost'] } }, response);
  expect(response.status).toHaveBeenCalledWith(400);
  expect(response.json).toHaveBeenCalledWith({ error: 'LLM backend not configured — configure a provider or connect a supported local agent' });
});
