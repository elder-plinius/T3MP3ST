import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { createRequire } from 'node:module';
const ts: typeof import('typescript') = createRequire(import.meta.url)('typescript');
import { expect, it, vi } from 'vitest';
import { MissionControl } from '../mission/index.js';
import { resolveMissionLaunchConfig, resolveMissionStatus } from '../mission/http-lifecycle.js';

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
  vm.runInNewContext(ts.transpileModule(route, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText, { app, getTempestCommand: () => cmd, resolveMissionStatus });
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
  vm.runInNewContext(ts.transpileModule(route, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText, { app, resolveGeneralLLMConfig, resolveMissionLaunchConfig });
  const response = { status: vi.fn().mockReturnThis(), json: vi.fn() };
  await app.post.mock.calls[0][1]({ body: { targets: ['localhost'] } }, response);
  expect(response.status).toHaveBeenCalledWith(400);
  expect(response.json).toHaveBeenCalledWith({ error: 'LLM backend not configured — configure a provider or connect a supported local agent' });
});


it('preserves configured defaults and forwards an explicit local URL without injecting one', () => {
  const config = { provider: 'local', model: 'local-model' };
  const resolve = vi.fn(() => config);
  expect(resolveMissionLaunchConfig({}, resolve)).toEqual({ ok: true, config });
  expect(resolve).toHaveBeenLastCalledWith(undefined, undefined, undefined);
  const selection = { provider: 'local', model: 'chosen', apiKey: 'request-key', baseUrl: 'http://127.0.0.1:8080' };
  expect(resolveMissionLaunchConfig(selection, resolve)).toEqual({ ok: true, config });
  expect(resolve).toHaveBeenLastCalledWith('local', 'chosen', 'request-key', 'http://127.0.0.1:8080');
});

it('turns thrown configuration errors into a sanitized failure result', () => {
  const result = resolveMissionLaunchConfig({}, () => { throw new Error('secret credential'); });
  expect(result).toEqual({ ok: false, error: 'LLM backend not configured — configure a provider or connect a supported local agent' });
  expect(JSON.stringify(result)).not.toContain('secret credential');
});

it('retains terminal identity without falling back to a different active mission', () => {
  const missions = new MissionControl();
  const completed = missions.createMission({ name: 'completed', description: '', objectives: [] });
  missions.startMission(completed.id);
  missions.completeMission(completed.id);
  expect(resolveMissionStatus(missions, completed.id)?.status).toBe('completed');
  expect(resolveMissionStatus(missions, undefined)).toBeUndefined();
  const active = missions.createMission({ name: 'active', description: '', objectives: [] });
  missions.startMission(active.id);
  expect(resolveMissionStatus(missions, completed.id)?.id).toBe(completed.id);
  expect(resolveMissionStatus(missions, undefined)?.id).toBe(active.id);
  expect(resolveMissionStatus(missions, ['malformed', 'query'])?.id).toBe(active.id);
  expect(resolveMissionStatus(missions, 'missing-run')).toBeUndefined();
});
