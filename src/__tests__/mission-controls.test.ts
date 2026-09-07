import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { afterEach, describe, expect, it, vi } from 'vitest';

const html = readFileSync('docs/index.html', 'utf8');
function harness(backend = true) {
  const elements = new Map<string, { textContent: string; style: Record<string, string>; disabled: boolean; onclick?: unknown }>();
  const element = (id: string) => {
    if (!elements.has(id)) elements.set(id, { textContent: '', style: {}, disabled: false });
    const node = elements.get(id);
    if (!node) throw new Error(`Missing element: ${id}`);
    return node;
  };
  const context = vm.createContext({
    document: { getElementById: element }, missionRunning: true,
    missionLifecycle: { backend, starting: false, pending: null }, missionTimer: null, missionStartTime: 1,
    setTimeout, clearTimeout, clearInterval, AbortController, fetch: vi.fn(), T3MP3ST_API: { baseUrl: '' },
    updateKillChain: vi.fn(), resetEngageUI: vi.fn(), addIntel: vi.fn(), toast: vi.fn(), confirm: () => true,
  });
  const dispatchStart = html.indexOf('            async missionRequest(endpoint,', html.indexOf('const BackendDispatch'));
  const dispatchEnd = html.indexOf('\n        };', dispatchStart);
  vm.runInContext(`var BackendDispatch = {${html.slice(dispatchStart, dispatchEnd)}};`, context);
  const controlsStart = html.indexOf('        async function controlMission(action)');
  vm.runInContext(html.slice(controlsStart, html.indexOf('        // Update mission timer', controlsStart)), context);
  return { context, element, dispatch: context.BackendDispatch, pause: () => context.pauseMission(), resume: () => context.resumeMission(), stop: () => context.abortMission(true) };
}

afterEach(() => vi.useRealTimers());

describe('mission control acknowledgements', () => {
  it('waits for stop acknowledgement, suppresses duplicates, and preserves running state on rejection', async () => {
    const h = harness();
    let resolve!: (value: unknown) => void;
    h.dispatch.stopMission = vi.fn(() => new Promise(done => { resolve = done; }));
    const pending = h.stop();
    expect(h.context.missionRunning).toBe(true);
    expect(h.element('cmdMissionStatus').textContent).toContain('awaiting confirmation');
    await h.stop();
    expect(h.dispatch.stopMission).toHaveBeenCalledTimes(1);
    resolve({ success: false, error: 'offline' });
    await pending;
    expect(h.context.missionRunning).toBe(true);
    expect(h.element('cmdMissionStatus').textContent).toContain('unconfirmed');
    h.dispatch.stopMission.mockResolvedValue({ success: true });
    await h.stop();
    expect(h.context.missionRunning).toBe(false);
    expect(h.element('cmdMissionStatus').textContent).toContain('in-flight work may finish');
  });

  it('awaits pause and resume and exposes a retry after a rejected control', async () => {
    const h = harness();
    h.dispatch.pauseMission = vi.fn().mockRejectedValueOnce(new Error('offline')).mockResolvedValue({ success: true });
    h.dispatch.resumeMission = vi.fn().mockResolvedValue({ success: true });
    await h.pause();
    expect(h.element('cmdMissionStatus').textContent).toContain('unconfirmed');
    expect(h.element('cmdPauseBtn').disabled).toBe(false);
    await h.pause();
    expect(h.element('cmdPauseBtn').textContent).toBe('▶');
    await h.resume();
    expect(h.element('cmdPauseBtn').textContent).toBe('⏸');
  });

  it('does not claim browser pause or dispatch controls while launch is pending', async () => {
    const h = harness(false);
    await h.pause();
    expect(h.context.toast).toHaveBeenCalledWith(expect.stringContaining('unavailable'), 'warning');
    h.context.missionLifecycle.starting = true;
    await h.stop();
    expect(h.context.missionRunning).toBe(true);
    h.context.missionLifecycle.starting = false;
    await h.stop();
    expect(h.context.missionRunning).toBe(false);
  });
});

describe('mission status polling', () => {
  it('rejects HTTP, transport, and malformed status responses instead of inventing completion', async () => {
    const h = harness();
    h.context.fetch.mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValueOnce({ ok: false, status: 503 })
      .mockResolvedValueOnce({ ok: true, json: async () => ({ error: 'missing status' }) });
    await expect(h.dispatch.getStatus()).rejects.toThrow('offline');
    await expect(h.dispatch.getStatus()).rejects.toThrow('503');
    await expect(h.dispatch.getStatus()).rejects.toThrow('Invalid mission status');
  });

  it('keeps stalled missions resumable, retries network errors, and waits for explicit inactivity', async () => {
    vi.useFakeTimers();
    const h = harness();
    h.dispatch.getStatus = vi.fn()
      .mockResolvedValueOnce({ active: true, paused: true, stallReason: 'provider unavailable' })
      .mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValueOnce({ active: true, paused: false })
      .mockResolvedValueOnce({ active: false, mission: { status: 'completed' } });
    const update = vi.fn();
    let finished = false;
    const result = h.dispatch.pollUntilComplete(update, 10).then((status: unknown) => { finished = true; return status; });
    await vi.advanceTimersByTimeAsync(0);
    expect(finished).toBe(false);
    expect(update).toHaveBeenCalledWith(expect.objectContaining({ paused: true }));
    await vi.advanceTimersByTimeAsync(10);
    expect(finished).toBe(false);
    expect(update).toHaveBeenCalledWith({ statusError: 'offline' });
    await vi.advanceTimersByTimeAsync(20);
    expect(await result).toEqual({ active: false, mission: { status: 'completed' } });
  });

  it('does not report completion while stop is pending or after stop is acknowledged', async () => {
    vi.useFakeTimers();
    const h = harness();
    h.dispatch.getStatus = vi.fn().mockResolvedValue({ active: false });
    let resolve!: (value: unknown) => void;
    h.dispatch.stopMission = vi.fn(() => new Promise(done => { resolve = done; }));
    const stop = h.stop();
    const update = vi.fn();
    const poll = h.dispatch.pollUntilComplete(update, 10);
    await vi.advanceTimersByTimeAsync(10);
    expect(update).not.toHaveBeenCalled();
    resolve({ success: true });
    await stop;
    await vi.advanceTimersByTimeAsync(10);
    expect(await poll).toBeNull();
    expect(h.element('cmdMissionStatus').textContent).toContain('scheduler stopped');
  });
});

it('discards an old polling response when a new run has taken ownership', async () => {
  const h = harness();
  let resolve!: (value: unknown) => void;
  h.dispatch.getStatus = vi.fn(() => new Promise(done => { resolve = done; }));
  const update = vi.fn();
  const poll = h.dispatch.pollUntilComplete(update, 10);
  h.context.missionLifecycle = { backend: true, pending: null, starting: false };
  resolve({ active: false, mission: { status: 'completed' } });
  expect(await poll).toBeNull();
  expect(update).not.toHaveBeenCalled();
});

it('times out a hung mission control and allows a retry without claiming it stopped', async () => {
  vi.useFakeTimers();
  const h = harness();
  h.context.fetch.mockImplementation((_url: string, options: { signal: AbortSignal }) => new Promise((_resolve, reject) => {
    options.signal.addEventListener('abort', () => reject(new Error('Request timed out')));
  }));
  h.dispatch.stopMission = () => h.dispatch.missionRequest('/api/mission/stop', 'POST');
  const result = h.stop();
  await vi.advanceTimersByTimeAsync(15000);
  expect(await result).toBe(false);
  expect(h.context.missionRunning).toBe(true);
  expect(h.context.missionLifecycle.pending).toBeNull();
  expect(h.element('cmdAbortBtn').disabled).toBe(false);
  expect(h.element('cmdMissionStatus').textContent).toContain('unconfirmed');
});

it('routes Abort to the backend after a General plan launches', async () => {
  const h = harness(false);
  Object.assign(h.context, {
    missionRunning: false, generalPlanData: { codename: 'local test' },
    getGeneralConfig: () => ({}), window: { t3mpHasBackend: () => true },
    _generalNormalizePlan: (plan: unknown) => plan, _generalIsStandalone: () => false, getApiBase: () => '',
  });
  h.context.fetch.mockResolvedValue({ ok: true, json: async () => ({ success: true, codename: 'local test' }) });
  const start = html.indexOf('        async function generalExecutePlan()');
  const end = html.indexOf('        async function generalFullAuto(', start);
  vm.runInContext(html.slice(start, end), h.context);
  await h.context.generalExecutePlan();
  h.dispatch.stopMission = vi.fn().mockResolvedValue({ success: true });
  await h.stop();
  expect(h.dispatch.stopMission).toHaveBeenCalledTimes(1);
  expect(h.context.missionRunning).toBe(false);
});

it('stops browser scheduling after an in-flight reasoning stage settles', async () => {
  const h = harness(false);
  let resolve!: (value: unknown) => void;
  const reason = vi.fn(() => new Promise(done => { resolve = done; }));
  const review = vi.fn();
  const onPhaseComplete = vi.fn();
  Object.assign(h.context, {
    MissionContext: { reset: vi.fn(), targets: [], getContextFor: () => ({}) },
    state: { operators: ['recon'] }, ReasoningEngine: { reason }, Tastemaker: { review },
  });
  const start = html.indexOf('            async runPipeline(target, options = {})');
  const end = html.indexOf('            // Adaptive collaboration selection based on phase characteristics', start);
  vm.runInContext(`var pipeline = { ${html.slice(start, end)} };`, h.context);
  Object.assign(h.context.pipeline, {
    phases: ['reconnaissance', 'scanning'], phaseAgents: { reconnaissance: ['recon'], scanning: ['recon'] },
    config: { collaborationMode: 'sequential', useTastemaker: true, maxRetries: 1 }, getPhaseTask: () => 'test',
  });
  let cancelled = false;
  const pending = h.context.pipeline.runPipeline('localhost', { isCancelled: () => cancelled, onPhaseComplete });
  cancelled = true;
  resolve({ response: 'late result' });
  expect(await pending).toEqual({ pipeline: [], cancelled: true });
  expect(reason).toHaveBeenCalledTimes(1);
  expect(review).not.toHaveBeenCalled();
  expect(onPhaseComplete).not.toHaveBeenCalled();
});
