/**
 * REGRESSION COVERAGE for PR #127 review:
 *  1. The keyless mission path (provider:'local-agent') must be self-contained — ConfigManager
 *     .getLLMConfig needs a `local-agent` case, or getLLMConfig('local-agent') throws and missions
 *     dead-end. (Finding 1.)
 *  2. Pin precedence + model passthrough must be consistent across EVERY dispatch surface (mission,
 *     General, Admiral): an explicit pin outranks a stored API key, and the picked local model rides
 *     along as "agentId::model" instead of being dropped. All three surfaces route through the ONE
 *     centralized resolver `window.t3mpDispatchAgent`. (Finding 2.)
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { config } from '../config/index.js';

// ─────────────────────────────────────────────────────────────────────────────
// Finding 1 — getLLMConfig('local-agent') is self-contained (no throw, keyless)
// ─────────────────────────────────────────────────────────────────────────────
describe('getLLMConfig — local-agent case (keyless mission path is self-contained)', () => {
  it('resolves provider:local-agent with the agent id in model and no API key', () => {
    const cfg = config.getLLMConfig('local-agent', 'claude');
    expect(cfg.provider).toBe('local-agent');
    expect(cfg.model).toBe('claude');
    expect(cfg.apiKey).toBeUndefined();
  });

  it('passes an "agentId::model" spec through untouched (LocalAgentAdapter splits it later)', () => {
    const cfg = config.getLLMConfig('local-agent', 'claude::opus');
    expect(cfg.provider).toBe('local-agent');
    expect(cfg.model).toBe('claude::opus');
  });

  it('preserves the established claude default when none is supplied (no throw)', () => {
    expect(() => config.getLLMConfig('local-agent')).not.toThrow();
    expect(config.getLLMConfig('local-agent').model).toBe('claude');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Finding 2 (behavior) — the centralized resolver window.t3mpDispatchAgent, evaluated
// from the shipped docs/index.html source with its closure deps injected.
// ─────────────────────────────────────────────────────────────────────────────
const uiSource = readFileSync(join(process.cwd(), 'docs/index.html'), 'utf8');

function loadDispatchAgent(deps: {
  getActiveAgent: () => string;
  preferredAgent: () => string | null;
  agentModelFor: (id: string) => string | undefined;
}) {
  const marker = 'window.t3mpDispatchAgent = ';
  const start = uiSource.indexOf(marker);
  expect(start, 'window.t3mpDispatchAgent must be defined in docs/index.html').toBeGreaterThanOrEqual(0);
  const fnStart = uiSource.indexOf('function', start);
  const end = uiSource.indexOf('\n  };', fnStart); // the 2-space-indented closer inside the IIFE
  expect(end, 'could not find the end of t3mpDispatchAgent').toBeGreaterThan(fnStart);
  const funcExpr = uiSource.slice(fnStart, end) + '\n  }';
  const factory = new Function('getActiveAgent', 'preferredAgent', 'agentModelFor', `return (${funcExpr});`);
  return factory(deps.getActiveAgent, deps.preferredAgent, deps.agentModelFor) as (apiKey?: string) => { id: string; model: string } | null;
}

function loadIntegratedDispatch(deps: {
  connectedIds: string[];
  pingStatus: Record<string, { ok: boolean }>;
  serverAgents?: Array<{ id: string; lastPing?: { ok: boolean } }>;
  pinned: string;
}) {
  const start = uiSource.indexOf('function preferredAgent(){');
  const marker = 'window.t3mpDispatchAgent = ';
  const dispatchStart = uiSource.indexOf(marker, start);
  const end = uiSource.indexOf('\n  };', dispatchStart);
  expect(start).toBeGreaterThanOrEqual(0);
  expect(dispatchStart).toBeGreaterThan(start);
  expect(end).toBeGreaterThan(dispatchStart);

  const source = uiSource.slice(start, end + '\n  };'.length);
  const windowState = { __t3mpServerAgents: deps.serverAgents };
  const factory = new Function(
    'connectedIds',
    'pingStatus',
    'window',
    'getActiveAgent',
    'agentModelFor',
    `${source}; return window.t3mpDispatchAgent;`,
  );
  return factory(
    deps.connectedIds,
    deps.pingStatus,
    windowState,
    () => deps.pinned,
    () => undefined,
  ) as (apiKey?: string) => { id: string; model: string } | null;
}

describe('t3mpDispatchAgent — pin precedence + model passthrough (shared by mission/General/Admiral)', () => {
  it('an explicit pin OUTRANKS a stored API key', () => {
    const fn = loadDispatchAgent({ getActiveAgent: () => 'claude', preferredAgent: () => 'claude', agentModelFor: () => undefined });
    const r = fn('sk-or-v1-storedkey-should-not-win');
    expect(r).not.toBeNull();
    expect(r!.id).toBe('claude');
  });

  it('encodes the picked model as "agentId::model" so it is never dropped', () => {
    const fn = loadDispatchAgent({ getActiveAgent: () => 'claude', preferredAgent: () => 'claude', agentModelFor: (id) => (id === 'claude' ? 'opus' : undefined) });
    expect(fn('')!.model).toBe('claude::opus');
  });

  it('a bare agent (no picked model) yields just the agent id', () => {
    const fn = loadDispatchAgent({ getActiveAgent: () => 'codex', preferredAgent: () => 'codex', agentModelFor: () => undefined });
    expect(fn('')!.model).toBe('codex');
  });

  it('with no pin and no key, falls back to the auto-preferred agent', () => {
    const fn = loadDispatchAgent({ getActiveAgent: () => '', preferredAgent: () => 'hermes', agentModelFor: () => undefined });
    expect(fn('')!.id).toBe('hermes');
  });

  it('with a key and NO pin, returns null (defers to the keyed provider chain)', () => {
    const fn = loadDispatchAgent({ getActiveAgent: () => '', preferredAgent: () => 'codex', agentModelFor: () => undefined });
    expect(fn('sk-ant-somekey')).toBeNull();
  });

  it('honors the pin only when it is the live/preferred agent (stale pin defers to preferred)', () => {
    const fn = loadDispatchAgent({ getActiveAgent: () => 'claude', preferredAgent: () => 'codex', agentModelFor: () => undefined });
    // pinned claude is not the preferred (e.g. not live) and no key → falls back to preferred codex
    expect(fn('')!.id).toBe('codex');
  });

  it('does not let a connected-but-stale pin displace a working keyed provider', () => {
    const fn = loadIntegratedDispatch({
      connectedIds: ['claude'],
      pingStatus: { claude: { ok: false } },
      pinned: 'claude',
    });
    expect(fn('sk-or-working-provider')).toBeNull();
  });

  it('lets a live pin deliberately outrank a stored key', () => {
    const fn = loadIntegratedDispatch({
      connectedIds: ['claude'],
      pingStatus: { claude: { ok: true } },
      pinned: 'claude',
    });
    expect(fn('sk-or-working-provider')!.id).toBe('claude');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Finding 2 (centralization invariant) — every dispatch surface uses t3mpDispatchAgent
// ─────────────────────────────────────────────────────────────────────────────
function fnBody(name: string, closer: string): string {
  const start = uiSource.indexOf(name);
  expect(start, `missing ${name}`).toBeGreaterThanOrEqual(0);
  const end = uiSource.indexOf(closer, start);
  expect(end, `missing closer for ${name}`).toBeGreaterThan(start);
  return uiSource.slice(start, end);
}

describe('dispatch surfaces are centralized on t3mpDispatchAgent', () => {
  it('the General resolver (getGeneralConfig) routes through t3mpDispatchAgent', () => {
    expect(fnBody('function getGeneralConfig()', '\n        }')).toContain('t3mpDispatchAgent');
  });

  it('the Admiral resolver (_admBackbone) routes through t3mpDispatchAgent', () => {
    expect(fnBody('function _admBackbone()', '\n  }')).toContain('t3mpDispatchAgent');
  });

  it('the mission BACKEND DISPATCH block routes through t3mpDispatchAgent', () => {
    expect(fnBody('BACKEND DISPATCH: Use real operators', 'BackendDispatch.startMission')).toContain('t3mpDispatchAgent');
  });

  it('t3mpDispatchAgent is defined once and used by all three surfaces', () => {
    const uses = (uiSource.match(/t3mpDispatchAgent/g) || []).length;
    expect(uses).toBeGreaterThanOrEqual(4); // 1 definition + 3 call sites
  });
});
