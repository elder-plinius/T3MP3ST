import { describe, expect, it, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { getSpec, childEnv, authState } from '../agent/local-agents.js';
import { getLLMConfig } from '../config/index.js';

// Behavioral coverage for the kimi local-agent adapter (complements the static
// invariants in local-agent-kimi-static.test.ts). Exercises the REAL functions:
// argv construction, spawned-env sanitization, auth detection semantics, and
// getLLMConfig resolution — the failure classes the static file cannot see.

const TOUCHED = [
  'KIMI_MODEL_NAME', 'KIMI_MODEL_API_KEY', 'KIMI_MODEL_BASE_URL', 'KIMI_MODEL_PROVIDER_TYPE',
  'TEMPEST_TARGET_HEADERS', 'TEMPEST_LOCAL_API_KEY', 'KIMI_CODE_HOME', 'T3MP3ST_LOCAL_AGENT_TIMEOUT_MS',
] as const;
const saved = new Map<string, string | undefined>(TOUCHED.map((k) => [k, process.env[k]]));
afterEach(() => {
  for (const k of TOUCHED) {
    const v = saved.get(k);
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
});

describe('kimi oneShot argv', () => {
  it('builds the verified headless argv (prompt as -p value, text output)', () => {
    const spec = getSpec('kimi');
    expect(spec).toBeDefined();
    expect(spec!.oneShot('PROMPT')).toEqual(['-p', 'PROMPT', '--output-format', 'text']);
  });

  it('passes a real CLI model alias via -m, never the agent id by default', () => {
    const spec = getSpec('kimi')!;
    expect(spec.oneShot('PROMPT', 'kimi-code/k3')).toEqual([
      '-p', 'PROMPT', '--output-format', 'text', '-m', 'kimi-code/k3',
    ]);
  });
});

describe('childEnv sanitization', () => {
  it('strips the KIMI_MODEL_* credential channel and t3mp3st secret config', () => {
    process.env.KIMI_MODEL_NAME = 'kimi-for-coding';
    process.env.KIMI_MODEL_API_KEY = 'sk-test-credential';
    process.env.KIMI_MODEL_BASE_URL = 'https://api.example.com/v1';
    process.env.KIMI_MODEL_PROVIDER_TYPE = 'kimi';
    process.env.TEMPEST_TARGET_HEADERS = '{"Authorization":"Bearer target-secret"}';
    process.env.TEMPEST_LOCAL_API_KEY = 'local-secret';

    const env = childEnv();
    for (const k of [
      'KIMI_MODEL_NAME', 'KIMI_MODEL_API_KEY', 'KIMI_MODEL_BASE_URL', 'KIMI_MODEL_PROVIDER_TYPE',
      'TEMPEST_TARGET_HEADERS', 'TEMPEST_LOCAL_API_KEY',
    ]) {
      expect(env[k], `${k} must not reach the spawned CLI`).toBeUndefined();
    }
    // HOME stays pinned to the real agent home so the CLI finds its own login.
    expect(env.HOME).toBeTruthy();
  });
});

describe('authState with KIMI_CODE_HOME', () => {
  it('treats a relocated data root as a full replacement (dir with only mcp/ is NOT authed)', () => {
    const spec = getSpec('kimi')!;
    const dir = mkdtempSync(join(tmpdir(), 'kimi-home-'));
    try {
      process.env.KIMI_CODE_HOME = dir;
      expect(authState(spec).authed).toBe(false);

      mkdirSync(join(dir, 'credentials', 'mcp'), { recursive: true });
      expect(authState(spec).authed).toBe(false);

      writeFileSync(join(dir, 'credentials', 'kimi-code.json'), '{}');
      expect(authState(spec)).toEqual({ authed: true, method: 'file' });
    } finally {
      delete process.env.KIMI_CODE_HOME;
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('getLLMConfig local-agent resolution', () => {
  it('resolves the agent id keylessly with the 600s default timeout', () => {
    delete process.env.T3MP3ST_LOCAL_AGENT_TIMEOUT_MS;
    const cfg = getLLMConfig('local-agent', 'kimi');
    expect(cfg.provider).toBe('local-agent');
    expect(cfg.model).toBe('kimi');
    expect(cfg.apiKey).toBeUndefined();
    expect(cfg.baseUrl).toBeUndefined();
    expect(cfg.timeout).toBeGreaterThanOrEqual(600000);
  });

  it('honors an explicit operator timeout override (any positive value wins)', () => {
    process.env.T3MP3ST_LOCAL_AGENT_TIMEOUT_MS = '300000';
    expect(getLLMConfig('local-agent', 'kimi').timeout).toBe(300000);
  });
});
