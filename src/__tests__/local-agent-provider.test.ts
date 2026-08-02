import { describe, expect, it } from 'vitest';
import { config, AVAILABLE_MODELS } from '../config/index.js';

// Regression guard for #118: getLLMConfig had no `case 'local-agent'`, so it fell
// through to `default` and threw `Unknown provider: local-agent`, aborting every
// keyless (connected-agent) mission. These assertions fail if that case is removed.
describe("local-agent provider wiring (#118)", () => {
  it('resolves a keyless config for local-agent with the agent id carried in model', () => {
    const cfg = config.getLLMConfig('local-agent', 'claude');
    expect(cfg.provider).toBe('local-agent');
    expect(cfg.model).toBe('claude');
    // Keyless: the connected CLI agent uses its own login — no API key or base URL.
    expect(cfg.apiKey).toBeUndefined();
    expect(cfg.baseUrl).toBeUndefined();
  });

  it('preserves any supported agent id passed as the model', () => {
    for (const agent of ['codex', 'claude', 'hermes', 'opencode', 'omp']) {
      const cfg = config.getLLMConfig('local-agent', agent);
      expect(cfg.provider).toBe('local-agent');
      expect(cfg.model).toBe(agent);
      expect(cfg.apiKey).toBeUndefined();
      expect(cfg.baseUrl).toBeUndefined();
    }
  });

  it('falls back to the default agent id when no model is given', () => {
    const cfg = config.getLLMConfig('local-agent');
    expect(cfg.provider).toBe('local-agent');
    expect(cfg.model).toBe('claude');
    expect(cfg.apiKey).toBeUndefined();
    expect(cfg.baseUrl).toBeUndefined();
  });

  it('does not throw "Unknown provider" for local-agent', () => {
    expect(() => config.getLLMConfig('local-agent')).not.toThrow();
  });

  it('surfaces the connected-agent ids as available local-agent models', () => {
    expect(AVAILABLE_MODELS['local-agent']?.map(m => m.id)).toEqual(
      expect.arrayContaining(['codex', 'claude', 'hermes', 'opencode', 'omp']),
    );
  });
});
