import { describe, expect, it, afterEach } from 'vitest';
import {
  config,
  AVAILABLE_MODELS,
} from '../config/index.js';
import { createOrcaRouterBackbone } from '../llm/index.js';

const KEY = 'orcarouter-key-abcdef123456';

describe('OrcaRouter provider wiring', () => {
  afterEach(() => { delete process.env.ORCAROUTER_API_KEY; });

  it('resolves OrcaRouter base URL, default model, and key from ORCAROUTER_API_KEY', () => {
    process.env.ORCAROUTER_API_KEY = KEY;
    const cfg = config.getLLMConfig('orcarouter');
    expect(cfg.provider).toBe('orcarouter');
    expect(cfg.baseUrl).toBe('https://api.orcarouter.ai/v1');
    expect(cfg.model).toBe('anthropic/claude-sonnet-4.6');
    expect(cfg.apiKey).toBe(KEY);
  });

  it('routes through the OpenAI-compatible backbone and validates with a key', () => {
    process.env.ORCAROUTER_API_KEY = KEY;
    const bb = createOrcaRouterBackbone();
    expect(bb.getProvider()).toBe('orcarouter');
    expect(bb.validateConfig().valid).toBe(true);
  });

  it('surfaces OrcaRouter models and configured provider state', () => {
    process.env.ORCAROUTER_API_KEY = KEY;
    expect(AVAILABLE_MODELS.orcarouter?.map(m => m.id)).toEqual(
      expect.arrayContaining(['anthropic/claude-sonnet-4.6', 'openai/gpt-5.4-mini']),
    );
    expect(config.getConfiguredProviders()).toContain('orcarouter');
  });

  it('respects a custom model override through the backbone', () => {
    process.env.ORCAROUTER_API_KEY = KEY;
    const cfg = config.getLLMConfig('orcarouter', 'openai/gpt-5.4-mini');
    expect(cfg.model).toBe('openai/gpt-5.4-mini');
  });
});
