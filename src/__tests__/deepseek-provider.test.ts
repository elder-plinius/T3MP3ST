import { describe, expect, it, afterEach } from 'vitest';
import {
  config,
  AVAILABLE_MODELS,
  migrateLegacyDeepSeekSettings,
} from '../config/index.js';
import { createDeepSeekBackbone } from '../llm/index.js';

const KEY = 'deepseek-key-abcdef123456';

describe('DeepSeek provider wiring (#62)', () => {
  afterEach(() => { delete process.env.DEEPSEEK_API_KEY; });

  it('resolves DeepSeek base URL, supported migrated model, and key from DEEPSEEK_API_KEY', () => {
    process.env.DEEPSEEK_API_KEY = KEY;
    const cfg = config.getLLMConfig('deepseek');
    expect(cfg.provider).toBe('deepseek');
    expect(cfg.baseUrl).toBe('https://api.deepseek.com');
    expect(['deepseek-v4-flash', 'deepseek-v4-pro']).toContain(cfg.model);
    expect(cfg.apiKey).toBe(KEY);
  });

  it('routes through the OpenAI-compatible backbone and validates with a key', () => {
    process.env.DEEPSEEK_API_KEY = KEY;
    const bb = createDeepSeekBackbone();
    expect(bb.getProvider()).toBe('deepseek');
    expect(bb.validateConfig().valid).toBe(true);
  });

  it('surfaces native DeepSeek models and configured provider state', () => {
    process.env.DEEPSEEK_API_KEY = KEY;
    expect(AVAILABLE_MODELS.deepseek?.map(m => m.id)).toEqual(
      expect.arrayContaining(['deepseek-v4-flash', 'deepseek-v4-pro']),
    );
    expect(config.getConfiguredProviders()).toContain('deepseek');
  });

  it('migrates only retired DeepSeek defaults and preserves custom settings', () => {
    expect(migrateLegacyDeepSeekSettings({
      baseUrl: 'https://api.deepseek.com/v1',
      defaultModel: 'deepseek-chat',
    })).toEqual({
      baseUrl: 'https://api.deepseek.com',
      defaultModel: 'deepseek-v4-flash',
    });
    expect(migrateLegacyDeepSeekSettings({
      baseUrl: 'https://api.deepseek.com/v1',
      defaultModel: 'deepseek-reasoner',
    }).defaultModel).toBe('deepseek-v4-pro');
    expect(migrateLegacyDeepSeekSettings({
      baseUrl: 'https://gateway.example/v1',
      defaultModel: 'custom/deepseek',
    })).toEqual({
      baseUrl: 'https://gateway.example/v1',
      defaultModel: 'custom/deepseek',
    });
  });
});
