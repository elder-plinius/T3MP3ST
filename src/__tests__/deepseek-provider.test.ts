import { describe, expect, it, afterEach } from 'vitest';
import { config, AVAILABLE_MODELS } from '../config/index.js';
import { createDeepSeekBackbone } from '../llm/index.js';

const KEY = 'deepseek-key-abcdef123456';

describe('DeepSeek provider wiring (#62)', () => {
  afterEach(() => { delete process.env.DEEPSEEK_API_KEY; });

  it('resolves DeepSeek base URL, default model, and key from DEEPSEEK_API_KEY', () => {
    process.env.DEEPSEEK_API_KEY = KEY;
    const cfg = config.getLLMConfig('deepseek');
    expect(cfg.provider).toBe('deepseek');
    expect(cfg.baseUrl).toBe('https://api.deepseek.com');
    expect(cfg.model).toBe('deepseek-v4-pro');
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
});
