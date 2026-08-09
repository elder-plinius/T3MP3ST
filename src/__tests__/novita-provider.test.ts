import { describe, expect, it, afterEach } from 'vitest';
import { config, AVAILABLE_MODELS } from '../config/index.js';
import { createNovitaBackbone } from '../llm/index.js';

const KEY = 'sk_novita-test-key-0123456789';

describe('Novita AI provider wiring', () => {
  afterEach(() => { delete process.env.NOVITA_API_KEY; });

  it('resolves the Novita base URL, default model, and key from NOVITA_API_KEY', () => {
    process.env.NOVITA_API_KEY = KEY;
    const cfg = config.getLLMConfig('novita');
    expect(cfg.provider).toBe('novita');
    expect(cfg.baseUrl).toBe('https://api.novita.ai/openai/v1');
    expect(cfg.model).toBe('zai-org/glm-5.2');
    expect(cfg.apiKey).toBe(KEY);
    expect(`${cfg.baseUrl}/chat/completions`).toBe(
      'https://api.novita.ai/openai/v1/chat/completions',
    );
  });

  it('routes through the OpenAI-compatible backbone and validates with a key', () => {
    process.env.NOVITA_API_KEY = KEY;
    const bb = createNovitaBackbone();
    expect(bb.getProvider()).toBe('novita');
    expect(bb.validateConfig().valid).toBe(true);
  });

  it('publishes a non-empty Novita model catalog and configured provider state', () => {
    process.env.NOVITA_API_KEY = KEY;
    expect(AVAILABLE_MODELS.novita?.length ?? 0).toBeGreaterThan(0);
    expect(config.getConfiguredProviders()).toContain('novita');
  });
});
