/**
 * Venice provider — OpenRouter-parity wiring.
 * Venice is OpenAI-compatible, so it plugs in everywhere OpenRouter does: the LLMProvider
 * union, the config key/provider block, getLLMConfig, the fallback ladder, and a
 * VeniceAdapter that reuses the OpenRouter adapter with Venice's base URL. This pins that
 * the provider resolves end-to-end so a refactor can't silently drop it.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { config, AVAILABLE_MODELS } from '../config/index.js';
import { createVeniceBackbone } from '../llm/index.js';

const KEY = 'venice-key-abcdef123456';

describe('Venice provider wiring (parity with OpenRouter)', () => {
  afterEach(() => { delete process.env.VENICE_API_KEY; });

  it('resolves the Venice base URL + default model + key from VENICE_API_KEY', () => {
    process.env.VENICE_API_KEY = KEY;
    const cfg = config.getLLMConfig('venice');
    expect(cfg.provider).toBe('venice');
    expect(cfg.baseUrl).toBe('https://api.venice.ai/api/v1');
    expect(cfg.model).toBe('llama-3.3-70b');
    expect(cfg.apiKey).toBe(KEY);
  });

  it('the Venice backbone validates and reports the venice provider', () => {
    process.env.VENICE_API_KEY = KEY;
    const bb = createVeniceBackbone();
    expect(bb.getProvider()).toBe('venice');
    expect(bb.validateConfig().valid).toBe(true);
  });

  it('surfaces venice in AVAILABLE_MODELS and getConfiguredProviders', () => {
    process.env.VENICE_API_KEY = KEY;
    expect(AVAILABLE_MODELS.venice?.length).toBeGreaterThan(0);
    expect(config.getConfiguredProviders()).toContain('venice');
  });
});
