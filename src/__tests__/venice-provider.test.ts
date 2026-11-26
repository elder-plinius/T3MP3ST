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
    expect(cfg.model).toBe('qwen-3-8-27b');
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

  // The static catalog offered `venice-uncensored` for months; Venice serves no such tag, so it
  // was a choice that failed at call time. A retired id is worse than a missing one — the panel
  // looks complete and the failure only appears on a live mission.
  it('offers only real venice model tags (no retired bare venice-uncensored)', () => {
    const ids = (AVAILABLE_MODELS.venice || []).map(m => m.id);
    expect(ids).not.toContain('venice-uncensored');
    // The tags Venice actually serves for the uncensored family.
    expect(ids).toContain('venice-uncensored-1-2');
    expect(ids).toContain('venice-uncensored-role-play');
  });

  it('does not advertise tool-calling on a model that cannot call tools', () => {
    // venice-uncensored-1-2 accepts a tools array but returns an empty tool_calls array.
    const flagged = (AVAILABLE_MODELS.venice || []).filter(m => m.capabilities.includes('tools'));
    expect(flagged.map(m => m.id)).not.toContain('venice-uncensored-1-2');
  });
});
