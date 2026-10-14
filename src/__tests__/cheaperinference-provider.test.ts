import { describe, expect, it, afterEach, vi } from 'vitest';
import { config, AVAILABLE_MODELS } from '../config/index.js';
import { createCheaperInferenceBackbone } from '../llm/index.js';

const KEY = 'ci_live_test-key-0123456789';

describe('Cheaper Inference provider wiring', () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    delete process.env.CHEAPERINFERENCE_API_KEY;
    delete process.env.TEMPEST_MODEL_FALLBACK;
    global.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it('resolves the Cheaper Inference base URL, default model, and key from CHEAPERINFERENCE_API_KEY', () => {
    process.env.CHEAPERINFERENCE_API_KEY = KEY;
    const cfg = config.getLLMConfig('cheaperinference');
    expect(cfg.provider).toBe('cheaperinference');
    expect(cfg.baseUrl).toBe('https://api.cheaperinference.com/v1');
    expect(cfg.model).toBe('gpt-5.4-mini');
    expect(cfg.apiKey).toBe(KEY);
    expect(`${cfg.baseUrl}/chat/completions`).toBe(
      'https://api.cheaperinference.com/v1/chat/completions',
    );
  });

  it('routes through the OpenAI-compatible backbone and validates with a key', () => {
    process.env.CHEAPERINFERENCE_API_KEY = KEY;
    const bb = createCheaperInferenceBackbone();
    expect(bb.getProvider()).toBe('cheaperinference');
    expect(bb.validateConfig().valid).toBe(true);
  });

  it('requires the provider-specific key instead of reporting an OpenAI credential error', () => {
    expect(createCheaperInferenceBackbone().validateConfig()).toEqual({
      valid: false,
      error: expect.stringContaining('CHEAPERINFERENCE_API_KEY'),
    });
  });

  it('sends chat to the Cheaper Inference endpoint with Bearer auth and the configured model', async () => {
    const fetchSpy = vi.fn(async (_url: string | URL, _init?: RequestInit) => ({
      ok: true,
      json: async () => ({
        model: 'gpt-5.4-mini',
        choices: [{ message: { content: 'ok' }, finish_reason: 'stop' }],
      }),
    }));
    global.fetch = fetchSpy as unknown as typeof fetch;

    const response = await createCheaperInferenceBackbone(KEY).chat([{ role: 'user', content: 'hello' }]);
    expect(response.content).toBe('ok');
    const [url, init] = fetchSpy.mock.calls[0];
    expect(url).toBe('https://api.cheaperinference.com/v1/chat/completions');
    expect((init as RequestInit).headers).toMatchObject({
      Authorization: `Bearer ${KEY}`,
      'Content-Type': 'application/json',
    });
    expect(JSON.parse(String((init as RequestInit).body))).toMatchObject({
      model: 'gpt-5.4-mini',
      messages: [{ role: 'user', content: 'hello' }],
    });
  });

  it.each([401, 429])('surfaces HTTP %i without silently changing providers', async (status) => {
    const fetchSpy = vi.fn(async (_url: string | URL, _init?: RequestInit) => ({
      ok: false,
      status,
      headers: { get: () => null },
      text: async () => 'provider error',
    }));
    global.fetch = fetchSpy as unknown as typeof fetch;

    await expect(createCheaperInferenceBackbone(KEY).chat([{ role: 'user', content: 'hello' }]))
      .rejects.toMatchObject({ status });
    expect(fetchSpy).toHaveBeenCalledTimes(status === 401 ? 1 : 3);
    for (const [url] of fetchSpy.mock.calls) {
      expect(url).toBe('https://api.cheaperinference.com/v1/chat/completions');
    }
  }, 10_000);

  it('keeps cross-provider fallback disabled unless the operator opts in', () => {
    process.env.CHEAPERINFERENCE_API_KEY = KEY;
    expect(config.getLLMConfig('cheaperinference').fallbackChain).toEqual([]);
  });

  it('publishes a non-empty Cheaper Inference model catalog and configured provider state', () => {
    process.env.CHEAPERINFERENCE_API_KEY = KEY;
    expect(AVAILABLE_MODELS.cheaperinference?.length ?? 0).toBeGreaterThan(0);
    expect(config.getConfiguredProviders()).toContain('cheaperinference');
  });
});
