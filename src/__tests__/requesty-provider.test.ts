import { describe, expect, it, afterEach, vi } from 'vitest';
import { config, AVAILABLE_MODELS } from '../config/index.js';
import { createRequestyBackbone } from '../llm/index.js';

const KEY = 'rqsty-test-key-0123456789';

describe('Requesty provider wiring', () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    delete process.env.REQUESTY_API_KEY;
    delete process.env.TEMPEST_MODEL_FALLBACK;
    global.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it('resolves the Requesty base URL, default model, and key from REQUESTY_API_KEY', () => {
    process.env.REQUESTY_API_KEY = KEY;
    const cfg = config.getLLMConfig('requesty');
    expect(cfg.provider).toBe('requesty');
    expect(cfg.baseUrl).toBe('https://router.requesty.ai/v1');
    expect(cfg.model).toBe('anthropic/claude-sonnet-5');
    expect(cfg.apiKey).toBe(KEY);
    expect(`${cfg.baseUrl}/chat/completions`).toBe(
      'https://router.requesty.ai/v1/chat/completions',
    );
  });

  it('routes through the OpenAI-compatible backbone and validates with a key', () => {
    process.env.REQUESTY_API_KEY = KEY;
    const bb = createRequestyBackbone();
    expect(bb.getProvider()).toBe('requesty');
    expect(bb.validateConfig().valid).toBe(true);
  });

  it('requires the provider-specific key instead of reporting an OpenAI credential error', () => {
    expect(createRequestyBackbone().validateConfig()).toEqual({
      valid: false,
      error: expect.stringContaining('REQUESTY_API_KEY'),
    });
  });

  it('sends chat to the Requesty endpoint with Bearer auth and the configured model', async () => {
    const fetchSpy = vi.fn(async (_url: string | URL, _init?: RequestInit) => ({
      ok: true,
      json: async () => ({
        model: 'anthropic/claude-sonnet-5',
        choices: [{ message: { content: 'ok' }, finish_reason: 'stop' }],
      }),
    }));
    global.fetch = fetchSpy as unknown as typeof fetch;

    const response = await createRequestyBackbone(KEY).chat([{ role: 'user', content: 'hello' }]);
    expect(response.content).toBe('ok');
    const [url, init] = fetchSpy.mock.calls[0];
    expect(url).toBe('https://router.requesty.ai/v1/chat/completions');
    expect((init as RequestInit).headers).toMatchObject({
      Authorization: `Bearer ${KEY}`,
      'Content-Type': 'application/json',
    });
    expect(JSON.parse(String((init as RequestInit).body))).toMatchObject({
      model: 'anthropic/claude-sonnet-5',
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

    await expect(createRequestyBackbone(KEY).chat([{ role: 'user', content: 'hello' }]))
      .rejects.toMatchObject({ status });
    expect(fetchSpy).toHaveBeenCalledTimes(status === 401 ? 1 : 3);
    for (const [url] of fetchSpy.mock.calls) {
      expect(url).toBe('https://router.requesty.ai/v1/chat/completions');
    }
  }, 10_000);

  it('keeps cross-provider fallback disabled unless the operator opts in', () => {
    process.env.REQUESTY_API_KEY = KEY;
    expect(config.getLLMConfig('requesty').fallbackChain).toEqual([]);
  });

  it('is never added to another provider\'s opt-in fallback chain', () => {
    process.env.REQUESTY_API_KEY = KEY;
    process.env.TEMPEST_MODEL_FALLBACK = '1';
    const chain = config.getLLMConfig('mock').fallbackChain ?? [];
    expect(chain.map((entry) => entry.provider)).not.toContain('requesty');
  });

  it('publishes a non-empty Requesty model catalog and configured provider state', () => {
    process.env.REQUESTY_API_KEY = KEY;
    expect(AVAILABLE_MODELS.requesty?.length ?? 0).toBeGreaterThan(0);
    expect(config.getConfiguredProviders()).toContain('requesty');
  });
});
