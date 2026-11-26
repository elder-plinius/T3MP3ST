/**
 * Refuseless provider wiring.
 *
 * Refuseless is a hosted OpenAI-compatible API of abliterated open models, so it plugs in
 * exactly where Novita/NanoGPT do: the LLMProvider union, the config key/provider block,
 * getLLMConfig, the fallback ladder, the .env bridge and the env template. This pins the
 * provider resolving end-to-end so a refactor cannot silently drop it — and pins the two
 * things that would be quietly wrong if copied blindly: the endpoint shape and the key name.
 *
 * The base URL is measured, not remembered: an unkeyed GET /v1/models answers
 * {"error":{"code":"invalid_key"}} in OpenAI shape (probed 2026-10-31), i.e. the API sits in
 * front of the Cloudflare wall the marketing pages have. The model ids are the ones the
 * provider's own toolkit documents; "Fetch models" replaces the static list live.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import { config, AVAILABLE_MODELS } from '../config/index.js';
import { createRefuselessBackbone } from '../llm/index.js';

const KEY = 'rf-test-key-0123456789';

describe('Refuseless provider wiring', () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    delete process.env.REFUSELESS_API_KEY;
    delete process.env.T3MP3ST_FORCE_UNCONFIGURED;
    delete process.env.TEMPEST_MODEL_FALLBACK;
    global.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it('resolves the Refuseless base URL, default model, and key from REFUSELESS_API_KEY', () => {
    process.env.REFUSELESS_API_KEY = KEY;
    const cfg = config.getLLMConfig('refuseless');
    expect(cfg.provider).toBe('refuseless');
    expect(cfg.baseUrl).toBe('https://refuseless.com/v1');
    expect(cfg.model).toBe('glm-5.3-abliterated');
    expect(cfg.apiKey).toBe(KEY);
    // The OpenAIAdapter posts to ${baseUrl}/chat/completions — the measured surface.
    expect(`${cfg.baseUrl}/chat/completions`).toBe('https://refuseless.com/v1/chat/completions');
  });

  it('routes through the OpenAI-compatible backbone and validates with a key', () => {
    process.env.REFUSELESS_API_KEY = KEY;
    const bb = createRefuselessBackbone();
    expect(bb.getProvider()).toBe('refuseless');
    expect(bb.validateConfig().valid).toBe(true);
  });

  it('requires the provider-specific key instead of reporting an OpenAI credential error', () => {
    // Isolate from any key persisted in the operator's Conf store; the sanctioned
    // force-unconfigured switch makes the no-key state reproducible everywhere.
    process.env.T3MP3ST_FORCE_UNCONFIGURED = '1';
    expect(createRefuselessBackbone().validateConfig()).toEqual({
      valid: false,
      error: expect.stringContaining('REFUSELESS_API_KEY'),
    });
  });

  it('sends chat to the Refuseless endpoint with Bearer auth and the configured model', async () => {
    const fetchSpy = vi.fn(async (_url: string | URL, _init?: RequestInit) => ({
      ok: true,
      json: async () => ({
        model: 'glm-5.3-abliterated',
        choices: [{ message: { content: 'ok' }, finish_reason: 'stop' }],
      }),
    }));
    global.fetch = fetchSpy as unknown as typeof fetch;

    const response = await createRefuselessBackbone(KEY).chat([{ role: 'user', content: 'hello' }]);
    expect(response.content).toBe('ok');
    const [url, init] = fetchSpy.mock.calls[0];
    expect(url).toBe('https://refuseless.com/v1/chat/completions');
    expect((init as RequestInit).headers).toMatchObject({
      Authorization: `Bearer ${KEY}`,
      'Content-Type': 'application/json',
    });
    expect(JSON.parse(String((init as RequestInit).body))).toMatchObject({
      model: 'glm-5.3-abliterated',
      messages: [{ role: 'user', content: 'hello' }],
    });
  });

  it('keeps cross-provider fallback disabled unless the operator opts in', () => {
    process.env.REFUSELESS_API_KEY = KEY;
    expect(config.getLLMConfig('refuseless').fallbackChain).toEqual([]);
  });

  it('publishes a non-empty Refuseless model catalog and configured provider state', () => {
    process.env.REFUSELESS_API_KEY = KEY;
    expect(AVAILABLE_MODELS.refuseless?.length ?? 0).toBeGreaterThan(0);
    expect(config.getConfiguredProviders()).toContain('refuseless');
  });

  it('lists the provider as abliterated in its catalog entries', () => {
    // The whole reason to route here; a plain model under this provider would be a
    // silent substitution of the feature the operator selected it for.
    for (const m of AVAILABLE_MODELS.refuseless) {
      expect(m.provider).toBe('Refuseless');
      expect(m.capabilities).toContain('uncensored');
    }
  });

  it('joins the fallback ladder when it is enabled and keyed', () => {
    process.env.REFUSELESS_API_KEY = KEY;
    process.env.TEMPEST_MODEL_FALLBACK = '1';
    const chain = config.getLLMConfig('openrouter').fallbackChain ?? [];
    expect(chain.map((e) => e.provider)).toContain('refuseless');
    const hop = chain.find((e) => e.provider === 'refuseless');
    expect(hop?.baseUrl).toBe('https://refuseless.com/v1');
    expect(hop?.model).toBe('glm-5.3-abliterated');
  });
});
