/**
 * Model-list fetching for the Universal API Config panel (issue #90).
 *
 * The Settings "Fetch models" button can't call api.openai.com/v1/models etc. directly from the
 * browser (CORS), and today there are TWO hardcoded, already-drifting model lists (config
 * AVAILABLE_MODELS vs the UI's MODELS array). `listProviderModels` is the server-side, testable core
 * that queries a provider's own model endpoint with the OpenAI-compatible / Anthropic wire shape.
 * It THROWS on any failure so the caller (the /api/models route) can fail open to the static list —
 * a broken/keyless provider must never leave the panel empty.
 */
import { describe, it, expect, vi } from 'vitest';
import { listProviderModels, resolveModels } from '../config/provider-models.js';

/** A fake fetch returning `body` as JSON with the given ok/status. Records the call. */
function fakeFetch(body: unknown, ok = true, status = 200) {
  return vi.fn(async (_url: string, _init?: unknown) => ({
    ok, status, json: async () => body,
  }));
}

describe('listProviderModels — OpenAI-compatible providers', () => {
  it('GETs {baseUrl}/models with a Bearer key and returns the data[].id list', async () => {
    const f = fakeFetch({ data: [{ id: 'gpt-4o' }, { id: 'gpt-4o-mini' }] });
    const models = await listProviderModels('openai', { baseUrl: 'https://api.openai.com/v1', apiKey: 'sk-test', fetchImpl: f });

    expect(models.map((m) => m.id)).toEqual(['gpt-4o', 'gpt-4o-mini']);
    const [url, init] = f.mock.calls[0];
    expect(url).toBe('https://api.openai.com/v1/models');
    expect((init as { headers: Record<string, string> }).headers.Authorization).toBe('Bearer sk-test');
  });

  it('handles venice/xai/local the same OpenAI-compatible way (base already ends in /v1)', async () => {
    const f = fakeFetch({ data: [{ id: 'llama-3.3-70b' }] });
    const models = await listProviderModels('venice', { baseUrl: 'https://api.venice.ai/api/v1', apiKey: 'k', fetchImpl: f });
    expect(models.map((m) => m.id)).toEqual(['llama-3.3-70b']);
    expect(f.mock.calls[0][0]).toBe('https://api.venice.ai/api/v1/models');
  });
});

describe('listProviderModels — Anthropic wire', () => {
  it('GETs {baseUrl}/v1/models with x-api-key + anthropic-version headers', async () => {
    const f = fakeFetch({ data: [{ id: 'claude-opus-4-8' }, { id: 'claude-sonnet-4-5' }] });
    const models = await listProviderModels('anthropic', { baseUrl: 'https://api.anthropic.com', apiKey: 'sk-ant', fetchImpl: f });

    expect(models.map((m) => m.id)).toEqual(['claude-opus-4-8', 'claude-sonnet-4-5']);
    const [url, init] = f.mock.calls[0];
    expect(url).toBe('https://api.anthropic.com/v1/models');
    const headers = (init as { headers: Record<string, string> }).headers;
    expect(headers['x-api-key']).toBe('sk-ant');
    expect(headers['anthropic-version']).toBeTruthy();
    expect(headers.Authorization).toBeUndefined();  // Anthropic does NOT use Bearer
  });
});

describe('listProviderModels — OpenRouter', () => {
  it('lists from the OpenRouter models endpoint (works without a key)', async () => {
    const f = fakeFetch({ data: [{ id: 'anthropic/claude-opus-4.8' }, { id: 'google/gemini-2.5-pro' }] });
    const models = await listProviderModels('openrouter', { fetchImpl: f });
    expect(models.map((m) => m.id)).toEqual(['anthropic/claude-opus-4.8', 'google/gemini-2.5-pro']);
    expect(String(f.mock.calls[0][0])).toContain('openrouter.ai');
  });

  it('honors a custom OpenRouter-compatible base URL when provided', async () => {
    const f = fakeFetch({ data: [{ id: 'x' }] });
    await listProviderModels('openrouter', { baseUrl: 'https://my-gateway.local/v1', fetchImpl: f });
    expect(f.mock.calls[0][0]).toBe('https://my-gateway.local/v1/models');
  });
});

describe('listProviderModels — base URL normalization', () => {
  it('does not double /v1 for Anthropic when the base already ends in /v1', async () => {
    const f = fakeFetch({ data: [{ id: 'claude-x' }] });
    await listProviderModels('anthropic', { baseUrl: 'https://api.anthropic.com/v1', apiKey: 'k', fetchImpl: f });
    expect(f.mock.calls[0][0]).toBe('https://api.anthropic.com/v1/models');   // not /v1/v1/models
  });
});

describe('listProviderModels — failure modes (caller fails open to the static list)', () => {
  it('throws on a non-ok HTTP response', async () => {
    const f = fakeFetch({ error: 'unauthorized' }, false, 401);
    await expect(listProviderModels('openai', { baseUrl: 'https://api.openai.com/v1', apiKey: 'bad', fetchImpl: f }))
      .rejects.toThrow();
  });

  it('throws for a keyless/local-only provider that has no remote model list', async () => {
    const f = fakeFetch({});
    await expect(listProviderModels('codex', { fetchImpl: f })).rejects.toThrow();
    expect(f).not.toHaveBeenCalled();  // no pointless network call
  });

  it('throws when the response has no data[] array (malformed)', async () => {
    const f = fakeFetch({ nonsense: true });
    await expect(listProviderModels('openai', { baseUrl: 'https://api.openai.com/v1', apiKey: 'k', fetchImpl: f }))
      .rejects.toThrow();
  });
});

describe('resolveModels — fail-open orchestrator (never throws; the panel is never empty)', () => {
  const STATIC = [{ id: 'static-fallback-model' }];

  it('returns live models when the fetch succeeds', async () => {
    const f = fakeFetch({ data: [{ id: 'gpt-4o' }] });
    const r = await resolveModels('openai', { baseUrl: 'https://api.openai.com/v1', apiKey: 'k', fetchImpl: f, staticFallback: STATIC });
    expect(r.source).toBe('live');
    expect(r.models.map((m) => m.id)).toEqual(['gpt-4o']);
  });

  it('fails open to the static list (with a note) when the fetch errors', async () => {
    const f = fakeFetch({ error: 'nope' }, false, 500);
    const r = await resolveModels('openai', { baseUrl: 'https://api.openai.com/v1', apiKey: 'k', fetchImpl: f, staticFallback: STATIC });
    expect(r.source).toBe('static');
    expect(r.models).toEqual(STATIC);
    expect(r.note).toContain('500');
  });

  it('fails open for a keyless provider with no remote list', async () => {
    const r = await resolveModels('codex', { staticFallback: STATIC, fetchImpl: fakeFetch({}) });
    expect(r.source).toBe('static');
    expect(r.models).toEqual(STATIC);
  });
});
