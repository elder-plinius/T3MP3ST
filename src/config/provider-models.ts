/**
 * Server-side model-list fetching for the Universal API Config panel (issue #90).
 *
 * The Settings "Fetch models" button can't hit api.openai.com/v1/models (etc.) directly from the
 * browser (CORS), so the /api/models route calls this. It queries a provider's own model endpoint
 * using the correct wire shape (OpenAI-compatible Bearer `/models`, or the Anthropic `x-api-key`
 * `/v1/models`), and THROWS on any failure so the route can fail open to the static AVAILABLE_MODELS
 * list — a broken/keyless provider must never leave the panel empty.
 */

export interface ProviderModel {
  id: string;
}

type FetchLike = (
  url: string,
  init?: { headers?: Record<string, string>; signal?: AbortSignal },
) => Promise<{ ok: boolean; status: number; json: () => Promise<unknown> }>;

const ANTHROPIC_VERSION = '2023-06-01';
const OPENROUTER_MODELS_URL = 'https://openrouter.ai/api/v1/models';
const DEFAULT_MODEL_LIST_TIMEOUT_MS = 15_000;

// Pseudo-providers with no remote model list (CLI-driven or in-process).
const NO_REMOTE_LIST = new Set(['codex', 'mock', 'local-agent']);
const OPENAI_COMPATIBLE_REMOTE_LIST = new Set(['openai', 'venice', 'xai', 'gemini', 'local']);
const DIRECT_REMOTE_LIST = new Set(['anthropic', 'openrouter']);

const stripTrailingSlash = (u: string): string => u.replace(/\/+$/, '');

export function providerCanListModels(provider: string): boolean {
  return DIRECT_REMOTE_LIST.has(provider) || OPENAI_COMPATIBLE_REMOTE_LIST.has(provider);
}

function timeoutSignal(timeoutMs: number): AbortSignal | undefined {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) return undefined;
  if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function') {
    return AbortSignal.timeout(timeoutMs);
  }
  if (typeof AbortController === 'undefined') return undefined;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  if (typeof timeout.unref === 'function') timeout.unref();
  return controller.signal;
}

/** Extract `data[].id` from an OpenAI-/Anthropic-shaped model-list response, or throw if malformed/empty. */
function parseModelList(body: unknown): ProviderModel[] {
  const data = (body as { data?: unknown } | null)?.data;
  if (!Array.isArray(data)) throw new Error('provider model-list response has no data[] array');
  const models = data
    .map((m) => (m && typeof m === 'object' ? (m as { id?: unknown }).id : undefined))
    .filter((id): id is string => typeof id === 'string' && id.length > 0)
    .map((id) => ({ id }));
  if (!models.length) throw new Error('provider returned an empty model list');
  return models;
}

/**
 * List a provider's available models via its own endpoint. Throws on any failure (missing baseUrl,
 * non-2xx, malformed/empty body, or a provider with no remote list) — the caller fails open.
 */
export async function listProviderModels(
  provider: string,
  opts: { baseUrl?: string; apiKey?: string; fetchImpl?: FetchLike; timeoutMs?: number } = {},
): Promise<ProviderModel[]> {
  if (NO_REMOTE_LIST.has(provider)) {
    throw new Error(`provider '${provider}' has no remote model list`);
  }
  if (!providerCanListModels(provider)) {
    throw new Error(`provider '${provider}' is not supported for remote model listing`);
  }
  const doFetch = opts.fetchImpl ?? (globalThis.fetch as unknown as FetchLike | undefined);
  if (!doFetch) throw new Error('no fetch implementation available');

  let url: string;
  const headers: Record<string, string> = {};

  if (provider === 'anthropic') {
    // Strip a trailing /v1 first so a user who types ".../v1" (matching every other provider's base)
    // doesn't get a double /v1/v1/models → 404.
    const abase = stripTrailingSlash(opts.baseUrl || 'https://api.anthropic.com').replace(/\/v1$/, '');
    url = `${abase}/v1/models`;
    headers['anthropic-version'] = ANTHROPIC_VERSION;                       // Anthropic uses x-api-key, NOT Bearer
    if (opts.apiKey) headers['x-api-key'] = opts.apiKey;
  } else if (provider === 'openrouter') {
    // Honor a custom OpenRouter-compatible base URL if given; else the public list.
    url = opts.baseUrl && opts.baseUrl.trim() ? `${stripTrailingSlash(opts.baseUrl)}/models` : OPENROUTER_MODELS_URL;
    if (opts.apiKey) headers.Authorization = `Bearer ${opts.apiKey}`;
  } else {
    // OpenAI-compatible: openai / venice / xai / gemini / local / litellm / openai-compat.
    const base = opts.baseUrl && opts.baseUrl.trim() ? stripTrailingSlash(opts.baseUrl) : undefined;
    if (!base) throw new Error(`provider '${provider}' requires a baseUrl to list models`);
    url = `${base}/models`;
    if (opts.apiKey) headers.Authorization = `Bearer ${opts.apiKey}`;
  }

  const signal = timeoutSignal(opts.timeoutMs ?? DEFAULT_MODEL_LIST_TIMEOUT_MS);
  const res = await doFetch(url, { headers, signal });
  if (!res.ok) throw new Error(`model-list request failed: HTTP ${res.status}`);
  return parseModelList(await res.json());
}

export interface ResolvedModels {
  source: 'live' | 'static';
  models: ProviderModel[];
  note?: string;
}

/**
 * Live models with a guaranteed fail-open to `staticFallback` — NEVER throws. The /api/models route
 * uses this so a missing key, CORS/network error, or unlisted provider still returns the static
 * AVAILABLE_MODELS list (the panel is never empty) with `source:'static'` so the UI can flag it.
 */
export async function resolveModels(
  provider: string,
  opts: { baseUrl?: string; apiKey?: string; fetchImpl?: FetchLike; timeoutMs?: number; staticFallback: ProviderModel[] },
): Promise<ResolvedModels> {
  try {
    return { source: 'live', models: await listProviderModels(provider, opts) };
  } catch (e) {
    return { source: 'static', models: opts.staticFallback, note: (e as Error).message };
  }
}
