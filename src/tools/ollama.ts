// A LAN/local model box must NEVER traverse the SOCKS egress proxy — the global
// dispatcher fails to reach it. All calls here go through fetchBypassingProxy.
//
// Direct Ollama path for the OSINT AI features (pretext lab, search director,
// extraction assist). Bypasses the global cloud backbone so these run on the
// operator's own box; supports BOTH wire shapes: native /api/chat and
// OpenAI-compatible /v1/chat/completions. Model is per-request selectable.

import { fetchBypassingProxy } from '../net/proxy.js';

export interface OllamaEndpoint { base: string; native: boolean; source: string }

/** Resolve the Ollama endpoint: env first (authoritative), then saved settings
 *  when they are not the untouched 127.0.0.1:8080 defaults. */
export function resolveOllamaEndpoint(saved?: { localHost?: string; localPort?: string; localPath?: string } | null): OllamaEndpoint {
  const envBase = (process.env.TEMPEST_LOCAL_BASE_URL || process.env.OLLAMA_BASE_URL || '').trim();
  if (envBase) {
    const base = envBase.replace(/\/$/, '');
    return { base, native: !/\/v1$/i.test(base), source: 'env' };
  }
  const host = (saved?.localHost || '').trim();
  const isDefault = host === '127.0.0.1' || host === 'localhost' || !host;
  if (host && !isDefault) {
    const port = (saved?.localPort || '11434').trim();
    const path = (saved?.localPath || '/api').trim();
    const base = `http://${host}:${port}${path}`.replace(/\/$/, '');
    return { base, native: !/\/v1$/i.test(base), source: 'settings' };
  }
  return { base: 'http://127.0.0.1:11434/api', native: true, source: 'default' };
}

async function ollamaJson(url: string, init: RequestInit, timeoutMs: number): Promise<any> {
  const res = await (fetchBypassingProxy as unknown as typeof fetch)(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
  if (!res.ok) throw new Error(`Ollama HTTP ${res.status}`);
  return res.json();
}

export interface OllamaModel { id: string; size?: number; family?: string }

/** List served models from the resolved endpoint. */
export async function listOllamaModels(endpoint: OllamaEndpoint = resolveOllamaEndpoint()): Promise<{ models: OllamaModel[]; endpoint: string; native: boolean }> {
  if (endpoint.native) {
    const j = await ollamaJson(`${endpoint.base}/tags`, { method: 'GET' }, 8000);
    const models = (Array.isArray(j?.models) ? j.models : []).map((m: any) => ({
      id: String(m?.name || m?.model || ''),
      size: typeof m?.size === 'number' ? m.size : undefined,
      family: typeof m?.details?.family === 'string' ? m.details.family : undefined,
    })).filter((m: OllamaModel) => m.id);
    return { models, endpoint: endpoint.base, native: true };
  }
  const j = await ollamaJson(`${endpoint.base}/models`, { method: 'GET' }, 8000);
  const models = (Array.isArray(j?.data) ? j.data : []).map((m: any) => ({ id: String(m?.id || '') })).filter((m: OllamaModel) => m.id);
  return { models, endpoint: endpoint.base, native: false };
}

/** One chat completion against the local model. Local CPU inference is slow, so
 *  the timeout is generous; errors surface honestly (no silent cloud fallback). */
export async function ollamaChat(model: string, system: string, user: string, endpoint: OllamaEndpoint = resolveOllamaEndpoint()): Promise<{ content: string; model: string }> {
  const tag = model.trim();
  if (!tag) throw new Error('no Ollama model selected');
  if (endpoint.native) {
    const body = (think: boolean) => JSON.stringify({ model: tag, stream: false, ...(think ? {} : { think: false }), options: { temperature: 0.7, num_predict: 1200 }, messages: [{ role: 'system', content: system }, { role: 'user', content: user }] });
    const init = { method: 'POST', headers: { 'content-type': 'application/json' } };
    let j: any;
    try {
      // think:false — thinking models (gemma4, qwen3) otherwise burn the entire
      // num_predict budget inside <think> and return empty content.
      j = await ollamaJson(`${endpoint.base}/chat`, { ...init, body: body(false) }, 300_000);
    } catch (e) {
      // older Ollama builds reject the unknown think field — retry without it.
      j = await ollamaJson(`${endpoint.base}/chat`, { ...init, body: body(true) }, 300_000);
    }
    return { content: String(j?.message?.content || j?.response || ''), model: tag };
  }
  const j = await ollamaJson(`${endpoint.base}/chat/completions`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ model: tag, temperature: 0.7, max_tokens: 1600, messages: [{ role: 'system', content: system }, { role: 'user', content: user }] }),
  }, 300_000);
  return { content: String(j?.choices?.[0]?.message?.content || ''), model: tag };
}
