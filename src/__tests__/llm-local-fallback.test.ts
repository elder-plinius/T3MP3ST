/**
 * LLM fallback ladder — local primary escalates to the next hop
 *
 * Raul's rule: "if it times out then send it to openrouter." The ladder lives in
 * LLMBackbone.chat; a local/local-agent TIMEOUT (or connection refusal) must be
 * treated as permanent — no same-model retry storm — and advance straight to the
 * next hop. Uses two real local HTTP fakes (hang server + respond server) so the
 * undici-based fetch path is exercised without any external traffic.
 */

import { describe, it, expect, afterAll } from 'vitest';
import http from 'node:http';
import { LLMBackbone } from '../llm/index.js';
import type { FallbackEntry, LLMConfig } from '../types/index.js';

let hangServer: http.Server | null = null;
let replyServer: http.Server | null = null;
const hangHits: number[] = [];

function listen(server: http.Server): Promise<number> {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve((server.address() as any).port)));
}

async function startFakes(): Promise<{ hangPort: number; replyPort: number }> {
  hangServer = http.createServer((_req, res) => {
    // Accept the request and never respond — the backbone's timeout must fire.
    hangHits.push(Date.now());
    res.on('close', () => { /* client aborts when the ladder advances */ });
  });
  replyServer = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      // Ollama native /api/chat wire
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ model: 'qwen3:8b', message: { role: 'assistant', content: 'FALLBACK-REPLY' }, done_reason: 'stop' }));
    });
  });
  const hangPort = await listen(hangServer);
  const replyPort = await listen(replyServer);
  return { hangPort, replyPort };
}

const fakesPromise = startFakes();

afterAll(() => {
  hangServer?.close();
  replyServer?.close();
});

function makeBackbone(hangPort: number, replyPort: number): LLMBackbone {
  const cfg: LLMConfig = {
    provider: 'local',
    model: 'qwen3:8b',
    baseUrl: `http://127.0.0.1:${hangPort}/api`,
    apiKey: undefined,
    maxTokens: 256,
    temperature: 0.2,
    timeout: 700, // short so the test stays fast
    fallbackChain: [
      { provider: 'local', model: 'qwen3:8b', baseUrl: `http://127.0.0.1:${replyPort}/api` } as FallbackEntry,
    ],
  } as LLMConfig;
  return new LLMBackbone(cfg);
}

describe('LLMBackbone ladder — local timeout escalates', () => {
  it('advances to the fallback hop on a local timeout without same-model retries', async () => {
    const { hangPort, replyPort } = await fakesPromise;
    const backbone = makeBackbone(hangPort, replyPort);
    const response = await backbone.chat([{ role: 'user', content: 'ping' }]);
    expect(response.content).toBe('FALLBACK-REPLY');
    // exactly ONE attempt against the hanging primary — a timeout must not be retried in place
    expect(hangHits.length).toBe(1);
  }, 15000);

  it('advances on a connection-refused local primary instead of stalling', async () => {
    // Port 9 on loopback: nothing listens; refused fast.
    const { replyPort } = await fakesPromise;
    const cfg: LLMConfig = {
      provider: 'local',
      model: 'qwen3:8b',
      baseUrl: 'http://127.0.0.1:9/api',
      maxTokens: 256,
      temperature: 0.2,
      timeout: 2000,
      fallbackChain: [
        { provider: 'local', model: 'qwen3:8b', baseUrl: `http://127.0.0.1:${replyPort}/api` } as FallbackEntry,
      ],
    } as LLMConfig;
    const backbone = new LLMBackbone(cfg);
    const response = await backbone.chat([{ role: 'user', content: 'ping' }]);
    expect(response.content).toBe('FALLBACK-REPLY');
  }, 15000);
});
