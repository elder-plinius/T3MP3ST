// =============================================================================
// OUTBOUND WEBHOOKS — fire POSTs to registered URLs on internal events
// =============================================================================
// Registration: POST /api/webhooks
// Delivery: HMAC-SHA256 signed, with exponential-back-off retry (3 attempts)
// Pre-load: set T3MP3ST_WEBHOOK_URL=https://... (comma-separated) to register
//   catch-all hooks at startup without an API call.
// =============================================================================

import { createHmac, randomUUID } from 'crypto';
import { assertPublicHttpUrl } from './net/ssrf.js';

export interface WebhookRegistration {
  id: string;
  url: string;
  /** Event type patterns — trailing '*' glob supported; '*' matches all events. */
  events: string[];
  /** If set, each delivery includes X-Tempest-Signature: sha256=<hmac>. */
  secret?: string;
  enabled: boolean;
  createdAt: number;
  lastFiredAt?: number;
  failCount: number;
}

const _webhooks = new Map<string, WebhookRegistration>();

// Pre-load catch-all hooks from environment variable
((): void => {
  const raw = process.env.T3MP3ST_WEBHOOK_URL ?? '';
  for (const url of raw.split(',').map((u) => u.trim()).filter(Boolean)) {
    const id = `wh-env-${Buffer.from(url).toString('base64').slice(-8).replace(/[^A-Za-z0-9]/g, '_')}`;
    _webhooks.set(id, { id, url, events: ['*'], enabled: true, createdAt: Date.now(), failCount: 0 });
  }
})();

// =============================================================================
// REGISTRATION API
// =============================================================================

export function registerWebhook(
  url: string,
  events: string[],
  secret?: string,
): WebhookRegistration {
  const id = randomUUID();
  const wh: WebhookRegistration = {
    id,
    url,
    events: events.length ? events : ['*'],
    secret,
    enabled: true,
    createdAt: Date.now(),
    failCount: 0,
  };
  _webhooks.set(id, wh);
  return wh;
}

export function removeWebhook(id: string): boolean {
  return _webhooks.delete(id);
}

export function listWebhooks(): WebhookRegistration[] {
  return Array.from(_webhooks.values());
}

export function setWebhookEnabled(id: string, enabled: boolean): boolean {
  const wh = _webhooks.get(id);
  if (!wh) return false;
  wh.enabled = enabled;
  return true;
}

// =============================================================================
// DELIVERY
// =============================================================================

const MAX_RETRIES = 2; // 3 total attempts (0-indexed)
const RETRY_DELAYS_MS = [1_000, 5_000, 30_000];

function _eventMatches(pattern: string, event: string): boolean {
  if (pattern === '*') return true;
  if (pattern.endsWith('*')) return event.startsWith(pattern.slice(0, -1));
  return pattern === event;
}

function _sign(body: string, secret: string): string {
  return 'sha256=' + createHmac('sha256', secret).update(body).digest('hex');
}

async function _deliverOnce(
  url: string,
  body: string,
  headers: Record<string, string>,
): Promise<void> {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body,
    signal: AbortSignal.timeout(10_000),
    redirect: 'error',   // never follow redirects — prevents redirect-based SSRF
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
}

async function _deliverWithRetry(
  wh: WebhookRegistration,
  event: string,
  data: Record<string, unknown>,
): Promise<void> {
  // Re-validate at delivery time — DNS may have changed since registration
  try {
    await assertPublicHttpUrl(wh.url, 'webhook URL');
  } catch (err) {
    wh.failCount++;
    console.warn(
      `[webhooks] delivery blocked (${wh.id} → ${wh.url}): ${(err as Error).message}`,
    );
    return;
  }

  const deliveryId = randomUUID();
  const body = JSON.stringify({ event, data, deliveryId, ts: Date.now() });
  const headers: Record<string, string> = {
    'X-Tempest-Event': event,
    'X-Tempest-Delivery': deliveryId,
  };
  if (wh.secret) headers['X-Tempest-Signature'] = _sign(body, wh.secret);

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    try {
      await _deliverOnce(wh.url, body, headers);
      wh.lastFiredAt = Date.now();
      wh.failCount = 0;
      return;
    } catch (err) {
      if (attempt < MAX_RETRIES) {
        await new Promise<void>((r) => setTimeout(r, RETRY_DELAYS_MS[attempt]));
      } else {
        wh.failCount++;
        console.warn(
          `[webhooks] delivery failed (${wh.id} → ${wh.url}): ${(err as Error).message}`,
        );
      }
    }
  }
}

/**
 * Fire all matching enabled webhooks for the given event.
 * Called from broadcastEvent — errors are swallowed per webhook so one bad
 * endpoint cannot disrupt the others.
 */
export async function fireWebhooks(
  event: string,
  data: Record<string, unknown>,
): Promise<void> {
  const matching = Array.from(_webhooks.values()).filter(
    (wh) => wh.enabled && wh.events.some((p) => _eventMatches(p, event)),
  );
  if (!matching.length) return;
  await Promise.allSettled(matching.map((wh) => _deliverWithRetry(wh, event, data)));
}
