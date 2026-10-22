/**
 * Supabase state persistence — database memory/storage for the T3MP3ST server.
 *
 * Mirrors the state.json snapshot semantics into two Supabase tables (see
 * scripts/supabase-schema.sql):
 *   - t3mp3st_state_snapshots: single row (id='latest') holding the FULL redacted
 *     ledger snapshot (evidence, findings, hypotheses, work orders, retests, watch
 *     cycles, memory capsule/proposals, drafts, approvals) — upserted on the
 *     debounced persist tick and on graceful shutdown.
 *   - t3mp3st_state_events: append-only contract-event audit log (batched flush).
 *
 * Design constraints:
 *  - REST only (PostgREST via the Data API) — no extra npm dependencies.
 *  - Direct egress (fetchBypassingProxy): operator credentials must never ride the
 *    SOCKS pentest proxy.
 *  - Best-effort: every failure logs ONE warning and disables the backend until
 *    restart — persistence problems must never take scans down.
 *  - Service-role secret is server-side only; tables are RLS-locked with no anon policies.
 */

import { fetchBypassingProxy } from '../net/proxy.js';

export interface SupabaseStateSnapshot {
  [key: string]: unknown;
}

interface SupabaseEnv {
  url: string;
  key: string;
}

let disabled = false; // latched when the backend is unreachable/missing tables
let warned = false;

function readEnv(key: string): string {
  return (process.env[key] || '').trim();
}

function supabaseEnv(): SupabaseEnv | null {
  if ((readEnv('T3MP3ST_STATE_BACKEND') || '').toLowerCase() !== 'supabase') return null;
  if (disabled) return null;
  const url = readEnv('SUPABASE_URL') || readEnv('NEXT_PUBLIC_SUPABASE_URL');
  const key = readEnv('SUPABASE_SECRET_KEY') || readEnv('SUPABASE_SERVICE_ROLE_KEY');
  if (!url || !key) {
    if (!warned) {
      warned = true;
      console.warn('[supabase] T3MP3ST_STATE_BACKEND=supabase but SUPABASE_URL / SUPABASE_SECRET_KEY are missing — persistence stays off');
    }
    return null;
  }
  return { url: url.replace(/\/+$/, ''), key };
}

function headers(env: SupabaseEnv, extra: Record<string, string> = {}): Record<string, string> {
  return {
    apikey: env.key,
    Authorization: `Bearer ${env.key}`,
    'Content-Type': 'application/json',
    ...extra,
  };
}

/** Minimal response surface — avoids undici Response vs DOM Response type clashes. */
interface RestResponse {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
  text(): Promise<string>;
}

async function call(env: SupabaseEnv, path: string, init: Record<string, unknown>): Promise<RestResponse> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10_000);
  try {
    return await (fetchBypassingProxy as unknown as (url: string, init?: Record<string, unknown>) => Promise<unknown>)(
      `${env.url}${path}`,
      { ...init, signal: controller.signal }
    ) as RestResponse;
  } finally {
    clearTimeout(timer);
  }
}

function latchFailure(where: string, error: unknown): void {
  const message = error instanceof Error ? error.message : String(error);
  if (!warned) {
    warned = true;
    disabled = true;
    console.warn(`[supabase] state persistence disabled after failure at ${where}: ${message} — fix and restart to re-enable`);
  }
}

/** Latest snapshot row, or null when unset/unavailable. */
export async function loadSupabaseState(): Promise<SupabaseStateSnapshot | null> {
  const env = supabaseEnv();
  if (!env) return null;
  try {
    const res = await call(env, '/rest/v1/t3mp3st_state_snapshots?select=snapshot,reason,updated_at&id=eq.latest&limit=1', {
      method: 'GET',
      headers: headers(env),
    });
    if (!res.ok) {
      latchFailure('load', new Error(`HTTP ${res.status} ${await res.text().catch(() => '')}`.slice(0, 200)));
      return null;
    }
    const rows = (await res.json()) as Array<{ snapshot: SupabaseStateSnapshot }>;
    return rows?.[0]?.snapshot || null;
  } catch (error) {
    latchFailure('load', error);
    return null;
  }
}

/** Upsert the redacted full snapshot as the single 'latest' row. */
export async function persistSupabaseState(snapshot: SupabaseStateSnapshot, reason: string): Promise<void> {
  const env = supabaseEnv();
  if (!env) return;
  try {
    const res = await call(env, '/rest/v1/t3mp3st_state_snapshots', {
      method: 'POST',
      headers: headers(env, { Prefer: 'resolution=merge-duplicates,return=minimal' }),
      body: JSON.stringify([{ id: 'latest', reason, snapshot, updated_at: new Date().toISOString() }]),
    });
    if (!res.ok) {
      latchFailure('persist', new Error(`HTTP ${res.status} ${await res.text().catch(() => '')}`.slice(0, 200)));
    }
  } catch (error) {
    latchFailure('persist', error);
  }
}

// Contract events are buffered and flushed with the debounced persist tick — one
// REST round-trip per burst instead of one per event.
const eventBuffer: Array<{ type: string; payload: unknown; ts: string }> = [];

export function bufferSupabaseEvent(type: string, payload: Record<string, unknown>): void {
  if (!supabaseEnv()) return;
  eventBuffer.push({ type, payload, ts: new Date().toISOString() });
  if (eventBuffer.length >= 50) void flushSupabaseEvents();
}

export async function flushSupabaseEvents(): Promise<void> {
  if (!eventBuffer.length) return;
  const env = supabaseEnv();
  if (!env) {
    eventBuffer.length = 0;
    return;
  }
  const batch = eventBuffer.splice(0, eventBuffer.length);
  try {
    const res = await call(env, '/rest/v1/t3mp3st_state_events', {
      method: 'POST',
      headers: headers(env, { Prefer: 'return=minimal' }),
      body: JSON.stringify(batch),
    });
    if (!res.ok) {
      latchFailure('events', new Error(`HTTP ${res.status} ${await res.text().catch(() => '')}`.slice(0, 200)));
    }
  } catch (error) {
    latchFailure('events', error);
  }
}
