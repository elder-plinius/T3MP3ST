/**
 * Inbound Bearer-token auth — the opt-in guard that must exist before this
 * server is exposed to anything beyond localhost.
 *
 * WHY THIS EXISTS: the server binds 127.0.0.1 by default and its startup banner
 * says so explicitly — "This API executes commands and has NO built-in
 * authentication … Do NOT put this on a LAN or the internet without real auth".
 * That warning is only honest if the upgrade path it names actually works, so
 * these tests pin it.
 *
 * Two properties matter and they pull in opposite directions:
 *   1. INERT BY DEFAULT. With T3MP3ST_AUTH_TOKEN unset, every route behaves
 *      exactly as before. A guard that silently changed localhost behaviour
 *      would be a worse outage than no guard.
 *   2. Actually gating. When the token IS set, the credential vault and the
 *      rest of /api must refuse an absent or wrong token — a guard that logs a
 *      401 and then calls next() is worse than no guard at all, because it
 *      reads like protection.
 *
 * These are static + behavioural assertions on the real middleware in server.ts,
 * plus a live check against a spawned server on a spare port.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawn, type ChildProcess } from 'node:child_process';
import type { AddressInfo } from 'node:net';

const SERVER_SRC = readFileSync(join(process.cwd(), 'src', 'server.ts'), 'utf8');
const TOKEN = 'test-operator-token-9f3a2b';

describe('bearer auth — wiring', () => {
  it('is opt-in: the middleware is registered only when the env var is set', () => {
    // The single most important property. An always-on guard would lock the
    // operator out of their own localhost server.
    expect(SERVER_SRC).toMatch(/const AUTH_TOKEN = \(process\.env\.T3MP3ST_AUTH_TOKEN \?\? ''\)\.trim\(\);/);
    expect(SERVER_SRC).toMatch(/if \(AUTH_TOKEN\) \{\s*app\.use\(/);
  });

  it('compares the token in constant time', () => {
    // A `===` on a bearer token is recoverable byte-by-byte by timing the
    // response. The helper hashes both sides to fixed width first because
    // timingSafeEqual throws on a length mismatch — which would leak the length.
    expect(SERVER_SRC).toMatch(/function timingSafeEqual\(a: string, b: string\): boolean/);
    expect(SERVER_SRC).toMatch(/createHash\('sha256'\)\.update\(a, 'utf8'\)\.digest\(\)/);
    expect(SERVER_SRC).toMatch(/timingSafeEqualRaw\(ha, hb\)/);
  });

  it('gates the API but not the UI bootstrap', () => {
    // Locking /ui or /api/health would break the panel's own load with a 401 it
    // cannot render its way out of.
    expect(SERVER_SRC).toMatch(/if \(!req\.path\.startsWith\('\/api\/'\)\) return next\(\);/);
    expect(SERVER_SRC).toMatch(/if \(req\.path === '\/api\/health'\) return next\(\);/);
  });

  it('is mounted BEFORE any API route is declared', () => {
    const guard = SERVER_SRC.indexOf('if (AUTH_TOKEN) {');
    const firstApiRoute = SERVER_SRC.indexOf("app.get('/api/");
    expect(guard).toBeGreaterThan(-1);
    expect(firstApiRoute).toBeGreaterThan(-1);
    // Express runs middleware in registration order, so a guard mounted after
    // the routes would authenticate nothing at all.
    expect(guard, 'auth middleware is registered after the first API route').toBeLessThan(firstApiRoute);
  });
});

describe('bearer auth — live behaviour', () => {
  let proc: ChildProcess | undefined;
  let PORT = 0;

  afterAll(() => {
    if (proc && !proc.killed) proc.kill();
  });

  /** Ask the OS for a free port rather than hard-coding one. A fixed port made
   *  this test fail for a reason that had nothing to do with the guard: a
   *  previous run's listener was still bound, so the fetch silently hit THAT
   *  server instead of the one just spawned. */
  const freePort = async (): Promise<number> => {
    const net = await import('node:net');
    return new Promise((resolve, reject) => {
      const srv = net.createServer();
      srv.once('error', reject);
      srv.listen(0, '127.0.0.1', () => {
        const p = (srv.address() as AddressInfo).port;
        srv.close(() => resolve(p));
      });
    });
  };

  const get = async (path: string, headers: Record<string, string> = {}) => {
    const res = await fetch(`http://127.0.0.1:${PORT}${path}`, { headers });
    return res.status;
  };

  it('gates sensitive routes when the token is set, and opens them with it', async () => {
    PORT = await freePort();
    proc = spawn(process.execPath, [join(process.cwd(), 'dist', 'server.js')], {
      env: { ...process.env, T3MP3ST_PORT: String(PORT), T3MP3ST_AUTH_TOKEN: TOKEN, T3MP3ST_HOST: '127.0.0.1' },
      stdio: 'ignore',
    });

    // Wait for the listener rather than sleeping a fixed amount.
    let up = false;
    for (let i = 0; i < 40 && !up; i++) {
      await new Promise((r) => setTimeout(r, 500));
      try {
        const res = await fetch(`http://127.0.0.1:${PORT}/api/health`);
        up = res.ok;
      } catch { /* not listening yet */ }
    }
    expect(up, 'server did not come up on the test port').toBe(true);

    // The credential vault is the reason this guard exists — assert on it first.
    expect(await get('/api/credentials')).toBe(401);
    expect(await get('/api/credentials', { authorization: `Bearer ${TOKEN}` })).toBe(200);

    // Absent, wrong, and empty tokens all refuse.
    expect(await get('/api/evidence')).toBe(401);
    expect(await get('/api/evidence', { authorization: 'Bearer wrong' })).toBe(401);
    expect(await get('/api/evidence', { authorization: 'Bearer ' })).toBe(401);
    expect(await get('/api/evidence', { authorization: TOKEN })).toBe(401); // no "Bearer " prefix
    expect(await get('/api/evidence', { authorization: `Bearer ${TOKEN}` })).toBe(200);

    // Scheme is case-insensitive per RFC 7235.
    expect(await get('/api/settings', { authorization: `bearer ${TOKEN}` })).toBe(200);

    // UI + health stay reachable so the panel can still boot.
    expect(await get('/api/health')).toBe(200);
    expect(await get('/api/health', { authorization: `Bearer ${TOKEN}` })).toBe(200);
    const ui = await fetch(`http://127.0.0.1:${PORT}/ui/osint.html`);
    expect(ui.status).toBe(200);
  }, 60_000);
});