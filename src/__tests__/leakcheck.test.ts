import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import { createServer, type Server } from 'http';
import { readFileSync } from 'node:fs';
import { AddressInfo } from 'net';
import {
  leakcheckPublic,
  leakcheckPro,
  getDumpKey,
  setDumpKey,
  OSINT_TOOLS,
} from '../tools/osint.js';

// =============================================================================
// LEAKCHECK.IO lane — https://docs.leakcheck.io/overview
//   Public API : GET /api/public?check={q}          (free, 1 rps, no key)
//   Pro API v2 : GET /api/v2/query/{q}?type=…       (X-API-Key, 3 rps)
//
// The Pro row shape is load-bearing and was verified live: each row carries a
// `source` OBJECT {name, breach_date, unverified, passwordless, compilation}
// plus a `fields` list. The previous implementation read `rec.sources` — a
// string the API never sends — so every record silently lost its breach
// attribution. The tests below pin the real shape.
// =============================================================================

let srv: Server;
let base: string;
let lastAuth: string | undefined;
let lastUrl = '';
const env = { ...process.env };

beforeAll(async () => {
  srv = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      const url = req.url || '';
      lastUrl = url;
      lastAuth = req.headers['x-api-key'] as string | undefined;
      const json = (o: unknown, status = 200) => {
        res.writeHead(status, { 'content-type': 'application/json' });
        res.end(JSON.stringify(o));
      };
      if (url.startsWith('/api/public')) {
        if (url.includes('ratelimited')) return json({ message: 'rate limit' }, 429);
        if (url.includes('rejected')) return json({ success: false, error: 'invalid check' });
        if (url.includes('clean')) return json({ success: true, found: 0 });
        return json({
          success: true,
          found: 2,
          fields: ['password', 'email', 'dob'],
          sources: [{ name: 'BreachedWebsite.net', date: '2019-07' }, { name: 'Collection 1', date: '2019-01' }],
        });
      }
      if (url.startsWith('/api/v2/query/')) {
        if (!lastAuth) return json({ success: false, error: 'missing api key' }, 401);
        if (url.includes('enterpriseonly')) return json({ success: false, error: 'Active plan required' });
        if (url.includes('cannotdetect')) return json({ success: false, error: 'Could not determine search type automatically' });
        if (url.includes('nothing')) return json({ success: true, found: 0, quota: 100, result: [] });
        return json({
          success: true,
          found: 3,
          quota: 42,
          result: [
            {
              email: 'a@example.com', password: 'p1', fields: ['password', 'email'],
              source: { name: 'BreachedWebsite.net', breach_date: '2019-07', unverified: 0, passwordless: 0, compilation: 0 },
            },
            {
              email: 'a@example.com', password: 'p2', fields: ['password', 'email'],
              source: { name: 'BreachedWebsite.net', breach_date: '2019-07', unverified: 0, passwordless: 0, compilation: 0 },
            },
            {
              username: 'a', first_name: 'A', last_name: 'B', dob: '1990-01-01', city: 'Lyon', country: 'FR',
              collected: 'April 2024 or earlier',
              source: { name: 'InfostealerLog', breach_date: null, unverified: 1, passwordless: 1, compilation: 0 },
            },
          ],
        });
      }
      res.writeHead(404); res.end('{}');
    });
  });
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
});

afterAll(async () => { await new Promise<void>((r) => srv.close(() => r())); });

afterEach(() => {
  process.env = { ...env };
  setDumpKey('leakcheck', undefined);
});

/** Point the module at the stub by abusing the normal fetch chain. */
function withStub(fn: () => Promise<void>): Promise<void> {
  return (async () => {
    const real = globalThis.fetch;
    globalThis.fetch = (async (input: any, init: any) => {
      const url = typeof input === 'string' ? input : String(input?.url || input);
      if (url.includes('leakcheck.io')) {
        return real(base + url.replace('https://leakcheck.io', '') + (init?.signal ? '' : ''), init);
      }
      return real(input, init);
    }) as typeof fetch;
    try { await fn(); } finally { globalThis.fetch = real; }
  })();
}

describe('leakcheckPublic — free lane', () => {
  it('returns breach sources and exposed field names, never values', async () => {
    await withStub(async () => {
      const r = await leakcheckPublic('a@example.com');
      expect(r.found).toBe(2);
      expect(r.fields).toContain('password');
      expect(r.sources?.[0]).toBe('BreachedWebsite.net (2019-07)');
      expect(r.note).toMatch(/public API/i);
    });
  });

  it('an honest zero is not the same as a failure', async () => {
    await withStub(async () => {
      const r = await leakcheckPublic('clean@example.com');
      expect(r.found).toBe(0);
      expect(r.note).toMatch(/no breach source/i);
    });
  });

  it('a rate-limited lane says so instead of reporting "clean"', async () => {
    await withStub(async () => {
      const r = await leakcheckPublic('ratelimited@example.com');
      expect(r.found).toBe('unknown');
      expect(r.note).toMatch(/1 request\/second/);
    });
  });

  it('a rejected query is surfaced, not silently counted as zero', async () => {
    await withStub(async () => {
      const r = await leakcheckPublic('rejected@example.com');
      expect(r.found).toBe('unknown');
      expect(r.note).toMatch(/rejected/i);
    });
  });
});

describe('leakcheckPro — keyed lane', () => {
  it('is honestly gated when no key is configured', async () => {
    // vitest loads the real .env, so every alias has to be cleared explicitly.
    process.env = { ...env };
    delete process.env.T3MP3ST_LEAKCHECK_KEY;
    delete process.env.LEAKCHECKIO;
    delete process.env.LEAKCHECK_APIKEY;
    delete process.env.LEAKCHECK_KEY;
    delete process.env.LEAKCHECKIO_API_KEY;
    delete process.env.LEAKCHECKIO;
    setDumpKey('leakcheck', undefined);
    const r = await leakcheckPro('a@example.com', 'email');
    expect(r.found).toBe(0);
    expect(r.note).toMatch(/not configured/i);
    expect(r.note).toMatch(/LEAKCHECKIO/);
  });

  it('reads the key from the LEAKCHECKIO_API_KEY / LEAKCHECK_APIKEY aliases', () => {
    process.env = { ...env, T3MP3ST_LEAKCHECK_KEY: '', LEAKCHECKIO_API_KEY: 'io-key-1234' };
    expect(getDumpKey('leakcheck')).toBe('io-key-1234');
    process.env = { ...env, T3MP3ST_LEAKCHECK_KEY: '', LEAKCHECKIO_API_KEY: '', LEAKCHECK_APIKEY: 'docs-key-5678' };
    expect(getDumpKey('leakcheck')).toBe('docs-key-5678');
    // A runtime-pasted key still wins over every env var.
    setDumpKey('leakcheck', 'runtime-key');
    expect(getDumpKey('leakcheck')).toBe('runtime-key');
  });

  // Live-caught: operators set LEAKCHECKIO to the API BASE URL
  // (https://leakcheck.io/api/v2), not to a key. Treating it as one armed the
  // lane with a URL, so the panel reported ARMED while every query returned
  // "Invalid X-API-Key" — the worst combination: confidently wrong.
  it('never arms the lane from a URL-shaped value', () => {
    process.env = {
      ...env,
      T3MP3ST_LEAKCHECK_KEY: '',
      LEAKCHECKIO_API_KEY: '',
      LEAKCHECK_APIKEY: '',
      LEAKCHECKIO: 'https://leakcheck.io/api/v2',
    };
    setDumpKey('leakcheck', undefined);
    expect(getDumpKey('leakcheck')).toBeUndefined();
  });

  it('falls back through the aliases when the primary holds a URL', () => {
    process.env = {
      ...env,
      T3MP3ST_LEAKCHECK_KEY: 'https://leakcheck.io/api/v2',
      LEAKCHECKIO_API_KEY: 'real-key-value-here',
    };
    expect(getDumpKey('leakcheck')).toBe('real-key-value-here');
  });

  it('parses the real `source` OBJECT — breach attribution is not lost', async () => {
    await withStub(async () => {
      setDumpKey('leakcheck', 'test-key');
      const r = await leakcheckPro('a@example.com', 'email');
      expect(r.found).toBe(3);
      expect(r.quota).toBe(42);
      // THIS is the regression the old lane had: `sources` is a string it read,
      // which the API never sends — so every record came back unattributed.
      expect(r.rows[0].source).toEqual({ name: 'BreachedWebsite.net', breach_date: '2019-07', unverified: 0, passwordless: 0, compilation: 0 });
      expect(r.rows.every((row) => row.source?.name)).toBe(true);
    });
  });

  it('aggregates per-source row counts and carries the exposure flags', async () => {
    await withStub(async () => {
      setDumpKey('leakcheck', 'test-key');
      const r = await leakcheckPro('a@example.com', 'email');
      const website = r.sources.find((s) => s.name === 'BreachedWebsite.net');
      expect(website?.count).toBe(2);
      expect(website?.date).toBe('2019-07');
      const stealer = r.sources.find((s) => s.name === 'InfostealerLog');
      expect(stealer?.unverified).toBe(true);
      expect(r.sources[0].count).toBeGreaterThanOrEqual(r.sources[1].count);
      expect(r.fields).toEqual(expect.arrayContaining(['password', 'email']));
    });
  });

  it('sends the key as X-API-Key and never in the URL', async () => {
    await withStub(async () => {
      setDumpKey('leakcheck', 'secret-key-value');
      await leakcheckPro('a@example.com', 'email');
      expect(lastAuth).toBe('secret-key-value');
      expect(lastUrl).not.toContain('secret-key-value');
      expect(lastUrl).not.toContain('key=');
    });
  });

  it('omits the type param on auto (the API rejects nothing) and sends it otherwise', async () => {
    await withStub(async () => {
      setDumpKey('leakcheck', 'k');
      await leakcheckPro('a@example.com', 'auto');
      expect(lastUrl).toBe('/api/v2/query/a%40example.com');
      await leakcheckPro('a@example.com', 'phone');
      expect(lastUrl).toBe('/api/v2/query/a%40example.com?type=phone');
    });
  });

  it('does not send limit/offset — the live API ignores limit and 0-rows on offset', async () => {
    await withStub(async () => {
      setDumpKey('leakcheck', 'k');
      await leakcheckPro('a@example.com', 'email');
      expect(lastUrl).not.toContain('limit=');
      expect(lastUrl).not.toContain('offset=');
    });
  });

  it('"Active plan required" reads as a plan gate, not a broken lane, and points at the free lane', async () => {
    await withStub(async () => {
      setDumpKey('leakcheck', 'k');
      const r = await leakcheckPro('enterpriseonly', 'domain');
      expect(r.found).toBe(0);
      expect(r.note).toMatch(/Active plan required/);
      expect(r.note).toMatch(/PUBLIC lane still returns/);
    });
  });

  it('a 422 auto-detect failure tells the operator to pass an explicit type', async () => {
    await withStub(async () => {
      setDumpKey('leakcheck', 'k');
      const r = await leakcheckPro('cannotdetect');
      expect(r.note).toMatch(/explicit type/i);
    });
  });

  it('a clean result is a real zero with no error note', async () => {
    await withStub(async () => {
      setDumpKey('leakcheck', 'k');
      const r = await leakcheckPro('nothing', 'email');
      expect(r.found).toBe(0);
      expect(r.note).toBeUndefined();
      expect(r.rows).toEqual([]);
    });
  });

  it('refuses a query under 3 characters before spending a call', async () => {
    await withStub(async () => {
      setDumpKey('leakcheck', 'k');
      const r = await leakcheckPro('ab', 'email');
      expect(r.note).toMatch(/at least 3 characters/);
    });
  });
});

describe('osint_leakcheck agent tool', () => {
  it('is registered with a required query and the honest-hit caveat', () => {
    const tool = OSINT_TOOLS.find((t) => t.name === 'osint_leakcheck');
    expect(tool).toBeTruthy();
    expect(tool!.description).toContain('LeakCheck');
    expect(tool!.description).toMatch(/does not prove the account is still active/i);
    expect(tool!.parameters?.find((p) => p.name === 'query')?.required).toBe(true);
  });
});

describe('dump-lane arming is complete', () => {
  // The ARMED count on the OSINT panel is the operator's only at-a-glance answer
  // to "what is actually live here". It once read 1/3 while TWO lanes were
  // armed, because the OpenCellID key lived in a separate `gps` object that the
  // lane list — and therefore the counter — never saw. Any lane with a key must
  // appear in `lanes`, or the number is a lie.
  const server = readFileSync(new URL('../server.ts', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
  const block = server.slice(
    server.indexOf("app.get('/api/osint/dump-status'"),
    server.indexOf('allowDirect:', server.indexOf("app.get('/api/osint/dump-status'")),
  );

  it('every keyed lane is in the lanes list, including the GPS cell-site lane', () => {
    for (const service of ['LeakCheck Pro v2 (keyed)', 'DeHashed', 'Snusbase', 'OpenCellID (GPS towers)']) {
      expect(block, `lane missing from dump-status: ${service}`).toContain(service);
    }
  });

  it('the opencellid lane is in `lanes` and is not only reachable via `gps`', () => {
    expect(block).toMatch(/key:\s*'opencellid'/);
    // The counter is computed from `lanes`; if opencellid were absent from that
    // array the panel under-reports. `gps` is derived from the same entry.
    expect(block).toContain('lanes: enriched');
  });

  it('the stat card is not hardcoded to a fixed lane count', () => {
    const page = readFileSync(new URL('../../docs/osint.html', import.meta.url), 'utf8');
    expect(page).toContain('id="statKeyedLanes"');
    expect(page).not.toMatch(/id="statKeyedLanes">\s*0\/\d/);
  });

  // LeakCheck is a DEEP DUMP LANE, the same class of thing as DeHashed and
  // Snusbase — not a bespoke tool. It was renamed "Keyed Lanes Armed" once and
  // relabelled "LEAKCHECK.IO", which is how it started reading as a separate
  // thing bolted onto the panel. Terminology is part of the contract here.
  it('LeakCheck is presented as a deep dump lane, not a separate tool', () => {
    const page = readFileSync(new URL('../../docs/osint.html', import.meta.url), 'utf8');
    expect(page).toContain('Deep Dump Lanes Armed');
    expect(page).not.toMatch(/Keyed Lanes Armed/);
    expect(page).toContain('LEAKCHECK PRO V2 <span class="count">deep dump lane</span>');
  });

  // The panel must never tell an operator to set a URL as if it were a key.
  it('no UI text names LEAKCHECKIO or LEAKCHECK_PUBLIC_API as a key variable', () => {
    const page = readFileSync(new URL('../../docs/osint.html', import.meta.url), 'utf8');
    expect(page).not.toMatch(/LEAKCHECKIO\s*\/|LEAKCHECKIO_APIKEY(?!.*not keys)/);
    // wherever the two URL variables appear, they must be labelled as URLs
    for (const m of page.matchAll(/LEAKCHECKIO\b|LEAKCHECK_PUBLIC_API/g)) {
      const window = page.slice(Math.max(0, m.index! - 260), m.index! + 260);
      expect(window, `LEAKCHECKIO presented without URL framing near index ${m.index}`).toMatch(/URL|not a key|not keys|endpoint/i);
    }
  });
});
