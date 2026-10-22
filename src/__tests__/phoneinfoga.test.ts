import { describe, it, expect, afterEach } from 'vitest';
import { createServer, type Server } from 'http';
import { AddressInfo } from 'net';
import {
  phoneIntel,
  phoneInfogaDorks,
  phoneInfogaDorkStats,
  phoneInfogaScan,
  phoneInfogaRemoteInfo,
  phoneInfogaRemoteScan,
  phoneInfogaRemoteRun,
  phoneInfogaRemoteGoogleDorks,
  OSINT_TOOLS,
} from '../tools/osint.js';

// =============================================================================
// PHONEINFOGA INTEGRATION — port of sundowndev/phoneinfoga (GPL-3.0) plus the
// remote REST adapter that speaks the project's own swagger v2 contract:
//   GET  /api/v2/scanners · POST /api/v2/numbers
//   POST /api/v2/scanners/{scanner}/run | /dryrun
// =============================================================================

describe('phoneIntel — local formatting (PhoneInfoga local scanner)', () => {
  it('parses an international number into every format the swagger number.Number exposes', () => {
    const p = phoneIntel('+33 6 12 34 56 78');
    expect(p.e164).toBe('+33612345678');
    expect(p.countryCode).toBe('33');
    expect(p.countryIso).toBe('FR');
    expect(p.country).toContain('France');
    expect(p.national).toBe('612345678');
    expect(p.rawLocal).toBe('612345678');
    expect(p.valid).toBe(true);
    expect(p.lengthValid).toBe(true);
  });

  it('assumes +1 for a bare 10-digit NANP number and validates the area code', () => {
    const p = phoneIntel('2025550143');
    expect(p.e164).toBe('+12025550143');
    expect(p.nanp).toMatchObject({ areaCode: '202', exchange: '555', validAreaCode: true });
    // 0/1-leading area codes are not real NANP codes.
    expect(phoneIntel('1235550143').nanp?.validAreaCode).toBe(false);
  });

  it('rejects garbage rather than inventing a parse', () => {
    expect(() => phoneIntel('not-a-number')).toThrow(/Invalid phone number/);
    expect(() => phoneIntel('12345')).toThrow(/Invalid phone number/);
  });
});

describe('phoneInfogaDorks — the googlesearch scanner', () => {
  it('covers all five PhoneInfoga dork categories', () => {
    const stats = phoneInfogaDorkStats(phoneInfogaDorks('+1 202 555 0143'));
    expect(stats.social).toBe(5);
    expect(stats.disposable).toBeGreaterThanOrEqual(20);
    expect(stats.reputation).toBe(10);
    expect(stats.individuals).toBe(7);
    expect(stats.general).toBe(2);
  });

  it('every dork is a Google URL carrying the E.164 or international form', () => {
    const dorks = phoneInfogaDorks('+1 202 555 0143');
    for (const d of dorks) {
      expect(d.url.startsWith('https://www.google.com/search?q=')).toBe(true);
      expect(d.query.length).toBeGreaterThan(5);
      expect(decodeURIComponent(d.url)).toContain('202');
    }
  });

  it('returns an empty set for an unparseable number instead of throwing', () => {
    expect(phoneInfogaDorks('nope')).toEqual([]);
  });
});

describe('phoneInfogaScan — composite local scan', () => {
  const env = { ...process.env };
  afterEach(() => {
    process.env = { ...env };
  });

  it('always reports an honest Numverify gate and an OVH country verdict', async () => {
    delete process.env.T3MP3ST_NUMVERIFY_KEY;
    delete process.env.NUMVERIFY_API_KEY;
    const s = await phoneInfogaScan('+1 202 555 0143');
    expect(s.e164).toBe('+12025550143');
    expect(s.numverify?.configured).toBe(false);
    // CC 1 is not in the OVH country set — the result says so rather than guessing.
    expect(s.ovh?.supported).toBe(false);
    expect(s.dorks.length).toBeGreaterThanOrEqual(45);
    expect(s.remote).toBeNull();
    expect(s.scanNote).toContain('does NOT hack phone');
  });
});

// ── Remote REST adapter: proven against a live stub speaking the swagger shapes ──
describe('phoneInfoga remote REST adapter (swagger v2)', () => {
  const servers: Server[] = [];
  const env = { ...process.env };

  afterEach(async () => {
    process.env = { ...env };
    await Promise.all(servers.splice(0).map((s) => new Promise<void>((r) => s.close(() => r()))));
  });

  async function startStub(): Promise<string> {
    const srv = createServer((req, res) => {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        const json = (o: unknown) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
        const url = req.url || '';
        if (url === '/api/') return json({ success: true, version: 'v2.11.0', commit: 'deadbeef', demo: false });
        if (url === '/api/v2/scanners') {
          return json({ scanners: [
            { name: 'local', description: 'Local scanner' },
            { name: 'googlesearch', description: 'Google search dorks' },
            { name: 'ovh', description: 'OVH VoIP ranges' },
            { name: 'numverify', description: 'Numverify API' },
          ] });
        }
        if (url === '/api/v2/numbers' && req.method === 'POST') {
          return json({ carrier: '', country: 'France', countryCode: 33, e164: '+33612345678', international: '+33 6 12 34 56 78', local: '06 12 34 56 78', rawLocal: '612345678', valid: true });
        }
        if (/\/api\/v2\/scanners\/googlesearch\/run$/.test(url)) {
          return json({ result: {
            social_media: [{ dork: 'site:facebook.com intext:"+33612345678"', url: 'https://www.google.com/search?q=a', number: '+33612345678' }],
            disposable_providers: [{ dork: 'site:hs3x.com ("+33612345678")', url: 'https://www.google.com/search?q=b', number: '+33612345678' }],
            reputation: [], individuals: [], general: [],
          } });
        }
        if (/\/api\/v2\/scanners\/ovh\/run$/.test(url)) {
          return json({ result: { found: true, number_range: '336123xxxx', city: 'Lyon', zip_code: '69000' } });
        }
        if (/\/api\/v2\/scanners\/numverify\/run$/.test(url)) {
          return json({ result: { valid: true, carrier: 'Orange', line_type: 'mobile', location: 'Lyon', country_name: 'France', country_code: 'FR' } });
        }
        if (/\/api\/v2\/scanners\/[\w-]+\/dryrun$/.test(url)) return json({ success: true });
        res.writeHead(404, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: `not found: ${url}` }));
      });
    });
    servers.push(srv);
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
    const { port } = srv.address() as AddressInfo;
    return `http://127.0.0.1:${port}`;
  }

  it('reports "not configured" honestly when no instance URL is set', async () => {
    delete process.env.T3MP3ST_PHONEINFOGA_URL;
    const info = await phoneInfogaRemoteInfo();
    expect(info.configured).toBe(false);
    expect(info.reachable).toBe(false);
    expect(info.error).toMatch(/T3MP3ST_PHONEINFOGA_URL/);
  });

  it('discovers a live instance: health version + scanner list', async () => {
    const url = await startStub();
    process.env.T3MP3ST_PHONEINFOGA_URL = url;
    const info = await phoneInfogaRemoteInfo();
    expect(info.reachable).toBe(true);
    expect(info.version).toBe('v2.11.0');
    expect(info.scanners?.map((s) => s.name)).toContain('googlesearch');
  });

  it('folds remote numverify + ovh + googlesearch results into the local scan', async () => {
    const url = await startStub();
    process.env.T3MP3ST_PHONEINFOGA_URL = url;
    const scan = await phoneInfogaScan('+33 6 12 34 56 78', { remote: true });
    expect(scan.remote?.reachable).toBe(true);
    // remote numverify scanner fills carrier/line/location that the unkeyed local port cannot
    expect(scan.carrier).toBe('Orange');
    expect(scan.lineType).toBe('mobile');
    expect(scan.location).toBe('Lyon');
    // remote OVH scanner flips the VoIP verdict with its swagger field names
    expect(scan.ovh?.found).toBe(true);
    expect(scan.ovh?.numberRange).toBe('336123xxxx');
    expect(scan.ovh?.city).toBe('Lyon');
    // remote dorks are merged and deduped against the local set
    const remoteDorks = scan.dorks.filter((d) => d.label.startsWith('Remote'));
    expect(remoteDorks.length).toBeGreaterThan(0);
    const queries = new Set(scan.dorks.map((d) => d.query));
    expect(queries.size).toBe(scan.dorks.length);
  });

  it('the remote google dork helper returns the categorized swagger arrays', async () => {
    const url = await startStub();
    process.env.T3MP3ST_PHONEINFOGA_URL = url;
    const grouped = await phoneInfogaRemoteGoogleDorks('+33 6 12 34 56 78');
    expect(grouped.social_media?.[0]?.dork).toContain('facebook.com');
    expect(grouped.disposable_providers?.[0]?.dork).toContain('hs3x.com');
  });

  it('dry-run reports scanner readiness without running any scan', async () => {
    const url = await startStub();
    process.env.T3MP3ST_PHONEINFOGA_URL = url;
    const dry = await phoneInfogaRemoteScan('+33 6 12 34 56 78', { dryRun: true });
    expect(dry.dryRuns).toMatchObject({ googlesearch: 'ready', ovh: 'ready', numverify: 'ready' });
    expect(dry.results?.googlesearch).toBeUndefined();
  });

  it('an unreachable configured instance is a labeled lane failure, not a crash', async () => {
    process.env.T3MP3ST_PHONEINFOGA_URL = 'http://127.0.0.1:1';
    const scan = await phoneInfogaScan('+1 202 555 0143', { remote: true });
    expect(scan.remote?.configured).toBe(true);
    expect(scan.remote?.reachable).toBe(false);
    expect(scan.e164).toBe('+12025550143');
    expect(scan.scanNote).toContain('UNREACHABLE');
  });

  it('a single scanner run returns its result or its error string', async () => {
    const url = await startStub();
    process.env.T3MP3ST_PHONEINFOGA_URL = url;
    const ok = await phoneInfogaRemoteRun('+33 6 12 34 56 78', 'ovh');
    expect(ok.ok).toBe(true);
    expect((ok.result as any).found).toBe(true);
    const bad = await phoneInfogaRemoteRun('+33 6 12 34 56 78', 'nosuchscanner');
    expect(bad.ok).toBe(false);
  });
});

describe('PhoneInfoga agent tool registration', () => {
  it('osint_phone_scan is registered and carries the doctrine disclaimer', () => {
    const tool = OSINT_TOOLS.find((t) => t.name === 'osint_phone_scan');
    expect(tool).toBeTruthy();
    expect(tool!.description).toContain('PhoneInfoga');
    expect(tool!.description).toMatch(/does NOT track phone in real time/i);
    const phoneParam = tool!.parameters?.find((p) => p.name === 'phone');
    expect(phoneParam?.required).toBe(true);
  });

  it('osint_phone_lookup keeps working as the fast local path', () => {
    const tool = OSINT_TOOLS.find((t) => t.name === 'osint_phone_lookup');
    expect(tool).toBeTruthy();
    expect(tool!.description).toContain('PhoneInfoga');
  });
});
