import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, type Server } from 'http';
import {
  mapSherlockEntry,
  mapSherlockData,
  buildSherlockMergedCatalog,
  inferSherlockCategory,
  loadSherlockData,
  SHERLOCK_DATA_PATH,
  SHERLOCK_SOURCE,
} from '../tools/sherlock-sites.js';
import {
  OSINT_SITES,
  getMergedSiteCatalog,
  runUsernameSweep,
  type OsintSite,
} from '../tools/osint.js';

// =============================================================================
// SHERLOCK INTEGRATION — the vendored platform database and, more importantly,
// the three absence-detection techniques it contributes to the username sweep:
//
//   errorType: message      → 2xx + any error marker in the body = ABSENT
//   errorType: response_url → 2xx but redirected to the error page = ABSENT
//   regexCheck              → a username the platform cannot accept is SKIPPED
//
// Each is proven behaviorally against a local HTTP stub, not just mapped.
// =============================================================================

describe('sherlock site database (vendored)', () => {
  it('the vendored data.json loads and is a real platform database', () => {
    const data = loadSherlockData();
    expect(Object.keys(data).length).toBeGreaterThan(400);
    expect(data.GitHub?.url).toBe('https://www.github.com/{}');
  });

  it('reports upstream provenance for the UI', () => {
    expect(SHERLOCK_SOURCE).toContain('sherlock-project/sherlock');
    expect(SHERLOCK_DATA_PATH.replace(/\\/g, '/')).toContain('tools/sherlock/data.json');
  });

  it('maps every errorType onto a representable site (POST-only entries are the only skips)', () => {
    const { sites, skipped, byErrorType } = mapSherlockData(loadSherlockData());
    expect(sites.length).toBeGreaterThan(400);
    // The database carries three absence semantics; all three must survive the map.
    expect(byErrorType.status_code).toBeGreaterThan(250);
    expect(byErrorType.message).toBeGreaterThan(100);
    expect(byErrorType.response_url).toBeGreaterThan(20);
    // Only POST/HEAD entries may be skipped — a GET-probed misclassification is worse than a miss.
    expect(skipped.length).toBeLessThanOrEqual(5);
    for (const name of skipped) expect(['Anilist', 'Discord', 'Holopin']).toContain(name);
  });

  it('every mapped site has a usable template and a sane reliability', () => {
    const { sites } = mapSherlockData(loadSherlockData());
    for (const s of sites) {
      expect(s.urlTemplate, `${s.name} urlTemplate`).toContain('{u}');
      expect(s.probeUrlTemplate, `${s.name} probeUrlTemplate`).toContain('{u}');
      expect(s.probeUrlTemplate, `${s.name} probe url`).toMatch(/^https:\/\//);
      expect(s.source).toBe('sherlock');
      expect(['high', 'medium', 'low']).toContain(s.reliability);
    }
  });
});

describe('sherlock entry mapping', () => {
  it('status_code → plain status probe', () => {
    const site = mapSherlockEntry('Example', { errorType: 'status_code', url: 'https://example.com/{}' });
    expect(site?.probeType).toBe('status');
    expect(site?.absentMarkers).toBeUndefined();
  });

  it('message → any-of absent markers, and tolerates the string form', () => {
    // The database stores errorMsg as a bare string far more often than an array.
    const asString = mapSherlockEntry('A', { errorType: 'message', errorMsg: 'no such user', url: 'https://a.com/{}' });
    expect(asString?.absentMarkers).toEqual(['no such user']);
    const asArray = mapSherlockEntry('B', { errorType: 'message', errorMsg: ['x', 'y'], url: 'https://b.com/{}' });
    expect(asArray?.absentMarkers).toEqual(['x', 'y']);
  });
  it('message with no usable marker is refused rather than guessed', () => {
    expect(mapSherlockEntry('C', { errorType: 'message', url: 'https://c.com/{}' })).toBeNull();
  });

  it('response_url → redirect-target absence check', () => {
    const site = mapSherlockEntry('D', { errorType: 'response_url', errorUrl: 'https://d.com/', url: 'https://d.com/{}/' });
    expect(site?.absentRedirectPrefix).toBe('https://d.com/');
  });

  it('regexCheck is carried through only when it compiles', () => {
    const ok = mapSherlockEntry('E', { errorType: 'status_code', regexCheck: '^[a-z]{3,10}$', url: 'https://e.com/{}' });
    expect(ok?.usernameRegex).toBe('^[a-z]{3,10}$');
    const bad = mapSherlockEntry('F', { errorType: 'status_code', regexCheck: '([unclosed', url: 'https://f.com/{}' });
    expect(bad?.usernameRegex).toBeUndefined();
  });

  it('urlProbe wins over the human page and POST entries are refused', () => {
    const site = mapSherlockEntry('G', {
      errorType: 'status_code', url: 'https://g.com/{}', urlProbe: 'https://api.g.com/user/{}',
    });
    expect(site?.probeUrlTemplate).toBe('https://api.g.com/user/{u}');
    expect(site?.urlTemplate).toBe('https://g.com/{u}');
    expect(mapSherlockEntry('H', { errorType: 'status_code', url: 'https://h.com/{}', request_method: 'POST' })).toBeNull();
  });

  it('an API-only entry (no profile-page placeholder) still maps via urlProbe', () => {
    const site = mapSherlockEntry('I', { errorType: 'status_code', urlProbe: 'https://i.com/api/user/{}' });
    expect(site?.probeUrlTemplate).toBe('https://i.com/api/user/{u}');
  });

  it('category inference keeps adult platforms out of the default bucket', () => {
    expect(inferSherlockCategory('Pornhub', { url: 'https://pornhub.com/users/{}' })).toBe('adult');
    expect(inferSherlockCategory('SomeForum', { url: 'https://x.com/{}' })).not.toBe('adult');
    // The inference must not collapse into one bucket.
    const { sites } = mapSherlockData(loadSherlockData());
    const cats = new Set(sites.map((s) => s.category));
    expect(cats.size).toBeGreaterThanOrEqual(6);
  });
});

describe('merged catalog', () => {
  it('curated entries win on name collision and carry provenance', () => {
    const merged = buildSherlockMergedCatalog(OSINT_SITES);
    expect(merged.curatedCount).toBe(OSINT_SITES.length);
    expect(merged.catalog.length).toBe(merged.curatedCount + merged.sherlockCount);
    // GitHub is in both catalogs — the hand-probed API version must survive.
    const gh = merged.catalog.filter((s) => s.name === 'GitHub');
    expect(gh).toHaveLength(1);
    expect(gh[0].source).toBe('curated');
    expect(gh[0].probeUrlTemplate).toContain('api.github.com');
    for (const s of merged.catalog) expect(['curated', 'sherlock']).toContain(s.source);
  });

  it('the live merged catalog is the full sweep surface and adult sites are flagged', () => {
    const cat = getMergedSiteCatalog();
    expect(cat.catalog.length).toBeGreaterThan(400);
    expect(cat.catalog.filter((s) => s.source === 'sherlock').length).toBeGreaterThan(300);
    // Sherlock's own isNSFW flags must survive into the sweep filter.
    expect(cat.catalog.filter((s) => s.adult).length).toBeGreaterThanOrEqual(15);
  });
});

// =============================================================================
// BEHAVIOR — the three techniques against a real HTTP server, through the real
// sweep (customSites hook). A classifier that only "looks right" in the mapper
// would still fail here.
// =============================================================================
describe('sherlock absence techniques (live stub)', () => {
  let server: Server;
  let port = 0;

  beforeAll(async () => {
    server = createServer((req, res) => {
      const u = req.url || '';
      if (u === '/soft404/user/alice') {            // exists → clean 200
        res.writeHead(200, { 'content-type': 'text/html' });
        res.end('<html><body>alice profile</body></html>');
      } else if (u === '/soft404/user/nobody') {     // missing → 200 + error marker
        res.writeHead(200, { 'content-type': 'text/html' });
        res.end('<html><head><title>Error something went wrong.</title></head></html>');
      } else if (u === '/redirect/taken') {
        res.writeHead(200, { 'content-type': 'text/html' });
        res.end('<html>ok</html>');
      } else if (u === '/redirect/missing') {
        res.writeHead(302, { location: '/error404.aspx' });
        res.end();
      } else if (u === '/error404.aspx') {
        res.writeHead(200, { 'content-type': 'text/html' });
        res.end('<html>not found</html>');
      } else {
        res.writeHead(404); res.end('nope');
      }
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
    port = (server.address() as { port: number }).port;
  });

  afterAll(async () => { await new Promise<void>((r) => server.close(() => r())); });

  const mk = (over: Partial<OsintSite>): OsintSite => ({
    name: 'stub', category: 'social',
    urlTemplate: `http://127.0.0.1:${port}/x`,
    probeUrlTemplate: `http://127.0.0.1:${port}/x`,
    probeType: 'status', reliability: 'high', ...over,
  });

  it('message markers: a 200 soft-404 is ABSENT, a clean 200 is FOUND', async () => {
    const sites = [
      mk({ name: 'SoftFound', urlTemplate: `http://127.0.0.1:${port}/soft404/user/alice`, probeUrlTemplate: `http://127.0.0.1:${port}/soft404/user/alice`, probeType: 'body_contains', absentMarkers: ['<title>Error something went wrong.</title>'] }),
      mk({ name: 'SoftMissing', urlTemplate: `http://127.0.0.1:${port}/soft404/user/nobody`, probeUrlTemplate: `http://127.0.0.1:${port}/soft404/user/nobody`, probeType: 'body_contains', absentMarkers: ['<title>Error something went wrong.</title>'] }),
    ];
    // The same username each time; the site URL decides the outcome.
    const found = await runUsernameSweep('alice', { customSites: [sites[0]] });
    const missing = await runUsernameSweep('alice', { customSites: [sites[1]] });
    expect(found.found.map((h) => h.site)).toEqual(['SoftFound']);
    expect(missing.absent).toBe(1);
    expect(missing.found).toHaveLength(0);
  });

  it('response_url: a 200 that redirects to the error page is ABSENT', async () => {
    const missing = await runUsernameSweep('ghost', {
      customSites: [mk({
        name: 'RedirectMissing',
        urlTemplate: `http://127.0.0.1:${port}/redirect/missing`,
        probeUrlTemplate: `http://127.0.0.1:${port}/redirect/missing`,
        probeType: 'status',
        absentRedirectPrefix: `http://127.0.0.1:${port}/error404.aspx`,
      })],
    });
    const taken = await runUsernameSweep('ghost', {
      customSites: [mk({
        name: 'RedirectTaken',
        urlTemplate: `http://127.0.0.1:${port}/redirect/taken`,
        probeUrlTemplate: `http://127.0.0.1:${port}/redirect/taken`,
        probeType: 'status',
        absentRedirectPrefix: `http://127.0.0.1:${port}/error404.aspx`,
      })],
    });
    expect(missing.absent).toBe(1);
    expect(missing.found).toHaveLength(0);
    expect(taken.found.map((h) => h.site)).toEqual(['RedirectTaken']);
  });

  it('regexCheck: an impossible username is SKIPPED, never a false ABSENT', async () => {
    const r = await runUsernameSweep('way_too_long_for_this_platform', {
      customSites: [mk({
        name: 'ShapeGated',
        urlTemplate: `http://127.0.0.1:${port}/soft404/user/nobody`,
        probeUrlTemplate: `http://127.0.0.1:${port}/soft404/user/nobody`,
        probeType: 'status',
        usernameRegex: '^[a-z]{3,10}$',
      })],
    });
    expect(r.absent).toBe(0);
    expect(r.found).toHaveLength(0);
    expect(r.skippedByShape).toEqual(['ShapeGated']);
    expect(r.details[0].note).toContain('cannot exist on this platform');
  });

  it('a regex-matching username is probed normally', async () => {
    const r = await runUsernameSweep('alice', {
      customSites: [mk({
        name: 'ShapeOk',
        urlTemplate: `http://127.0.0.1:${port}/soft404/user/alice`,
        probeUrlTemplate: `http://127.0.0.1:${port}/soft404/user/alice`,
        probeType: 'status',
        usernameRegex: '^[a-z]{3,10}$',
      })],
    });
    expect(r.found.map((h) => h.site)).toEqual(['ShapeOk']);
    expect(r.skippedByShape).toHaveLength(0);
  });
});
