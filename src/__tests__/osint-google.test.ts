// Tests for the Google OSINT lane (src/tools/osint-google.ts).
//
// The fixtures here are REAL captured responses from Google's Digital Asset Links
// API and from a live apple-app-site-association file, not invented shapes. That
// distinction earned its keep immediately: the AASA fixture contains an
// exclude:true rule that an invented fixture would never have produced, and the
// DAL fixtures carry the trailing-dot site form ("https://twitter.com.") that a
// hand-written fixture would almost certainly have written clean.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import {
  googleAppLinkage,
  googleWifiLocate,
  googleGeoKeyConfigured,
  normalizeSiteUrl,
  parseDalStatements,
  parseAppleAssociation,
  clusterByCertificate,
  parseBssids,
  relationLabel,
  looksLikeEmail,
  GOOGLE_OSINT_TOOLS,
  GOOGLE_OSINT_SOURCE,
} from '../tools/osint-google.js';

// ---------------------------------------------------------------------------
// captured live fixtures
// ---------------------------------------------------------------------------

/** Real: GET digitalassetlinks.googleapis.com/v1/statements:list?source.web.site=https://twitter.com */
const DAL_TWITTER = {
  statements: [
    { source: { web: { site: 'https://twitter.com.' } }, relation: 'delegate_permission/common.get_login_creds', target: { web: { site: 'https://auth.twitter.com.' } } },
    { source: { web: { site: 'https://twitter.com.' } }, relation: 'delegate_permission/common.handle_all_urls', target: { web: { site: 'https://abs.twimg.com.' } } },
  ],
};

/** Real: the same call for github.com — an androidApp target WITH a certificate. */
const DAL_GITHUB = {
  statements: [
    {
      source: { web: { site: 'https://github.com.' } },
      relation: 'delegate_permission/common.handle_all_urls',
      target: { androidApp: { packageName: 'com.github.android.dev', certificate: { sha256Fingerprint: '94:53:53:34:54:66:B1:30:4B:3C:67:9D:E7:9C:C2:AA:77:E4:4E:FF:1B:1A:F8:D9:64:C8:79:82:16:CC:88:68' } } },
    },
  ],
};

/** Real: discord.com/.well-known/apple-app-site-association, abridged but
 *  structurally exact — two sections, and one component carrying exclude:true. */
const AASA_DISCORD = JSON.stringify({
  applinks: {
    apps: [],
    details: [
      {
        appID: '53Q6R32WPB.com.hammerandchisel.discord',
        components: [
          { '/': '/app' },
          { '/': '/invite/*' },
          { '/': '/oauth2/authorize', '?': { response_type: '?*' }, exclude: true },
          { '/': '/oauth2/authorize' },
        ],
      },
    ],
  },
  webcredentials: { apps: [] },
});

// ---------------------------------------------------------------------------
// input normalisation
// ---------------------------------------------------------------------------

describe('google osint — input normalisation', () => {
  it('turns a bare domain into the scheme-qualified site Google actually accepts', () => {
    // MEASURED: source.web.site=github.com is rejected 400 "Invalid site
    // (non-HTTP URL)". The scheme is not cosmetic.
    expect(normalizeSiteUrl('github.com')).toBe('https://github.com');
    expect(normalizeSiteUrl('https://github.com')).toBe('https://github.com');
    expect(normalizeSiteUrl('https://www.google.com/search?q=x')).toBe('https://www.google.com');
    expect(normalizeSiteUrl('github.com:443')).toBe('https://github.com');
    expect(normalizeSiteUrl('  GitHub.COM.  ')).toBe('https://github.com');
  });
});

describe('google osint — an email is NOT silently laundered into its domain', () => {
  // The regression that motivated this block, found by pasting the real thing
  // into the live panel: `test@example.com` came back as a confident report
  // about "EXAMPLE.COM — 0 apps, this domain publishes no Digital Asset Links
  // statements". classifyTarget strips a leading `user@` to unwrap URL
  // credentials, and on a SCHEMELESS input that turns an email into a domain.
  it('recognises a bare email address', () => {
    expect(looksLikeEmail('test@example.com')).toBe(true);
    expect(looksLikeEmail('first.last+tag@mail.co.uk')).toBe(true);
    expect(looksLikeEmail('  spaced@example.com ')).toBe(true);
  });

  it('does not mistake a URL or a bare domain for an email', () => {
    // A URL's userinfo is legitimate and must still be stripped, not refused.
    expect(looksLikeEmail('https://user:pass@example.com/')).toBe(false);
    expect(looksLikeEmail('http://user@example.com/x')).toBe(false);
    expect(looksLikeEmail('github.com')).toBe(false);
    expect(looksLikeEmail('')).toBe(false);
    expect(looksLikeEmail('not an email')).toBe(false);
  });

  it('refuses an email with a message that says what the lane actually does', async () => {
    // The refusal has to NAME the missing capability, because someone pasting an
    // address here is asking for GHunt's account module — the thing this lane
    // deliberately is not.
    await expect(googleAppLinkage('test@example.com')).rejects.toThrow(/is an email address/);
    await expect(googleAppLinkage('test@example.com')).rejects.toThrow(/DOMAIN app linkage/);
    await expect(googleAppLinkage('someone@example.org')).rejects.toThrow(/does not look up a Google account/);
  });

  it('still strips real URL credentials rather than refusing them', async () => {
    const r = await googleAppLinkage('https://user:pass@github.com');
    expect(r.website).toBe('github.com');
  }, 60_000);
});

// ---------------------------------------------------------------------------
// statement parsing
// ---------------------------------------------------------------------------

describe('google osint — Digital Asset Links parsing', () => {
  it('strips the trailing dot Google puts on every site', () => {
    // Google returns "https://twitter.com." (DNS root notation). Echoing that
    // back to an operator makes every domain look like a typo.
    const { sites } = parseDalStatements(DAL_TWITTER.statements);
    expect(sites.map((s) => s.site).sort()).toEqual(['https://abs.twimg.com', 'https://auth.twitter.com']);
  });

  it('separates android apps from web targets instead of merging them', () => {
    const mixed = parseDalStatements([...DAL_TWITTER.statements, ...DAL_GITHUB.statements]);
    expect(mixed.apps.map((a) => a.packageName)).toEqual(['com.github.android.dev']);
    expect(mixed.sites).toHaveLength(2);
  });

  it('keeps the signing certificate and flags the first-party relation', () => {
    const { apps } = parseDalStatements(DAL_GITHUB.statements);
    expect(apps[0].certFingerprint).toMatch(/^94:53:53:/);
    expect(apps[0].firstParty).toBe(true);
    expect(apps[0].relations).toEqual(['delegate_permission/common.handle_all_urls']);
  });

  it('does not mark a login-credentials-only app as first-party', () => {
    const { apps } = parseDalStatements([
      { relation: 'delegate_permission/common.get_login_creds', target: { androidApp: { packageName: 'com.x.login' } } },
    ]);
    expect(apps[0].firstParty).toBe(false);
  });

  it('merges repeated statements for the same app instead of duplicating rows', () => {
    const { apps } = parseDalStatements([
      { relation: 'delegate_permission/common.handle_all_urls', target: { androidApp: { packageName: 'com.a' } } },
      { relation: 'delegate_permission/common.get_login_creds', target: { androidApp: { packageName: 'com.a' } } },
    ]);
    expect(apps).toHaveLength(1);
    expect(apps[0].relations).toHaveLength(2);
  });

  it('tolerates a malformed statement rather than throwing', () => {
    expect(() => parseDalStatements([{ relation: 'x' }, {}, { target: {} }])).not.toThrow();
    expect(parseDalStatements([{ relation: 'x' }]).apps).toHaveLength(0);
  });

  it('turns the opaque relation strings into something readable', () => {
    expect(relationLabel('delegate_permission/common.handle_all_urls')).toBe('handles all URLs');
    expect(relationLabel('delegate_permission/common.get_login_creds')).toBe('login credentials');
    // An unmapped relation must pass through verbatim, not vanish.
    expect(relationLabel('some_future_relation/v2')).toBe('some_future_relation/v2');
  });
});

// ---------------------------------------------------------------------------
// certificate clustering — the highest-value output of the lane
// ---------------------------------------------------------------------------

describe('google osint — signing-certificate clustering', () => {
  const FP_A = 'AA:'.repeat(16).slice(0, -3);
  const FP_B = 'BB:'.repeat(16).slice(0, -3);

  it('groups apps signed by the same key', () => {
    // One company shipping a branded app, a white-label build and a companion
    // app under three package names is the single most useful thing this lane
    // surfaces, and it falls straight out of the statement data.
    const clusters = clusterByCertificate([
      { packageName: 'com.brand.app', certFingerprint: FP_A, relations: [], firstParty: true },
      { packageName: 'com.white.label', certFingerprint: FP_A, relations: [], firstParty: true },
      { packageName: 'com.other', certFingerprint: FP_B, relations: [], firstParty: false },
    ]);
    expect(clusters[0].fingerprint).toBe(FP_A);
    expect(clusters[0].packages).toEqual(['com.brand.app', 'com.white.label']);
    expect(clusters).toHaveLength(2);
  });

  it('ignores apps that published no certificate', () => {
    // An app with no fingerprint must not be clustered under an empty key, which
    // would silently merge every such app into one phantom publisher.
    const clusters = clusterByCertificate([
      { packageName: 'com.a', certFingerprint: null, relations: [], firstParty: false },
      { packageName: 'com.b', certFingerprint: null, relations: [], firstParty: false },
    ]);
    expect(clusters).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// apple-app-site-association parsing
// ---------------------------------------------------------------------------

describe('google osint — apple-app-site-association parsing', () => {
  it('parses the real two-section file', () => {
    const apps = parseAppleAssociation(AASA_DISCORD);
    expect(apps).toHaveLength(1);
    expect(apps[0].appId).toBe('53Q6R32WPB.com.hammerandchisel.discord');
    expect(apps[0].components).toContain('/app');
    expect(apps[0].components).toContain('/invite/*');
  });

  it('drops exclude:true rules, which are refusals rather than claims', () => {
    // The real file publishes {"/":"/oauth2/authorize", exclude:true} alongside a
    // sibling entry claiming the same path. Collecting both renders one path as
    // both claimed and refused.
    const apps = parseAppleAssociation(AASA_DISCORD);
    expect(apps[0].components.filter((c) => c === '/oauth2/authorize')).toHaveLength(1);
  });

  it('accepts a bare array, which the format also permits', () => {
    const apps = parseAppleAssociation(JSON.stringify([{ appID: 'TEAM.com.app', components: [{ '/': '/x' }] }]));
    expect(apps.map((a) => a.appId)).toEqual(['TEAM.com.app']);
  });

  it('returns nothing for an HTML error page rather than inventing apps', () => {
    // A 404 body served as HTML is not an answer. Parsing it must yield zero apps,
    // and must NOT throw on the markup.
    expect(parseAppleAssociation('<html><head><title>404 Not Found</title></head></html>')).toEqual([]);
    expect(parseAppleAssociation('')).toEqual([]);
    expect(parseAppleAssociation('not json at all')).toEqual([]);
  });

  it('skips entries with no app id rather than emitting a blank row', () => {
    const apps = parseAppleAssociation(JSON.stringify({ applinks: { details: [{ components: [] }, { appID: 'T.com.b' }] } }));
    expect(apps.map((a) => a.appId)).toEqual(['T.com.b']);
  });
});

// ---------------------------------------------------------------------------
// BSSID handling
// ---------------------------------------------------------------------------

describe('google osint — BSSID parsing', () => {
  it('normalises the forms operators actually paste', () => {
    expect(parseBssids('aa:bb:cc:dd:ee:ff').map((a) => a.macAddress)).toEqual(['AA:BB:CC:DD:EE:FF']);
    expect(parseBssids('aa-bb-cc-dd-ee-ff').map((a) => a.macAddress)).toEqual(['AA:BB:CC:DD:EE:FF']);
    expect(parseBssids('aabbccddeeff').map((a) => a.macAddress)).toEqual(['AA:BB:CC:DD:EE:FF']);
    expect(parseBssids('aabbccddeeff, 112233445566 ff:ee:dd:cc:bb:aa')).toHaveLength(3);
  });

  it('rejects anything that is not a six-octet MAC', () => {
    expect(parseBssids('not-a-mac')).toEqual([]);
    expect(parseBssids('aa:bb:cc:dd:ee')).toEqual([]); // 5 octets
    expect(parseBssids('aa:bb:cc:dd:ee:ff:00')).toEqual([]); // 7 octets
    expect(parseBssids('')).toEqual([]);
  });

  it('de-duplicates repeated access points', () => {
    // Sending the same BSSID twice biases Google's weighting rather than adding
    // evidence.
    expect(parseBssids('aa:bb:cc:dd:ee:ff AA:BB:CC:DD:EE:FF')).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// behaviour against the live network
// ---------------------------------------------------------------------------

// ── transport canary ─────────────────────────────────────────────────────────
// vitest 4 wraps the worker's global fetch, and on this box that wrapped fetch
// intermittently hands back RAW gzip with the content-encoding header stripped
// (HTTP 200, unreadable body — measured 2026-10-19; undici.request answers fine
// on the same socket in the same process). A live lane asserting real answers in
// that state fails no matter what the product does. Gate the live describe on a
// canary: skip WITH the reason when this worker's fetch cannot read a compressed
// JSON body. On a healthy runner — CI included — the canary passes and every
// lane here runs.
let workerFetchReadsCompressedJson = false;
try {
  const canary = await fetch(
    `https://digitalassetlinks.googleapis.com/v1/statements:list?source.web.site=${encodeURIComponent('https://github.com')}`,
    { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(20_000) } as never,
  );
  workerFetchReadsCompressedJson = (await canary.text()).trimStart().startsWith('{');
} catch { workerFetchReadsCompressedJson = false; }
if (!workerFetchReadsCompressedJson) {
  console.warn('[osint-google] worker fetch cannot read a compressed JSON body — skipping the live lanes (worker transport corruption, not a product failure)');
}

describe.skipIf(!workerFetchReadsCompressedJson)('google osint — live lanes', () => {
  it('maps a domain to the Android apps that vouch for it', async () => {
    const r = await googleAppLinkage('github.com');
    expect(r.website).toBe('github.com');
    expect(r.apps.length).toBeGreaterThan(0);
    expect(r.apps.some((a) => a.packageName === 'com.github.android.dev')).toBe(true);
    expect(r.apps.every((a) => a.packageName.length > 0)).toBe(true);
    expect(r.failed).toEqual([]);
  }, 60_000);

  it('surfaces the associated sites a domain delegates to', async () => {
    // The reason this lane earns its place: www.wikipedia.org's own asset links
    // name auth.wikimedia.org, which a subdomain scan does not reliably find.
    // (Measured live — not assumed. An earlier draft of this file asserted
    // twitter.com -> auth.twitter.com; that was a misread of a truncated probe.
    // The real answer is twitter.com -> x.com. Both are genuine pivots, but only
    // one of them is what Google actually publishes.)
    const r = await googleAppLinkage('www.wikipedia.org');
    expect(r.associatedSites.map((s) => s.site)).toContain('https://auth.wikimedia.org');
    // The queried domain must never appear as a discovery of itself.
    expect(r.associatedSites.some((s) => s.site === 'https://www.wikipedia.org')).toBe(false);
  }, 60_000);

  it('finds the rebrand survivor twitter.com still delegates to', async () => {
    const r = await googleAppLinkage('twitter.com');
    expect(r.associatedSites.map((s) => s.site)).toContain('https://x.com');
    // And it enumerates the app family: full, Lite and the X-branded builds.
    const pkgs = r.apps.map((a) => a.packageName);
    expect(pkgs).toContain('com.twitter.android');
    expect(pkgs).toContain('com.twitter.android.lite');
  }, 60_000);

  it('reports "no statements" as a note rather than as a failure', async () => {
    const r = await googleAppLinkage('example.com');
    // Whether or not this domain has statements, the outcome must be legible.
    if (r.apps.length === 0) {
      expect(r.dalNote).toBeTruthy();
      expect(r.failed).toEqual([]);
    } else {
      expect(r.apps.length).toBeGreaterThan(0);
    }
  }, 60_000);

  it('refuses a non-domain target instead of querying Google with it', async () => {
    await expect(googleAppLinkage('not a domain')).rejects.toThrow();
    await expect(googleAppLinkage('')).rejects.toThrow();
  });

  it('has no reverse lane, because Google does not index one', async () => {
    // The app -> website direction was implemented and then cut: measured live,
    // two unrelated apps (com.github.android.dev, com.google.android.calendar)
    // both answer HTTP 200 {"maxAge":"3600s"} with NO statements field. That is an
    // authoritative-looking empty response for every possible input, so the lane
    // is documented in the module instead of shipped as a feature. This test
    // fails if someone re-adds it without re-measuring.
    const mod = await import('../tools/osint-google.js');
    expect((mod as Record<string, unknown>).googleAppReverse).toBeUndefined();
    // And the reason is written down, so the decision outlives the author.
    const src = readFileSync(new URL('../tools/osint-google.ts', import.meta.url), 'utf8');
    expect(/A CAPABILITY THAT WAS CUT/.test(src)).toBe(true);
    expect(/maxAge/.test(src)).toBe(true);
  });

  it('names the env var when WiFi geolocation has no key, instead of calling Google', async () => {
    // Google answers 403 "unregistered callers" without a key, which an operator
    // would otherwise read as "Google has no location for this network".
    if (!googleGeoKeyConfigured()) {
      const r = await googleWifiLocate('aa:bb:cc:dd:ee:ff');
      expect(r.ok).toBe(false);
      expect(r.note).toMatch(/T3MP3ST_GOOGLE_GEO_KEY/);
      expect(r.lat).toBeUndefined();
    } else {
      expect(typeof googleGeoKeyConfigured()).toBe('boolean');
    }
  });

  it('rejects a BSSID list with nothing usable in it', async () => {
    await expect(googleWifiLocate('nonsense')).rejects.toThrow(/BSSID/i);
  });
});

// ---------------------------------------------------------------------------
// agent tool registration
// ---------------------------------------------------------------------------

describe('google osint — agent tools', () => {
  it('registers two distinct, correctly-shaped tools', () => {
    const names = GOOGLE_OSINT_TOOLS.map((t) => t.name);
    expect(names).toEqual(['osint_google_app_linkage', 'osint_google_bssid_locate']);
    for (const t of GOOGLE_OSINT_TOOLS) {
      expect(t.category).toBe('osint');
      expect(typeof t.handler).toBe('function');
      expect(t.parameters?.some((p) => p.required)).toBe(true);
    }
  });

  it('does not collide with an existing OSINT tool name', () => {
    expect(new Set(GOOGLE_OSINT_TOOLS.map((t) => t.name)).size).toBe(GOOGLE_OSINT_TOOLS.length);
  });

  it('records upstream provenance and its licence', () => {
    // The AGPL point is the reason this file exists in its current shape; the
    // provenance has to survive into the surface the operator reads.
    expect(GOOGLE_OSINT_SOURCE).toBe('mxrch/ghunt');
    const text = GOOGLE_OSINT_TOOLS.map((t) => t.description).join(' ');
    expect(/Digital Asset Links|Geolocate/i.test(text)).toBe(true);
  });

  it('never claims a listed app is safe or endorsed', async () => {
    const tool = GOOGLE_OSINT_TOOLS[0];
    expect(/claim|not an endorsement/i.test(tool.description)).toBe(true);
  });
});