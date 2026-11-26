/**
 * SEARCH-ENGINE DISCOVERY LANE — the coverage for the login-walled platforms.
 *
 * Every fixture below is modelled on output CAPTURED LIVE on 2026-10-25 during the
 * KellyHeadley75 investigation: the DDG result shape (class="result__a" + uddg redirect),
 * the anomaly challenge page, the junk-padding failure mode (Bing answered a quoted
 * personal-name query with unrelated foreign-language results), the Cash App embedded
 * profile JSON, and the syndication oracle discriminator that separates an existing X
 * handle from a never-registered one. The lane exists because the direct probes of
 * Facebook/Instagram/TikTok/Reddit answer identically for existing and fake handles —
 * these tests pin the lane that DOES see them, and the guards that keep it honest.
 */

import { describe, it, expect } from 'vitest';
import {
  parseDdgResults,
  resultsLookRelevant,
  buildSearchQueries,
  classifySearchHit,
  parseCashAppProfile,
  parseCashtagSeed,
  bootstrapCashtag,
  searchEngineDiscovery,
  searchLaneSummary,
} from '../tools/osint-searchdiscovery.js';
import { correlateAccounts } from '../tools/osint-correlate.js';
import type { UsernameHit } from '../tools/osint.js';

// ── Captured-shape fixtures ─────────────────────────────────────────────────

const DDG_RESULT_PAGE = `<!DOCTYPE html><html><head><title>kelly headley at DuckDuckGo</title></head><body>
<div class="result results_links results_links_default">
  <h2 class="result__title">
    <a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fwww.linkedin.com%2Fin%2Fkelly-headley-978866342&amp;rut=abc">
      Kelly Headley - -- | LinkedIn
    </a>
  </h2>
  <a class="result__snippet" href="#">-- &middot; Experience: DHL &middot; Location: Brooklyn. View Kelly Headley&#x27;s profile</a>
</div>
<div class="result results_links results_links_default">
  <h2 class="result__title">
    <a rel="nofollow" class="result__a" href="https://www.facebook.com/public/Kelly-Headley/">
      Kelly Headley Profiles - Facebook
    </a>
  </h2>
  <a class="result__snippet" href="#">View the profiles of people named Kelly Headley. Join Facebook to connect</a>
</div>
<div class="result results_links results_links_default">
  <h2 class="result__title">
    <a rel="nofollow" class="result__a" href="https://www.instagram.com/kelly_headley_/">
      Kelly Headley (@kelly_headley_) &bull; Instagram photos and videos
    </a>
  </h2>
  <a class="result__snippet" href="#">215 Followers, 328 Following, 6 Posts - Kelly Headley (@kelly_headley_)</a>
</div>
</body></html>`;

const DDG_ANOMALY_PAGE = `<html><head><title>Verifying your browser</title></head><body>
<div class="anomaly">Unfortunately, bots use DuckDuckGo too. Please complete the following challenge to confirm this search was made by a human.</div>
</body></html>`;

const DDG_NO_RESULTS_PAGE = `<html><body>
<div class="no-results">No results could be found for your search. Try different keywords.</div>
</body></html>`;

/** The junk-padding failure, from the live capture: Bing served a quoted personal-name
 *  query with organic-looking results that have nothing to do with it. */
const JUNK_PADDED_PAGE = `<!DOCTYPE html><html><body>
<div class="result"><h2><a href="https://vislokaal.com/vissoorten/heilbot/">Alles over heilbot</a></h2><p>Alles over heilbot: hoe smaakt hij, wanneer is het seizoen?</p></div>
<div class="result"><h2><a href="https://www.kbb.com/">Kelley Blue Book</a></h2><p>New and used car pricing.</p></div>
</body></html>`;

/** The real embedded profile line, captured from cash.app/$KellyHeadley75 on 2026-10-25. */
const CASH_PROFILE_JSON =
  `var profile = {"display_name":"Kelly Headley","formatted_cashtag":"$KellyHeadley75","is_verified_account":false,"rate_plan":"PERSONAL","payment_button_type":"PAY","country_code":"US","avatar":{"image_url":"https://franklin-assets.s3.amazonaws.com/apps/imgs/x.jpeg","initial":"K","accent_color":"#B141FF"}};`;

/** The syndication discriminator, captured 2026-10-25: an existing handle echoes
 *  headerProps with its screenName; a never-registered one omits the key entirely. */
const X_EMBED_EXISTING =
  `{"props":{"pageProps":{"contextProvider":{"scribeData":{}},"hasResults":true,"timeline":{"entries":[{"id":"1"}]},"headerProps":{"screenName":"kellyheadley1"}}}}`;
const X_EMBED_ABSENT =
  `{"props":{"pageProps":{"contextProvider":{"scribeData":{}},"timeline":{"entries":[]}}}}`;

const page = (status: number, body: string, via = 'egress') => ({ status, body, via });

describe('DDG result parsing', () => {
  it('extracts results and decodes the uddg redirect to the real URL', () => {
    const p = parseDdgResults(DDG_RESULT_PAGE);
    expect(p.anomaly).toBe(false);
    expect(p.results).toHaveLength(3);
    expect(p.results[0].url).toBe('https://www.linkedin.com/in/kelly-headley-978866342');
    expect(p.results[0].title).toContain('Kelly Headley');
    expect(p.results[0].snippet).toContain('DHL');
    expect(p.results[1].url).toBe('https://www.facebook.com/public/Kelly-Headley/');
    expect(p.results[2].url).toBe('https://www.instagram.com/kelly_headley_/');
  });

  it('reads the anomaly challenge page as an engine failure, not a result set', () => {
    const p = parseDdgResults(DDG_ANOMALY_PAGE);
    expect(p.anomaly).toBe(true);
    expect(p.results).toHaveLength(0);
  });

  it('reads a genuine zero-results page as empty, not as a failure', () => {
    const p = parseDdgResults(DDG_NO_RESULTS_PAGE);
    expect(p.anomaly).toBe(false);
    expect(p.noResults).toBe(true);
    expect(p.results).toHaveLength(0);
  });
});

describe('the anti-laundering relevance guard', () => {
  it('passes a page whose results actually carry the query terms', () => {
    const p = parseDdgResults(DDG_RESULT_PAGE);
    expect(resultsLookRelevant(p.results, '"kelly headley"')).toBe(true);
  });

  it('rejects the junk-padding page (measured: Bing served halibut recipes for a quoted name)', () => {
    // Bing's page is NOT in the DDG shape — its results are fed to the guard directly,
    // exactly as they appeared in the live capture.
    const bingShaped = [
      { url: 'https://vislokaal.com/vissoorten/heilbot/', title: 'Alles over heilbot', snippet: 'Alles over heilbot: hoe smaakt hij, wanneer is het seizoen?' },
      { url: 'https://www.kbb.com/', title: 'Kelley Blue Book', snippet: 'New and used car pricing.' },
    ];
    expect(resultsLookRelevant(bingShaped, '"kelly headley"')).toBe(false);
    expect(resultsLookRelevant(bingShaped, 'kellyheadley75')).toBe(false);
  });

  it('treats an empty result list as a true zero, not padding', () => {
    expect(resultsLookRelevant([], '"kelly headley"')).toBe(true);
  });

  it('ignores terms shorter than 4 chars so a numeric suffix matches nothing', () => {
    // "75" alone must not make every page "relevant".
    const bingShaped = [
      { url: 'https://vislokaal.com/vissoorten/heilbot/', title: 'Alles over heilbot', snippet: 'hoe smaakt hij' },
    ];
    expect(resultsLookRelevant(bingShaped, '75')).toBe(true); // no usable terms -> cannot judge -> pass
  });
});

describe('query plan', () => {
  it('without a name: the quoted and plain handle, and no more', () => {
    expect(buildSearchQueries('KellyHeadley75')).toEqual(['"KellyHeadley75"', 'KellyHeadley75']);
  });

  it('with a name: adds the quoted name and one scoped query per walled platform', () => {
    const q = buildSearchQueries('KellyHeadley75', 'Kelly Headley');
    expect(q[0]).toBe('"KellyHeadley75"');
    expect(q).toContain('"Kelly Headley"');
    for (const site of ['linkedin.com', 'instagram.com', 'facebook.com', 'x.com', 'tiktok.com', 'reddit.com']) {
      expect(q.some((x) => x.includes(`site:${site}`))).toBe(true);
    }
    expect(q.length).toBeLessThanOrEqual(9);
  });

  it('never returns fewer than the two handle queries', () => {
    expect(buildSearchQueries('abc', '').length).toBeGreaterThanOrEqual(2);
  });
});

describe('result classification', () => {
  it('a LinkedIn vanity-slug profile with the name in the snippet is an ACCOUNT name-match', () => {
    const c = classifySearchHit(
      'https://www.linkedin.com/in/kelly-headley-978866342',
      'Kelly Headley - -- | LinkedIn',
      '-- · Experience: DHL · Location: Brooklyn. View Kelly Headley',
      'kellyheadley75',
      'Kelly Headley'
    );
    // The slug is NOT handle-similar to the cashtag; the name carries it.
    expect(c.kind).toBe('account');
    expect(c.platform?.site).toBe('LinkedIn');
    expect(c.nameInResult).toBe(true);
  });

  it('an exact-handle Instagram profile is an account even without the name', () => {
    const c = classifySearchHit(
      'https://www.instagram.com/kellyheadley75/',
      'Kelly Headley (@kellyheadley75) • Instagram',
      'followers and posts',
      'kellyheadley75',
      undefined
    );
    expect(c.kind).toBe('account');
    expect(c.handle).toBe('kellyheadley75');
    expect(c.nameInResult).toBe(false);
  });

  it('facebook.com/public/ is a NAME DIRECTORY, not a profile page', () => {
    const c = classifySearchHit(
      'https://www.facebook.com/public/Kelly-Headley/',
      'Kelly Headley Profiles - Facebook',
      'View the profiles of people named Kelly Headley',
      'kellyheadley75',
      'Kelly Headley'
    );
    expect(c.kind).toBe('directory');
    expect(c.platform?.site).toBe('Facebook');
  });

  it('linkedin.com/pub/dir/ is a name directory too', () => {
    const c = classifySearchHit(
      'https://www.linkedin.com/pub/dir/Kelly/Headley',
      '10+ "Kelly Headley" profiles | LinkedIn',
      'View the profiles of professionals named "Kelly Headley"',
      'kellyheadley75',
      'Kelly Headley'
    );
    expect(c.kind).toBe('directory');
  });

  it('a name-bearing non-profile page is a web MENTION', () => {
    const c = classifySearchHit(
      'https://www.psychologytoday.com/us/therapists/kelly-headley-sterling-va/1585698',
      'Kelly Headley, Clinical Social Work/Therapist, Sterling, VA',
      '(571) 440-7669, I currently have openings on Fridays and Saturdays',
      'kellyheadley75',
      'Kelly Headley'
    );
    expect(c.kind).toBe('mention');
  });

  it('ignores results with no platform and no name', () => {
    const c = classifySearchHit(
      'https://vislokaal.com/vissoorten/heilbot/',
      'Alles over heilbot',
      'hoe smaakt hij',
      'kellyheadley75',
      'Kelly Headley'
    );
    expect(c.kind).toBe('ignore');
  });

  it('a same-name profile on a platform is an account when the name corroborates', () => {
    const c = classifySearchHit(
      'https://www.facebook.com/kelly.schuening/',
      'Kelly Headley - Facebook',
      'Kelly Headley is on Facebook. Join Facebook to connect',
      'kellyheadley75',
      'Kelly Headley'
    );
    expect(c.kind).toBe('account');
    expect(c.platform?.site).toBe('Facebook');
  });
});

describe('Cash App cashtag bootstrap', () => {
  it('parses the real embedded profile JSON (captured 2026-10-25)', () => {
    const b = parseCashAppProfile(`<html><head><title>Pay $KellyHeadley75 on Cash App</title></head>
      <script>var kCashtagImageUrl = 'x'; ${CASH_PROFILE_JSON}</script></html>`);
    expect(b.exists).toBe(true);
    expect(b.displayName).toBe('Kelly Headley');
    expect(b.verified).toBe(false);
    expect(b.countryCode).toBe('US');
  });

  it('falls back to the title marker when the profile JSON is absent', () => {
    const b = parseCashAppProfile('<html><head><title>Pay me on Cash App</title></head><body>og:description "Instantly exchange money for free on Cash App"</body></html>');
    expect(b.exists).toBe(true);
    expect(b.displayName).toBeUndefined();
  });

  it('rejects a page with no recognisable profile markers', () => {
    const b = parseCashAppProfile('<html><head><title>Some other page</title></head></html>');
    expect(b.exists).toBeNull();
  });

  it('reads a clean 404 as NOT REGISTERED, not as an error', async () => {
    const b = await bootstrapCashtag('DefinitelyNotRegistered9', async () => page(404, ''));
    expect(b.exists).toBe(false);
  });

  it('reports a server failure honestly instead of reading it as absence', async () => {
    const b = await bootstrapCashtag('whatever', async () => page(503, '', 'tor'));
    expect(b.exists).toBeNull();
    expect(b.note).toContain('503');
  });

  it('survives a throwing transport', async () => {
    const b = await bootstrapCashtag('whatever', async () => { throw new Error('dead'); });
    expect(b.exists).toBeNull();
    expect(b.note).toContain('dead');
  });
});

describe('cashtag seed parsing', () => {
  it('strips a leading $', () => {
    expect(parseCashtagSeed('$KellyHeadley75')).toEqual({ handle: 'KellyHeadley75', wasCashtag: true });
  });
  it('accepts a cash.app URL', () => {
    expect(parseCashtagSeed('https://cash.app/$KellyHeadley75')).toEqual({ handle: 'KellyHeadley75', wasCashtag: true });
    expect(parseCashtagSeed('cash.app/KellyHeadley75')).toEqual({ handle: 'KellyHeadley75', wasCashtag: true });
  });
  it('passes a bare handle through as non-cashtag', () => {
    expect(parseCashtagSeed('KellyHeadley75')).toEqual({ handle: 'KellyHeadley75', wasCashtag: false });
  });
  it('refuses a malformed cashtag', () => {
    expect(parseCashtagSeed('$bad handle!')).toBeNull();
    expect(parseCashtagSeed('')).toBeNull();
  });
});

describe('searchEngineDiscovery (stubbed transport)', () => {
  const stubFetcher = (pages: Record<string, { status: number; body: string }>) => async (url: string) => {
    const q = decodeURIComponent(url.replace('https://html.duckduckgo.com/html/?q=', ''));
    const hit = Object.keys(pages).find((k) => q.includes(k));
    if (!hit) throw new Error(`stub has no page for ${q}`);
    return page(pages[hit].status, pages[hit].body);
  };

  it('emits account hits, mentions, directories and discovered handles from a live-shaped page', async () => {
    const r = await searchEngineDiscovery('kellyheadley75', {
      name: 'Kelly Headley',
      paceMs: 0,
      fetcher: stubFetcher({
        '"kellyheadley75"': { status: 200, body: DDG_RESULT_PAGE },
        'KellyHeadley75': { status: 200, body: DDG_NO_RESULTS_PAGE },
        '"Kelly Headley"': { status: 200, body: DDG_RESULT_PAGE },
        'site:': { status: 200, body: DDG_NO_RESULTS_PAGE },
      }),
    });
    const sites = r.hits.map((h) => h.site);
    expect(sites).toContain('LinkedIn');
    expect(sites).toContain('Instagram');
    const linkedin = r.hits.find((h) => h.site === 'LinkedIn')!;
    expect(linkedin.status).toBe('found');
    expect(linkedin.identity).toBe('name-match');
    expect(linkedin.note).toContain('search-engine discovery');
    expect(r.directories.some((d) => d.platform === 'Facebook')).toBe(true);
    expect(r.discoveredHandles).toContain('kelly-headley-978866342');
    expect(r.engineStatus).toBe('ok');
  });

  it('emits NOTHING from a junk-padded page and keeps going', async () => {
    const r = await searchEngineDiscovery('kellyheadley75', {
      paceMs: 0,
      fetcher: stubFetcher({
        '"kellyheadley75"': { status: 200, body: JUNK_PADDED_PAGE },
        'KellyHeadley75': { status: 200, body: DDG_NO_RESULTS_PAGE },
      }),
    });
    expect(r.hits).toHaveLength(0);
    expect(r.mentions).toHaveLength(0);
    expect(r.pagesWithResults).toBe(0);
    expect(r.engineStatus).toBe('ok');
  });

  it('stops after two consecutive rate-limits and says so instead of returning silence', async () => {
    let calls = 0;
    const r = await searchEngineDiscovery('kellyheadley75', {
      name: 'Kelly Headley',
      paceMs: 0,
      fetcher: async () => { calls++; return page(403, ''); },
    });
    expect(calls).toBe(2);
    expect(r.engineStatus).toContain('rate-limited');
    expect(r.hits).toHaveLength(0);
  });

  it('treats an anomaly challenge the same way (an unanswered engine is not a negative verdict)', async () => {
    let calls = 0;
    const r = await searchEngineDiscovery('kellyheadley75', {
      paceMs: 0,
      fetcher: async () => { calls++; return page(200, DDG_ANOMALY_PAGE); },
    });
    expect(calls).toBe(2);
    expect(r.engineStatus).toContain('anomaly');
  });

  it('a page that answers after one failure resets the failure counter', async () => {
    let calls = 0;
    const r = await searchEngineDiscovery('kellyheadley75', {
      paceMs: 0,
      fetcher: async () => {
        calls++;
        if (calls === 1) return page(403, '');
        return page(200, DDG_RESULT_PAGE);
      },
    });
    expect(calls).toBeGreaterThanOrEqual(2);
    expect(r.engineStatus).toBe('ok');
    expect(r.hits.length).toBeGreaterThan(0);
  });

  it('honours the deadline and reports the queries it never ran', async () => {
    const r = await searchEngineDiscovery('kellyheadley75', {
      name: 'Kelly Headley',
      deadlineMs: Date.now() - 1, // already out of budget
      fetcher: async () => page(200, DDG_RESULT_PAGE),
    });
    expect(r.queriesRun).toHaveLength(0);
    expect(r.engineStatus).toContain('budget');
  });
});

describe('the lane summary reads like an operator note, not a counter', () => {
  it('names counts and the engine state', async () => {
    const r = await searchEngineDiscovery('kellyheadley75', {
      paceMs: 0,
      fetcher: stubFetcher2(),
    });
    const s = searchLaneSummary(r);
    expect(s).toContain('search-engine lane');
    expect(s).toContain('DDG');
  });
});

function stubFetcher2() {
  return async () => page(200, DDG_NO_RESULTS_PAGE);
}

describe('the X syndication discriminator the catalog now probes (fixture-pinned)', () => {
  // The curated X entry is body_contains on this literal — these two captured shapes are
  // exactly what it will see. Pinned here so the probeValue cannot silently drift.
  it('an existing handle embeds headerProps with the screenName', () => {
    expect(X_EMBED_EXISTING).toContain('"headerProps":{"screenName"');
  });
  it('a never-registered handle omits the key entirely', () => {
    expect(X_EMBED_ABSENT).not.toContain('"headerProps"');
  });
});

describe('clustering ignores low-confidence shell-200 hits when pairing by handle shape', () => {
  // Measured live 2026-10-25: one curated sweep chained Instagram/TikTok/Threads/Pinterest/
  // Steam (all 200-app-shell "found"s) plus the real X hit into a 37-site WEAK group.
  const shellHit = (site: string, handle: string, confidence: 'low' | 'medium' | 'high'): UsernameHit => ({
    site, category: 'social', url: `https://${site.toLowerCase().replace(/[^a-z]/g, '')}.com/${handle}`,
    status: 'found', confidence,
  });
  const X = shellHit('X (Twitter)', 'kellyheadley1', 'medium');
  const IG = shellHit('Instagram', 'kellyheadley1', 'low');
  const Steam = shellHit('Steam', 'kellyheadley1', 'medium');

  it('low-confidence hits are excluded from handle-shape pairing', () => {
    const groups = correlateAccounts([X, IG, Steam]);
    // Without the exclusion this is one 3-member group built on two shell-200s.
    expect(groups).toHaveLength(0);
  });

  it('real evidence still groups a low-confidence hit', () => {
    const withAvatar = { ...IG, profile: { imageUrl: 'https://img/x.jpg' } };
    const XAvatar = { ...X, profile: { imageUrl: 'https://img/x.jpg' } };
    const groups = correlateAccounts([XAvatar, withAvatar]);
    expect(groups).toHaveLength(1);
    expect(groups[0].strength).toBe('medium');
    expect(groups[0].evidence.some((e) => e.startsWith('Same avatar'))).toBe(true);
  });
});
