/**
 * SEARCH-ENGINE DISCOVERY — the lane that covers the walled platforms.
 *
 * WHY THIS EXISTS — measured live on 2026-10-25 during the KellyHeadley75 investigation:
 * Facebook answers 400 to every unauthenticated probe (datacenter AND Tor), Reddit 403s
 * datacenter and Tor IPs, Instagram/TikTok/Twitch/Pinterest/Threads serve an identical 200
 * app-shell for EXISTING and NEVER-REGISTERED handles alike, and X's own site serves the
 * logged-out 404 shell for both. A URL-concatenation sweep therefore CANNOT see the big
 * socials — it reports `unknown`/`absent` for accounts that exist, which reads as "not there".
 *
 * What DOES see them is a search engine's index. One DDG name query surfaced — in seconds,
 * keyless — a LinkedIn profile, two Instagram profiles, a Facebook directory page, an X
 * account, and public-records pages that URL-attachment will never produce. That is the
 * technique this module wires into the sweep.
 *
 * DOCTRINE, from the repo's own standing lessons:
 *  - A 200 with junk is worse than a 403. Engines soft-serve plausible garbage when they
 *    flag the client (measured: Bing answered a quoted personal-name query with Dutch
 *    halibut recipes and KBB listings). So every result page passes a RELEVANCE GUARD: if
 *    no result's URL/title/snippet carries a query term, the page is recorded as
 *    unreliable and NOTHING from it is emitted.
 *  - An engine that did not answer is not a negative verdict. Rate-limit/challenge pages
 *    stop the lane and are reported as a caveat — never folded into "no footprint".
 *  - Search hits are DISCOVERIES, not confirmations: a profile found through an index gets
 *    `status: 'found'` with a note naming the lane, and identity corroboration only when
 *    the subject's name actually appears in the result.
 */

import type { OsintSiteCategory, UsernameHit } from './osint.js';
import { egressProbe } from './osint.js';
import { handleFromProfileUrl, handleSimilarity, isPlausibleHandle } from './osint-correlate.js';

// ═══════════════════════════════════════════════════════════════════════════
// Transport — injectable for tests; default rides the osint egress ladder.
// ═══════════════════════════════════════════════════════════════════════════

export interface PageResult { status: number; body: string; via: string }
export type SearchFetcher = (url: string) => Promise<PageResult>;

const FETCH_TIMEOUT_MS = 20_000;

export const defaultSearchFetcher: SearchFetcher = async (url) => {
  const r = await egressProbe(url, FETCH_TIMEOUT_MS);
  return { status: r.status, body: r.body, via: r.via };
};

// ═══════════════════════════════════════════════════════════════════════════
// 1. DDG HTML PARSER — validated live against real result pages (2026-10-25)
// ═══════════════════════════════════════════════════════════════════════════

export interface DdgResult { url: string; title: string; snippet: string }
export interface DdgPage { anomaly: boolean; noResults: boolean; results: DdgResult[] }

/** DuckDuckGo blocks scripted clients with an "anomaly" challenge page — that is an
 *  engine failure, never a result set. Detected by its own marker. */
export function parseDdgResults(html: string): DdgPage {
  const anomaly = /anomaly|anomaly-access|challenge/i.test(html) && !/result__a/.test(html);
  const out: DdgResult[] = [];
  for (const m of html.matchAll(/<a[^>]*class="result__a"[^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/g)) {
    let u = m[1];
    // DDG routes through /l/?uddg=<urlencoded target> — decode to the real URL.
    const ud = u.match(/uddg=([^&]+)/);
    if (ud) { try { u = decodeURIComponent(ud[1]); } catch { /* keep raw */ } }
    const title = m[2].replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim();
    out.push({ url: u, title, snippet: '' });
  }
  const snippets = [...html.matchAll(/class="result__snippet"[^>]*>([\s\S]*?)<\/a>/g)]
    .map((x) => x[1].replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim());
  out.forEach((r, i) => { r.snippet = snippets[i] || ''; });
  const noResults = /No results|did not match|not find any result/i.test(html);
  return { anomaly, noResults, results: out };
}

/**
 * ANTI-LAUNDERING GUARD. A result page counts only if at least one result actually carries
 * the query — contiguously, separator-normalized (kelly_headley ≡ kellyheadley ≡ kelly
 * headley), or as the alpha prefix of a handle-with-digits (KellyHeadley75 → "kellyheadley").
 * Measured failure this guards against: Bing served a quoted-name query with ten
 * organic-looking results about halibut and car prices — status 200, zero matches. Terms
 * shorter than 4 characters are ignored ("75" alone would match anything).
 */
export function resultsLookRelevant(results: DdgResult[], query: string): boolean {
  if (!results.length) return true; // an empty page is a true zero, not padding
  const raw = query.toLowerCase().split(/[\s"'+]+/);
  const terms = raw.map((t) => t.replace(/^site:[a-z.]+/, '').replace(/[^a-z0-9$]/g, '')).filter((t) => t.length >= 4);
  if (!terms.length) return true;
  // Alpha fragments of handle-shaped terms: "kellyheadley75" also matches pages that only
  // carry "kelly headley" or "kelly_headley" — on-topic, not padding.
  const alphaFragments = terms
    .filter((t) => /\d/.test(t))
    .map((t) => t.replace(/[^a-z]/g, ''))
    .filter((t) => t.length >= 6);
  const normTerms = terms.map((t) => t.replace(/[^a-z0-9]/g, ''));
  for (const r of results) {
    const hay = `${r.url} ${r.title} ${r.snippet}`.toLowerCase();
    const hayNorm = hay.replace(/[-_.]/g, '');
    if (terms.some((t) => hay.includes(t))) return true;
    if (normTerms.some((t) => hayNorm.includes(t))) return true;
    if (alphaFragments.some((t) => hayNorm.includes(t))) return true;
  }
  return false;
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. QUERY PLAN — quoted handle first, then the name, then the walled sites
// ═══════════════════════════════════════════════════════════════════════════

const WALED_SITES: Array<{ op: string; why: string }> = [
  { op: 'linkedin.com', why: 'authwall' },
  { op: 'instagram.com', why: 'login wall' },
  { op: 'facebook.com', why: 'login wall' },
  { op: 'x.com', why: 'logged-out shell' },
  { op: 'tiktok.com', why: 'challenge wall' },
  { op: 'reddit.com', why: 'IP block' },
];

/** Lower-bounded so a caller passing an empty name still gets the handle queries. */
export function buildSearchQueries(handle: string, name?: string, max = 9): string[] {
  const h = handle.replace(/^@/, '');
  const q: string[] = [`"${h}"`, h];
  const nm = (name || '').trim();
  if (nm) {
    q.push(`"${nm}"`);
    for (const s of WALED_SITES) q.push(`site:${s.op} "${nm}"`);
  }
  return q.slice(0, Math.max(2, max));
}

/** NAME-ONLY query plan — the people-search variant. No handle exists yet; the name is
 *  the seed. Quoted name, then one scoped query per walled platform. */
export function buildNameQueries(name: string, max = 8): string[] {
  const nm = (name || '').trim();
  if (!nm) return [];
  return [`"${nm}"`, ...WALED_SITES.map((s) => `site:${s.op} "${nm}"`)].slice(0, Math.max(2, max));
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. RESULT CLASSIFICATION — profile page vs name-directory vs web mention
// ═══════════════════════════════════════════════════════════════════════════

const PLATFORM_BY_HOST: Record<string, { site: string; category: OsintSiteCategory }> = {
  'x.com': { site: 'X (Twitter)', category: 'social' },
  'twitter.com': { site: 'X (Twitter)', category: 'social' },
  'instagram.com': { site: 'Instagram', category: 'social' },
  'facebook.com': { site: 'Facebook', category: 'social' },
  'linkedin.com': { site: 'LinkedIn', category: 'social' },
  'tiktok.com': { site: 'TikTok', category: 'video' },
  'youtube.com': { site: 'YouTube', category: 'video' },
  'youtu.be': { site: 'YouTube', category: 'video' },
  'reddit.com': { site: 'Reddit', category: 'social' },
  'pinterest.com': { site: 'Pinterest', category: 'social' },
  'threads.net': { site: 'Threads', category: 'social' },
  't.me': { site: 'Telegram', category: 'messaging' },
  'telegram.me': { site: 'Telegram', category: 'messaging' },
  'snapchat.com': { site: 'Snapchat', category: 'social' },
  'venmo.com': { site: 'Venmo', category: 'money' },
  'cash.app': { site: 'Cash App', category: 'money' },
  'twitch.tv': { site: 'Twitch', category: 'video' },
  'github.com': { site: 'GitHub', category: 'dev' },
  'soundcloud.com': { site: 'SoundCloud', category: 'music' },
  'flickr.com': { site: 'Flickr', category: 'art' },
  'vimeo.com': { site: 'Vimeo', category: 'video' },
  'medium.com': { site: 'Medium', category: 'blog' },
  'tumblr.com': { site: 'Tumblr', category: 'blog' },
  'bsky.app': { site: 'Bluesky', category: 'social' },
  'mastodon.social': { site: 'Mastodon', category: 'social' },
  'open.spotify.com': { site: 'Spotify', category: 'music' },
  'spotify.com': { site: 'Spotify', category: 'music' },
  'patreon.com': { site: 'Patreon', category: 'money' },
  'ko-fi.com': { site: 'Ko-fi', category: 'money' },
};

export type SearchHitKind = 'account' | 'mention' | 'directory' | 'ignore';

export interface ClassifyOutcome {
  kind: SearchHitKind;
  platform?: { site: string; category: OsintSiteCategory };
  handle?: string;
  /** The subject's name appears in the result's title/snippet — the only corroboration
   *  an indexed profile can carry. */
  nameInResult: boolean;
}

export function classifySearchHit(
  url: string,
  title: string,
  snippet: string,
  seed: string,
  name?: string
): ClassifyOutcome {
  let host = '';
  try { host = new URL(url).hostname.toLowerCase().replace(/^www\./, ''); } catch { return { kind: 'ignore', nameInResult: false }; }

  const nm = (name || '').trim().toLowerCase();
  const hay = `${title} ${snippet}`.toLowerCase();
  const nameInResult = nm.length >= 4 && hay.includes(nm);

  const platform = PLATFORM_BY_HOST[host];
  if (!platform) {
    // A non-profile URL that carries the name is still a web mention worth reporting.
    return { kind: nameInResult ? 'mention' : 'ignore', nameInResult };
  }

  // Name directories (facebook.com/public/Kelly-Headley/, linkedin.com/pub/dir/Kelly/Headley)
  // prove the NAME is on the platform without identifying WHICH profile is the subject.
  if (/\/public\/|^\/pub\/dir\//.test(new URL(url).pathname)) {
    return { kind: 'directory', platform, nameInResult };
  }

  const handle = handleFromProfileUrl(url) || undefined;
  const seedNorm = seed.toLowerCase().replace(/^@/, '');
  const handleMatches = Boolean(
    handle &&
    (handle.toLowerCase() === seedNorm || handleSimilarity(handle, seedNorm) >= 0.8)
  );

  // An exact-handle profile is the subject's shape even without the name in the snippet.
  if (handleMatches) return { kind: 'account', platform, handle, nameInResult };
  // A site-scoped name hit on a walled platform: the name carries it (e.g. a LinkedIn
  // vanity slug like /in/kelly-headley-978866342 is NOT handle-similar to kellyheadley75).
  if (nameInResult && handle) return { kind: 'account', platform, handle, nameInResult };
  if (nameInResult) return { kind: 'mention', platform, nameInResult };
  return { kind: 'ignore', platform, handle, nameInResult };
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. CASH APP CASHTAG BOOTSTRAP — a cashtag carries the subject's display name
// ═══════════════════════════════════════════════════════════════════════════

export interface CashtagBootstrap {
  /** true = cashtag live; false = 404; null = could not measure. */
  exists: boolean | null;
  displayName?: string;
  verified?: boolean;
  countryCode?: string;
  note?: string;
}

/** The cashtag page embeds `var profile = {...}` with display_name, is_verified_account and
 *  country_code (measured 2026-10-25). That display name is what unlocks the NAME queries —
 *  the whole reason one `$handle` paste turned into LinkedIn/Instagram/public-records hits. */
export function parseCashAppProfile(body: string): CashtagBootstrap {
  const m = body.match(/var profile = (\{.*?\});/s);
  if (m) {
    try {
      const j = JSON.parse(m[1]) as { display_name?: string; is_verified_account?: boolean; country_code?: string };
      return {
        exists: true,
        displayName: j.display_name || undefined,
        verified: j.is_verified_account === true,
        countryCode: j.country_code || undefined,
      };
    } catch { /* fall through to title */ }
  }
  const title = body.match(/<title[^>]*>([^<]*)<\/title>/)?.[1] || '';
  // Both live title shapes: "Pay $Cashtag on Cash App" (tab title) and "Pay me on Cash App" (og:title).
  if (/pay .*cash app/i.test(title)) return { exists: true, note: 'profile page live but profile JSON absent' };
  return { exists: null, note: '200 without recognisable profile markers' };
}

export async function bootstrapCashtag(
  handle: string,
  fetcher: SearchFetcher = defaultSearchFetcher
): Promise<CashtagBootstrap> {
  let res: PageResult;
  try {
    res = await fetcher(`https://cash.app/$${encodeURIComponent(handle)}`);
  } catch (e) {
    return { exists: null, note: `cash.app probe failed: ${(e as Error).message}` };
  }
  if (res.status === 404 || res.status === 410) return { exists: false, note: 'cashtag not registered (clean 404)' };
  if (res.status !== 200) return { exists: null, note: `cash.app probe HTTP ${res.status} via ${res.via}` };
  return parseCashAppProfile(res.body);
}

/** Accept `$handle`, `cash.app/$handle` or a bare handle — returns the stripped handle
 *  and whether this was a cashtag seed. Null when the input names nothing usable. */
export function parseCashtagSeed(raw: string): { handle: string; wasCashtag: boolean } | null {
  const t = (raw || '').trim();
  if (!t) return null;
  const url = t.match(/cash\.app\/\$?([A-Za-z0-9._-]+)/i);
  if (url) return { handle: url[1], wasCashtag: true };
  if (t.startsWith('$')) {
    const h = t.slice(1);
    return /^[A-Za-z0-9._-]{1,40}$/.test(h) ? { handle: h, wasCashtag: true } : null;
  }
  if (/^[A-Za-z0-9._-]{1,64}$/.test(t)) return { handle: t, wasCashtag: false };
  return null;
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. THE LANE — paced DDG queries over the egress ladder
// ═══════════════════════════════════════════════════════════════════════════

/** Measured 2026-10-25: DDG serves the anomaly challenge to bursts — ~6 queries inside a
 *  minute of each other started 403ing even through one Tor circuit. Pacing is the cost of
 *  the lane staying alive; the sweep budget bounds the total anyway. */
const DDG_PACE_MS = 3_000;
const DDG_ENDPOINT = 'https://html.duckduckgo.com/html/?q=';

export interface SearchDiscoveryOptions {
  name?: string;
  /** Wall-clock deadline (ms epoch) — the lane stops STARTING queries past it. */
  deadlineMs?: number;
  fetcher?: SearchFetcher;
  /** Pacing between queries (tests pass 0). Default keeps DDG's anomaly tripwire quiet. */
  paceMs?: number;
  /** Override the query plan (people-name mode passes buildNameQueries(name)). */
  queries?: string[];
  onStage?: (stage: string, detail: string) => void;
}

export interface SearchDiscoveryResult {
  hits: UsernameHit[];
  mentions: Array<{ title: string; url: string; snippet: string }>;
  directories: Array<{ platform: string; url: string }>;
  discoveredHandles: string[];
  queriesRun: string[];
  pagesWithResults: number;
  /** Honest engine state: 'ok' | partial reason | 'unreachable'. */
  engineStatus: string;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function searchEngineDiscovery(
  seed: string,
  opts: SearchDiscoveryOptions = {}
): Promise<SearchDiscoveryResult> {
  const fetcher = opts.fetcher || defaultSearchFetcher;
  const paceMs = opts.paceMs ?? DDG_PACE_MS;
  const queries = opts.queries || buildSearchQueries(seed, opts.name);
  const out: SearchDiscoveryResult = {
    hits: [], mentions: [], directories: [], discoveredHandles: [],
    queriesRun: [], pagesWithResults: 0, engineStatus: 'ok',
  };
  const seenUrls = new Set<string>();
  let consecutiveFailures = 0;
  const seedNorm = seed.toLowerCase().replace(/^@/, '');

  for (let i = 0; i < queries.length; i++) {
    const query = queries[i];
    if (opts.deadlineMs && Date.now() > opts.deadlineMs - 5_000) {
      out.engineStatus = `stopped early — sweep budget reached after ${i}/${queries.length} queries`;
      break;
    }
    if (i > 0) await sleep(paceMs);
    opts.onStage?.('search', `search engine: ${query}`);

    let page: DdgPage;
    try {
      const res = await fetcher(DDG_ENDPOINT + encodeURIComponent(query));
      if (res.status === 403 || res.status === 429 || res.status === 0) {
        consecutiveFailures++;
        if (consecutiveFailures >= 2) { out.engineStatus = `engine rate-limited (HTTP ${res.status}) after ${i} query(ies) — rerun to widen coverage`; break; }
        continue;
      }
      page = parseDdgResults(res.body);
      if (page.anomaly) {
        consecutiveFailures++;
        if (consecutiveFailures >= 2) { out.engineStatus = `engine serving anomaly challenges after ${i} query(ies) — rerun to widen coverage`; break; }
        continue;
      }
    } catch (e) {
      consecutiveFailures++;
      if (consecutiveFailures >= 2) { out.engineStatus = `engine unreachable (${(e as Error).message}) after ${i} query(ies)`; break; }
      continue;
    }
    consecutiveFailures = 0;
    out.queriesRun.push(query);

    // The anti-laundering gate: an answered page whose results never touch the query is
    // junk-padding (measured on Bing), and NOTHING from it may reach the report.
    if (!resultsLookRelevant(page.results, query)) continue;
    if (page.results.length) out.pagesWithResults++;

    for (const r of page.results) {
      const key = r.url.toLowerCase().replace(/\/$/, '');
      if (!r.url.startsWith('http') || seenUrls.has(key)) continue;
      seenUrls.add(key);
      const c = classifySearchHit(r.url, r.title, r.snippet, seedNorm, opts.name);
      if (c.kind === 'ignore') continue;
      if (c.kind === 'directory') {
        out.directories.push({ platform: c.platform!.site, url: r.url });
        continue;
      }
      if (c.kind === 'mention') {
        out.mentions.push({ title: r.title, url: r.url, snippet: r.snippet });
        continue;
      }
      // account — the discovery this lane exists for.
      out.hits.push({
        site: c.platform!.site,
        category: c.platform!.category,
        url: r.url,
        status: 'found',
        confidence: 'medium',
        note: 'search-engine discovery — direct probe of this platform is login/challenge-walled from server vantages (measured 2026-10-25)',
        identity: c.nameInResult ? 'name-match' : 'handle-only',
      });
      if (c.handle && isPlausibleHandle(c.handle) && c.handle.toLowerCase() !== seedNorm) {
        out.discoveredHandles.push(c.handle);
      }
    }
  }
  // De-duplicate discovered handles, seed-exact first.
  out.discoveredHandles = [...new Set(out.discoveredHandles.map((h) => h.toLowerCase()))];
  return out;
}

/** One-line honest summary for caveats/notes. */
export function searchLaneSummary(r: SearchDiscoveryResult): string {
  const parts = [
    `search-engine lane (${r.queriesRun.length} DDG queries, ${r.pagesWithResults} result page(s)): ` +
    `${r.hits.length} profile hit(s), ${r.mentions.length} mention(s), ${r.directories.length} name-directory page(s)`,
  ];
  if (r.engineStatus !== 'ok') parts.push(r.engineStatus);
  return parts.join(' — ');
}
