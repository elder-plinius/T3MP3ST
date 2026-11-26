// =============================================================================
// GPS AREA NEWS — keyless "what's the news where I dropped the pin" lane
// =============================================================================
// When the operator lands a pin, the useful question is "what is happening
// HERE", not "what is on the map" (the map already answers that). A local LLM
// cannot browse, so the model is never the source: this module fetches real
// indexed coverage for the pin's PLACE and hands the model a headline list it
// may only summarize. Same grounding contract as the copilot — the server
// gathers, the model phrases.
//
// Sources, both keyless and both verified live from this box:
//   - Google News RSS (`news.google.com/rss/search`) — primary; ~100 items for a
//     city query, each with source + pubDate.
//   - Bing News RSS (`bing.com/news/search?format=RSS`) — secondary; smaller but
//     useful when Google throttles.
// GDELT DOC was evaluated and rejected as a source here: it answers HTTP 429
// ("one every 5 seconds") from our shared proxy egress, so it is not a
// dependable feed for an on-pin-drop lane.
//
// Scope: this is public news INDEXING for a named place the operator selected.
// It is not people-tracking — nothing is correlated with a person, and a pin is
// a place, not a device.

export interface AreaArticle {
  title: string;
  source: string;
  published: string;
  link: string;
  ageHours?: number;
}

export interface AreaNewsResult {
  query: string;
  articles: AreaArticle[];
  sourcesTried: string[];
  note?: string;
}

type Fetcher = (url: string, init?: Record<string, unknown>) => Promise<{ ok: boolean; status: number; json: () => Promise<unknown>; text: () => Promise<string> }>;

import { directFetch } from '../net/proxy.js';
// Same egress path as every other feed module (egress proxy → Tor → direct), so
// the news RSS calls behave like the rest of the app's public-data lanes.
const defaultFetch: Fetcher = (url, init) => directFetch(url as any, init as any) as unknown as ReturnType<Fetcher>;

// --- XML helpers ---------------------------------------------------------------
// No XML dependency in this project: these feeds are flat RSS, so a targeted
// reader is smaller and safer than pulling a parser in.

function decodeEntities(s: string): string {
  return String(s || '')
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&#0?39;/g, "'").replace(/&apos;/g, "'")
    .replace(/&nbsp;/g, ' ')
    .replace(/&#(\d+);/g, (_m, d) => String.fromCharCode(Number(d)))
    .replace(/&#x([0-9a-fA-F]+);/g, (_m, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/&amp;/g, '&');
}

function stripTags(s: string): string {
  return decodeEntities(String(s || '').replace(/<[^>]*>/g, ' ')).replace(/\s+/g, ' ').trim();
}

function tagText(block: string, tag: string): string {
  const m = block.match(new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)</${tag}>`, 'i'));
  if (!m) return '';
  // Unwrap CDATA BEFORE stripping tags: a `<![CDATA[…]]>` run matches the
  // generic tag pattern, so stripping first deletes the whole title.
  return stripTags(decodeEntities(m[1]));
}

/** Parse a flat RSS document into article records. Tolerates CDATA, missing
 *  <source>, and titles that carry a trailing " - Publisher" suffix. */
export function parseNewsRss(xml: string): AreaArticle[] {
  const out: AreaArticle[] = [];
  const blocks = String(xml || '').match(/<item[\s>][\s\S]*?<\/item>/gi) || [];
  for (const b of blocks) {
    let title = tagText(b, 'title');
    if (!title) continue;
    const link = tagText(b, 'link');
    const published = tagText(b, 'pubDate');
    let source = tagText(b, 'source');
    // Google appends " - Publisher" to the title. Sometimes <source> repeats it,
    // sometimes <source> is empty — either way the suffix is redundant, so split
    // it off the head and use it as the publisher when nothing else supplied one.
    const suffix = title.match(/^(.*)\s+-\s+([^-]{1,40})$/);
    if (suffix) {
      const tail = suffix[2].trim();
      if (!source || source.toLowerCase() === tail.toLowerCase()) {
        title = suffix[1].trim();
        if (!source) source = tail;
      }
    }
    if (!source) source = hostOf(link);
    out.push({ title, source, published, link });
  }
  return out;
}

function hostOf(url: string): string {
  const m = String(url || '').match(/^https?:\/\/([^/]+)/i);
  return m ? m[1].replace(/^www\./, '') : '';
}

export function ageHoursOf(published: string, now = Date.now()): number | undefined {
  const t = Date.parse(published || '');
  if (!Number.isFinite(t)) return undefined;
  return Math.max(0, Math.round((now - t) / 36e5));
}

// --- place → query -------------------------------------------------------------

/** Nominatim addresses vary wildly by feature; news wants the SETTLEMENT, not
 *  the street. Building the query from a house number or a road name returns
 *  national noise, so prefer the locality keys and fall back to the label. */
export function areaQueryFor(label: string, address?: Record<string, string> | null): string {
  const a = address || {};
  const pick = (...keys: string[]) => {
    for (const k of keys) { const v = a[k]; if (v && String(v).trim()) return String(v).trim(); }
    return '';
  };
  const specific = pick('neighbourhood', 'neighborhood', 'borough', 'suburb', 'quarter', 'ward');
  const city = pick('city', 'town', 'village', 'municipality', 'hamlet', 'county');
  const state = pick('state', 'region', 'province');
  const country = pick('country');
  // Nominatim files a pin inside a city under its NEIGHBOURHOOD (Brooklyn ⊂ New
  // York). News coverage follows the neighbourhood, so when the label's first
  // segment IS that specific area, search that + the state — "Brooklyn, New
  // York", not every story about the whole city. Otherwise use the city/town.
  const firstSeg = String(label || '').split(',')[0].trim().toLowerCase();
  const head = (specific && specific.toLowerCase() === firstSeg) ? specific : (city || specific);
  const parts: string[] = [];
  if (head) parts.push(head);
  // A bare "Paris, France" and "Paris, Texas" are different places; include the
  // state when the city name is common enough that a state disambiguator helps.
  if (state && (!country || !/^(united states|usa|france|germany|italy|spain|uk|united kingdom)$/i.test(country) || /united states/i.test(country))) {
    if (state !== head) parts.push(state);
  }
  if (!parts.length) {
    // No structured address (a forward-geocode match): use the label, minus a
    // leading house number and trailing postal code.
    const cleaned = String(label || '')
      .replace(/^\d+[A-Za-z]?\s+/, '')
      .replace(/\s+\d{5}(-\d{4})?,\s*United States.*$/i, '')
      .split(',').map((s) => s.trim()).filter(Boolean).slice(0, 2).join(', ');
    return cleaned.trim();
  }
  return parts.join(', ');
}

/** Quotes each comma-separated term so a multi-word city name is treated as a
 *  phrase rather than a bag of words. */
export function newsQuery(q: string): string {
  return String(q || '').split(',').map((s) => s.trim()).filter(Boolean).map((s) => `"${s}"`).join(' AND ');
}

// --- fetching ------------------------------------------------------------------

async function fetchText(url: string, fetcher: Fetcher | undefined, timeoutMs: number): Promise<string> {
  const f = fetcher || defaultFetch;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await f(url, {
      headers: { 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) T3MP3ST/1.5 area-news' },
      signal: ctrl.signal,
    } as never);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return await r.text();
  } finally {
    clearTimeout(timer);
  }
}

function dedupe(articles: AreaArticle[]): AreaArticle[] {
  const seen = new Set<string>();
  const out: AreaArticle[] = [];
  for (const a of articles) {
    const key = a.title.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim().slice(0, 70);
    if (!key || seen.has(key)) continue;
    seen.add(key);
    out.push(a);
  }
  return out;
}

const newsCache = new Map<string, { at: number; result: AreaNewsResult }>();

/** Fetch indexed coverage for a place. Cached per query for `ttlMs` so a pin
 *  dragged back and forth does not hammer two third-party feeds. */
export async function fetchAreaNews(
  label: string,
  address?: Record<string, string> | null,
  opts: { fetcher?: Fetcher; limit?: number; ttlMs?: number; refresh?: boolean; now?: number } = {}
): Promise<AreaNewsResult> {
  const place = areaQueryFor(label, address);
  if (!place) return { query: '', articles: [], sourcesTried: [], note: 'no place name to search on' };
  const query = newsQuery(place);
  const key = query.toLowerCase();
  const ttl = opts.ttlMs ?? 600_000;
  const now = opts.now ?? Date.now();
  const hit = newsCache.get(key);
  if (!opts.refresh && hit && now - hit.at < ttl) return { ...hit.result, note: 'cached' };

  const f = opts.fetcher;
  const limit = opts.limit ?? 25;
  const sourcesTried: string[] = [];
  const collected: AreaArticle[] = [];
  const notes: string[] = [];

  const targets: Array<{ name: string; url: string }> = [
    { name: 'Google News', url: `https://news.google.com/rss/search?q=${encodeURIComponent(query)}&hl=en-US&gl=US&ceid=US:en` },
    { name: 'Bing News', url: `https://www.bing.com/news/search?q=${encodeURIComponent(query)}&format=RSS` },
  ];

  for (const t of targets) {
    sourcesTried.push(t.name);
    try {
      const xml = await fetchText(t.url, f as Fetcher, 15_000);
      const items = parseNewsRss(xml);
      if (!items.length) { notes.push(`${t.name}: no items`); continue; }
      for (const it of items) collected.push({ ...it, source: it.source || t.name });
    } catch (e) {
      notes.push(`${t.name}: ${(e as Error).message.slice(0, 60)}`);
    }
  }

  const nowMs = opts.now ?? Date.now();
  const articles = dedupe(collected)
    .map((a) => ({ ...a, ageHours: ageHoursOf(a.published, nowMs) }))
    .sort((a, b) => (a.ageHours ?? 9999) - (b.ageHours ?? 9999))
    .slice(0, limit);

  const result: AreaNewsResult = {
    query,
    articles,
    sourcesTried,
    note: articles.length ? (notes.length ? notes.join(' · ') : undefined) : `no indexed coverage for "${place}" in the last 24h (${notes.join(' · ') || 'feeds returned nothing'})`,
  };
  if (articles.length) newsCache.set(key, { at: now, result });
  return result;
}

/** @internal test hook */
export function __clearAreaNewsCache(): void {
  newsCache.clear();
}

/** Headlines reduced to the lines a model is allowed to summarize. */
export function newsFactLines(result: AreaNewsResult, max = 18): string[] {
  if (!result.articles.length) return [];
  return result.articles.slice(0, max).map((a, i) => {
    const age = typeof a.ageHours === 'number' ? (a.ageHours < 1 ? '<1h ago' : `${a.ageHours}h ago`) : 'date unknown';
    return `${i + 1}. [${a.source || 'unknown source'}] ${a.title} (${age})`;
  });
}
