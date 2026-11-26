import { describe, it, expect, beforeEach } from 'vitest';
import {
  parseNewsRss,
  areaQueryFor,
  newsQuery,
  ageHoursOf,
  fetchAreaNews,
  newsFactLines,
  __clearAreaNewsCache,
} from '../tools/gps-area-news.js';

const GOOGLE_RSS = `<?xml version="1.0"?><rss><channel>
<item><title>Brooklyn bridge closure looms - The City Reporter</title><link>https://cityreporter.example/a</link><pubDate>Thu, 24 Sep 2026 18:44:00 GMT</pubDate><source url="https://cityreporter.example">The City Reporter</source></item>
<item><title><![CDATA[Queens &amp; Brooklyn housing fight escalates]]></title><link>https://paper.example/b</link><pubDate>Thu, 24 Sep 2026 10:00:00 GMT</pubDate></item>
<item><title>Duplicate headline - X</title><link>https://x.example/c</link><pubDate>Thu, 24 Sep 2026 09:00:00 GMT</pubDate></item>
<item><title>Transit funding roundup</title><link>https://transit.example/f</link><pubDate>Thu, 24 Sep 2026 08:00:00 GMT</pubDate></item>
<item><title>Transit funding roundup</title><link>https://transit.example/g</link><pubDate>Thu, 24 Sep 2026 07:00:00 GMT</pubDate></item>
<item><title></title><link>https://empty.example</link></item>
</channel></rss>`;

const BING_RSS = `<?xml version="1.0"?><rss><channel>
<item><title>Brooklyn rabbi attacked</title><link>https://n.example/e</link><pubDate>Thu, 24 Sep 2026 14:50:00 GMT</pubDate></item>
</channel></rss>`;

const okResponse = (body: string) => ({ ok: true, status: 200, json: async () => JSON.parse(body), text: async () => body });
const errResponse = (status: number) => ({ ok: false, status, json: async () => ({}), text: async () => '' });

// ── parsing ──────────────────────────────────────────────────────────────────

describe('area news RSS parsing', () => {
  const items = parseNewsRss(GOOGLE_RSS);

  it('extracts title, link, date and source', () => {
    expect(items).toHaveLength(5);
    expect(items[0]).toMatchObject({ title: 'Brooklyn bridge closure looms', source: 'The City Reporter', link: 'https://cityreporter.example/a' });
  });

  it('decodes CDATA and XML entities', () => {
    expect(items[1].title).toBe('Queens & Brooklyn housing fight escalates');
  });

  it('recovers the publisher from a " - Publisher" title suffix', () => {
    expect(items[2].title).toBe('Duplicate headline');
    expect(items[2].source).toBe('X');
  });

  it('skips items with no title', () => {
    expect(items.some((i) => i.link === 'https://empty.example')).toBe(false);
  });

  it('falls back to the link host when no publisher is present', () => {
    expect(items[3].source).toBe('transit.example');
  });
});

describe('age parsing', () => {
  it('computes age in hours and tolerates junk dates', () => {
    const now = Date.parse('Thu, 24 Sep 2026 20:44:00 GMT');
    expect(ageHoursOf('Thu, 24 Sep 2026 18:44:00 GMT', now)).toBe(2);
    expect(ageHoursOf('not a date', now)).toBeUndefined();
  });
});

// ── query building ───────────────────────────────────────────────────────────

describe('area query building', () => {
  it('searches the neighbourhood when the pin sits inside one, not the whole city', () => {
    expect(areaQueryFor('Brooklyn, Kings County, New York, United States', { suburb: 'Brooklyn', city: 'New York', state: 'New York', country: 'United States' })).toBe('Brooklyn, New York');
  });

  it('falls back to the city when the label is not the neighbourhood', () => {
    expect(areaQueryFor('Syracuse, New York, United States', { suburb: 'Downtown', city: 'Syracuse', state: 'New York', country: 'United States' })).toBe('Syracuse, New York');
  });

  it('does not repeat the city as its own state', () => {
    expect(areaQueryFor('Paris, France', { city: 'Paris', country: 'France' })).toBe('Paris');
  });

  it('strips a house number and trailing US zip when there is no structured address', () => {
    expect(areaQueryFor('200 Flushing Ave, Brooklyn, NY 11205, United States', null)).toBe('Flushing Ave, Brooklyn');
  });

  it('quotes each term so a multi-word city stays a phrase', () => {
    expect(newsQuery('New York, New York')).toBe('"New York" AND "New York"');
  });

  it('returns empty for an empty place', () => {
    expect(areaQueryFor('', {})).toBe('');
  });
});

// ── fetching ─────────────────────────────────────────────────────────────────

describe('fetchAreaNews', () => {
  beforeEach(() => __clearAreaNewsCache());

  const stub = (map: Record<string, () => any>) => {
    return async (url: string) => {
      for (const key of Object.keys(map)) {
        if (url.includes(key)) return map[key]();
      }
      return errResponse(404);
    };
  };

  it('merges both feeds, dedupes and sorts newest first', async () => {
    const now = Date.parse('Thu, 24 Sep 2026 20:44:00 GMT');
    const r = await fetchAreaNews('Brooklyn', { city: 'Brooklyn', state: 'New York', country: 'United States' }, {
      fetcher: stub({ 'news.google.com': () => okResponse(GOOGLE_RSS), 'bing.com': () => okResponse(BING_RSS) }) as any,
      now,
    });
    expect(r.articles.length).toBe(5); // 4 unique Google (1 duplicate dropped) + 1 Bing
    expect(r.articles[0].published).toContain('18:44');
    expect(r.sourcesTried).toEqual(['Google News', 'Bing News']);
    expect(r.articles.every((a) => typeof a.ageHours === 'number')).toBe(true);
  });

  it('serves the second call for the same place from cache', async () => {
    let calls = 0;
    const counting = async () => { calls++; return okResponse(BING_RSS); };
    await fetchAreaNews('Brooklyn', { city: 'Brooklyn' }, { fetcher: counting as any });
    const afterFirst = calls; // one hit per source
    await fetchAreaNews('Brooklyn', { city: 'Brooklyn' }, { fetcher: counting as any });
    expect(afterFirst).toBe(2);
    expect(calls).toBe(afterFirst);
  });

  it('still returns what it has when one feed is down', async () => {
    const r = await fetchAreaNews('Brooklyn', { city: 'Brooklyn' }, {
      fetcher: stub({ 'news.google.com': () => okResponse(GOOGLE_RSS), 'bing.com': () => errResponse(503) }) as any,
    });
    expect(r.articles.length).toBe(4);
    expect(r.note).toContain('Bing News: HTTP 503');
  });

  it('reports honestly when nothing is indexed for the place', async () => {
    const r = await fetchAreaNews('Nowhere Township', { city: 'Nowhere Township' }, {
      fetcher: stub({ 'news.google.com': () => okResponse('<rss><channel></channel></rss>'), 'bing.com': () => okResponse('<rss><channel></channel></rss>') }) as any,
    });
    expect(r.articles).toEqual([]);
    expect(r.note).toContain('no indexed coverage');
  });

  it('refuses to search an unnamed pin', async () => {
    const r = await fetchAreaNews('', null, { fetcher: (async () => okResponse(BING_RSS)) as any });
    expect(r.articles).toEqual([]);
    expect(r.note).toContain('no place name');
  });
});

describe('news fact lines', () => {
  it('renders outlet and age for the model, and nothing when empty', () => {
    const lines = newsFactLines({
      query: '"Brooklyn"',
      sourcesTried: ['Google News'],
      articles: [{ title: 'Something happened', source: 'The Paper', published: '', link: '', ageHours: 3 }],
    });
    expect(lines[0]).toBe('1. [The Paper] Something happened (3h ago)');
    expect(newsFactLines({ query: '', sourcesTried: [], articles: [] })).toEqual([]);
  });
});
