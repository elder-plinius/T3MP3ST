import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import {
  MemoryFeedCache,
  ThreatFeedClient,
  normalizeEpss,
  normalizeKev,
  type CachedFeed,
  type KevRecord,
} from '../threat-intel/feed.js';

const fixture = async (name: string): Promise<unknown> =>
  JSON.parse(await readFile(new URL(`./fixtures/${name}`, import.meta.url), 'utf8')) as unknown;
const response = (body: unknown, init?: ResponseInit): Response => new Response(JSON.stringify(body), init);

describe('threat intelligence feed ingestion', () => {
  it('normalizes, deduplicates, and retains CISA provenance', async () => {
    const feed = normalizeKev(await fixture('cisa-kev.json'), 'https://cisa.example/kev.json', '2026-09-03T00:00:00.000Z');
    expect(feed.records).toHaveLength(2);
    expect(feed.records[0]?.cveId).toBe('CVE-2024-0001');
    expect(feed.provenance).toEqual({
      source: 'cisa-kev', sourceUrl: 'https://cisa.example/kev.json', retrievedAt: '2026-09-03T00:00:00.000Z',
      schemaVersion: '2026.09.01', upstreamPublishedAt: '2026-09-01T10:00:00.000Z',
      upstreamRecordCount: 3,
    });
    expect(feed.records[0]?.provenance).toBe(feed.provenance);
  });

  it('normalizes numeric EPSS probabilities and deduplicates CVEs', async () => {
    const feed = normalizeEpss(await fixture('first-epss.json'), 'https://first.example/epss', '2026-09-03T00:00:00.000Z');
    expect(feed.records).toHaveLength(2);
    expect(feed.records[0]).toMatchObject({ cveId: 'CVE-2024-0001', score: 0.125, percentile: 0.75 });
    expect(feed.provenance.schemaVersion).toBe('1.0');
    expect(feed.provenance).toMatchObject({ upstreamRecordCount: 3, pageOffset: 0, pageLimit: 100 });
  });

  it('refreshes both sources independently and writes the cache', async () => {
    const kev = await fixture('cisa-kev.json');
    const epss = await fixture('first-epss.json');
    const client = new ThreatFeedClient({
      fetch: async (url) => response(String(url).includes('cisa') ? kev : epss),
      now: () => new Date('2026-09-03T00:00:00.000Z'),
    });
    const result = await client.refresh();
    expect(result.errors).toEqual({});
    expect(result.kev).toMatchObject({ state: 'fresh', stale: false });
    expect(result.epss).toMatchObject({ state: 'fresh', stale: false });
  });

  it('returns a stale cached source while preserving a successful source', async () => {
    const cache = new MemoryFeedCache();
    const old = normalizeKev(await fixture('cisa-kev.json'), 'https://old.example/kev', '2026-08-01T00:00:00.000Z');
    await cache.set('cisa-kev', old);
    const epss = await fixture('first-epss.json');
    const client = new ThreatFeedClient({
      cache,
      fetch: async (url) => {
        if (String(url).includes('cisa')) throw new Error('offline');
        return response(epss);
      },
      now: () => new Date('2026-09-03T00:00:00.000Z'),
      maxCacheAgeMs: 86_400_000,
    });
    const result = await client.refresh();
    expect(result.kev).toMatchObject({ state: 'cached', stale: true });
    expect(result.epss).toMatchObject({ state: 'fresh', stale: false });
    expect(result.errors['cisa-kev']).toBe('offline');
  });

  it('reports a missing failed source without discarding the other source', async () => {
    const epss = await fixture('first-epss.json');
    const client = new ThreatFeedClient({ fetch: async (url) => String(url).includes('cisa') ? response({}, { status: 503 }) : response(epss) });
    const result = await client.refresh();
    expect(result.kev).toBeUndefined();
    expect(result.epss?.records).toHaveLength(2);
    expect(result.errors['cisa-kev']).toContain('HTTP 503');
  });

  it('rejects malformed schemas and out-of-range scores', () => {
    expect(() => normalizeKev({ catalogVersion: '1', vulnerabilities: {} }, 'u', '2026-01-01T00:00:00Z')).toThrow('array');
    expect(() => normalizeEpss({ version: '1', data: [{ cve: 'CVE-2024-0001', epss: '2', percentile: '0.5', date: '2026-01-01' }] }, 'u', '2026-01-01T00:00:00Z')).toThrow('probability');
  });

  it('reports malformed JSON without replacing it with invented records', async () => {
    const client = new ThreatFeedClient({ fetch: async () => new Response('{not-json') });
    const result = await client.refresh();
    expect(result.kev).toBeUndefined();
    expect(result.epss).toBeUndefined();
    expect(result.errors['cisa-kev']).toContain('malformed JSON');
    expect(result.errors['first-epss']).toContain('malformed JSON');
  });

  it('bounds declared and streamed response sizes', async () => {
    const declared = new ThreatFeedClient({ fetch: async () => new Response('{}', { headers: { 'content-length': '999' } }), maxResponseBytes: 10 });
    expect((await declared.refresh()).errors['cisa-kev']).toContain('size limit');
    const streamed = new ThreatFeedClient({ fetch: async () => response({ version: '1', data: [] }), maxResponseBytes: 4 });
    expect((await streamed.refresh()).errors['first-epss']).toContain('size limit');
  });

  it('aborts requests that exceed the configured timeout', async () => {
    const hangingFetch = (_url: string | URL | Request, init?: RequestInit): Promise<Response> => new Promise((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => reject(new Error('timed out')));
    });
    const result = await new ThreatFeedClient({ fetch: hangingFetch, timeoutMs: 5 }).refresh();
    expect(result.errors['cisa-kev']).toBe('timed out');
    expect(result.errors['first-epss']).toBe('timed out');
  });

  it('marks an invalid cache timestamp stale', async () => {
    const cache = new MemoryFeedCache();
    const value = normalizeKev(await fixture('cisa-kev.json'), 'u', '2026-09-03T00:00:00.000Z') as CachedFeed<KevRecord>;
    value.cachedAt = 'invalid';
    await cache.set('cisa-kev', value);
    const result = await new ThreatFeedClient({ cache, fetch: async () => { throw new Error('offline'); } }).refresh();
    expect(result.kev?.stale).toBe(true);
  });
});
