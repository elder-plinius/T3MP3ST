export const CISA_KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
export const FIRST_EPSS_URL = 'https://api.first.org/data/v1/epss';

export type FeedSource = 'cisa-kev' | 'first-epss';

export interface FeedProvenance {
  source: FeedSource;
  sourceUrl: string;
  retrievedAt: string;
  schemaVersion: string;
  upstreamPublishedAt?: string;
  upstreamRecordCount?: number;
  pageOffset?: number;
  pageLimit?: number;
}

export interface KevRecord {
  cveId: string;
  vendor: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  dueDate: string;
  requiredAction: string;
  knownRansomwareCampaignUse: string;
  provenance: FeedProvenance;
}

export interface EpssRecord {
  cveId: string;
  score: number;
  percentile: number;
  scoreDate: string;
  provenance: FeedProvenance;
}

export interface CachedFeed<T> {
  provenance: FeedProvenance;
  records: T[];
  cachedAt: string;
}

export interface FeedCache {
  get<T>(source: FeedSource): Promise<CachedFeed<T> | undefined>;
  set<T>(source: FeedSource, value: CachedFeed<T>): Promise<void>;
}

export interface FeedResult<T> extends CachedFeed<T> {
  state: 'fresh' | 'cached';
  stale: boolean;
}

export interface ThreatFeedSnapshot {
  kev?: FeedResult<KevRecord>;
  epss?: FeedResult<EpssRecord>;
  errors: Partial<Record<FeedSource, string>>;
}

export class MemoryFeedCache implements FeedCache {
  private readonly values = new Map<FeedSource, CachedFeed<unknown>>();

  async get<T>(source: FeedSource): Promise<CachedFeed<T> | undefined> {
    return this.values.get(source) as CachedFeed<T> | undefined;
  }

  async set<T>(source: FeedSource, value: CachedFeed<T>): Promise<void> {
    this.values.set(source, value as CachedFeed<unknown>);
  }
}

export interface ThreatFeedClientOptions {
  fetch?: typeof fetch;
  cache?: FeedCache;
  now?: () => Date;
  timeoutMs?: number;
  maxResponseBytes?: number;
  maxCacheAgeMs?: number;
  kevUrl?: string;
  epssUrl?: string;
}

const CVE_ID = /^CVE-\d{4}-\d{4,}$/i;

function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function string(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.trim() === '') throw new Error(`${label} must be a non-empty string`);
  return value.trim();
}

function probability(value: unknown, label: string): number {
  const parsed = typeof value === 'string' ? Number(value) : value;
  if (typeof parsed !== 'number' || !Number.isFinite(parsed) || parsed < 0 || parsed > 1) {
    throw new Error(`${label} must be a probability`);
  }
  return parsed;
}

function optionalNonNegativeInteger(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
}

export function normalizeKev(payload: unknown, sourceUrl: string, retrievedAt: string): CachedFeed<KevRecord> {
  const root = object(payload, 'CISA KEV response');
  if (!Array.isArray(root.vulnerabilities)) throw new Error('CISA KEV vulnerabilities must be an array');
  const provenance: FeedProvenance = {
    source: 'cisa-kev', sourceUrl, retrievedAt,
    schemaVersion: string(root.catalogVersion, 'CISA KEV catalogVersion'),
    ...(typeof root.dateReleased === 'string' ? { upstreamPublishedAt: root.dateReleased } : {}),
    ...(optionalNonNegativeInteger(root.count) !== undefined ? { upstreamRecordCount: optionalNonNegativeInteger(root.count) } : {}),
  };
  const records = new Map<string, KevRecord>();
  for (const raw of root.vulnerabilities) {
    const item = object(raw, 'CISA KEV vulnerability');
    const cveId = string(item.cveID, 'CISA KEV cveID').toUpperCase();
    if (!CVE_ID.test(cveId)) throw new Error(`invalid CISA KEV cveID: ${cveId}`);
    if (records.has(cveId)) continue;
    records.set(cveId, {
      cveId,
      vendor: string(item.vendorProject, `${cveId} vendorProject`),
      product: string(item.product, `${cveId} product`),
      vulnerabilityName: string(item.vulnerabilityName, `${cveId} vulnerabilityName`),
      dateAdded: string(item.dateAdded, `${cveId} dateAdded`),
      dueDate: string(item.dueDate, `${cveId} dueDate`),
      requiredAction: string(item.requiredAction, `${cveId} requiredAction`),
      knownRansomwareCampaignUse: string(item.knownRansomwareCampaignUse, `${cveId} knownRansomwareCampaignUse`),
      provenance,
    });
  }
  return { provenance, records: [...records.values()], cachedAt: retrievedAt };
}

export function normalizeEpss(payload: unknown, sourceUrl: string, retrievedAt: string): CachedFeed<EpssRecord> {
  const root = object(payload, 'FIRST EPSS response');
  if (!Array.isArray(root.data)) throw new Error('FIRST EPSS data must be an array');
  const provenance: FeedProvenance = {
    source: 'first-epss', sourceUrl, retrievedAt,
    schemaVersion: string(root.version, 'FIRST EPSS version'),
    ...(optionalNonNegativeInteger(root.total) !== undefined ? { upstreamRecordCount: optionalNonNegativeInteger(root.total) } : {}),
    ...(optionalNonNegativeInteger(root.offset) !== undefined ? { pageOffset: optionalNonNegativeInteger(root.offset) } : {}),
    ...(optionalNonNegativeInteger(root.limit) !== undefined ? { pageLimit: optionalNonNegativeInteger(root.limit) } : {}),
  };
  const records = new Map<string, EpssRecord>();
  for (const raw of root.data) {
    const item = object(raw, 'FIRST EPSS record');
    const cveId = string(item.cve, 'FIRST EPSS cve').toUpperCase();
    if (!CVE_ID.test(cveId)) throw new Error(`invalid FIRST EPSS cve: ${cveId}`);
    if (records.has(cveId)) continue;
    records.set(cveId, {
      cveId,
      score: probability(item.epss, `${cveId} epss`),
      percentile: probability(item.percentile, `${cveId} percentile`),
      scoreDate: string(item.date, `${cveId} date`),
      provenance,
    });
  }
  return { provenance, records: [...records.values()], cachedAt: retrievedAt };
}

export class ThreatFeedClient {
  private readonly fetchImpl: typeof fetch;
  private readonly cache: FeedCache;
  private readonly now: () => Date;
  private readonly timeoutMs: number;
  private readonly maxResponseBytes: number;
  private readonly maxCacheAgeMs: number;
  private readonly kevUrl: string;
  private readonly epssUrl: string;

  constructor(options: ThreatFeedClientOptions = {}) {
    this.fetchImpl = options.fetch ?? globalThis.fetch;
    this.cache = options.cache ?? new MemoryFeedCache();
    this.now = options.now ?? (() => new Date());
    this.timeoutMs = options.timeoutMs ?? 20_000;
    this.maxResponseBytes = options.maxResponseBytes ?? 16 * 1024 * 1024;
    this.maxCacheAgeMs = options.maxCacheAgeMs ?? 24 * 60 * 60 * 1000;
    this.kevUrl = options.kevUrl ?? CISA_KEV_URL;
    this.epssUrl = options.epssUrl ?? FIRST_EPSS_URL;
  }

  async refresh(): Promise<ThreatFeedSnapshot> {
    const [kev, epss] = await Promise.all([
      this.refreshSource('cisa-kev', this.kevUrl, normalizeKev),
      this.refreshSource('first-epss', this.epssUrl, normalizeEpss),
    ]);
    return {
      ...(kev.feed ? { kev: kev.feed } : {}),
      ...(epss.feed ? { epss: epss.feed } : {}),
      errors: { ...(kev.error ? { 'cisa-kev': kev.error } : {}), ...(epss.error ? { 'first-epss': epss.error } : {}) },
    };
  }

  private async refreshSource<T>(
    source: FeedSource,
    url: string,
    normalize: (payload: unknown, sourceUrl: string, retrievedAt: string) => CachedFeed<T>,
  ): Promise<{ feed?: FeedResult<T>; error?: string }> {
    try {
      const retrievedAt = this.now().toISOString();
      const payload = await this.fetchJson(url);
      const value = normalize(payload, url, retrievedAt);
      await this.cache.set(source, value);
      return { feed: { ...value, state: 'fresh', stale: false } };
    } catch (error) {
      const cached = await this.cache.get<T>(source);
      const message = error instanceof Error ? error.message : String(error);
      if (!cached) return { error: message };
      const age = this.now().getTime() - Date.parse(cached.cachedAt);
      return { feed: { ...cached, state: 'cached', stale: !Number.isFinite(age) || age > this.maxCacheAgeMs }, error: message };
    }
  }

  private async fetchJson(url: string): Promise<unknown> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetchImpl(url, {
        signal: controller.signal,
        headers: { accept: 'application/json', 'user-agent': 'T3MP3ST/1.0 threat-feed-ingestion' },
      });
      if (!response.ok) throw new Error(`${url} returned HTTP ${response.status}`);
      const declared = Number(response.headers.get('content-length'));
      if (Number.isFinite(declared) && declared > this.maxResponseBytes) throw new Error(`${url} response exceeds size limit`);
      if (!response.body) throw new Error(`${url} returned an empty body`);
      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let size = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > this.maxResponseBytes) {
          await reader.cancel();
          throw new Error(`${url} response exceeds size limit`);
        }
        chunks.push(value);
      }
      const bytes = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
      try { return JSON.parse(new TextDecoder().decode(bytes)) as unknown; }
      catch { throw new Error(`${url} returned malformed JSON`); }
    } finally {
      clearTimeout(timer);
    }
  }
}
