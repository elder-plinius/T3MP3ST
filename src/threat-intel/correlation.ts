import type { EpssRecord, FeedProvenance, FeedResult, FeedSource, KevRecord } from './feed.js';

export interface TechnologyObservation { name: string; version?: string; source?: string }
export interface CorrelationRequest { technologies: TechnologyObservation[]; kev: FeedResult<KevRecord>; epss?: FeedResult<EpssRecord> }
export interface CorrelationMatch {
  cveId: string; technology: TechnologyObservation; vendor: string; product: string; vulnerabilityName: string;
  confidence: number; matchBasis: 'exact-product' | 'token-overlap' | 'alias';
  versionStatus: 'not-provided' | 'not-evaluated'; verificationStatus: 'unverified-candidate';
  kev: KevRecord; epss?: EpssRecord; stale: boolean;
}
export interface CorrelationResponse {
  status: 'ok' | 'empty-feed'; matches: CorrelationMatch[]; warnings: string[];
  source: { kev: FeedResult<KevRecord>['provenance']; epss?: FeedResult<EpssRecord>['provenance'] };
}
export interface CorrelationApiResult { status: 200 | 400; body: CorrelationResponse | { error: string } }

const ALIASES: Readonly<Record<string, readonly string[]>> = {
  nginx: ['nginx'], openssh: ['openssh', 'ssh'], 'apache http server': ['apache', 'http server'],
  'microsoft exchange': ['microsoft', 'exchange'], 'citrix netscaler': ['citrix', 'netscaler'],
  'palo alto pan os': ['palo alto', 'pan os'],
};
function normalized(value: string): string { return value.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim().replace(/\s+/g, ' '); }
function words(value: string): string[] { return normalized(value).split(' ').filter((word) => word.length >= 3); }
function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}
function text(value: unknown, label: string, max = 2_000): string {
  if (typeof value !== 'string' || !value.trim() || value.length > max) throw new Error(`${label} must be a non-empty string of at most ${max} characters`);
  return value;
}
function provenance(value: unknown, source: FeedSource, label: string): FeedProvenance {
  const item = object(value, `${label}.provenance`);
  if (item.source !== source) throw new Error(`${label}.provenance.source must be ${source}`);
  text(item.sourceUrl, `${label}.provenance.sourceUrl`);
  text(item.retrievedAt, `${label}.provenance.retrievedAt`, 100);
  text(item.schemaVersion, `${label}.provenance.schemaVersion`, 100);
  return item as unknown as FeedProvenance;
}
function feed(value: unknown, source: FeedSource, label: string): Record<string, unknown> {
  const item = object(value, label);
  if (!Array.isArray(item.records) || item.records.length > 10_000) throw new Error(`${label}.records must be an array with at most 10000 records`);
  provenance(item.provenance, source, label);
  text(item.cachedAt, `${label}.cachedAt`, 100);
  if (item.state !== 'fresh' && item.state !== 'cached') throw new Error(`${label}.state must be fresh or cached`);
  if (typeof item.stale !== 'boolean') throw new Error(`${label}.stale must be a boolean`);
  return item;
}
function validateKev(value: unknown): FeedResult<KevRecord> {
  const item = feed(value, 'cisa-kev', 'kev');
  for (const [index, raw] of (item.records as unknown[]).entries()) {
    const record = object(raw, `kev.records[${index}]`);
    if (!/^CVE-\d{4}-\d{4,}$/i.test(text(record.cveId, `kev.records[${index}].cveId`, 40))) throw new Error(`kev.records[${index}].cveId must be a CVE identifier`);
    for (const field of ['vendor', 'product', 'vulnerabilityName', 'dateAdded', 'dueDate', 'requiredAction', 'knownRansomwareCampaignUse'] as const) text(record[field], `kev.records[${index}].${field}`);
    provenance(record.provenance, 'cisa-kev', `kev.records[${index}]`);
  }
  return item as unknown as FeedResult<KevRecord>;
}
function validateEpss(value: unknown): FeedResult<EpssRecord> {
  const item = feed(value, 'first-epss', 'epss');
  for (const [index, raw] of (item.records as unknown[]).entries()) {
    const record = object(raw, `epss.records[${index}]`);
    if (!/^CVE-\d{4}-\d{4,}$/i.test(text(record.cveId, `epss.records[${index}].cveId`, 40))) throw new Error(`epss.records[${index}].cveId must be a CVE identifier`);
    for (const field of ['score', 'percentile'] as const) if (typeof record[field] !== 'number' || !Number.isFinite(record[field]) || record[field] < 0 || record[field] > 1) throw new Error(`epss.records[${index}].${field} must be a probability`);
    text(record.scoreDate, `epss.records[${index}].scoreDate`, 100);
    provenance(record.provenance, 'first-epss', `epss.records[${index}]`);
  }
  return item as unknown as FeedResult<EpssRecord>;
}

function validateRequest(value: unknown): CorrelationRequest {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('request body must be an object');
  const body = value as Partial<CorrelationRequest>;
  if (!Array.isArray(body.technologies) || body.technologies.length === 0 || body.technologies.length > 100) throw new Error('technologies must contain 1 to 100 observations');
  for (const [index, technology] of body.technologies.entries()) {
    if (!technology || typeof technology.name !== 'string' || !normalized(technology.name) || technology.name.length > 200) throw new Error(`technologies[${index}].name must be a non-empty string of at most 200 characters`);
    if (technology.version !== undefined && (typeof technology.version !== 'string' || technology.version.length > 100)) throw new Error(`technologies[${index}].version must be a string of at most 100 characters`);
  }
  return { technologies: body.technologies, kev: validateKev(body.kev), ...(body.epss ? { epss: validateEpss(body.epss) } : {}) };
}

function matchTechnology(technology: TechnologyObservation, record: KevRecord): Pick<CorrelationMatch, 'confidence' | 'matchBasis'> | undefined {
  const needle = normalized(technology.name);
  const product = normalized(record.product);
  const vendorProduct = normalized(`${record.vendor} ${record.product}`);
  if (needle === product || needle === vendorProduct) return { confidence: 0.95, matchBasis: 'exact-product' };
  const needleWords = words(needle);
  const recordWords = words(vendorProduct);
  if (needleWords.length && needleWords.every((word) => recordWords.includes(word))) return { confidence: needleWords.length > 1 ? 0.8 : 0.45, matchBasis: 'token-overlap' };
  const aliases = ALIASES[needle];
  if (aliases?.some((alias) => vendorProduct.includes(alias))) return { confidence: 0.75, matchBasis: 'alias' };
  return undefined;
}

export function correlateTechnologies(request: CorrelationRequest): CorrelationResponse {
  const epss = new Map(request.epss?.records.map((record) => [record.cveId, record]));
  const matches = new Map<string, CorrelationMatch>();
  const stale = request.kev.stale || Boolean(request.epss?.stale);
  for (const technology of request.technologies) {
    for (const kev of request.kev.records) {
      const match = matchTechnology(technology, kev);
      if (!match) continue;
      const candidate: CorrelationMatch = {
        cveId: kev.cveId, technology: { ...technology }, vendor: kev.vendor, product: kev.product,
        vulnerabilityName: kev.vulnerabilityName, confidence: stale ? Math.min(match.confidence, 0.5) : match.confidence,
        matchBasis: match.matchBasis, versionStatus: technology.version ? 'not-evaluated' : 'not-provided',
        verificationStatus: 'unverified-candidate', kev, ...(epss.get(kev.cveId) ? { epss: epss.get(kev.cveId) } : {}), stale,
      };
      const previous = matches.get(kev.cveId);
      if (!previous || candidate.confidence > previous.confidence) matches.set(kev.cveId, candidate);
    }
  }
  return {
    status: request.kev.records.length ? 'ok' : 'empty-feed',
    matches: [...matches.values()].sort((a, b) => b.confidence - a.confidence || a.cveId.localeCompare(b.cveId)),
    warnings: ['Technology correlation identifies unverified candidates; it does not establish that an observed version is affected.', ...(stale ? ['One or more source feeds are stale; confidence is capped at 0.5.'] : [])],
    source: { kev: request.kev.provenance, ...(request.epss ? { epss: request.epss.provenance } : {}) },
  };
}

export function handleCorrelationApi(body: unknown): CorrelationApiResult {
  try { return { status: 200, body: correlateTechnologies(validateRequest(body)) }; }
  catch (error) { return { status: 400, body: { error: error instanceof Error ? error.message : 'invalid correlation request' } }; }
}
