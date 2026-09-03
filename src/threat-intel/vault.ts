import { correlateTechnologies, type CorrelationResponse } from './correlation.js';
import { ThreatFeedClient, type ThreatFeedSnapshot } from './feed.js';

export interface CveVaultSearchResponse extends CorrelationResponse { feedErrors: ThreatFeedSnapshot['errors'] }
export interface CveVaultSearchResult { status: 200 | 400 | 503; body: CveVaultSearchResponse | { error: string } }

export class CveVaultService {
  constructor(private readonly feeds: Pick<ThreatFeedClient, 'refresh'> = new ThreatFeedClient()) {}
  async search(body: unknown): Promise<CveVaultSearchResult> {
    if (!body || typeof body !== 'object' || Array.isArray(body)) return { status: 400, body: { error: 'request body must be an object' } };
    const query = (body as Record<string, unknown>).query;
    if (typeof query !== 'string' || !query.trim() || query.length > 200) return { status: 400, body: { error: 'query must be a non-empty string of at most 200 characters' } };
    const snapshot = await this.feeds.refresh();
    if (!snapshot.kev) return { status: 503, body: { error: 'CISA KEV feed is unavailable and no cached snapshot exists' } };
    const response = correlateTechnologies({ technologies: [{ name: query.trim(), source: 'cve-vault-search' }], kev: snapshot.kev, ...(snapshot.epss ? { epss: snapshot.epss } : {}) });
    return { status: 200, body: { ...response, feedErrors: snapshot.errors } };
  }
}
