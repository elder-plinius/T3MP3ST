/**
 * Sploitus Exploit & CVE Intelligence Search
 * Ported & adapted from PentAGI (pkg/tools/sploitus.go)
 * Queries the Sploitus API (https://sploitus.com/search) for public exploits, PoCs, and CVE advisories.
 */

export interface SploitusResult {
  title: string;
  type: 'exploit' | 'tool' | 'advisory';
  source: string;
  url: string;
  date?: string;
  score?: number;
  author?: string;
  description?: string;
  cve?: string[];
}

export interface SploitusQueryOptions {
  query: string;
  type?: 'exploits' | 'tools';
  sort?: 'default' | 'date' | 'score';
  maxResults?: number;
  timeoutMs?: number;
}

export class SploitusClient {
  private static readonly API_URL = 'https://sploitus.com/search';
  private static readonly DEFAULT_TIMEOUT = 15000;

  public static async search(options: SploitusQueryOptions): Promise<{ total: number; results: SploitusResult[] }> {
    const {
      query,
      type = 'exploits',
      sort = 'default',
      maxResults = 10,
      timeoutMs = SploitusClient.DEFAULT_TIMEOUT
    } = options;

    if (!query || !query.trim()) {
      return { total: 0, results: [] };
    }

    const payload = {
      type,
      sort,
      query: query.trim(),
      title: false,
      offset: 0
    };

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(SploitusClient.API_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'T3MP3ST/2.0 (Security Intelligence Agent)'
        },
        body: JSON.stringify(payload),
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`Sploitus HTTP ${response.status}: ${response.statusText}`);
      }

      const data = (await response.json()) as any;
      const rawResults: any[] = data.exploits || data.tools || [];

      const results: SploitusResult[] = rawResults.slice(0, Math.max(1, Math.min(maxResults, 25))).map(item => {
        const cveMatches = (item.title + ' ' + (item.description || '')).match(/CVE-\d{4}-\d{4,7}/gi) || [];
        return {
          title: item.title || 'Untitled',
          type: item.type === 'tool' ? 'tool' : (item.type === 'advisory' ? 'advisory' : 'exploit'),
          source: item.source || item.href || 'sploitus',
          url: item.href || (item.id ? `https://sploitus.com/exploit?id=${encodeURIComponent(item.id)}` : ''),
          date: item.published || item.date || undefined,
          score: typeof item.score === 'number' ? item.score : undefined,
          author: item.author || undefined,
          description: item.description ? (item.description.length > 500 ? item.description.substring(0, 500) + '...' : item.description) : undefined,
          cve: Array.from(new Set(cveMatches.map((c: string) => c.toUpperCase())))
        };
      });

      return {
        total: (typeof data.total === 'number' ? data.total : results.length),
        results
      };
    } catch (err: any) {
      if (controller.signal.aborted) {
        throw new Error(`Sploitus query timed out after ${timeoutMs}ms`);
      }
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }
}
