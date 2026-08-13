/**
 * T3MP3ST kev_check — CISA Known Exploited Vulnerabilities lookup.
 *
 * Matches detected software (vendor:product) against the CISA KEV catalog
 * (the list of vulnerabilities KNOWN to be exploited in the wild). A hit is a
 * high-priority lead: real attackers are using it right now. The catalog is
 * fetched once per process and cached 24h; the tool is a pure lookup over real
 * government-published data — never fabricated.
 */

import type { CustomTool } from '../types/index.js';

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const TTL_MS = 24 * 60 * 60 * 1000;

let cache: { at: number; items: { cve: string; product: string; vendor: string; due: string; name: string }[] } | null = null;

async function loadKev(): Promise<typeof cache> {
  if (cache && Date.now() - cache.at < TTL_MS) return cache;
  try {
    const res = await fetch(KEV_URL, { signal: AbortSignal.timeout(20000) });
    const json = (await res.json()) as { vulnerabilities?: { cveID: string; vendorProject: string; product: string; dueDate: string; vulnerabilityName: string }[] };
    const items = (json.vulnerabilities ?? []).map((v) => ({
      cve: v.cveID,
      vendor: String(v.vendorProject ?? ''),
      product: String(v.product ?? ''),
      due: String(v.dueDate ?? ''),
      name: String(v.vulnerabilityName ?? ''),
    }));
    cache = { at: Date.now(), items };
    return cache;
  } catch {
    return cache; // stale cache ok; null if never loaded
  }
}

export const kevCheckTool: CustomTool = {
  name: 'kev_check',
  description: 'Check software names (vendor:product, e.g. "nginx" or "apache:http_server") against the CISA Known Exploited Vulnerabilities catalog — hits are vulnerabilities actively exploited in the wild',
  category: 'vuln',
  parameters: [
    { name: 'software', type: 'string', description: 'Software to look up, e.g. nginx, php, apache:http_server', required: true },
  ],
  handler: async (context) => {
    const query = String(context.parameters.software || '').trim().toLowerCase();
    if (!query) return { success: false, error: 'kev_check: software required' };
    const kev = await loadKev();
    if (!kev || kev.items.length === 0) {
      return { success: false, error: 'kev_check: CISA KEV catalog unavailable (network or parse error)' };
    }
    const qParts = query.split(':').map((p) => p.trim().toLowerCase()).filter(Boolean);
    const hits = kev.items.filter((v) => {
      const hay = `${v.vendor} ${v.product}`.toLowerCase();
      return qParts.some((p) => hay.includes(p)) || qParts.some((p) => v.product.toLowerCase().includes(p));
    }).slice(0, 10);

    if (hits.length === 0) {
      return { success: true, output: `kev_check "${query}": no known-exploited vulnerabilities found in the CISA catalog (${kev.items.length} entries checked).` };
    }
    const lines = hits.map((h) => `  ${h.cve} | ${h.vendor}:${h.product} | due ${h.due} | ${h.name.slice(0, 80)}`);
    return {
      success: true,
      output: `kev_check "${query}": ${hits.length} actively-exploited CVE(s):\n${lines.join('\n')}`,
      findings: [{
        title: `Actively Exploited: ${query} (CISA KEV)`,
        severity: 'high',
        details: `Software matching "${query}" appears in the CISA Known Exploited Vulnerabilities catalog: ${hits.map((h) => `${h.cve} (${h.name.slice(0, 60)}, due ${h.due})`).join('; ')}. Verify the deployed version against these CVEs.`,
      }],
    };
  },
};
