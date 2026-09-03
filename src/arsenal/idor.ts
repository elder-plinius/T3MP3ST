/**
 * T3MP3ST idor_probe — automated IDOR (Insecure Direct Object Reference) probe.
 *
 * Enumerates numeric object IDs on an endpoint with the SAME auth token and
 * compares responses: when neighbor IDs return the same 200-shape as the
 * operator's own object (or simply 200 where others 403/404), that is a
 * cross-user access candidate the analyst can verify.
 *
 * Safety contract:
 *  - GET-only, read-only; never mutates state
 *  - bounded range (default 1..20, hard cap 50) with a small delay between
 *    probes — no hammering
 *  - declares `url` so the arsenal egress scope gate fences the target
 *  - never fabricates: only REAL HTTP responses are summarized; candidates are
 *    labeled as candidates ("verify manually"), not confirmed breaches
 */

import type { CustomTool, ToolFinding } from '../types/index.js';

interface ProbeResult {
  id: number;
  status: number;
  length: number;
  fingerprint: string;
}

async function probe(urlTemplate: string, id: number, token: string | undefined, delayMs: number): Promise<ProbeResult | null> {
  const url = urlTemplate.replace(/\{id\}/g, String(id));
  try {
    const res = await fetch(url, {
      method: 'GET',
      signal: AbortSignal.timeout(12000),
      headers: token ? { authorization: `Bearer ${token}`, accept: 'application/json' } : { accept: 'application/json' },
    });
    const body = await res.text().catch(() => '');
    const fingerprint = `${res.status}|${body.length}|${(body || '').slice(0, 120).replace(/\s+/g, ' ')}`;
    await new Promise((r) => setTimeout(r, delayMs));
    return { id, status: res.status, length: body.length, fingerprint };
  } catch {
    await new Promise((r) => setTimeout(r, delayMs));
    return null;
  }
}

export const idorProbeTool: CustomTool = {
  name: 'idor_probe',
  description: 'Enumerate numeric object IDs on a URL template with {id} using the same token; detect neighbor IDs returning the same 200-shape (cross-user access / IDOR candidates). GET-only, read-only, bounded.',
  category: 'vuln',
  parameters: [
    { name: 'url', type: 'string', description: 'URL template containing {id}, e.g. https://x/api/fanfics/{id}', required: true },
    { name: 'token', type: 'string', description: 'Bearer token to send (your own session)', required: false },
    { name: 'start', type: 'number', description: 'First id to probe (default 1)', required: false },
    { name: 'end', type: 'number', description: 'Last id to probe (default 20, hard cap 50)', required: false },
    { name: 'own_id', type: 'number', description: 'Your own object id (baseline that should return 200)', required: false },
  ],
  handler: async (context) => {
    const url = String(context.parameters.url || '').trim();
    if (!url.includes('{id}') || !/^https?:\/\//i.test(url)) {
      return { success: false, error: 'idor_probe: url must be http(s) and contain {id}' };
    }
    const start = Math.max(1, Number(context.parameters.start) || 1);
    const end = Math.min(start + 49, Number(context.parameters.end) || Math.min(start + 19, 50));
    const ownId = context.parameters.own_id !== undefined ? Number(context.parameters.own_id) : undefined;
    const token = context.parameters.token ? String(context.parameters.token) : undefined;

    const results: ProbeResult[] = [];
    for (let id = start; id <= end; id++) {
      const r = await probe(url, id, token, 150);
      if (r) results.push(r);
    }
    if (results.length === 0) {
      return { success: true, output: 'idor_probe: no responses received (target unreachable or all requests failed).' };
    }

    const ok200 = results.filter((r) => r.status === 200);
    const baseline = ownId !== undefined ? results.find((r) => r.id === ownId) : ok200[0];

    const candidates: ProbeResult[] = [];
    if (baseline) {
      for (const r of ok200) {
        if (r.id === ownId) continue;
        const similar = r.status === baseline.status &&
          Math.abs(r.length - baseline.length) <= Math.max(50, baseline.length * 0.2);
        if (similar) candidates.push(r);
      }
    } else {
      // No baseline: any 200 on a neighbor id where siblings 403/404 is a candidate.
      const nonOk = results.filter((r) => r.status !== 200);
      if (ok200.length > 0 && nonOk.length > 0 && ok200.length <= end - start + 1) {
        candidates.push(...ok200);
      }
    }

    const lines = results.map((r) => `  id ${r.id}: ${r.status} (${r.length}b)`);
    const output = [
      `IDOR probe ${url.replace('{id}', `${start}..${end}`)}${token ? ' (with token)' : ' (no token)'}:`,
      ...lines,
      baseline ? `Baseline: id ${baseline.id} (${baseline.status}, ${baseline.length}b)` : '',
      candidates.length ? `CANDIDATES: ${candidates.map((c) => c.id).join(', ')}` : 'No IDOR candidates detected.',
      'Candidates are cross-user access suspects — verify manually with two accounts before reporting.',
    ].filter(Boolean).join('\n');

    const findings: ToolFinding[] | undefined = candidates.length
      ? [{
          title: `IDOR Candidates on ${new URL(url.replace(/\{id\}/g, String(start))).pathname}`,
          severity: 'medium',
          details: `With the same token, ids ${candidates.map((c) => c.id).join(', ')} returned 200 with the baseline shape (baseline id ${baseline?.id ?? ownId ?? '?'}). Verify with two accounts: if a second user's token reaches these objects, it is a confirmed IDOR.`,
          cwe: ['CWE-639'],
        }]
      : undefined;

    return { success: true, output, findings };
  },
};
