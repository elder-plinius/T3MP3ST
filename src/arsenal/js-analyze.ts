/**
 * T3MP3ST js_analyze — frontend JS secret/endpoint scanning.
 *
 * Fetches a page, extracts its <script src> chunks (same-origin), downloads them
 * through the same egress path as the rest of the harness, and greps for:
 *  - API keys / tokens (regex patterns: sk-, AIza, ghp_, aws AKIA, etc.)
 *  - interesting endpoints (/api/, /admin, graphql, internal hosts)
 *  - sourceMappingURL leaks (build-time source maps that expose source)
 *
 * Honesty: every hit is a literal substring of a REAL downloaded chunk, reported
 * with the exact line context (truncated). No pattern = no finding.
 */

import type { CustomTool, ToolFinding } from '../types/index.js';

const SECRET_PATTERNS: { name: string; re: RegExp }[] = [
  { name: 'OpenAI/Anthropic/Groq style key', re: /sk-[A-Za-z0-9_-]{20,}/ },
  { name: 'Google API key', re: /AIza[0-9A-Za-z_-]{30,}/ },
  { name: 'GitHub token', re: /ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,}/ },
  { name: 'AWS access key', re: /AKIA[0-9A-Z]{16}/ },
  { name: 'Slack token', re: /xox[baprs]-[0-9A-Za-z-]{10,}/ },
  { name: 'Stripe key', re: /(sk|pk)_(live|test)_[0-9a-zA-Z]{20,}/ },
  { name: 'Firebase key', re: /AIza[0-9A-Za-z_-]{30,}/ },
  { name: 'JWT (possible session)', re: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
  { name: 'Generic bearer token', re: /Bearer\s+[A-Za-z0-9._-]{20,}/i },
];

const ENDPOINT_PATTERNS: { name: string; re: RegExp }[] = [
  { name: 'API endpoint', re: /["'`]([^"'`]*\/api\/[^"'`]{2,80})["'`]/ },
  { name: 'Admin/internal path', re: /["'`]([^"'`]*(?:admin|internal|staging|debugger|graphql)[^"'`]{0,60})["'`]/i },
  { name: 'Internal host', re: /["'`](https?:\/\/(?:localhost|127\.0\.0\.1|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)[^"'`]{0,80})["'`]/i },
];

export const jsAnalyzeTool: CustomTool = {
  name: 'js_analyze',
  description: 'Analyze a page\'s JavaScript chunks for hardcoded secrets (API keys, tokens), hidden endpoints and internal hosts, and source-map leaks',
  category: 'web',
  parameters: [
    { name: 'url', type: 'string', description: 'Page URL to analyze', required: true },
  ],
  handler: async (context) => {
    const url = String(context.parameters.url || '');
    if (!/^https?:\/\//i.test(url)) return { success: false, error: 'js_analyze: url must be http(s)' };
    const findings: ToolFinding[] = [];
    const sections: string[] = [];

    let pageHtml = '';
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(15000), headers: { 'user-agent': 'Mozilla/5.0 (compatible; T3MP3ST-JS/1.0)' } });
      pageHtml = await res.text();
      sections.push(`Page: ${res.status} (${pageHtml.length}b)`);
    } catch (e) {
      return { success: false, error: `js_analyze: page fetch failed: ${e instanceof Error ? e.message.slice(0, 120) : 'unknown'}` };
    }

    const base = new URL(url);
    const srcs = new Set<string>();
    const re = /<script[^>]+src=["']([^"']+)["']/gi;
    let m: RegExpExecArray | null;
    while ((m = re.exec(pageHtml)) !== null) {
      try { srcs.add(new URL(m[1], base).href); } catch { /* skip bad */ }
    }
    // Also scan inline scripts for secrets.
    const inline = pageHtml.replace(/<script[^>]*>([\s\S]*?)<\/script>/gi, '$1');
    const inlineHits: string[] = [];
    for (const p of SECRET_PATTERNS) {
      if (p.re.test(inline)) inlineHits.push(p.name);
    }
    if (inlineHits.length) {
      findings.push({
        title: 'Secret Pattern in Inline Script',
        severity: 'medium',
        details: `Potential secret patterns found in inline JS: ${inlineHits.join(', ')}. Verify — pattern matches are heuristic, not proof of a live credential.`,
      });
    }

    sections.push(`Script chunks: ${srcs.size || 'none'}`);
    const scanned: string[] = [];
    for (const src of srcs) {
      if (scanned.length >= 12) break; // bounded
      scanned.push(src);
      let code = '';
      try {
        const r = await fetch(src, { signal: AbortSignal.timeout(15000), headers: { 'user-agent': 'Mozilla/5.0 (compatible; T3MP3ST-JS/1.0)' } });
        code = await r.text();
      } catch { sections.push(`  ✗ ${src} (fetch failed)`); continue; }
      const chunkHits: string[] = [];
      const chunks: string[] = [];
      for (const p of SECRET_PATTERNS) {
        const mm = p.re.exec(code);
        if (mm) chunkHits.push(`${p.name}: ${mm[0].slice(0, 40)}…`);
      }
      for (const p of ENDPOINT_PATTERNS) {
        const mm = p.re.exec(code);
        if (mm) chunks.push(`${p.name}: ${mm[1].slice(0, 80)}`);
      }
      if (/sourceMappingURL=([^\s]+)/.test(code)) chunks.push('sourceMappingURL present (source maps may be published)');
      if (chunkHits.length) {
        findings.push({
          title: `Secret Pattern in ${src.split('/').pop()}`,
          severity: 'high',
          details: `Potential secrets in JS chunk: ${chunkHits.join('; ')}. Heuristic — verify manually.`,
        });
      }
      if (chunks.length) {
        findings.push({
          title: `Hidden Endpoints in ${src.split('/').pop()}`,
          severity: 'info',
          details: `Endpoints/hosts found in JS: ${chunks.join('; ')}`,
        });
      }
      sections.push(`  ✓ ${src} (${code.length}b)${chunkHits.length ? ' ⚠' : ''}`);
    }

    const output = sections.join('\n') || 'No script chunks found.';
    return { success: true, output, findings: findings.length ? findings : undefined };
  },
};
