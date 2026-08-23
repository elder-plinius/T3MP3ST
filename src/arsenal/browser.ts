/**
 * T3MP3ST browser probe — headless-Chromium tool for client-side checks.
 *
 * Closes the project's biggest black-box gap (BrowserAutomation was a stub):
 *  - captures rendered DOM, title, cookies (flags only — never values), console errors
 *  - performs a REAL XSS check: injects a payload into a query parameter, reloads,
 *    and detects both reflection (payload in rendered DOM) and EXECUTION (alert dialog fired)
 *
 * Safety contract (same as every tool):
 *  - GET-only, read-only, never submits forms or mutates state
 *  - respects the egress scope gate (declares `url` so Arsenal.execute() fences it)
 *  - never fabricates: every finding cites the actual page behavior
 */

import type { CustomTool, ToolFinding } from '../types/index.js';

const XSS_PAYLOAD = '"><svg/onload=alert(1)>';
// Plain-text marker rides alongside the payload: the serialized DOM never keeps
// the payload verbatim (the browser parses it into elements), but a marker in a
// text node always survives serialization — reliable reflection signal.
const XSS_MARKER = 'T3MP3STXSSMARKER123';

export function browserRequestInScope(approvedHost: string, requestedUrl: string): boolean {
  try {
    const requested = new URL(requestedUrl);
    return ['http:', 'https:'].includes(requested.protocol)
      && requested.hostname.toLowerCase() === approvedHost.toLowerCase();
  } catch { return false; }
}

/** Screenshot of the current page as base64 evidence (type: 'screenshot'). */
async function screenshotEvidence(page: { screenshot: (o?: { type?: 'png'; fullPage?: boolean }) => Promise<Buffer> }, tag: string): Promise<{ type: 'screenshot'; content: string; timestamp: number; metadata?: Record<string, unknown> } | undefined> {
  try {
    const buf = await page.screenshot({ type: 'png' });
    return { type: 'screenshot', content: `data:image/png;base64,${buf.toString('base64')}`, timestamp: Date.now(), metadata: { tag } };
  } catch { return undefined; }
}

export const browserProbeTool: CustomTool = {
  name: 'browser_probe',
  description: 'Open a URL in a headless browser: inspect rendered DOM, cookie flags, console errors, and test for reflected/executed XSS (GET only, read-only)',
  category: 'web',
  parameters: [
    { name: 'url', type: 'string', description: 'URL to open (http/https)', required: true },
  ],
  handler: async (context) => {
    const url = String(context.parameters.url || '');
    if (!/^https?:\/\//i.test(url)) {
      return { success: false, error: 'browser_probe: url must be http(s)' };
    }

    let chromium: typeof import('playwright').chromium | null = null;
    try {
      const pw = await import('playwright');
      chromium = pw.chromium;
      // Route the browser through the configured SOCKS proxy (OPSEC parity with the
      // Node fetch layer): read config.proxyUrl like src/net/proxy.ts does. Loopback
      // and private-lab targets bypass the proxy (same rule as the fetch layer) —
      // Tor cannot reach 127.0.0.1:8080.
      let proxy: { server: string } | undefined;
      try {
        const targetHost = new URL(url).hostname;
        const isLoopback = targetHost === 'localhost' || targetHost === '127.0.0.1' || targetHost === '::1' || /^10\.|^192\.168\.|^172\.(1[6-9]|2\d|3[01])\./.test(targetHost);
        if (!isLoopback) {
          const { config } = await import('../config/index.js');
          const proxyUrl = config.getProxyUrl?.();
          // Chromium rejects the socks5h:// scheme (ERR_NO_SUPPORTED_PROXIES) —
          // normalize to socks5://. DNS then resolves via the system resolver,
          // but the CONNECTION still tunnels through the SOCKS proxy.
          if (proxyUrl && /^socks/i.test(proxyUrl)) proxy = { server: proxyUrl.replace(/^socks5h:\/\//i, 'socks5://') };
        }
      } catch { /* no proxy configured */ }
      const browser = await chromium.launch({ headless: true, ...(proxy ? { proxy } : {}) });
      const findings: ToolFinding[] = [];
      const sections: string[] = [];
      try {
        const page = await browser.newPage();
        page.setDefaultTimeout(15000);

        // Playwright follows redirects and loads subresources outside the Arsenal's
        // initial execute() gate. Keep every browser request on the exact host that
        // was approved; abort cross-host redirects, frames, scripts, and images.
        const approvedHost = new URL(url).hostname.toLowerCase();
        await page.route('**/*', async (route) => {
          try {
            if (!browserRequestInScope(approvedHost, route.request().url())) {
              await route.abort('blockedbyclient');
              return;
            }
            await route.continue();
          } catch {
            await route.abort('blockedbyclient');
          }
        });

        let dialogFired = false;
        const consoleErrors: string[] = [];
        page.on('dialog', async (d) => { dialogFired = true; await d.dismiss().catch(() => {}); });
        page.on('console', (msg) => { if (msg.type() === 'error') consoleErrors.push(msg.text().slice(0, 200)); });
        page.on('pageerror', (err) => consoleErrors.push(String(err).slice(0, 200)));

        // 1. Baseline load
        let finalUrl = url;
        try {
          const resp = await page.goto(url, { waitUntil: 'domcontentloaded' });
          const observedUrl = page.url();
          finalUrl = new URL(observedUrl).hostname.toLowerCase() === approvedHost ? observedUrl : url;
          sections.push(`Baseline: ${resp?.status() ?? '?'} (final URL: ${finalUrl})`);
        } catch (e) {
          sections.push(`Baseline load failed: ${e instanceof Error ? e.message.slice(0, 150) : 'unknown'}`);
        }

        // 2. Cookies — flags only, never values
        try {
          const cookies = await page.context().cookies();
          if (cookies.length) {
            const lines = cookies.map((c) => {
              const flags = [c.httpOnly ? 'HttpOnly' : '', c.secure ? 'Secure' : '', c.sameSite ? `SameSite=${c.sameSite}` : ''].filter(Boolean).join(',') || 'no flags';
              return `  ${c.name}: ${flags}`;
            });
            sections.push(`Cookies (${cookies.length}):\n${lines.join('\n')}`);
            const insecure = cookies.filter((c) => !c.httpOnly || !c.secure);
            if (insecure.length) {
              findings.push({
                title: 'Insecure Cookie Flags (browser)',
                severity: 'low',
                details: `Cookies missing HttpOnly/Secure: ${insecure.map((c) => c.name).join(', ')}. Missing HttpOnly enables XSS cookie theft; missing Secure allows plaintext transmission.`,
              });
            }
          } else {
            sections.push('Cookies: none');
          }
        } catch { /* no cookie access */ }

        // 3. Rendered DOM (truncated) + title
        try {
          const title = await page.title();
          const text = (await page.locator('body').innerText().catch(() => '')).replace(/\s+/g, ' ').slice(0, 600);
          sections.push(`Title: ${title || '(empty)'}`);
          sections.push(`Rendered text: ${text || '(empty)'}`);
        } catch { /* ignore */ }

        // 4. XSS reflection + execution test on a query parameter
        let xssTried = false;
        try {
          const u = new URL(finalUrl);
          if (!u.search) u.searchParams.set('q', 'probe');
          const firstParam = u.searchParams.keys().next().value as string;
          const original = u.searchParams.get(firstParam) ?? '';
          u.searchParams.set(firstParam, original + XSS_MARKER + XSS_PAYLOAD);
          await page.goto(u.toString(), { waitUntil: 'domcontentloaded' });
          xssTried = true;
          const html = await page.content();
          // Marker survives DOM serialization even when the payload is parsed into
          // elements; the dialog is the execution signal. Raw payload string in DOM
          // is a bonus signal for servers that echo without parsing.
          const reflected = html.includes(XSS_MARKER) || html.includes(XSS_PAYLOAD);
          await page.waitForTimeout(1500); // let deferred onload handlers fire
          const xssShot = await screenshotEvidence(page, 'xss');
          if (reflected && dialogFired) {
            findings.push({
              title: `XSS Executed in '${firstParam}' (browser)`,
              severity: 'high',
              details: `Payload executed (alert dialog fired) after reflection in parameter '${firstParam}' at ${finalUrl}. Payload: ${XSS_PAYLOAD}`,
              cwe: ['CWE-79'],
              evidence: xssShot ? [xssShot] : undefined,
            });
          } else if (reflected) {
            findings.push({
              title: `XSS Reflected in '${firstParam}' (browser)`,
              severity: 'medium',
              details: `Payload appears unencoded in the rendered DOM of parameter '${firstParam}' at ${finalUrl}; execution not confirmed (no dialog fired). Verify manually. Payload: ${XSS_PAYLOAD}`,
              cwe: ['CWE-79'],
              evidence: xssShot ? [xssShot] : undefined,
            });
          } else {
            sections.push('XSS probe: payload not reflected — parameter appears safely encoded');
          }
        } catch (e) {
          sections.push(`XSS probe failed: ${e instanceof Error ? e.message.slice(0, 150) : 'unknown'}`);
        }
        void xssTried;

        if (consoleErrors.length) {
          findings.push({
            title: 'Client-Side JavaScript Errors',
            severity: 'info',
            details: `Console/page errors on load: ${consoleErrors.slice(0, 3).join(' | ')}`,
          });
        }
      } finally {
        await browser.close();
      }

      const output = sections.join('\n') || 'No browser output captured.';
      return { success: true, output, findings: findings.length ? findings : undefined };
    } catch (e) {
      return {
        success: false,
        error: `browser_probe failed: ${e instanceof Error ? e.message.slice(0, 200) : 'unknown'}`,
      };
    }
  },
};
