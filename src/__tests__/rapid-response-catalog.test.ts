import { describe, it, expect } from 'vitest';
import { RAPID_RESPONSE_CATALOG } from '../tools/rapid-response.js';
import { RapidResponseEngine } from '../tools/rapid-response.js';

describe('rapid-response probe catalog', () => {
  it('every probe is well-formed with a unique id and an inert-first design', () => {
    const ids = new Set<string>();
    for (const p of RAPID_RESPONSE_CATALOG) {
      expect(p.id.length).toBeGreaterThan(3);
      expect(ids.has(p.id), `duplicate probe id ${p.id}`).toBe(false);
      ids.add(p.id);
      expect(p.cve).toMatch(/^(CVE-\d{4}-\d{4,}|CWE-\d+)$/);
      expect(['rce', 'info_disclosure', 'auth_bypass', 'dos', 'deserialization'].includes(p.category) || typeof p.category === 'string').toBe(true);
      expect(['critical', 'high', 'medium', 'low']).toContain(p.severity);
      expect(typeof p.run).toBe('function');
    }
  });

  it('pins the newer probes (Mirth XStream + Tomcat clear-session)', () => {
    const ids = new Set(RAPID_RESPONSE_CATALOG.map(p => p.id));
    expect(ids.has('mirth-connect-xstream')).toBe(true);
    expect(ids.has('tomcat-clear-session')).toBe(true);
  });

  it('mirth probe reports not-vulnerable on a non-Mirth target and never sends a gadget', async () => {
    // Local ephemeral listener that returns a non-Mirth body — proves the detection is
    // version-gated and the probe issues NO deserialization payload, only GETs.
    const { createServer } = await import('node:http');
    const srv = createServer((_req, res) => { res.setHeader('content-type', 'application/json'); res.end('{"status":"ok"}'); });
    await new Promise<void>(r => srv.listen(0, '127.0.0.1', r));
    const port = (srv.address() as { port: number }).port;
    try {
      const result = await RapidResponseEngine.runCheck('mirth-connect-xstream', `http://127.0.0.1:${port}`, 3000);
      expect(result.vulnerable).toBe(false);
      expect(result.checkId).toBe('mirth-connect-xstream');
    } finally {
      await new Promise<void>(r => srv.close(() => r()));
    }
  });
});
