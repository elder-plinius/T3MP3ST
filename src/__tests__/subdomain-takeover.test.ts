/**
 * Coverage for the `subdomain_takeover_check` built-in tool.
 *  - The pure classifier (classifySubdomainTakeover) holds all decision logic and is tested directly.
 *  - One integration test drives the real tool handler with DNS + fetch mocked, proving the wiring
 *    (CNAME chain → dangling check → live-body fingerprint → verdict/finding).
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { classifySubdomainTakeover, renderTakeoverReport, TAKEOVER_FINGERPRINTS } from '../arsenal/takeover.js';

describe('classifySubdomainTakeover — decision logic', () => {
  it('CONFIRMS a takeover when the CNAME service and the live body fingerprint both match', () => {
    const v = classifySubdomainTakeover({ cname: 'my-bucket.s3.amazonaws.com', cnameResolves: true, body: '<Error><Code>NoSuchBucket</Code></Error>' });
    expect(v.confidence).toBe('confirmed');
    expect(v.vulnerable).toBe(true);
    expect(v.service).toBe('AWS/S3');
    expect(v.severity).toBe('high');
  });

  it('CONFIRMS on a dangling CNAME to an nxdomain-prone service (S3) even without a body', () => {
    const v = classifySubdomainTakeover({ cname: 'gone.s3.amazonaws.com', cnameResolves: false });
    expect(v.confidence).toBe('confirmed');
    expect(v.vulnerable).toBe(true);
    expect(v.service).toBe('AWS/S3');
  });

  it('is only POTENTIAL for a service whose dangling CNAME is not decisive and no fingerprint matched', () => {
    const v = classifySubdomainTakeover({ cname: 'app.herokudns.com', cnameResolves: false });
    expect(v.confidence).toBe('potential');
    expect(v.vulnerable).toBe(false); // not a confirmed finding
    expect(v.service).toBe('Heroku');
    expect(v.severity).toBe('medium');
  });

  it('does NOT confirm a known service that still resolves and serves a normal page', () => {
    const v = classifySubdomainTakeover({ cname: 'user.github.io', cnameResolves: true, body: '<html>welcome to my blog</html>' });
    expect(v.confidence).toBe('potential');
    expect(v.vulnerable).toBe(false);
  });

  it('flags a dangling CNAME to an UNRECOGNIZED service as potential', () => {
    const v = classifySubdomainTakeover({ cname: 'thing.unknown-vendor.example', cnameResolves: false });
    expect(v.confidence).toBe('potential');
    expect(v.service).toBeNull();
  });

  it('returns "none" when there is no CNAME (takeover is CNAME-based)', () => {
    const v = classifySubdomainTakeover({ cname: null, cnameResolves: false });
    expect(v.confidence).toBe('none');
    expect(v.vulnerable).toBe(false);
    expect(v.severity).toBe('info');
  });

  it('returns "none" for a CNAME that resolves and matches no fingerprint', () => {
    const v = classifySubdomainTakeover({ cname: 'cdn.some-cdn.example', cnameResolves: true, body: 'ok' });
    expect(v.confidence).toBe('none');
  });

  it('does not confirm on a fingerprint from a DIFFERENT service (no cross-matching)', () => {
    // GitHub Pages body signature but the CNAME points at S3 → not a GitHub confirmation.
    const v = classifySubdomainTakeover({ cname: 'x.s3.amazonaws.com', cnameResolves: true, body: "There isn't a GitHub Pages site here" });
    expect(v.confidence).toBe('potential'); // S3 matched by CNAME, but its own fingerprint didn't
    expect(v.service).toBe('AWS/S3');
  });

  it('every fingerprint entry is well-formed (service + cname regex)', () => {
    for (const f of TAKEOVER_FINGERPRINTS) {
      expect(f.service).toBeTruthy();
      expect(f.cname).toBeInstanceOf(RegExp);
      expect(typeof f.nxdomainVuln).toBe('boolean');
    }
  });
});

describe('renderTakeoverReport — output shape', () => {
  it('renders a confirmed verdict with the CNAME chain and severity', () => {
    const v = classifySubdomainTakeover({ cname: 'b.s3.amazonaws.com', cnameResolves: false });
    const out = renderTakeoverReport('blog.example.com', ['b.s3.amazonaws.com'], v);
    expect(out).toContain('VULNERABLE (confirmed)');
    expect(out).toContain('blog.example.com → b.s3.amazonaws.com');
    expect(out).toContain('Severity: high');
  });

  it('renders a non-candidate cleanly when there is no CNAME', () => {
    const v = classifySubdomainTakeover({ cname: null, cnameResolves: false });
    const out = renderTakeoverReport('www.example.com', [], v);
    expect(out).toContain('Not a takeover candidate');
    expect(out).toContain('(none — www.example.com has no CNAME)');
  });
});

// ── Integration: the real tool handler with DNS + fetch mocked ──────────────────────────────────
vi.mock('dns', () => {
  const ok = (result: unknown) => (...args: unknown[]) => (args[args.length - 1] as (e: unknown, r: unknown) => void)(null, result);
  const fail = (code: string) => (...args: unknown[]) => { const e = new Error(code) as Error & { code: string }; e.code = code; (args[args.length - 1] as (e: unknown) => void)(e); };
  return {
    // resolveCname is overridden per-test via the exported mock below
    resolveCname: vi.fn((_n: string, c: (e: unknown, r: unknown) => void) => c(null, ['dead-bucket.s3.amazonaws.com'])),
    resolve4: vi.fn(fail('ENOTFOUND')),         // CNAME target does not resolve → dangling
    resolve: vi.fn(fail('ENOTFOUND')),
    resolveMx: vi.fn(ok([])), resolveTxt: vi.fn(ok([])), resolveNs: vi.fn(ok([])),
    reverse: vi.fn(ok([])), lookup: vi.fn(ok('127.0.0.1')),
  };
});

describe('subdomain_takeover_check handler (integration, mocked DNS + fetch)', () => {
  const origFetch = global.fetch;
  afterEach(() => { global.fetch = origFetch; vi.clearAllMocks(); });
  beforeEach(() => {
    global.fetch = vi.fn(async () => ({ ok: false, status: 404, text: async () => '<Error><Code>NoSuchBucket</Code></Error>', headers: new Headers() } as unknown as Response)) as unknown as typeof fetch;
  });

  it('confirms an S3 takeover end-to-end and emits a high-severity finding', async () => {
    const { BUILTIN_TOOLS } = await import('../arsenal/index.js');
    const tool = BUILTIN_TOOLS.find((t) => t.name === 'subdomain_takeover_check');
    expect(tool).toBeTruthy();
    const res = await tool!.handler({ parameters: { target: 'blog.example.com' } } as never);
    expect(res.success).toBe(true);
    expect(res.output).toContain('VULNERABLE (confirmed)');
    expect(res.output).toContain('AWS/S3');
    expect(res.findings?.[0]?.severity).toBe('high');
    expect(res.findings?.[0]?.title).toContain('blog.example.com');
  });

  it('reports "not a candidate" when the host has no CNAME', async () => {
    const dns = await import('dns');
    (dns.resolveCname as unknown as ReturnType<typeof vi.fn>).mockImplementationOnce((_n: string, c: (e: unknown) => void) => { const e = new Error('ENODATA') as Error & { code: string }; e.code = 'ENODATA'; c(e); });
    const { BUILTIN_TOOLS } = await import('../arsenal/index.js');
    const tool = BUILTIN_TOOLS.find((t) => t.name === 'subdomain_takeover_check');
    const res = await tool!.handler({ parameters: { target: 'www.example.com' } } as never);
    expect(res.success).toBe(true);
    expect(res.output).toContain('Not a takeover candidate');
    expect(res.findings).toEqual([]);
  });
});
