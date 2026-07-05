/**
 * Egress scope gate — Phase-0 pack-hunt safety primitive.
 * arsenal.execute() must refuse a networked tool call whose target is outside the authorized
 * scope BEFORE the handler runs, so an LLM-supplied target can never reach an off-target host.
 * Pins: scopeViolation host math, and that execute() denies out-of-scope without invoking the handler.
 */
import { describe, it, expect } from 'vitest';
import { Arsenal, scopeViolation, hostFromTargetValue, type ArsenalScope } from '../arsenal/index.js';
import type { CustomTool, ToolContext } from '../types/index.js';

const scope: ArsenalScope = { allowedHosts: ['target.example.com'], allowLoopback: true, allowPrivate: true };
const ctx = (parameters: Record<string, unknown>, target?: string): ToolContext =>
  ({ parameters, ...(target ? { target: { id: 't', name: 't', type: 'web_application', address: target } as never } : {}) });

describe('egress scope gate', () => {
  it('extracts a bare host from urls / user@host:port / brackets', () => {
    expect(hostFromTargetValue('https://EVIL.com/admin?x=1')).toBe('evil.com');
    expect(hostFromTargetValue('root@10.0.0.5:22')).toBe('10.0.0.5');
    expect(hostFromTargetValue('scanme.example.com:443')).toBe('scanme.example.com');
    expect(hostFromTargetValue('not a host, just text')).toBe('not a host, just text'); // still lowered; scope decides
    expect(hostFromTargetValue(42)).toBeNull();
  });

  it('allows authorized host + its subdomains, loopback, and private ranges', () => {
    expect(scopeViolation(scope, ctx({ url: 'https://target.example.com/x' }))).toBeNull();
    expect(scopeViolation(scope, ctx({ url: 'https://api.target.example.com/x' }))).toBeNull(); // subdomain
    expect(scopeViolation(scope, ctx({ host: '127.0.0.1' }))).toBeNull();
    expect(scopeViolation(scope, ctx({ target: '10.1.2.3' }))).toBeNull();
    expect(scopeViolation(scope, ctx({ domain: 'localhost' }))).toBeNull();
  });

  it('blocks an out-of-scope host and reports it', () => {
    expect(scopeViolation(scope, ctx({ url: 'https://evil.com/x' }))).toBe('evil.com');
    expect(scopeViolation(scope, ctx({ target: '8.8.8.8' }))).toBe('8.8.8.8');
    // checks context.target.address too
    expect(scopeViolation(scope, ctx({}, 'http://attacker.net'))).toBe('attacker.net');
  });

  it('FAILS CLOSED on a network-shaped but unparseable target (//host, file://, scheme) — no fail-open', () => {
    // these host-normalize to '' — must be treated as OUT of scope, not "no host = allowed"
    expect(scopeViolation(scope, ctx({ url: '//evil.com' }))).toBe('//evil.com');
    expect(scopeViolation(scope, ctx({ target: 'file:///etc/passwd' }))).toBe('file:///etc/passwd');
    expect(scopeViolation(scope, ctx({ rhosts: '//9.9.9.9' }))).toBe('//9.9.9.9'); // rhosts now covered too
  });

  it('ZERO-REGRESSION: a plain absolute local path is NOT blocked (local-file tools run under a scope)', () => {
    // a path has no host and is not a network target — semgrep/trivy/slither scanning /code must pass
    expect(scopeViolation(scope, ctx({ target: '/code/src/app.py' }))).toBeNull();
  });

  it('validates a CIDR TARGET range, not just its slash-stripped base (mask-strip escape)', () => {
    // base 10.0.0.0 is private, but /0 would sweep the whole internet — block on the RANGE
    expect(scopeViolation(scope, ctx({ target: '10.0.0.0/0' }))).toBe('10.0.0.0/0');
    expect(scopeViolation(scope, ctx({ target: '192.168.0.0/8' }))).toBe('192.168.0.0/8'); // /8 base 192.168 spills out
    // an in-block private CIDR is still allowed (zero regression for legit internal scans)
    expect(scopeViolation(scope, ctx({ rhosts: '10.0.0.0/8' }))).toBeNull(); // exactly 10/8
    expect(scopeViolation(scope, ctx({ target: '10.1.2.0/24' }))).toBeNull(); // within 10/8
    // a URL path segment ending in /digits is NOT a CIDR mask
    expect(scopeViolation(scope, ctx({ url: 'https://target.example.com/api/12' }))).toBeNull();
  });

  it('a CIDR of an exactly-allowed host beyond /32 is out of scope', () => {
    const s2: ArsenalScope = { allowedHosts: ['203.0.113.10'], allowLoopback: false, allowPrivate: false };
    expect(scopeViolation(s2, ctx({ target: '203.0.113.10/8' }))).toBe('203.0.113.10/8');
    expect(scopeViolation(s2, ctx({ target: '203.0.113.10' }))).toBeNull(); // the host itself is fine
  });

  it('blocks cloud link-local / metadata (169.254 + IPv6 IMDS) even under allowPrivate, unless explicitly authorized', () => {
    // implicit private allowance must NEVER reach the IMDS / 169.254.0.0/16 link-local range
    expect(scopeViolation(scope, ctx({ url: 'http://169.254.169.254/latest/meta-data/iam/' }))).toBe('169.254.169.254');
    expect(scopeViolation(scope, ctx({ target: '169.254.0.1' }))).toBe('169.254.0.1');
    expect(scopeViolation(scope, ctx({ url: 'http://[fd00:ec2::254]/latest/meta-data/' }))).toBe('fd00:ec2::254');
    // a normal RFC1918 private host is still allowed under allowPrivate (zero regression)
    expect(scopeViolation(scope, ctx({ target: '10.1.2.3' }))).toBeNull();
    // an operator can still explicitly authorize a metadata host if they really mean to
    const explicit: ArsenalScope = { allowedHosts: ['169.254.169.254'], allowLoopback: false, allowPrivate: false };
    expect(scopeViolation(explicit, ctx({ url: 'http://169.254.169.254/x' }))).toBeNull();
  });

  it('no scope set = enforcement off (backward-compat)', () => {
    expect(scopeViolation(null, ctx({ url: 'https://evil.com' }))).toBeNull();
  });

  it('a tool with no target-like param is never gated', () => {
    expect(scopeViolation(scope, ctx({ hash: 'deadbeef', text: 'hello' }))).toBeNull();
  });

  it('execute() refuses an out-of-scope call WITHOUT running the handler', async () => {
    const ars = new Arsenal();
    let ran = false;
    const probe: CustomTool = {
      name: 'probe', description: 'x', category: 'web', parameters: [],
      handler: async () => { ran = true; return { success: true, output: 'hit' }; },
    };
    ars.register(probe);
    ars.setScope(scope);
    const denied = await ars.execute('probe', ctx({ url: 'https://evil.com' }));
    expect(ran).toBe(false);
    expect(denied.success).toBe(false);
    expect(denied.error).toMatch(/SCOPE DENIED/);
    // in-scope call runs the handler
    const ok = await ars.execute('probe', ctx({ url: 'https://target.example.com' }));
    expect(ran).toBe(true);
    expect(ok.success).toBe(true);
  });
});
