/**
 * Secret / credential redaction (server response + audit + SSE boundary). Pins the load-bearing scrub,
 * including the 7th-pass fix: a `scheme://user:pass@host` login URL (the shape approval audit target/
 * action strings take for a gated credential tool) must not leak its password over the REST endpoint or
 * the SSE feed.
 */
import { describe, it, expect } from 'vitest';
import { redactString, redactSecrets } from '../redact.js';

describe('redactString — URL userinfo (basic-auth) scrub', () => {
  it('strips the password from a scheme://user:pass@host login URL (all schemes)', () => {
    expect(redactString('https://admin:hunter2@vpn.corp/login')).toBe('https://[redacted]@vpn.corp/login');
    expect(redactString('ssh://root:toor@10.0.0.5')).toBe('ssh://[redacted]@10.0.0.5');
    expect(redactString('ftp://svc:S3cr3t@files.internal/x')).toBe('ftp://[redacted]@files.internal/x');
  });

  it('covers a password that itself contains @ (redacts up to the LAST @ before the host)', () => {
    expect(redactString('https://svcacct:S3cr3t-P@ss!23@intranet.corp/login'))
      .toBe('https://[redacted]@intranet.corp/login');
  });

  it('leaves credential-free URLs and non-authority URIs untouched', () => {
    expect(redactString('https://example.com/path?x=1')).toBe('https://example.com/path?x=1');
    expect(redactString('visit https://host/a@b/c for docs')).toBe('visit https://host/a@b/c for docs'); // @ after a path segment, not userinfo
    expect(redactString('mailto:alice@example.com')).toBe('mailto:alice@example.com'); // no ://, not userinfo
  });

  it('still redacts the pre-existing secret shapes (regression)', () => {
    expect(redactString('key AKIAIOSFODNN7EXAMPLE here')).toContain('[redacted]');
    expect(redactString('token=abc123def456ghi')).toBe('token=[redacted]');
    expect(redactString('Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9')).toContain('Bearer [redacted]');
  });
});

describe('redactSecrets — approval-audit record shape', () => {
  it('scrubs a userinfo password in the audit target/action a gated credential tool would record', () => {
    // mirrors what Arsenal.execute() records for password_spray({ url: 'https://user:pass@host/login' })
    const record = {
      tool: 'password_spray',
      risk: 'credential',
      target: 'https://admin:hunter2@vpn.corp/login',
      action: 'password_spray (url=https://admin:hunter2@vpn.corp/login username=admin) → https://admin:hunter2@vpn.corp/login',
      outcome: 'allowed-preapproved',
    };
    const out = redactSecrets(record) as typeof record;
    expect(out.target).toBe('https://[redacted]@vpn.corp/login');
    expect(out.action).not.toContain('hunter2');
    expect(out.action).toContain('[redacted]');
  });

  it('redacts a key named like a secret and recurses through arrays/objects', () => {
    const out = redactSecrets({ password: 'p', nested: [{ token: 't', url: 'https://u:pw@h/x' }] }) as {
      password: string; nested: Array<{ token: string; url: string }>;
    };
    expect(out.password).toBe('[redacted]');
    expect(out.nested[0].token).toBe('[redacted]');
    expect(out.nested[0].url).toBe('https://[redacted]@h/x');
  });
});
