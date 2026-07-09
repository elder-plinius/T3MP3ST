import { describe, expect, it } from 'vitest';
import { redactString } from '../redact.js';

describe('redactString — full private-key block redaction', () => {
  it('redacts an entire PEM private-key block, not just the BEGIN header', () => {
    const pem = [
      'before',
      '-----BEGIN RSA PRIVATE KEY-----',
      'MIIEpAIBAAKCAQEA7thisLineMustDisappear',
      'anotherSecretKeyLineMustDisappear',
      '-----END RSA PRIVATE KEY-----',
      'after',
    ].join('\n');

    const out = redactString(pem);

    expect(out).toContain('before');
    expect(out).toContain('after');
    expect(out).toContain('[redacted]');
    expect(out).not.toContain('BEGIN RSA PRIVATE KEY');
    expect(out).not.toContain('END RSA PRIVATE KEY');
    expect(out).not.toContain('thisLineMustDisappear');
    expect(out).not.toContain('anotherSecretKeyLineMustDisappear');
  });

  it('redacts OpenSSH private-key blocks as a whole', () => {
    const pem = 'x\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAAsecret\n-----END OPENSSH PRIVATE KEY-----\ny';

    const out = redactString(pem);

    expect(out).toBe('x\n[redacted]\ny');
  });
});
