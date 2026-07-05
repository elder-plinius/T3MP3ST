/**
 * File-path guard for the fuzz/credential tools. A wordlist/user/pass-list path is LLM-controlled and
 * its lines are sent to the (in-scope, possibly adversarial) target, so pointing one at a key/credential
 * file would exfiltrate it. isSensitiveFilePath denies the high-value secrets while leaving ordinary
 * wordlists untouched. Pure (home injectable).
 */
import { describe, it, expect } from 'vitest';
import { isSensitiveFilePath } from '../arsenal/path-guard.js';

const HOME = '/home/op';

describe('isSensitiveFilePath', () => {
  it('denies secret dotdirs under home (~ and absolute)', () => {
    expect(isSensitiveFilePath('~/.ssh/id_rsa', HOME)).toBe(true);
    expect(isSensitiveFilePath('/home/op/.aws/credentials', HOME)).toBe(true);
    expect(isSensitiveFilePath('~/.gnupg/secring.gpg', HOME)).toBe(true);
    expect(isSensitiveFilePath('~/.config/gh/hosts.yml', HOME)).toBe(true);
  });

  it('denies system credential stores and key files anywhere', () => {
    expect(isSensitiveFilePath('/etc/shadow', HOME)).toBe(true);
    expect(isSensitiveFilePath('/opt/certs/server.pem', HOME)).toBe(true);
    expect(isSensitiveFilePath('/tmp/id_ed25519', HOME)).toBe(true);
  });

  it('denies a traversal that resolves into a secret dir', () => {
    expect(isSensitiveFilePath('/home/op/lists/../.ssh/id_rsa', HOME)).toBe(true);
  });

  it('allows ordinary wordlists', () => {
    expect(isSensitiveFilePath('/usr/share/wordlists/dirb/common.txt', HOME)).toBe(false);
    expect(isSensitiveFilePath('~/seclists/Discovery/Web-Content/common.txt', HOME)).toBe(false);
    expect(isSensitiveFilePath('common', HOME)).toBe(false);
    expect(isSensitiveFilePath(undefined, HOME)).toBe(false);
  });
});
