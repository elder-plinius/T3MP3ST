/**
 * whois_lookup registry egress. The scope gate validates the `domain` param but the handler opens a
 * socket to a TLD-derived registry server the gate never sees. Registry egress is protocol
 * infrastructure (not scope-checked), but a model controls the domain — so an unknown/malformed TLD
 * must resolve to null (clean error) instead of a blind connect to an arbitrary whois.nic.<x> host.
 */
import { describe, it, expect } from 'vitest';
import { resolveWhoisServer } from '../arsenal/index.js';

const map: Record<string, string> = { com: 'whois.verisign-grs.com', io: 'whois.nic.io' };

describe('resolveWhoisServer', () => {
  it('uses the known-registry map first', () => {
    expect(resolveWhoisServer('com', map)).toBe('whois.verisign-grs.com');
  });

  it('falls back to the IANA-convention whois.nic.<tld> for a well-formed gTLD/ccTLD', () => {
    expect(resolveWhoisServer('xyz', map)).toBe('whois.nic.xyz');
    expect(resolveWhoisServer('shop', map)).toBe('whois.nic.shop');
  });

  it('resolves a punycode IDN TLD', () => {
    expect(resolveWhoisServer('xn--p1ai', map)).toBe('whois.nic.xn--p1ai');
  });

  it('returns null for an unsupported / malformed TLD instead of a blind connect', () => {
    expect(resolveWhoisServer('', map)).toBeNull();
    expect(resolveWhoisServer('123', map)).toBeNull();
    expect(resolveWhoisServer('a b', map)).toBeNull();
    expect(resolveWhoisServer('evil-injection.attacker', map)).toBeNull();
  });
});
