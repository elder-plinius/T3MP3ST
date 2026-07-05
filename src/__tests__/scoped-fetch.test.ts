/**
 * scopedFetch redirect revalidation — the egress scope gate validates only the INITIAL host, so a
 * hostile in-scope target that 30x-es the request must not carry the tool to an off-scope host.
 * resolveScopedRedirect is the pure hop-decision; these pins cover the same-host follow (zero
 * regression) and the cross-host block.
 */
import { describe, it, expect } from 'vitest';
import { resolveScopedRedirect, type ArsenalScope } from '../arsenal/index.js';

const scope: ArsenalScope = { allowedHosts: ['shop.example.com'], allowLoopback: false, allowPrivate: false };

describe('resolveScopedRedirect', () => {
  it('follows a same-host http->https redirect (zero regression)', () => {
    const r = resolveScopedRedirect(scope, 'http://shop.example.com/', 'https://shop.example.com/');
    expect(r).toEqual({ url: 'https://shop.example.com/' });
  });

  it('follows a same-host trailing-slash / relative redirect', () => {
    const r = resolveScopedRedirect(scope, 'https://shop.example.com/login', '/dashboard');
    expect(r).toEqual({ url: 'https://shop.example.com/dashboard' });
  });

  it('follows a redirect to an authorized subdomain', () => {
    const r = resolveScopedRedirect(scope, 'https://shop.example.com/', 'https://api.shop.example.com/v1');
    expect(r).toEqual({ url: 'https://api.shop.example.com/v1' });
  });

  it('BLOCKS a cross-host redirect to an off-scope public host', () => {
    const r = resolveScopedRedirect(scope, 'https://shop.example.com/', 'https://attacker-exfil.com/leak');
    expect(r).toEqual({ blocked: 'attacker-exfil.com' });
  });

  it('BLOCKS a redirect to cloud metadata even from an in-scope origin', () => {
    const r = resolveScopedRedirect(scope, 'https://shop.example.com/', 'http://169.254.169.254/latest/meta-data/');
    expect(r).toEqual({ blocked: '169.254.169.254' });
  });

  it('null scope = enforcement off, always follows (library/back-compat)', () => {
    const r = resolveScopedRedirect(null, 'https://shop.example.com/', 'https://anywhere.example.net/');
    expect(r).toEqual({ url: 'https://anywhere.example.net/' });
  });
});
