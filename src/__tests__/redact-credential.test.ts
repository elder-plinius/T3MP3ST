/**
 * redactCredential — the API/output redactor that keeps raw harvested secrets from ever
 * leaving the process (external-audit P0: /api/mission/findings previously returned raw
 * Credential.secret). Pins the invariant so a refactor can't silently re-expose secrets.
 */

import { describe, it, expect } from 'vitest';
import { redactCredential } from '../evidence/index.js';
import type { Credential } from '../types/index.js';

describe('redactCredential — raw secrets never leave the process', () => {
  const cred: Credential = {
    id: 'cred-1',
    type: 'password',
    username: 'admin',
    secret: 'sup3rs3cr3t!',
    domain: 'example.com',
    targetId: 't-1',
    source: 'harvest',
    discoveredAt: 1,
    validatedAt: 2,
    privilegeLevel: 'admin',
  };

  it('strips the raw secret entirely — no key, no value anywhere in the output', () => {
    const r = redactCredential(cred);
    expect('secret' in r).toBe(false);
    expect(JSON.stringify(r)).not.toContain('sup3rs3cr3t');
  });

  it('keeps the non-sensitive metadata + a secretCaptured flag', () => {
    const r = redactCredential(cred);
    expect(r.id).toBe('cred-1');
    expect(r.type).toBe('password');
    expect(r.username).toBe('admin');
    expect(r.domain).toBe('example.com');
    expect(r.privilegeLevel).toBe('admin');
    expect(r.secretCaptured).toBe(true);
  });

  it('secretCaptured is false when no secret was captured', () => {
    expect(redactCredential({ ...cred, secret: '' }).secretCaptured).toBe(false);
  });
});
