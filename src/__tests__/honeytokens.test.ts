import { randomBytes } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import { HoneytokenManager } from '../deception/honeytokens.js';

const NOW = 1_800_000_000_000;
const manager = (environments = new Set(['lab']), deliver?: (event: never) => Promise<void>) =>
  new HoneytokenManager(randomBytes(32), environments, deliver ? { deliver } : undefined, () => NOW);
const create = (subject: HoneytokenManager, environment = 'lab') => subject.create({ label: 'database decoy', kind: 'credential', environment, actor: 'operator' });

describe('scoped honeytoken lifecycle', () => {
  it('returns secret material once while list and audit surfaces remain secret-free', () => {
    const subject = manager();
    const material = create(subject);
    expect(material.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const outward = JSON.stringify({ list: subject.list(), audit: subject.getAudit() });
    expect(outward).not.toContain(material.token);
    expect(outward).not.toContain('auditKey');
    expect(subject.list()[0]).not.toHaveProperty('token');
  });

  it('fails closed when activation is not authorized for the environment', () => {
    const subject = manager(new Set(['production']));
    const material = create(subject, 'lab');
    expect(() => subject.activate(material.metadata.id, 'operator')).toThrow('not authorized');
    expect(subject.list()[0].state).toBe('created');
  });

  it('supports activate, rotate, revoke, and cleanup with auditable transitions', async () => {
    const subject = manager();
    const first = create(subject);
    expect(subject.activate(first.metadata.id, 'operator')).toMatchObject({ state: 'active', generation: 1 });
    const replacement = subject.rotate(first.metadata.id, 'operator');
    expect(replacement.token).not.toBe(first.token);
    expect(replacement.metadata).toMatchObject({ state: 'created', generation: 2 });
    expect(subject.list().find(({ id }) => id === first.metadata.id)?.state).toBe('revoked');
    const signature = subject.signTrigger(first.token, 'old-token', NOW);
    await expect(subject.trigger({ token: first.token, nonce: 'old-token', occurredAt: NOW, signature, source: '192.0.2.1' })).resolves.toBeUndefined();
    subject.activate(replacement.metadata.id, 'operator');
    expect(subject.cleanup(replacement.metadata.id, 'operator')).toBe(true);
    expect(subject.cleanup(replacement.metadata.id, 'operator')).toBe(false);
    expect(subject.getAudit().map(({ action }) => action)).toEqual(['created', 'activated', 'revoked', 'created', 'rotated', 'activated', 'cleaned']);
  });

  it('rejects arbitrary secret-shaped metadata instead of exporting it', () => {
    const subject = manager();
    expect(() => subject.create({ label: 'token=very-secret-value', kind: 'opaque', environment: 'lab', actor: 'operator' })).toThrow('unsupported metadata');
    expect(() => subject.create({ label: 'safe', kind: 'opaque', environment: '../prod', actor: 'operator' })).toThrow('unsupported metadata');
  });

  it('copies the caller-owned key at construction', async () => {
    const key = randomBytes(32);
    const subject = new HoneytokenManager(key, new Set(['lab']), undefined, () => NOW);
    const material = create(subject);
    subject.activate(material.metadata.id, 'operator');
    key.fill(0);
    const nonce = 'independent-key-copy';
    const event = await subject.trigger({ token: material.token, nonce, occurredAt: NOW, signature: subject.signTrigger(material.token, nonce, NOW), source: '198.51.100.2' });
    expect(event).toBeDefined();
  });
});

describe('trigger provenance and replay handling', () => {
  it('authenticates a fresh trigger, hashes sensitive metadata, and rejects replay', async () => {
    const subject = manager();
    const material = create(subject);
    subject.activate(material.metadata.id, 'operator');
    const nonce = 'unique-request-nonce';
    const source = '203.0.113.99';
    const signature = subject.signTrigger(material.token, nonce, NOW);
    const event = await subject.trigger({ token: material.token, nonce, occurredAt: NOW, signature, source });
    expect(event).toMatchObject({ tokenId: material.metadata.id, classification: 'pending', provenance: 'authenticated-honeytoken-use' });
    const serialized = JSON.stringify({ event, audit: subject.getAudit() });
    expect(serialized).not.toContain(material.token);
    expect(serialized).not.toContain(nonce);
    expect(serialized).not.toContain(source);
    await expect(subject.trigger({ token: material.token, nonce, occurredAt: NOW, signature, source })).resolves.toBeUndefined();
    expect(subject.getAudit().at(-1)?.action).toBe('replay-rejected');
  });

  it('rejects stale, forged, inactive, and empty-nonce triggers', async () => {
    const subject = manager();
    const material = create(subject);
    const call = (nonce: string, occurredAt: number, signature: string) => subject.trigger({ token: material.token, nonce, occurredAt, signature, source: 'source' });
    const valid = subject.signTrigger(material.token, 'nonce', NOW);
    await expect(call('nonce', NOW, valid)).resolves.toBeUndefined();
    subject.activate(material.metadata.id, 'operator');
    await expect(call('', NOW, valid)).resolves.toBeUndefined();
    await expect(call('nonce', NOW - 300_001, valid)).resolves.toBeUndefined();
    await expect(call('nonce', NOW, 'forged')).resolves.toBeUndefined();
  });

  it('supports explicit false-positive classification with audit provenance', async () => {
    const subject = manager();
    const material = create(subject);
    subject.activate(material.metadata.id, 'operator');
    const nonce = 'classification';
    const event = await subject.trigger({ token: material.token, nonce, occurredAt: NOW, signature: subject.signTrigger(material.token, nonce, NOW), source: 'source' });
    expect(event).toBeDefined();
    const classified = subject.classify(event?.id ?? '', 'dismissed', 'reviewer');
    expect(classified.classification).toBe('dismissed');
    expect(subject.getAudit().at(-1)).toMatchObject({ action: 'classified', actor: 'reviewer' });
  });

  it('isolates alert delivery failure from trigger state', async () => {
    const deliver = vi.fn().mockRejectedValue(new Error('dispatcher unavailable'));
    const subject = manager(new Set(['lab']), deliver);
    const material = create(subject);
    subject.activate(material.metadata.id, 'operator');
    const nonce = 'delivery-failure';
    const event = await subject.trigger({ token: material.token, nonce, occurredAt: NOW, signature: subject.signTrigger(material.token, nonce, NOW), source: 'source' });
    expect(deliver).toHaveBeenCalledOnce();
    expect(event).toMatchObject({ classification: 'pending' });
    expect(subject.getAudit().at(-1)?.action).toBe('triggered');
  });
});
