import { createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { redactString } from '../redact.js';

export type HoneytokenState = 'created' | 'active' | 'revoked';
export type HoneytokenKind = 'opaque' | 'api-key' | 'credential' | 'beacon';
export type TriggerClassification = 'pending' | 'confirmed' | 'dismissed';
export interface HoneytokenMetadata { id: string; label: string; kind: HoneytokenKind; environment: string; state: HoneytokenState; generation: number; createdAt: number; activatedAt?: number; revokedAt?: number }
export interface HoneytokenMaterial { metadata: HoneytokenMetadata; token: string }
export interface HoneytokenAudit { id: string; action: 'created' | 'activated' | 'rotated' | 'revoked' | 'cleaned' | 'triggered' | 'classified' | 'replay-rejected'; tokenId: string; at: number; actor: string; detail?: string }
export interface HoneytokenTrigger { id: string; tokenId: string; at: number; nonceHash: string; sourceHash: string; classification: TriggerClassification; provenance: 'authenticated-honeytoken-use' }
export interface HoneytokenAlertSink { deliver(event: HoneytokenTrigger): Promise<void> }

interface StoredToken { metadata: HoneytokenMetadata; token: Buffer; digest: string; nonces: Set<string> }
const cloneMetadata = (item: HoneytokenMetadata): HoneytokenMetadata => ({ ...item });

export class HoneytokenManager {
  private readonly tokens = new Map<string, StoredToken>();
  private readonly byDigest = new Map<string, string>();
  private readonly triggers = new Map<string, HoneytokenTrigger>();
  private readonly audits: HoneytokenAudit[] = [];
  private readonly auditKey: Buffer;

  constructor(
    auditKey: Uint8Array,
    private readonly authorizedEnvironments: ReadonlySet<string>,
    private readonly alertSink?: HoneytokenAlertSink,
    private readonly now: () => number = Date.now,
  ) {
    if (auditKey.byteLength < 32) throw new Error('Honeytoken audit key must contain at least 32 bytes');
    this.auditKey = Buffer.from(auditKey);
  }

  create(input: { label: string; kind: HoneytokenKind; environment: string; actor: string }): HoneytokenMaterial {
    if (!input.label.trim() || !input.kind.trim() || !input.environment.trim() || !input.actor.trim()) throw new Error('label, kind, environment, and actor are required');
    if (!/^[a-zA-Z0-9 ._-]{1,100}$/.test(input.label) || !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(input.environment)) throw new Error('label or environment contains unsupported metadata characters');
    const id = randomUUID();
    const token = randomBytes(32);
    const metadata: HoneytokenMetadata = { id, label: redactString(input.label), kind: input.kind, environment: input.environment, state: 'created', generation: 1, createdAt: this.now() };
    const stored = { metadata, token, digest: this.digest(token), nonces: new Set<string>() };
    this.tokens.set(id, stored);
    this.byDigest.set(stored.digest, id);
    this.audit('created', id, input.actor);
    return { metadata: cloneMetadata(metadata), token: token.toString('base64url') };
  }

  activate(id: string, actor: string): HoneytokenMetadata {
    this.requireActor(actor);
    const item = this.require(id);
    if (!this.authorizedEnvironments.has(item.metadata.environment)) throw new Error('Honeytoken deployment is not authorized for this environment');
    if (item.metadata.state !== 'created') throw new Error('Only a newly created honeytoken may be activated');
    item.metadata.state = 'active';
    item.metadata.activatedAt = this.now();
    this.audit('activated', id, actor);
    return cloneMetadata(item.metadata);
  }

  rotate(id: string, actor: string): HoneytokenMaterial {
    this.requireActor(actor);
    const old = this.require(id);
    this.revoke(id, actor);
    const material = this.create({ label: old.metadata.label, kind: old.metadata.kind, environment: old.metadata.environment, actor });
    const replacement = this.require(material.metadata.id);
    replacement.metadata.generation = old.metadata.generation + 1;
    material.metadata.generation = replacement.metadata.generation;
    this.audit('rotated', replacement.metadata.id, actor, `replaces:${id}`);
    return material;
  }

  revoke(id: string, actor: string): HoneytokenMetadata {
    this.requireActor(actor);
    const item = this.require(id);
    if (item.metadata.state !== 'revoked') {
      item.metadata.state = 'revoked';
      item.metadata.revokedAt = this.now();
      this.byDigest.delete(item.digest);
      item.token.fill(0);
      this.audit('revoked', id, actor);
    }
    return cloneMetadata(item.metadata);
  }

  cleanup(id: string, actor: string): boolean {
    this.requireActor(actor);
    const item = this.tokens.get(id);
    if (!item) return false;
    this.byDigest.delete(item.digest);
    item.token.fill(0);
    this.tokens.delete(id);
    this.audit('cleaned', id, actor);
    return true;
  }

  signTrigger(token: string, nonce: string, occurredAt: number): string {
    return createHmac('sha256', Buffer.from(token, 'base64url')).update(`${nonce}:${occurredAt}`).digest('base64url');
  }

  async trigger(input: { token: string; nonce: string; occurredAt: number; signature: string; source: string }): Promise<HoneytokenTrigger | undefined> {
    if (!input.nonce || Math.abs(this.now() - input.occurredAt) > 5 * 60_000) return undefined;
    const raw = Buffer.from(input.token, 'base64url');
    const id = this.byDigest.get(this.digest(raw));
    const item = id ? this.tokens.get(id) : undefined;
    if (!item || item.metadata.state !== 'active') return undefined;
    const expected = createHmac('sha256', item.token).update(`${input.nonce}:${input.occurredAt}`).digest();
    let supplied: Buffer;
    try { supplied = Buffer.from(input.signature, 'base64url'); } catch { return undefined; }
    if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) return undefined;
    const nonceHash = this.keyed(input.nonce);
    if (item.nonces.has(nonceHash)) {
      this.audit('replay-rejected', item.metadata.id, 'system');
      return undefined;
    }
    if (item.nonces.size >= 10_000) return undefined;
    item.nonces.add(nonceHash);
    const event: HoneytokenTrigger = { id: randomUUID(), tokenId: item.metadata.id, at: this.now(), nonceHash, sourceHash: this.keyed(input.source), classification: 'pending', provenance: 'authenticated-honeytoken-use' };
    this.triggers.set(event.id, event);
    this.audit('triggered', item.metadata.id, 'system', `event:${event.id}`);
    try { await this.alertSink?.deliver({ ...event }); } catch { /* delivery cannot corrupt lifecycle state */ }
    return { ...event };
  }

  classify(eventId: string, classification: Exclude<TriggerClassification, 'pending'>, actor: string): HoneytokenTrigger {
    this.requireActor(actor);
    const event = this.triggers.get(eventId);
    if (!event) throw new Error('Trigger event not found');
    event.classification = classification;
    this.audit('classified', event.tokenId, actor, `event:${event.id}:${classification}`);
    return { ...event };
  }

  list(): HoneytokenMetadata[] { return [...this.tokens.values()].map(({ metadata }) => cloneMetadata(metadata)); }
  getAudit(): HoneytokenAudit[] { return this.audits.map((item) => ({ ...item })); }

  private require(id: string): StoredToken {
    const item = this.tokens.get(id);
    if (!item) throw new Error('Honeytoken not found');
    return item;
  }
  private requireActor(actor: string): void { if (!actor.trim()) throw new Error('actor is required'); }
  private digest(value: Uint8Array): string { return createHmac('sha256', this.auditKey).update(value).digest('base64url'); }
  private keyed(value: string): string { return createHmac('sha256', this.auditKey).update(value).digest('base64url'); }
  private audit(action: HoneytokenAudit['action'], tokenId: string, actor: string, detail?: string): void {
    this.audits.push({ id: randomUUID(), action, tokenId, at: this.now(), actor: redactString(actor), ...(detail ? { detail } : {}) });
  }
}
