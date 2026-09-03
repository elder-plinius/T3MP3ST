import { redactSecrets } from '../redact.js';

export interface PersistenceSnapshot {
  id: string;
  tenantId: string;
  schemaVersion: string;
  savedAt: string;
  data: Record<string, unknown>;
}

export interface SupabasePersistenceSpec {
  allowedHosts: readonly string[];
  timeoutMs?: number;
  maxPayloadBytes?: number;
}

export interface SupabasePersistenceOptions {
  environment?: Readonly<Record<string, string | undefined>>;
  fetch?: (input: string, init: RequestInit) => Promise<Response>;
}

export type PersistenceReceipt =
  | { stored: true; backend: 'supabase'; status: number }
  | { stored: false; backend: 'supabase'; error: 'not-configured' | 'invalid-snapshot' | 'payload-too-large' | 'timeout' | 'network' | 'http-error'; status?: number };

interface ResolvedConfig {
  endpoint: URL;
  serviceKey: string;
}

function resolveConfig(spec: SupabasePersistenceSpec, environment: Readonly<Record<string, string | undefined>>): ResolvedConfig | undefined {
  const endpointValue = environment.SUPABASE_URL;
  const serviceKey = environment.SUPABASE_SERVICE_ROLE_KEY;
  if (!endpointValue && !serviceKey) return undefined;
  if (!endpointValue || !serviceKey) throw new Error('Supabase persistence requires both server environment values');
  if (!spec.allowedHosts.length) throw new Error('Supabase persistence requires an exact hostname allowlist');
  let endpoint: URL;
  try { endpoint = new URL(endpointValue); } catch { throw new Error('Supabase persistence endpoint is invalid'); }
  if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password || endpoint.hash || endpoint.search) throw new Error('Supabase persistence endpoint must use credential-free HTTPS URL syntax');
  if (!spec.allowedHosts.some((host) => endpoint.hostname.toLowerCase() === host.toLowerCase())) throw new Error('Supabase persistence endpoint is not allowlisted');
  return { endpoint, serviceKey };
}

function validSnapshot(snapshot: PersistenceSnapshot): boolean {
  const savedAt = new Date(snapshot.savedAt);
  return /^[a-zA-Z0-9_-]{1,128}$/.test(snapshot.id)
    && /^[a-zA-Z0-9_-]{1,128}$/.test(snapshot.tenantId)
    && /^[a-zA-Z0-9_./-]{1,64}$/.test(snapshot.schemaVersion)
    && !Number.isNaN(savedAt.getTime())
    && typeof snapshot.data === 'object' && snapshot.data !== null && !Array.isArray(snapshot.data);
}

export class SupabasePersistenceAdapter {
  private readonly config?: ResolvedConfig;
  private readonly fetcher: (input: string, init: RequestInit) => Promise<Response>;
  private readonly timeoutMs: number;
  private readonly maxPayloadBytes: number;

  constructor(spec: SupabasePersistenceSpec, options: SupabasePersistenceOptions = {}) {
    this.config = resolveConfig(spec, options.environment ?? process.env);
    this.fetcher = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
    this.timeoutMs = Math.min(60_000, Math.max(100, spec.timeoutMs ?? 10_000));
    this.maxPayloadBytes = Math.min(2 * 1024 * 1024, Math.max(1_024, spec.maxPayloadBytes ?? 512 * 1024));
  }

  status(): { configured: boolean; host?: string } {
    return this.config ? { configured: true, host: this.config.endpoint.hostname } : { configured: false };
  }

  async save(snapshot: PersistenceSnapshot): Promise<PersistenceReceipt> {
    if (!this.config) return { stored: false, backend: 'supabase', error: 'not-configured' };
    if (!validSnapshot(snapshot)) return { stored: false, backend: 'supabase', error: 'invalid-snapshot' };
    const body = JSON.stringify({ tenant_id: snapshot.tenantId, snapshot_id: snapshot.id, schema_version: snapshot.schemaVersion, saved_at: snapshot.savedAt, payload: redactSecrets(snapshot.data) });
    if (Buffer.byteLength(body) > this.maxPayloadBytes) return { stored: false, backend: 'supabase', error: 'payload-too-large' };
    return this.request('POST', 't3mp3st_snapshots?on_conflict=tenant_id,snapshot_id', body, { Prefer: 'resolution=merge-duplicates,return=minimal' });
  }

  async delete(tenantId: string, snapshotId: string): Promise<PersistenceReceipt> {
    if (!this.config) return { stored: false, backend: 'supabase', error: 'not-configured' };
    if (!/^[a-zA-Z0-9_-]{1,128}$/.test(tenantId) || !/^[a-zA-Z0-9_-]{1,128}$/.test(snapshotId)) return { stored: false, backend: 'supabase', error: 'invalid-snapshot' };
    const query = `t3mp3st_snapshots?tenant_id=eq.${encodeURIComponent(tenantId)}&snapshot_id=eq.${encodeURIComponent(snapshotId)}`;
    return this.request('DELETE', query, undefined, { Prefer: 'return=minimal' });
  }

  private async request(method: 'POST' | 'DELETE', relative: string, body?: string, extraHeaders: Record<string, string> = {}): Promise<PersistenceReceipt> {
    if (!this.config) return { stored: false, backend: 'supabase', error: 'not-configured' };
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const url = new URL(`/rest/v1/${relative}`, this.config.endpoint);
      const response = await this.fetcher(url.toString(), { method, redirect: 'manual', signal: controller.signal, headers: { apikey: this.config.serviceKey, authorization: `Bearer ${this.config.serviceKey}`, 'content-type': 'application/json', ...extraHeaders }, ...(body ? { body } : {}) });
      if (response.ok) return { stored: true, backend: 'supabase', status: response.status };
      return { stored: false, backend: 'supabase', error: 'http-error', status: response.status };
    } catch (error) {
      return { stored: false, backend: 'supabase', error: controller.signal.aborted || (error instanceof Error && error.name === 'AbortError') ? 'timeout' : 'network' };
    } finally { clearTimeout(timer); }
  }
}

export interface LocalSnapshotStore { save(snapshot: PersistenceSnapshot): Promise<void> }
export class LocalFirstPersistence {
  constructor(private readonly local: LocalSnapshotStore, private readonly remote?: SupabasePersistenceAdapter) {}
  async save(snapshot: PersistenceSnapshot): Promise<{ localStored: true; remote: PersistenceReceipt }> {
    await this.local.save(structuredClone(snapshot));
    const remote = this.remote ? await this.remote.save(structuredClone(snapshot)) : { stored: false as const, backend: 'supabase' as const, error: 'not-configured' as const };
    return { localStored: true, remote };
  }
}
