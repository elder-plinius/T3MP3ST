import { readFileSync } from 'node:fs';
import { describe, expect, it, vi } from 'vitest';
import { LocalFirstPersistence, SupabasePersistenceAdapter, type PersistenceSnapshot } from '../persistence/supabase.js';
import { migratePersistence, SUPABASE_MIGRATIONS, type MigrationStore } from '../persistence/migrations.js';

const snapshot = (overrides: Partial<PersistenceSnapshot> = {}): PersistenceSnapshot => ({ id: 'state-1', tenantId: 'tenant-1', schemaVersion: 't3mp3st_state/v1', savedAt: '2026-09-03T00:00:00.000Z', data: { findings: 2 }, ...overrides });
const spec = { allowedHosts: ['project.supabase.co'], timeoutMs: 100, maxPayloadBytes: 1024 };
const environment = { SUPABASE_URL: 'https://project.supabase.co', SUPABASE_SERVICE_ROLE_KEY: 'service-secret' };

describe('Supabase persistence trust boundary', () => {
  it('is optional and exposes no endpoint or credential when absent', async () => {
    const adapter = new SupabasePersistenceAdapter(spec, { environment: {} });
    expect(adapter.status()).toEqual({ configured: false });
    expect(await adapter.save(snapshot())).toMatchObject({ stored: false, error: 'not-configured' });
  });

  it.each(['http://project.supabase.co', 'https://user:pass@project.supabase.co', 'https://attacker.example'])("rejects unsafe endpoint %s", (url) => {
    expect(() => new SupabasePersistenceAdapter(spec, { environment: { ...environment, SUPABASE_URL: url } })).toThrow();
  });

  it('sends a tenant-scoped redacted upsert and does not expose response bodies', async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response('private provider details', { status: 503 }));
    const adapter = new SupabasePersistenceAdapter(spec, { environment, fetch: fetcher });
    const result = await adapter.save(snapshot({ data: { token: 'do-not-send', safe: 'yes' } }));
    expect(result).toEqual({ stored: false, backend: 'supabase', error: 'http-error', status: 503 });
    const [url, init] = fetcher.mock.calls[0];
    expect(url).toContain('/rest/v1/t3mp3st_snapshots?on_conflict=tenant_id,snapshot_id');
    expect(init).toMatchObject({ method: 'POST', redirect: 'manual' });
    expect(init.headers.apikey).toBe('service-secret');
    expect(init.body).not.toContain('do-not-send');
    expect(init.body).toContain('[redacted]');
    expect(JSON.stringify(result)).not.toContain('private provider details');
    expect(JSON.stringify(adapter.status())).not.toContain('service-secret');
  });

  it('enforces payload and identifier limits before network use', async () => {
    const fetcher = vi.fn();
    const adapter = new SupabasePersistenceAdapter(spec, { environment, fetch: fetcher });
    await expect(adapter.save(snapshot({ data: { text: 'x'.repeat(2_000) } }))).resolves.toMatchObject({ error: 'payload-too-large' });
    await expect(adapter.save(snapshot({ tenantId: '../escape' }))).resolves.toMatchObject({ error: 'invalid-snapshot' });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('supports tenant-scoped deletion without placing secrets in the URL', async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    const adapter = new SupabasePersistenceAdapter(spec, { environment, fetch: fetcher });
    await expect(adapter.delete('tenant-1', 'state-1')).resolves.toEqual({ stored: true, backend: 'supabase', status: 204 });
    expect(fetcher.mock.calls[0][0]).toContain('tenant_id=eq.tenant-1&snapshot_id=eq.state-1');
    expect(fetcher.mock.calls[0][0]).not.toContain('service-secret');
  });
});

describe('local-first failure isolation', () => {
  it('commits a defensive local copy before reporting a remote failure', async () => {
    let localCopy: PersistenceSnapshot | undefined;
    const local = { save: vi.fn(async (value: PersistenceSnapshot) => { localCopy = value; }) };
    const remoteFetch = vi.fn().mockRejectedValue(new Error('service-secret provider detail'));
    const coordinator = new LocalFirstPersistence(local, new SupabasePersistenceAdapter(spec, { environment, fetch: remoteFetch }));
    const input = snapshot();
    const result = await coordinator.save(input);
    input.data.findings = 99;
    expect(result).toEqual({ localStored: true, remote: { stored: false, backend: 'supabase', error: 'network' } });
    expect(localCopy?.data).toEqual({ findings: 2 });
  });
});

describe('versioned migration contract', () => {
  const store = (applied: number[] = []) => {
    const transactions: Array<{ statements: readonly string[]; version: number }> = [];
    const value: MigrationStore = { appliedVersions: async () => applied, transaction: async (statements, version) => { transactions.push({ statements, version }); } };
    return { value, transactions };
  };

  it('applies a clean database once and is idempotent for an existing database', async () => {
    const clean = store();
    await expect(migratePersistence(clean.value)).resolves.toEqual([1]);
    expect(clean.transactions[0].statements[0]).toContain('enable row level security');
    const existing = store([1]);
    await expect(migratePersistence(existing.value)).resolves.toEqual([]);
    expect(existing.transactions).toEqual([]);
  });

  it('rejects unknown migration history and publishes matching reversible SQL artifacts', async () => {
    await expect(migratePersistence(store([99]).value)).rejects.toThrow('unknown');
    const up = readFileSync('migrations/supabase/0001_create_t3mp3st_snapshots.up.sql', 'utf8');
    const down = readFileSync('migrations/supabase/0001_create_t3mp3st_snapshots.down.sql', 'utf8');
    expect(up.replace(/\s+/g, ' ').trim()).toBe(SUPABASE_MIGRATIONS[0].up.replace(/\s+/g, ' ').trim());
    expect(down.trim()).toBe(SUPABASE_MIGRATIONS[0].down);
  });

  it('does not introduce browser config, CORS overrides, or cwd dotenv loading', () => {
    const source = readFileSync('src/persistence/supabase.ts', 'utf8');
    expect(source).not.toMatch(/anon[_-]?key|cors|process\.cwd|dotenv|api\/config\/env/i);
    expect(source).toContain('SUPABASE_SERVICE_ROLE_KEY');
  });
});
