export interface PersistenceMigration {
  version: number;
  name: string;
  up: string;
  down: string;
}

export interface MigrationStore {
  appliedVersions(): Promise<readonly number[]>;
  transaction(statements: readonly string[], version: number): Promise<void>;
}

export const SUPABASE_MIGRATIONS: readonly PersistenceMigration[] = [{
  version: 1,
  name: 'create_t3mp3st_snapshots',
  up: `create table if not exists public.t3mp3st_snapshots (
  tenant_id text not null,
  snapshot_id text not null,
  schema_version text not null,
  saved_at timestamptz not null,
  payload jsonb not null,
  primary key (tenant_id, snapshot_id)
);
alter table public.t3mp3st_snapshots enable row level security;
revoke all on table public.t3mp3st_snapshots from anon, authenticated;`,
  down: 'drop table if exists public.t3mp3st_snapshots;',
}];

export async function migratePersistence(store: MigrationStore, target = SUPABASE_MIGRATIONS.at(-1)?.version ?? 0): Promise<number[]> {
  const known = new Set(SUPABASE_MIGRATIONS.map(({ version }) => version));
  const applied = [...await store.appliedVersions()].sort((a, b) => a - b);
  if (applied.some((version) => !known.has(version))) throw new Error('Database contains an unknown persistence migration');
  const executed: number[] = [];
  for (const migration of SUPABASE_MIGRATIONS) {
    if (migration.version <= target && !applied.includes(migration.version)) {
      await store.transaction([migration.up], migration.version);
      executed.push(migration.version);
    }
  }
  return executed;
}
