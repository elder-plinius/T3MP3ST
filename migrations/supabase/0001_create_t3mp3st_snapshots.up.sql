create table if not exists public.t3mp3st_snapshots (
  tenant_id text not null,
  snapshot_id text not null,
  schema_version text not null,
  saved_at timestamptz not null,
  payload jsonb not null,
  primary key (tenant_id, snapshot_id)
);

alter table public.t3mp3st_snapshots enable row level security;
revoke all on table public.t3mp3st_snapshots from anon, authenticated;
