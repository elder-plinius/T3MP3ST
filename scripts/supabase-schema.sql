-- T3MP3ST ↔ Supabase state persistence
-- Run once in Supabase Dashboard → SQL Editor.
-- Tables live in `public` so the service key reaches them over the Data API (REST),
-- but RLS is enabled with NO policies: anon/authenticated see nothing; only the
-- server's SUPABASE_SECRET_KEY / service role bypasses RLS.

create table if not exists public.t3mp3st_state_snapshots (
  id text primary key,
  reason text not null default 'state.updated',
  snapshot jsonb not null,
  updated_at timestamptz not null default now()
);

create table if not exists public.t3mp3st_state_events (
  id bigint generated always as identity primary key,
  type text not null,
  payload jsonb,
  ts timestamptz not null default now()
);

create index if not exists t3mp3st_state_events_ts_idx on public.t3mp3st_state_events (ts desc);

alter table public.t3mp3st_state_snapshots enable row level security;
alter table public.t3mp3st_state_events enable row level security;

revoke all on public.t3mp3st_state_snapshots from anon, authenticated;
revoke all on public.t3mp3st_state_events from anon, authenticated;
