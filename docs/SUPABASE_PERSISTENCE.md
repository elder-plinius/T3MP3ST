# Optional Supabase persistence

Supabase is an opt-in remote mirror. T3MP3ST's local state remains canonical and is written first; an unavailable or rejected remote write is reported separately and cannot roll back or mutate local state. Default operation does not construct this adapter and requires no Supabase account.

## Trust and credentials

The server reads only `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY`. The privileged service-role key must never be placed in browser code, API responses, logs, model context, or a target repository's `.env`; this adapter exposes only configured state and hostname. Browser-safe anonymous keys are intentionally unsupported because this is a server-side persistence path. Operators must pass an exact hostname allowlist, use HTTPS, and account for their configured network proxy outside this adapter.

Apply the numbered files in `migrations/supabase/` with a privileged migration identity. The table enables row-level security and revokes `anon` and `authenticated`; the server service role is the sole intended data-plane identity. Every key is `(tenant_id, snapshot_id)`, and callers must derive `tenant_id` from authenticated server context rather than user-controlled request fields.

## Data processing and lifecycle

Outbound rows contain tenant ID, snapshot ID, snapshot schema version, save timestamp, and the redacted snapshot payload. Snapshots can include operational state, findings, evidence metadata, approvals, and memory records, so treat the table as confidential security-testing data. Secret-like fields are redacted before transmission, but operators remain responsible for classifying free text before enabling the mirror.

Supabase is an external processor for hosted projects; review its region, subprocessors, backups, access logs, and contractual terms. Define retention in project policy and schedule deletion using `adapter.delete(tenantId, snapshotId)`. Deleting a row may not immediately remove provider backups; use the provider process for account/project erasure. The reversible down migration drops the entire table and is destructive, so export required records and obtain operator approval before applying it.

## Failure contract

Writes are bounded by HTTPS validation, exact-host authorization, a 512 KiB default payload limit, and a 10-second timeout. Redirects are not followed. Results expose only fixed failure categories and status codes, never response bodies, credentials, URLs, or payloads. Automatic retries are deliberately omitted to avoid duplicate load; callers may retry the idempotent tenant/snapshot upsert under their own bounded policy.
