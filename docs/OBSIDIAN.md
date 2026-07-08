# T3MP3ST ⇄ Obsidian

Treat your Obsidian vault as t3mp3st's long-term memory + command surface.

- **Sync** (`t3mp3st → vault`): live ledgers (missions, findings, evidence,
  hypotheses, retests, sitreps, memory) + CVE-bench results write into your
  vault as markdown notes with frontmatter and wikilinks. Idempotent — re-run
  any time, or `--watch` for continuous mirroring.
- **Inbox** (`vault → t3mp3st`): drop a markdown note in
  `T3MP3ST/Inbox/`, the watcher dispatches to `/api/general/auto` (or
  `/api/route-preview` etc.) and rewrites the note with the response.

## Quick start

```bash
# 1. One-shot sync (server can be offline — bench results sync regardless)
npm run obsidian

# 2. Continuous mirror (polls API + watches results dir every 10s)
npm run obsidian:watch

# 3. Inbox watcher (drops missions into t3mp3st when you save a note in vault)
npm run obsidian:inbox
```

Default vault path: `~/Desktop/younger_plinius/PliniVault`. Override with
`--vault <path>` or `OBSIDIAN_VAULT_PATH=...`.

If you don't have Obsidian installed yet, the folder works fine — install
Obsidian, choose "Open folder as vault", point it at the vault root, and
everything's instantly browsable.

## Layout the sync writes

```
<vault>/T3MP3ST/
├── _Index.md                  Operations Hub with Dataview queries
├── Missions/        M-<id>.md   t3mp3st mission records
├── Findings/        F-<id>.md   linked to mission, evidence, target, CWE
├── Evidence/        E-<id>.md   provenance (weak/tool/replayable)
├── Hypotheses/      H-<id>.md
├── Retests/         R-<id>.md
├── Sitreps/         S-<ts>.md
├── Memory/          MEM-<id>.md  accepted memory entries
├── Inbox/           drop new mission drafts here → watcher dispatches
└── CVE-Bench/
    ├── Corpus/      one note per CVE in bench corpus (gt + source + history)
    └── Runs/        one note per JSON report under bench/cve-hunt/results/
```

Every note has YAML frontmatter so Dataview can query everything.

## Vault Inbox — driving missions from notes

Open `T3MP3ST/Inbox/` in Obsidian, create a new markdown note:

```yaml
---
action: mission
title: Find SSRF in metadata fetcher
objective: Identify SSRF in the URL-fetching microservice that reaches cloud metadata
family: web_api
target: https://api.example.test/fetch
urgency: high
opsec: standard
---

Free-form context here. The watcher appends this as extra context
in the dispatched objective.
```

Save the file. Within `--interval` seconds (default 5), the watcher:

1. Parses frontmatter + body.
2. POSTs to t3mp3st (`/api/general/auto` for `mission`/`hunt`/`audit`,
   `/api/route-preview` for `route-preview`).
3. Auto-clears any approval gates (`auto-approve` is on by default).
4. Rewrites the note with `processed: true`, `mission_id`, and a
   `## Result` section containing the API response.

Then the **next sync** pulls the spawned mission's findings/evidence/sitreps
into `Missions/M-<id>.md`, `Findings/F-<id>.md`, etc., all backlinked.

### Available actions

| `action:` | Endpoint | Needs LLM key? |
|---|---|---|
| `mission` / `hunt` / `audit` | `/api/general/auto` | yes |
| `route-preview` | `/api/route-preview` | no |

LLM key resolution order: `env` → `.env` at repo root → macOS Keychain via
`scripts/keys.sh`. Set with: `npm run keys set OPENROUTER_API_KEY`.

## Dataview queries in `_Index.md`

Pre-wired, queries the frontmatter on every note:

- **Active missions** — filter `status != completed`
- **Recent critical findings** — `severity = critical or high`, sorted by confidence
- **CVE-Bench leaderboard** — last 25 runs ranked by score %, with FP / F1 columns
- **CVE-Bench corpus coverage** — every CVE in your corpus with CWE + class
- **Evidence by provenance** — last 50 evidence items
- **Hypotheses awaiting promotion** — open ones with confidence
- **Memory entries** — accepted memory by kind

Add your own. Example: per-CWE detection rate over time —

```dataview
TABLE rows.detected_count as detected, rows.fp_count as FP
FROM "T3MP3ST/CVE-Bench/Runs"
GROUP BY mode
```

## Bidirectional flow at a glance

```
   Obsidian vault                       t3mp3st (:3333)
   ┌──────────────────┐                ┌────────────────┐
   │ T3MP3ST/         │ ◀── sync ─────┤ /api/findings  │
   │   Findings/      │                │ /api/evidence  │
   │   Evidence/      │                │ /api/memory    │
   │   Missions/      │                │ /api/sitreps   │
   │   Sitreps/       │                │     ...        │
   │   CVE-Bench/     │                │                │
   │   _Index.md      │                │ /api/general/  │
   │                  │                │   auto         │
   │   Inbox/         │ ──── inbox ──▶ │ /api/route-    │
   │     draft.md     │     dispatch   │   preview      │
   └──────────────────┘                └────────────────┘
```

## Daemon-style run (recommended)

Three terminals (or `nohup` / launchd later):

```bash
# Terminal 1 — t3mp3st server
npm run server

# Terminal 2 — continuous vault sync
npm run obsidian:watch

# Terminal 3 — inbox dispatcher
npm run obsidian:inbox
```

Now anything t3mp3st emits lands in your vault in <10s, and anything you drop
in the Inbox dispatches in <5s.

## Configuration

| Env var | Purpose |
|---|---|
| `OBSIDIAN_VAULT_PATH` | Override vault root |
| `T3MP3ST_API_URL` | Override t3mp3st base URL |
| `OPENROUTER_API_KEY` / `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` | Provider for mission dispatch |

## What's next on the integration roadmap

- **Live SSE → vault streaming** (replace polling)
- **Vault-as-MCP-server** so agents can read/write the vault directly
- **Self-improvement loop** writing learning proposals to
  `T3MP3ST/Memory/Proposals/`, accept by flipping `accepted: true` in
  frontmatter, picked up on next sync
- **Per-CWE blind-spot heat-map** generated from CVE-Bench history
- **Obsidian plugin** (TypeScript, command palette, status bar, custom views)
