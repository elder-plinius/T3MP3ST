#!/usr/bin/env node
/**
 * T3MP3ST ← Obsidian Inbox watcher.
 *
 * Watches <vault>/T3MP3ST/Inbox/*.md for new mission-draft notes. When a new
 * (unprocessed) note appears, parses its frontmatter, POSTs to t3mp3st's
 * mission API, and writes the response back into the note as an updated
 * frontmatter + result block.
 *
 * The note format Pliny writes in Obsidian:
 *
 *   ---
 *   action: mission           # or: hunt, audit, route-preview, simurgh, sphinx
 *   title: Find SQLi in checkout
 *   objective: Identify and validate SQL injection in /checkout
 *   family: web_api
 *   target: https://shop.example
 *   urgency: high             # optional
 *   scope: external           # optional
 *   ---
 *
 *   (free-form body — appended to objective as extra context)
 *
 * After the watcher processes it, the note is rewritten with:
 *   - frontmatter `processed: true`, `mission_id: ...`, `processed_at: ...`
 *   - a new "## Result" section containing the API response
 *
 * Usage:
 *   node scripts/obsidian-inbox.mjs                     # default vault
 *   node scripts/obsidian-inbox.mjs --vault ~/MyVault
 *   node scripts/obsidian-inbox.mjs --interval 3        # poll every 3s
 *   node scripts/obsidian-inbox.mjs --api http://127.0.0.1:3333
 *   node scripts/obsidian-inbox.mjs --auto-approve      # auto-clear approval gate
 */

import fs   from 'node:fs';
import path from 'node:path';
import os   from 'node:os';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
const REPO       = path.resolve(__dirname, '..');

// Pre-load .env + Keychain so the watcher inherits keys the same way the bench does.
try {
  const envPath = path.resolve(REPO, '.env');
  if (fs.existsSync(envPath)) {
    for (const line of fs.readFileSync(envPath, 'utf8').split('\n')) {
      const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
      if (!m || line.trim().startsWith('#')) continue;
      let v = m[2];
      if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
      if (!process.env[m[1]]) process.env[m[1]] = v;
    }
  }
} catch {}
if (process.platform === 'darwin') {
  const { execFileSync } = await import('node:child_process');
  for (const name of ['OPENROUTER_API_KEY', 'ANTHROPIC_API_KEY', 'OPENAI_API_KEY']) {
    if (process.env[name]) continue;
    try {
      const v = execFileSync('security', ['find-generic-password', '-a', name, '-s', 't3mp3st-bench-keys', '-w'],
        { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
      if (v) process.env[name] = v;
    } catch {}
  }
}

function detectProvider() {
  if (process.env.OPENROUTER_API_KEY) return { provider: 'openrouter', apiKey: process.env.OPENROUTER_API_KEY };
  if (process.env.ANTHROPIC_API_KEY)  return { provider: 'anthropic',  apiKey: process.env.ANTHROPIC_API_KEY  };
  if (process.env.OPENAI_API_KEY)     return { provider: 'openai',     apiKey: process.env.OPENAI_API_KEY     };
  return null;
}

function parseArgs(argv) {
  const a = {
    vault: process.env.OBSIDIAN_VAULT_PATH
        || path.join(os.homedir(), 'Desktop', 'younger_plinius', 'PliniVault'),
    api: process.env.T3MP3ST_API_URL || 'http://127.0.0.1:3333',
    interval: 5,
    autoApprove: true,
    verbose: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    if      (k === '--vault')         a.vault = argv[++i];
    else if (k === '--api')           a.api = argv[++i];
    else if (k === '--interval')      a.interval = parseInt(argv[++i], 10);
    else if (k === '--no-auto-approve') a.autoApprove = false;
    else if (k === '--auto-approve')  a.autoApprove = true;
    else if (k === '-v' || k === '--verbose') a.verbose = true;
    else if (k === '-h' || k === '--help')    { help(); process.exit(0); }
  }
  return a;
}

function help() {
  console.log(`T3MP3ST ← Obsidian Inbox watcher

Options:
  --vault <path>          Vault root (default: ~/Desktop/younger_plinius/PliniVault)
  --api <url>             t3mp3st base URL (default: http://127.0.0.1:3333)
  --interval <sec>        Poll interval (default 5)
  --auto-approve          Auto-clear t3mp3st approval gates (default on)
  --no-auto-approve       Stop on approval gate, leave note untouched
  -v, --verbose
  -h, --help
`);
}

// ----- frontmatter helpers -----------------------------------------------

function splitFrontmatter(text) {
  if (!text.startsWith('---')) return { fm: {}, body: text };
  const m = text.match(/^---\n([\s\S]*?)\n---\n?([\s\S]*)$/);
  if (!m) return { fm: {}, body: text };
  const fmText = m[1];
  const body   = m[2];
  const fmObj  = {};
  for (const line of fmText.split('\n')) {
    const mm = line.match(/^([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$/);
    if (!mm) continue;
    let v = mm[2].trim();
    if (v === 'true')  v = true;
    else if (v === 'false') v = false;
    else if (v === '~' || v === 'null' || v === '') v = null;
    else if (/^-?\d+(\.\d+)?$/.test(v)) v = Number(v);
    else if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
    fmObj[mm[1]] = v;
  }
  return { fm: fmObj, body };
}

function reassemble(fmObj, body) {
  const lines = ['---'];
  for (const [k, v] of Object.entries(fmObj)) {
    let val;
    if (v === null || v === undefined) val = '';
    else if (typeof v === 'string' && /[:#&*!|>'"%@`,\[\]{}]/.test(v)) val = JSON.stringify(v);
    else val = String(v);
    lines.push(`${k}: ${val}`);
  }
  lines.push('---');
  return lines.join('\n') + '\n' + body;
}

// ----- t3mp3st dispatchers -----------------------------------------------

async function postWithApproval(url, body, opts) {
  const call = async () => {
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    const txt = await r.text();
    return { status: r.status, ok: r.ok, body: txt };
  };
  let attempt = await call();
  for (let i = 0; i < 4 && !attempt.ok && opts.autoApprove; i++) {
    let approvalId = null;
    try { approvalId = JSON.parse(attempt.body)?.approval?.id; } catch {}
    if (!approvalId) break;
    const ar = await fetch(`${opts.api}/api/approvals/${approvalId}/approve`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ approvedBy: 'obsidian-inbox', ttlMinutes: 30 }),
    });
    if (!ar.ok) break;
    body.approvalId = approvalId;
    attempt = await call();
  }
  return attempt;
}

async function dispatchMissionDraft(fmObj, body, opts) {
  const objective = String(fmObj.objective || fmObj.title || '').trim()
    + (body.trim() ? '\n\nAdditional context:\n' + body.trim() : '');
  if (!objective) return { error: 'note has no objective or title' };

  const provider = detectProvider();
  if (!provider) return { error: 'no LLM API key found in env/Keychain/.env' };

  // Use /api/general/auto for full-plan + execute path.
  const reqBody = {
    objective,
    apiKey: provider.apiKey,
    provider: provider.provider,
    model: fmObj.model || (provider.provider === 'openrouter' ? 'anthropic/claude-opus-4-7' : 'claude-opus-4-7'),
    urgency: fmObj.urgency || 'normal',
    opsecPreference: fmObj.opsec || fmObj.opsecPreference || 'standard',
    scopeHints: fmObj.target ? [fmObj.target] : undefined,
  };

  const attempt = await postWithApproval(`${opts.api}/api/general/auto`, reqBody, opts);
  let parsed;
  try { parsed = JSON.parse(attempt.body); } catch { parsed = { raw: attempt.body }; }
  return {
    ok: attempt.ok,
    status: attempt.status,
    mission_id: parsed?.execution?.missionName || parsed?.plan?.codename || null,
    codename: parsed?.plan?.codename || null,
    family: parsed?.plan?.family || null,
    operators: parsed?.execution?.operators || [],
    error: attempt.ok ? null : (parsed?.error || `status ${attempt.status}`),
    raw: parsed,
  };
}

async function dispatchRoutePreview(fmObj, body, opts) {
  try {
    const r = await fetch(`${opts.api}/api/route-preview`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        title: fmObj.title || 'inbox draft',
        objective: fmObj.objective || (body || '').trim() || '',
        family: fmObj.family,
      }),
    });
    const txt = await r.text();
    let parsed; try { parsed = JSON.parse(txt); } catch { parsed = { raw: txt }; }
    return {
      ok: r.ok,
      status: r.status,
      mission_id: null,
      family: parsed.family || parsed.routedFamily || null,
      codename: parsed.codename || null,
      operators: parsed.operators || [],
      error: r.ok ? null : (parsed.error || `status ${r.status}`),
      raw: parsed,
    };
  } catch (e) {
    return { ok: false, error: e.message, raw: null };
  }
}

const DISPATCHERS = {
  mission:         dispatchMissionDraft,
  hunt:            dispatchMissionDraft,
  audit:           dispatchMissionDraft,
  'route-preview': dispatchRoutePreview,
};

// ----- watcher -----------------------------------------------------------

async function processNote(file, opts) {
  const raw = fs.readFileSync(file, 'utf8');
  const { fm, body } = splitFrontmatter(raw);
  if (fm.processed) return { skipped: 'already processed' };
  const action = String(fm.action || 'mission').toLowerCase();
  const dispatch = DISPATCHERS[action] || dispatchMissionDraft;

  if (opts.verbose) console.log(`  → dispatch ${action} from ${path.basename(file)}`);
  const result = await dispatch(fm, body, opts);

  fm.processed = true;
  fm.processed_at = new Date().toISOString();
  fm.mission_id = result.mission_id || '';
  fm.dispatch_ok = !!result.ok;
  if (result.error) fm.dispatch_error = result.error;

  const newBody = body
    + '\n\n## Result\n\n'
    + '```json\n' + JSON.stringify(result, null, 2).slice(0, 6000) + '\n```\n';
  fs.writeFileSync(file, reassemble(fm, newBody));
  return { processed: true, file, action, mission_id: result.mission_id, error: result.error };
}

async function sweep(opts) {
  const dir = path.join(opts.vault, 'T3MP3ST', 'Inbox');
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
    return [];
  }
  const out = [];
  for (const name of fs.readdirSync(dir)) {
    if (!name.endsWith('.md')) continue;
    // skip README/templates/dotfiles (lead with _ or .)
    if (name.startsWith('_') || name.startsWith('.')) continue;
    const file = path.join(dir, name);
    try {
      const r = await processNote(file, opts);
      if (r.processed) out.push(r);
    } catch (e) {
      console.error(`error on ${name}: ${e.message}`);
    }
  }
  return out;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  console.log(`T3MP3ST Obsidian Inbox watcher  vault=${opts.vault}  api=${opts.api}  every ${opts.interval}s`);
  ensureInboxReadme(opts.vault);

  const run = async () => {
    const processed = await sweep(opts);
    if (processed.length > 0) {
      const ts = new Date().toISOString().slice(11, 19);
      for (const p of processed) {
        console.log(`[${ts}] dispatched ${p.action} → ${p.mission_id || '?'}${p.error ? ' (ERR: ' + p.error + ')' : ''}  ${path.basename(p.file)}`);
      }
    }
  };

  await run();
  setInterval(run, opts.interval * 1000);
}

function ensureInboxReadme(vault) {
  const dir = path.join(vault, 'T3MP3ST', 'Inbox');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const readme = path.join(dir, '_README.md');
  if (fs.existsSync(readme)) return;
  fs.writeFileSync(readme, `# T3MP3ST Inbox

Drop a markdown file in this folder with frontmatter, save it, the watcher
will pick it up within a few seconds, dispatch to t3mp3st, and rewrite the
note with the response.

## Mission draft format

\`\`\`yaml
---
action: mission                    # mission | hunt | audit | route-preview
title: Find SQLi in checkout
objective: Identify and validate SQL injection in /checkout
family: web_api                    # optional — auto-routed if omitted
target: https://shop.example       # optional — used as scope hint
urgency: high                      # optional — normal | high | critical
opsec: standard                    # optional — quiet | standard | loud
model: claude-opus-4-7             # optional — provider model id
---

Free-form context here. Appended to the objective.
\`\`\`

After dispatch the watcher rewrites the file with:
- \`processed: true\`
- \`mission_id: M-...\`
- \`processed_at: ISO timestamp\`
- a "## Result" section with the API response

Delete \`processed: true\` (or just delete the note + re-create) to re-fire.

## Action types

| action | endpoint | notes |
| --- | --- | --- |
| \`mission\` / \`hunt\` / \`audit\` | \`/api/general/auto\` | full plan + execute, auto-approval |
| \`route-preview\` | \`/api/route-preview\` | classify only, no execution |
`);
}

main().catch(e => { console.error('FATAL:', e); process.exit(1); });
