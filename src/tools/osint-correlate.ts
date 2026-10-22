/**
 * Cross-site correlation + iterative expansion for the OSINT username sweep.
 *
 * WHY THIS EXISTS — `runUsernameSweep` is a ONE-PASS probe: it attaches a handle to every
 * catalog site and reports. That is a search, not an investigation, and it is why the sweep
 * felt like it was "just attaching the search term to those sites": nothing it learned was
 * ever fed back in. A handle that EXISTS is the strongest asset the sweep produces, and the
 * one-pass design threw it away.
 *
 * The techniques here are the standard public-source ones an investigator actually uses, and
 * every one is a PUBLIC, keyless, legal read:
 *
 *  1. LINK HUBS — Keybase publishes a verified identity graph (`keybase.io/<user>.json`), and
 *     Linktree pages list every account a person keeps in one place. Both are explicit
 *     self-published cross-links, i.e. the STRONGEST possible non-infringing evidence that two
 *     handles are one person. The catalog already listed Keybase with a note saying it "lists
 *     linked identities" — and nothing ever read it.
 *  2. PROFILE-FIELD HARVEST — a public profile's own `blog` / `twitter` / display-name fields
 *     name other accounts. Free corroboration, already fetched by `PROFILE_APIS` and then
 *     discarded.
 *  3. ITERATIVE EXPANSION — sweep the discovered handles too, so one confirmed account
 *     unlocks a graph instead of a row.
 *  4. STRUCTURAL CORRELATION — cluster accounts that share an avatar, a bio, or a
 *     near-identical handle, so a sweep returns "these 6 are one person", not 6 loose rows.
 *
 * DOCTRINE: public/licensed/self-published sources only. Nothing here touches credential
 * marketplaces, and nothing here is subject-specific — the caller supplies the seed handle.
 */

import {
  runUsernameSweep,
  validateUsername,
  type OsintSiteCategory,
  type ProfileHint,
  type SweepResult,
  type UsernameHit,
} from './osint.js';
import type { CustomTool } from '../types/index.js';

const FETCH_TIMEOUT_MS = 12_000;

/**
 * USER-AGENT ROTATION.
 *
 * Every OSINT probe in this repo sent ONE static UA. WAFs fingerprint that: a burst of hundreds
 * of requests from an identical, obviously-automated string is exactly the shape that earns an
 * IP a 403, and a 403 is recorded as `unknown` — which the operator cannot tell apart from
 * "the account does not exist". Rotating a small set of ordinary desktop strings is the standard
 * mitigation and is what keeps the ABSENT side of the sweep honest.
 *
 * Written here rather than lifted from Blackbird's `data/useragents.txt`: that project ships no
 * LICENSE (verified: the LICENSE path 404s and the GitHub API reports `license: null`), so none
 * of its files are vendored. This is a hand-written list of ordinary browser strings.
 */
const UA_POOL = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0',
  'Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0',
];
let uaCursor = 0;
export function nextUserAgent(): string {
  uaCursor = (uaCursor + 1) % UA_POOL.length;
  return UA_POOL[uaCursor];
}

/** Injectable for tests — same idiom as the sweep's `customSites` hook. */
export type CorrelateFetcher = (url: string, init?: RequestInit) => Promise<Response>;

async function defaultFetch(url: string, init: RequestInit = {}): Promise<Response> {
  return globalThis.fetch(url, {
    ...init,
    headers: {
      'user-agent': nextUserAgent(),
      accept: 'text/html,application/json;q=0.9,*/*;q=0.8',
      // A real browser accepts compressed responses; without this some sites answer 406 and the
      // probe is recorded as `unknown`.
      'accept-language': 'en-US,en;q=0.9',
      'accept-encoding': 'gzip, deflate, br',
      ...(init.headers || {}),
    },
    signal: (init.signal as AbortSignal) || AbortSignal.timeout(FETCH_TIMEOUT_MS),
    redirect: 'follow',
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. HANDLE SIMILARITY — link accounts whose handles are near-identical
// ═══════════════════════════════════════════════════════════════════════════

/** Levenshtein distance, two-row implementation (no allocation per cell). */
export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  let prev = new Array<number>(b.length + 1);
  let cur = new Array<number>(b.length + 1);
  for (let j = 0; j <= b.length; j++) prev[j] = j;
  for (let i = 1; i <= a.length; i++) {
    cur[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
    }
    [prev, cur] = [cur, prev];
  }
  return prev[b.length];
}

/** Normalized 0..1 similarity. Separator-insensitive: john_smith ≡ johnsmith. */
export function handleSimilarity(a: string, b: string): number {
  const norm = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, '');
  const x = norm(a);
  const y = norm(b);
  if (!x || !y) return 0;
  if (x === y) return 1;
  // Containment: "jsmith" inside "johnsmith" is a strong signal, not a near-miss.
  if (x.length >= 4 && y.length >= 4 && (x.includes(y) || y.includes(x))) return 0.9;
  const d = levenshtein(x, y);
  return Math.max(0, 1 - d / Math.max(x.length, y.length));
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. KEYBASE IDENTITY GRAPH — self-published, verified cross-links
// ═══════════════════════════════════════════════════════════════════════════

export interface KeybaseIdentity {
  username: string;
  /** The service the identity is claimed on (github, twitter, reddit, …). */
  service: string;
  url: string;
  /** Keybase's own proof state — "unproven" is still a claim worth surfacing. */
  proof: string;
  proofUrl?: string;
}

interface KeybasePayload {
  user?: {
    username?: string;
    profile?: { bio?: string; location?: string };
  };
  identities?: Array<{
    username?: string;
    service_name?: string;
    proofs?: { service?: string; proof_url?: string; pretty_proof_url?: string }[];
  }>;
}

/**
 * Keybase identity graph — self-published, proven cross-links.
 *
 * ⚠ THE SERVICE IS DEFUNCT. Verified live from this box on 2026-09-28:
 *   • `keybase.io/<user>.json`  → **404 for every user** (the public JSON profile API is gone)
 *   • `keybase.io/_/api/1.0/user/lookup.json?username=X` → 200, but the payload carries NO
 *     `identities` field — only id/basics/profile/public_keys/proofs_summary. The linked-identity
 *     graph is not served any more.
 *   • `keybase.io/<user>` → the marketing homepage, not a profile.
 * So this returns [] and reports WHY, rather than a lane that silently finds nothing while the
 * UI advertises "self-published identity links". The `keybaseLinks` input to `correlateAccounts`
 * is kept — the grouping logic is sound and is exercised by tests — but the harvester states the
 * service is down instead of pretending to work.
 */
export const KEYBASE_STATUS =
  'Keybase identity graph is offline (public JSON profile API returns 404 and the v1.0 lookup no longer serves identities). Verified 2026-09-28 — cross-linking now runs off link hubs and published profile fields instead.';

export async function keybaseIdentities(
  username: string,
  fetcher: CorrelateFetcher = defaultFetch
): Promise<KeybaseIdentity[]> {
  // Legacy shape kept as the parser so the function still works if/when the API returns.
  const url = `https://keybase.io/${encodeURIComponent(username)}.json`;
  let payload: KeybasePayload | null = null;
  try {
    const res = await fetcher(url, { headers: { accept: 'application/json' } });
    if (!res.ok) return [];
    payload = (await res.json()) as KeybasePayload;
  } catch {
    return [];
  }
  const identities = Array.isArray(payload?.identities) ? payload!.identities : [];
  const out: KeybaseIdentity[] = [];
  for (const id of identities) {
    const u = (id?.username || '').trim();
    const service = (id?.service_name || '').trim();
    if (!u || !service) continue;
    // An identity naming the seed itself tells us nothing new.
    if (u.toLowerCase() === username.toLowerCase()) continue;
    const proof = id?.proofs?.[0];
    out.push({
      username: u,
      service,
      url: `https://keybase.io/${encodeURIComponent(u)}`,
      proof: proof?.service || 'unproven',
      proofUrl: proof?.pretty_proof_url || proof?.proof_url,
    });
  }
  return out;
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. LINKTREE / LINK HUB HARVEST
// ═══════════════════════════════════════════════════════════════════════════

/** Hosts worth pulling an outbound handle from when a profile links out. */
const HUB_HOSTS = ['linktr.ee', 'link.me', 'beacons.ai', 'bio.link', 'linkin.bio', 'stan.store', 'solo.to'];

export interface LinkHubHit {
  handle: string;
  hub: string;
  url: string;
}

/**
 * Pull other-account links off a link hub. A Linktree page is a person's own hand-curated
 * index of their accounts, so each outbound profile URL is an explicit claim of ownership.
 */
export async function linkHubLinks(
  username: string,
  fetcher: CorrelateFetcher = defaultFetch
): Promise<LinkHubHit[]> {
  const out: LinkHubHit[] = [];
  const seen = new Set<string>();
  for (const host of HUB_HOSTS) {
    const url = `https://${host}/${encodeURIComponent(username)}`;
    let html: string;
    try {
      const res = await fetcher(url, { headers: { accept: 'text/html' } });
      if (!res.ok) continue;
      html = await res.text();
    } catch {
      continue;
    }
    // Outbound profile links. A link-hub page is a link farm by construction: it inlines its
    // asset CDN, its own legal pages and its own nav. Only a link to a KNOWN profile host can
    // be a person's account, so that is the gate — without it one page yielded a 40-character
    // UGC blob id as a "handle".
    for (const m of html.matchAll(/href="(https?:\/\/[^"]+)"/g)) {
      let href: string;
      try {
        href = new URL(m[1]).toString();
      } catch {
        continue;
      }
      const parsed = new URL(href);
      const targetHost = parsed.hostname.toLowerCase().replace(/^www\./, '');
      if (HUB_HOSTS.includes(targetHost)) continue;
      if (!PROFILE_HOSTS.has(targetHost)) continue;
      if (/(?:^|\.)(?:about|legal|privacy|terms|help|support)\./i.test(targetHost)) continue;
      const handle = handleFromProfileUrl(href);
      if (!handle || seen.has(handle.toLowerCase())) continue;
      if (!isPlausibleHandle(handle)) continue;
      seen.add(handle.toLowerCase());
      out.push({ handle, hub: host, url: href });
    }
    // A page that yielded links is enough; no need to hammer the other hub hosts.
    if (out.length >= 3) break;
  }
  return out;
}

/** Hosts whose first path segment IS the handle — the reliable profile-URL shape. */
const PROFILE_HOSTS = new Set([
  'github.com', 'gitlab.com', 'bitbucket.org', 'codeberg.org', 'gitea.com',
  'x.com', 'twitter.com', 'instagram.com', 'facebook.com', 'linkedin.com',
  'reddit.com', 't.me', 'telegram.me', 'medium.com', 'substack.com',
  'youtube.com', 'youtu.be', 'twitch.tv', 'soundcloud.com', 'spotify.com',
  'steamcommunity.com', 'keybase.io', 'ko-fi.com', 'patreon.com', 'dev.to',
  'hackernoon.com', 'medium.com', 'bsky.app', 'mastodon.social', 'tumblr.com',
  'pinterest.com', 'vk.com', 'last.fm', 'bandcamp.com', 'lichess.org',
  'chess.com', 'lichess.org', 'about.me', 'linktr.ee', 'link.me', 'beacons.ai',
]);

/** Path segments that mean "this href is a site asset, not someone's profile". */
const ASSET_SEGMENTS = /^(?:_next|static|assets?|images?|img|fonts?|media|css|js|dist|build|public|files?|uploads?|cdn|vendor)$/i;
const ASSET_EXT = /\.(?:png|jpe?g|gif|webp|svg|ico|css|js|mjs|json|xml|txt|pdf|zip|mp4|webm|woff2?|ttf|map)$/i;

/** Extract a plausible handle from a social profile URL, or null if it isn't one. */
export function handleFromProfileUrl(url: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  const parts = parsed.pathname.split('/').filter(Boolean);
  if (parts.length === 0) return null;
  // Link-hub pages are Next.js apps that inline their whole asset CDN into the HTML. Without
  // this, `favicon.ico` and `_next/static/logo.png` were being harvested as "handles" — 25 of
  // them for one page. An asset path is never a person.
  if (parts.some((p) => ASSET_SEGMENTS.test(p))) return null;
  if (ASSET_EXT.test(parsed.pathname)) return null;
  // Skip obvious non-profile paths.
  if (parts.some((p) => /^(p|posts?|blog|about|privacy|terms|login|signup|share|home|explore|search|tag|tags|topic|topics)$/i.test(p))) return null;
  // Last path segment is the handle. Strip a leading @ (medium.com/@author) and drop query/hash.
  const last = decodeURIComponent(parts[parts.length - 1]).replace(/^@/, '');
  if (last.length < 2 || last.length > 40) return null;
  if (!/^[A-Za-z0-9._-]+$/.test(last)) return null;
  return last;
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. PROFILE-FIELD HARVEST — mine handles a public profile already publishes
// ═══════════════════════════════════════════════════════════════════════════

/** Handle-shaped strings we accept out of free text. Deliberately conservative. */
const HANDLE_IN_TEXT = /@([A-Za-z0-9][A-Za-z0-9._-]{1,38}[A-Za-z0-9])/g;
const HANDLE_IN_URL = /(?:https?:\/\/)?(?:www\.)?([a-z0-9-]+)\.(?:com|net|org|io|me|dev|app|xyz|gg|sh)\/([A-Za-z0-9._-]{2,40})/gi;

const NOT_HANDLES = new Set([
  'the', 'and', 'you', 'your', 'this', 'that', 'with', 'for', 'http', 'https', 'www', 'com',
  'free', 'best', 'new', 'all', 'get', 'our', 'out', 'not', 'but', 'its', 'his', 'her', 'are',
  'was', 'who', 'what', 'when', 'how', 'why', 'now', 'can', 'has', 'had', 'will', 'would',
]);

export function isPlausibleHandle(candidate: string): boolean {
  const h = candidate.trim().replace(/^@/, '');
  if (h.length < 3 || h.length > 40) return false;
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*[A-Za-z0-9]$/.test(h)) return false;
  if (NOT_HANDLES.has(h.toLowerCase())) return false;
  if (/^\d+$/.test(h)) return false;                       // pure digits = an id, not a handle
  if (/\.(png|jpg|jpeg|gif|webp|svg|js|css|html|php|aspx)$/i.test(h)) return false;
  if (!/[A-Za-z]/.test(h)) return false;                     // must contain a letter
  return validateUsername(h) !== null;
}

export interface HarvestedHandle {
  handle: string;
  /** Which technique surfaced it — provenance is the whole point. */
  via: 'keybase' | 'link-hub' | 'profile-field' | 'display-name' | 'seed';
  detail: string;
}

/**
 * Mine candidate handles out of a FOUND account. Three sources, weakest to strongest:
 * the profile's own declared cross-links, its display name, and free text.
 */
export function mineHandlesFromProfile(hit: UsernameHit): HarvestedHandle[] {
  const out: HarvestedHandle[] = [];
  const seen = new Set<string>();
  const push = (raw: string, via: HarvestedHandle['via'], detail: string) => {
    const h = (raw || '').trim().replace(/^@/, '');
    if (!isPlausibleHandle(h)) return;
    const k = h.toLowerCase();
    if (seen.has(k)) return;
    seen.add(k);
    out.push({ handle: h, via, detail });
  };

  const p: ProfileHint | undefined = hit.profile;

  // 4a. Declared cross-links on the profile itself.
  if (p?.twitter) push(p.twitter, 'profile-field', `${hit.site} profile twitter field`);
  if (p?.blog) {
    const fromUrl = handleFromProfileUrl(p.blog);
    if (fromUrl) push(fromUrl, 'profile-field', `${hit.site} profile blog ${p.blog}`);
    else {
      // A blog URL whose last segment is the person's handle.
      try {
        const seg = new URL(p.blog).pathname.split('/').filter(Boolean).pop();
        if (seg) push(decodeURIComponent(seg), 'profile-field', `${hit.site} profile blog path`);
      } catch { /* not a URL */ }
    }
  }

  // 4b. Display name as a handle — "John Smith" → johnsmith / jsmith / john.smith.
  // Lower-cased: handles are case-insensitive, so a capitalised guess only ever costs a probe.
  if (p?.displayName && /\s/.test(p.displayName)) {
    const [first, ...rest] = p.displayName.trim().split(/\s+/);
    const last = rest[rest.length - 1] || '';
    const f = first.toLowerCase();
    const l = last.toLowerCase();
    if (f && l) {
      push(`${f}${l}`, 'display-name', `${hit.site} display name "${p.displayName}"`);
      push(`${f[0]}${l}`, 'display-name', `${hit.site} display name initial+last`);
      push(`${f}.${l}`, 'display-name', `${hit.site} display name dotted`);
    }
  }

  // 4c. Free text (@mentions and profile URLs) in the bio.
  const bio = p?.bio || '';
  if (bio) {
    for (const m of bio.matchAll(HANDLE_IN_TEXT)) push(m[1], 'profile-field', `${hit.site} bio @mention`);
    for (const m of bio.matchAll(HANDLE_IN_URL)) push(m[2], 'profile-field', `${hit.site} bio profile link`);
  }

  return out;
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. STRUCTURAL CORRELATION — group accounts that look like one person
// ═══════════════════════════════════════════════════════════════════════════

export interface LinkedGroup {
  /** Stable key for the group, e.g. the strongest member's handle. */
  key: string;
  handles: string[];
  sites: string[];
  evidence: string[];
  /** strong = an explicit self-published cross-link; medium = shared avatar/bio; weak = name shape. */
  strength: 'strong' | 'medium' | 'weak';
}

const BIO_STOPWORDS = new Set([
  'the', 'and', 'for', 'with', 'that', 'this', 'from', 'have', 'has', 'was', 'were', 'are',
  'you', 'your', 'our', 'not', 'but', 'all', 'can', 'will', 'just', 'like', 'love', 'free',
  'new', 'get', 'out', 'now', 'one', 'two', 'who', 'what', 'when', 'how', 'why', 'its', 'his',
  'her', 'they', 'them', 'she', 'him', 'hey', 'hi', 'yes', 'via', 'about', 'more', 'info',
]);

function bioTokens(bio: string | undefined): Set<string> {
  const out = new Set<string>();
  if (!bio) return out;
  for (const t of bio.toLowerCase().match(/[a-z][a-z0-9+#.-]{3,}/g) || []) {
    if (!BIO_STOPWORDS.has(t)) out.add(t);
  }
  return out;
}

/**
 * Cluster found accounts. A cluster needs at least two accounts that share real evidence —
 * this never groups on "both exist", which is the failure mode that makes naive sweeps look
 * impressive while being worthless.
 */
export function correlateAccounts(
  hits: UsernameHit[],
  opts: { keybaseLinks?: Array<{ from: string; to: string; service: string; proof: string }> } = {}
): LinkedGroup[] {
  const found = hits.filter((h) => h.status === 'found' && h.site);
  if (found.length === 0) return [];

  // Union-find over account indices.
  const parent = found.map((_, i) => i);
  const find = (i: number): number => (parent[i] === i ? i : (parent[i] = find(parent[i])));
  const union = (i: number, j: number) => { const a = find(i), b = find(j); if (a !== b) parent[a] = b; };

  const evidence = new Map<string, string[]>();
  const addEvidence = (i: number, text: string) => {
    const k = String(find(i));
    if (!evidence.has(k)) evidence.set(k, []);
    const arr = evidence.get(k)!;
    if (!arr.includes(text) && arr.length < 24) arr.push(text);
  };

  const keybase = opts.keybaseLinks || [];

  // (a) Explicit self-published cross-links — the strongest signal there is.
  // Match a link endpoint against the HANDLE a hit's URL represents. Comparing the raw URL to a
  // bare handle (the first version did) never matches, so Keybase evidence silently did nothing.
  const handleOfHit = (h: UsernameHit): string =>
    (handleFromProfileUrl(h.url) || '').toLowerCase();
  for (const link of keybase) {
    const from = link.from.toLowerCase();
    const to = link.to.toLowerCase();
    const i = found.findIndex((h) => handleOfHit(h) === from);
    const j = found.findIndex((h) => handleOfHit(h) === to);
    if (i >= 0 && j >= 0 && i !== j) {
      union(i, j);
      addEvidence(i, `Keybase links this account to @${link.to} (${link.service}, proof: ${link.proof})`);
    }
  }

  // (b) Shared avatar URL — same image file reused across platforms.
  const byAvatar = new Map<string, number[]>();
  found.forEach((h, i) => {
    const a = h.profile?.imageUrl;
    if (a) {
      const k = a.split('?')[0].toLowerCase();
      if (!byAvatar.has(k)) byAvatar.set(k, []);
      byAvatar.get(k)!.push(i);
    }
  });
  for (const [avatar, idxs] of byAvatar) {
    if (idxs.length < 2) continue;
    for (let k = 1; k < idxs.length; k++) {
      union(idxs[0], idxs[k]);
      addEvidence(idxs[k], `Same avatar image as ${found[idxs[0]].site} (${avatar})`);
    }
  }

  // (c) Shared distinctive bio terms — requires a term on 2+ platforms.
  const byToken = new Map<string, number[]>();
  found.forEach((h, i) => {
    for (const t of bioTokens(h.profile?.bio)) {
      if (!byToken.has(t)) byToken.set(t, []);
      byToken.get(t)!.push(i);
    }
  });
  for (const [token, idxs] of byToken) {
    if (idxs.length < 2) continue;
    for (let k = 1; k < idxs.length; k++) {
      union(idxs[0], idxs[k]);
      addEvidence(idxs[k], `Shares bio term "${token}" with ${found[idxs[0]].site}`);
    }
  }

  // (d) Near-identical handle shape across different platforms.
  for (let i = 0; i < found.length; i++) {
    for (let j = i + 1; j < found.length; j++) {
      if (found[i].site === found[j].site) continue;
      const a = handleFromProfileUrl(found[i].url);
      const b = handleFromProfileUrl(found[j].url);
      if (!a || !b) continue;
      const sim = handleSimilarity(a, b);
      if (sim >= 0.92 && a.toLowerCase() !== b.toLowerCase()) {
        union(i, j);
        addEvidence(j, `Handle "${a}" is a ${Math.round(sim * 100)}% match for "${b}" on ${found[i].site}`);
      }
    }
  }

  // Emit one LinkedGroup per component with >= 2 members.
  const groups = new Map<number, number[]>();
  found.forEach((_, i) => {
    const r = find(i);
    if (!groups.has(r)) groups.set(r, []);
    groups.get(r)!.push(i);
  });

  const out: LinkedGroup[] = [];
  for (const [root, idxs] of groups) {
    if (idxs.length < 2) continue;
    const ev = evidence.get(String(root)) || [];
    out.push({
      key: found[idxs[0]].site,
      handles: idxs.map((i) => handleFromProfileUrl(found[i].url) || found[i].site),
      sites: idxs.map((i) => found[i].site),
      evidence: ev,
      strength: ev.some((e) => e.startsWith('Keybase')) ? 'strong'
        : ev.some((e) => e.startsWith('Same avatar') || e.startsWith('Shares bio')) ? 'medium'
          : 'weak',
    });
  }
  // Strongest evidence first.
  const rank = { strong: 0, medium: 1, weak: 2 } as const;
  out.sort((x, y) => rank[x.strength] - rank[y.strength] || y.sites.length - x.sites.length);
  return out;
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. ITERATIVE DEEP SWEEP — the orchestrator
// ═══════════════════════════════════════════════════════════════════════════

export interface DeepSweepOptions {
  /** Subject's real name, for identity corroboration on every pass. */
  name?: string;
  catalog?: 'curated' | 'sherlock' | 'full';
  includeAdult?: boolean;
  /** Extra sites for the first (full) pass. */
  sites?: string[];
  /** How many discovered handles to sweep in later passes. */
  maxExpansionHandles?: number;
  /** How many expansion rounds (1 = seed only). */
  rounds?: number;
  /**
   * Wall-clock ceiling for the whole investigation, in ms (default 240s).
   * A curated-catalog sweep of ONE handle measured 105-176s on this box, because a site that
   * blocks the egress burns the full escalation ladder (egress → fallback → Tor → direct) at
   * 4x the per-probe timeout. Without a budget, rounds x handles is a multi-hour request that
   * just hangs. When the budget is hit the sweep stops, KEEPS what it found, and says so.
   */
  budgetMs?: number;
  fetcher?: CorrelateFetcher;
  /** Progress callback for SSE/UI. */
  onStage?: (stage: string, detail: string) => void;
}

export interface DeepSweepRound {
  seed: string;
  /** Where this handle came from. */
  via: HarvestedHandle['via'] | 'seed';
  sitesChecked: number;
  found: UsernameHit[];
  durationMs: number;
}

export interface DeepSweepResult {
  seed: string;
  rounds: DeepSweepRound[];
  /** Every account found across every pass, de-duplicated by URL. */
  allAccounts: UsernameHit[];
  /** Accounts the name hint corroborates. */
  corroborated: UsernameHit[];
  /** Accounts that positively mismatch the name. */
  mismatched: UsernameHit[];
  groups: LinkedGroup[];
  keybaseLinks: Array<{ from: string; to: string; service: string; proof: string }>;
  harvested: HarvestedHandle[];
  /** Handles that were tried, including ones that produced nothing. */
  handlesTried: string[];
  durationMs: number;
  /** Honest note when something could not be done. */
  caveats: string[];
  /** True when the wall-clock budget stopped the investigation before it finished. */
  budgetHit: boolean;
}

const FAST_CATEGORIES: OsintSiteCategory[] = ['social', 'dev', 'blog', 'forum'];

/**
 * The real sweep. Seed → sweep → harvest cross-links from what was FOUND → sweep those →
 * correlate. Bounded by explicit caps so a single call can't run for an hour.
 */
/**
 * Derive candidate handles from an EMAIL address.
 *
 * This is the technique Blackbird (`antoniaci/blackbird`) exists to demonstrate — search the
 * social platforms by EMAIL, not just by a username someone already gave you. The local-part is
 * the handle far more often than not, but people mutate it: dots become nothing, `-`/`_`/`.`
 * become anything, and `+tag` is a mail provider's sub-addressing, not part of the identity.
 *
 * Reimplemented here rather than vendored: Blackbird publishes NO LICENSE (verified — the LICENSE
 * path 404s and the GitHub API reports `license: null`), so its `data/email-data.json` and
 * `data/useragents.txt` are not copied into this repo. Its email dataset is also 16 sites and
 * declares Gravatar as `hash-sha256` when Gravatar is MD5, so that lane can never match.
 */
export function emailHandleCandidates(email: string, max = 12): string[] {
  const raw = (email || '').trim().toLowerCase();
  const at = raw.lastIndexOf('@');
  if (at <= 0) return [];
  let local = raw.slice(0, at);
  // Sub-addressing: john.smith+tag@gmail.com → john.smith (the tag is the provider's, not the user's)
  const plus = local.indexOf('+');
  if (plus > 0) local = local.slice(0, plus);
  if (!local) return [];

  const out: string[] = [];
  const seen = new Set<string>();
  const add = (s: string) => {
    const h = s.replace(/^@/, '').trim();
    if (!isPlausibleHandle(h)) return;
    const k = h.toLowerCase();
    if (seen.has(k)) return;
    seen.add(k);
    out.push(h);
  };

  // 1. The local-part verbatim — by far the most common case.
  add(local);
  // 2. Gmail-style dot folding: john.smith and johnsmith are the same mailbox.
  if (local.includes('.')) add(local.replace(/\./g, ''));
  // 3. Separator normalisation, both directions.
  add(local.replace(/[._-]+/g, ''));
  add(local.replace(/[._-]/g, '.'));
  add(local.replace(/[._-]/g, '_'));
  add(local.replace(/[._-]/g, '-'));
  // 4. first.last → last.first, and first_last → flast. Cheap, and common enough to be worth 2 probes.
  const segs = local.split(/[._-]+/).filter(Boolean);
  if (segs.length >= 2) {
    add(`${segs[segs.length - 1]}${segs[0]}`);
    add(`${segs[0][0]}${segs[segs.length - 1]}`);
    add(`${segs[0]}${segs[segs.length - 1][0]}`);
  }
  return out.slice(0, Math.max(1, max));
}

export async function deepUsernameSweep(
  seedRaw: string,
  opts: DeepSweepOptions = {}
): Promise<DeepSweepResult> {
  const t0 = Date.now();
  const trimmed = (seedRaw || '').trim();
  const looksLikeEmail = trimmed.includes('@') && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(trimmed);

  // An email seed expands into its candidate handles; a username seed is itself the first handle.
  let seedHandles: string[] = [];
  let seedCandidatesDropped = 0;
  if (looksLikeEmail) {
    // The email lane is bounded by the SAME cap as later expansion. Unbounded, `a.b.c@x.com`
    // produced 12 full catalogue sweeps and the call simply never returned.
    const cap = Math.max(1, Math.min(opts.maxExpansionHandles ?? 8, 25));
    const all = emailHandleCandidates(trimmed, cap + 1);
    seedHandles = all.slice(0, cap);
    seedCandidatesDropped = all.length - seedHandles.length;
  } else {
    const seed = validateUsername(trimmed);
    if (!seed) throw new Error(`Invalid username: ${trimmed}`);
    seedHandles = [seed];
  }
  if (!seedHandles.length) throw new Error(`Could not derive any usable handles from: ${trimmed}`);
  const seed = seedHandles[0];

  const fetcher = opts.fetcher || defaultFetch;
  const rounds = Math.max(1, Math.min(opts.rounds ?? 2, 3));
  const maxExpansion = Math.max(0, Math.min(opts.maxExpansionHandles ?? 8, 25));
  const budgetMs = Math.max(30_000, Math.min(opts.budgetMs ?? 240_000, 1_800_000));
  const onStage = opts.onStage || (() => {});

  const caveats: string[] = [];
  let budgetHit = false;
  const allAccounts: UsernameHit[] = [];
  const seenUrls = new Set<string>();
  const handlesTried: string[] = [];
  const harvested: HarvestedHandle[] = [];
  const keybaseLinks: Array<{ from: string; to: string; service: string; proof: string }> = [];
  const roundResults: DeepSweepRound[] = [];

  let queue: Array<{ handle: string; via: HarvestedHandle['via'] }> = seedHandles.map((h) => ({
    handle: h,
    via: 'seed' as const,
  }));
  const usedHandles = new Set<string>(seedHandles.map((h) => h.toLowerCase()));

  for (let round = 1; round <= rounds; round++) {
    if (queue.length === 0) break;
    const batch = round === 1 ? queue : queue.slice(0, maxExpansion);
    queue = [];

    for (const { handle, via } of batch) {
      // Wall-clock ceiling. Stop STARTING handles once the budget is gone, keep every result
      // already gathered, and report the shortfall — never return a partial sweep silently.
      const elapsed = Date.now() - t0;
      if (elapsed > budgetMs) {
        budgetHit = true;
        const remaining = batch.slice(batch.indexOf(batch.find((b) => b.handle === handle)!) + 1).length + queue.length;
        caveats.push(`Budget reached (${(budgetMs / 1000).toFixed(0)}s) — stopped starting new handles; ${remaining} were not swept. The handle already in flight was allowed to finish, so total time can exceed the budget by roughly one sweep (~1-3 min on the curated catalog). Everything found so far is reported.`);
        break;
      }
      onStage('sweep', `${handle} (round ${round}) — probing the catalog`);
      const rt = Date.now();
      let sweep: SweepResult;
      try {
        // Round 1 honours the operator's full catalog choice; later rounds use a fast,
        // high-signal category subset so expansion does not multiply into an hour of probing.
        sweep = await runUsernameSweep(handle, {
          hints: opts.name ? { name: opts.name } : undefined,
          catalog: round === 1 ? (opts.catalog ?? 'full') : 'curated',
          categories: round === 1 ? undefined : FAST_CATEGORIES,
          sites: round === 1 ? opts.sites : undefined,
          includeAdult: opts.includeAdult,
        });
      } catch (e) {
        caveats.push(`Sweep for "${handle}" failed: ${(e as Error).message}`);
        continue;
      }
      const found = sweep.found.filter((h) => {
        const k = h.url.toLowerCase();
        if (seenUrls.has(k)) return false;
        seenUrls.add(k);
        return true;
      });
      roundResults.push({ seed: handle, via, sitesChecked: sweep.checked, found, durationMs: Date.now() - rt });
      allAccounts.push(...found);
      // Only count a handle once — the seed is swept in round 1 and the list is also the
      // "how many handles did this cost" figure the operator reads.
      if (!handlesTried.some((h) => h.toLowerCase() === handle.toLowerCase())) handlesTried.push(handle);

      // ── Harvest cross-links from everything we just confirmed. ──
      for (const hit of found) {
        for (const h of mineHandlesFromProfile(hit)) {
          harvested.push(h);
          const k = h.handle.toLowerCase();
          if (usedHandles.has(k) || handlesTried.length >= maxExpansion + 1) continue;
          usedHandles.add(k);
          queue.push({ handle: h.handle, via: h.via });
        }
      }

      // Keybase graph — was the strongest public cross-link source; the service is now offline,
      // so the outage is recorded ONCE in caveats rather than a silent [] every handle.
      const kb = await keybaseIdentities(handle, fetcher).catch(() => []);
      if (!kb.length && !caveats.some((c) => c.startsWith('Keybase'))) caveats.push(KEYBASE_STATUS);
      for (const id of kb) {
        keybaseLinks.push({ from: handle, to: id.username, service: id.service, proof: id.proof });
        const k = id.username.toLowerCase();
        if (usedHandles.has(k) || handlesTried.length >= maxExpansion + 1) continue;
        if (!isPlausibleHandle(id.username)) continue;
        usedHandles.add(k);
        harvested.push({ handle: id.username, via: 'keybase', detail: `Keybase identity on ${id.service} (proof: ${id.proof})` });
        queue.push({ handle: id.username, via: 'keybase' });
      }

      // Link hub.
      if (round === 1 && found.some((h) => /linktree|beacons|bio\.link/i.test(h.url))) {
        for (const link of await linkHubLinks(handle, fetcher).catch(() => [])) {
          const k = link.handle.toLowerCase();
          if (usedHandles.has(k)) continue;
          usedHandles.add(k);
          harvested.push({ handle: link.handle, via: 'link-hub', detail: `Linked from ${link.hub} → ${link.url}` });
          queue.push({ handle: link.handle, via: 'link-hub' });
        }
      }
    }
  }

  if (queue.length > 0) {
    caveats.push(`${queue.length} discovered handle(s) not swept — expansion cap (${maxExpansion}) reached. Raise maxExpansionHandles to follow them.`);
  }
  if (seedCandidatesDropped > 0) {
    // Never let a truncated list read as a complete one.
    caveats.push(`${seedCandidatesDropped} further handle candidate(s) derived from the email were not swept — raise maxExpansionHandles to follow them.`);
  }

  const groups = correlateAccounts(allAccounts, { keybaseLinks });
  const corroborated = allAccounts.filter((h) => h.identity === 'name-match');
  const mismatched = allAccounts.filter((h) => h.identity === 'name-mismatch');

  return {
    seed,
    rounds: roundResults,
    allAccounts,
    corroborated,
    mismatched,
    groups,
    keybaseLinks,
    harvested,
    handlesTried,
    durationMs: Date.now() - t0,
    caveats,
    budgetHit,
  };
}

/** Compact operator-facing text summary. */
export function formatDeepSweep(result: DeepSweepResult): string {
  const L: string[] = [];
  L.push(`DEEP SWEEP — seed @${result.seed}`);
  L.push(`${result.allAccounts.length} account(s) across ${result.handlesTried.length} handle(s) in ${(result.durationMs / 1000).toFixed(1)}s`);
  if (result.corroborated.length) L.push(`✓ ${result.corroborated.length} corroborated by name`);
  if (result.mismatched.length) L.push(`≠ ${result.mismatched.length} name mismatch (probably someone else)`);

  if (result.groups.length) {
    L.push('');
    L.push('LINKED GROUPS (same person):');
    for (const g of result.groups) {
      L.push(`  [${g.strength.toUpperCase()}] ${g.sites.join(' + ')}`);
      for (const e of g.evidence.slice(0, 4)) L.push(`      · ${e}`);
    }
  }

  if (result.keybaseLinks.length) {
    L.push('');
    L.push('KEYBASE SELF-PUBLISHED LINKS:');
    for (const l of result.keybaseLinks.slice(0, 15)) L.push(`  @${l.from} → @${l.to} (${l.service}, proof: ${l.proof})`);
  }

  if (result.harvested.length) {
    L.push('');
    L.push('HANDLES DISCOVERED:');
    for (const h of result.harvested.slice(0, 25)) L.push(`  @${h.handle} — via ${h.via}: ${h.detail}`);
  }

  const seen = new Set<string>();
  const uniq = result.allAccounts.filter((h) => !seen.has(h.url) && seen.add(h.url));
  L.push('');
  L.push('ACCOUNTS:');
  for (const h of uniq) {
    const badge = h.identity === 'name-match' ? '✓ IDENTITY MATCH' : h.identity === 'name-mismatch' ? '≠ DIFFERENT PERSON' : '? handle-only';
    const nm = h.profile?.displayName ? ` — "${h.profile.displayName}"` : '';
    L.push(`  [${h.confidence}] ${h.site} ${badge}: ${h.url}${nm}`);
  }

  if (result.caveats.length) {
    L.push('');
    L.push('CAVEATS:');
    for (const c of result.caveats) L.push(`  ! ${c}`);
  }
  return L.join('\n');
}

// ═══════════════════════════════════════════════════════════════════════════
// 7. AGENT TOOL
// ═══════════════════════════════════════════════════════════════════════════
// Registered separately from OSINT_TOOLS (which lives in osint.ts) precisely to avoid an
// import cycle: osint-correlate imports osint, so osint must not import this back.

export const OSINT_DEEP_TOOLS: CustomTool[] = [
  {
    name: 'osint_username_deep',
    description:
      'DEEP username investigation: iterative cross-site sweep. Sweeps the handle, reads the public Keybase identity graph and any link hub, harvests the handles those publish, sweeps those too, then clusters every account that shares real evidence (shared avatar, shared bio terms, near-identical handle, explicit cross-link). Prefer this over osint_username_sweep when the goal is a linked footprint rather than "does this handle exist".',
    category: 'osint',
    parameters: [
      { name: 'username', type: 'string', description: 'Seed username/handle to investigate (no @)', required: true },
      { name: 'name', type: 'string', description: "Known full name of the subject — separates the subject's accounts from a same-name stranger", required: false },
      { name: 'catalog', type: 'string', description: 'Catalog breadth for the FIRST pass: "curated" (fast), "sherlock", "full" (default). Later passes use a fast high-signal subset.', required: false },
      { name: 'rounds', type: 'number', description: 'Expansion rounds, 1-3 (default 2). Higher = deeper but slower.', required: false },
      { name: 'maxExpansionHandles', type: 'number', description: 'Cap on discovered handles to sweep, 0-25 (default 8).', required: false },
      { name: 'budgetMs', type: 'number', description: 'Wall-clock ceiling in ms (30000-1800000, default 240000). The sweep stops starting handles past it and reports what it skipped.', required: false },
      { name: 'includeAdult', type: 'boolean', description: 'Include adult platforms (excluded by default)', required: false },
    ],
    handler: async (context) => {
      const username = String(context.parameters.username || '');
      const name = context.parameters.name as string | undefined;
      const catalogRaw = String(context.parameters.catalog || 'full').toLowerCase();
      const catalog = (['curated', 'sherlock', 'full'].includes(catalogRaw) ? catalogRaw : 'full') as 'curated' | 'sherlock' | 'full';
      const rounds = Math.max(1, Math.min(3, Number(context.parameters.rounds) || 2));
      const maxExpansionHandles = Math.max(0, Math.min(25, Number(context.parameters.maxExpansionHandles) || 8));
      const budgetMs = Math.max(30_000, Math.min(1_800_000, Number(context.parameters.budgetMs) || 240_000));
      try {
        const result = await deepUsernameSweep(username, { name, catalog, rounds, maxExpansionHandles, budgetMs, includeAdult: context.parameters.includeAdult === true });
        // Only corroborated accounts become findings. An unverified handle collision is noise,
        // and a finding ledger padded with "maybe" stops being evidence.
        const findings = result.corroborated.slice(0, 20).map((h) => ({
          title: `Corroborated Social Account — ${h.site} (@${result.seed})`,
          severity: 'info' as const,
          details: `Corroborated against the subject name: ${h.url}`,
        }));
        return { success: true, output: formatDeepSweep(result), findings };
      } catch (error) {
        return { success: false, error: `Deep sweep failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
];
