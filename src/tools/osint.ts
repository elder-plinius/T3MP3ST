// =============================================================================
// OSINT ENGINE — public-source people lookup, username sweeps, breach exposure
// =============================================================================
// Every lookup here rides PUBLIC, keyless sources (site profile probes, Gravatar,
// XposedOrNot, LeakCheck public, HIBP catalog + Pwned Passwords k-anonymity).
// The deep "dump lane" (LeakCheck v2 / DeHashed / Snusbase / IntelligenceX) is
// wired but KEY-GATED via env — no key, no query, and the panel says so honestly.
//
// All HTTP goes through globalThis.fetch → undici global dispatcher, so the SOCKS
// proxy (when armed) covers OSINT egress exactly like every other recon path.
// Nothing here is an active probe of a target system: these are lookups against
// third-party public services, the same doctrine as the CVE/EPSS feed.

import { createHash } from 'crypto';
import { promises as dns } from 'dns';
import { directFetch } from '../net/proxy.js';
import { buildSherlockMergedCatalog } from './sherlock-sites.js';
import type { Credential, CustomTool } from '../types/index.js';
import { buildGoogleDorks } from './google-dorks.js';
import { DIRECTOR_SYSTEM, buildDirectorBrief, parseDirectorPicks, directorHandleCandidates, queryHasUnknownIdentifier } from './osint-aggressive.js';
import type { AggressiveSearchResult, DirectorMethodRun, DirectorPick, DirectorMethodId } from './osint-aggressive.js';

const UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const PROBE_TIMEOUT_MS = 8000;
const SWEEP_CONCURRENCY = 8;

async function osintFetch(url: string, init: RequestInit = {}): Promise<Response> {
  return globalThis.fetch(url, {
    ...init,
    headers: { 'user-agent': UA, accept: 'text/html,application/json;q=0.9,*/*;q=0.8', ...(init.headers || {}) },
    signal: (init.signal as AbortSignal) || AbortSignal.timeout(PROBE_TIMEOUT_MS),
    redirect: 'follow',
  });
}

async function fetchJson<T = unknown>(url: string, init: RequestInit = {}): Promise<T | null> {
  try {
    const r = await osintFetch(url, init);
    if (!r.ok) return null;
    return (await r.json()) as T;
  } catch {
    return null;
  }
}

// =============================================================================
// SOCIAL SITE CATALOG
// =============================================================================
// probeType semantics:
//   status             → 2xx = FOUND, 404/410 = absent, anything else = unknown
//   body_contains      → 2xx AND body contains probeValue = FOUND; 2xx without it = absent
//                        (handles soft-404 pages like t.me's "no such user")
//   json_array_nonempty→ 2xx AND JSON array with length > 0 = FOUND; [] = absent
//   json_field         → 2xx AND object field (probeValue, dotted path) truthy = FOUND
// Sherlock-derived entries add three more signals (see src/tools/sherlock-sites.ts):
//   absentMarkers       → 2xx AND body contains ANY marker = absent (soft-404 pages)
//   absentRedirectPrefix→ 2xx but the final URL lands on the error page = absent
//   usernameRegex       → non-matching username is SKIPPED, never probed
// reliability: how much a FOUND can be trusted (login walls / soft-200s downgrade it)

export type OsintSiteCategory =
  | 'social' | 'dev' | 'gaming' | 'music' | 'art' | 'forum' | 'blog' | 'money' | 'video' | 'messaging' | 'adult';

export interface OsintSite {
  name: string;
  category: OsintSiteCategory;
  /** Human-viewable profile URL ({u} = username) */
  urlTemplate: string;
  /** URL actually probed — may differ (API endpoints give clean 404s) */
  probeUrlTemplate: string;
  probeType: 'status' | 'body_contains' | 'json_array_nonempty' | 'json_field';
  probeValue?: string;
  reliability: 'high' | 'medium' | 'low';
  notes?: string;
  /** Secondary probe when the primary is rate-limited/WAF-blocked (e.g. GitHub API 403 → HTML page). */
  fallbackProbeUrlTemplate?: string;
  fallbackProbeType?: OsintSite['probeType'];
  fallbackProbeValue?: string;
  /** Any-of markers that mean ABSENT on a 2xx (Sherlock `errorType: message` carries a list). */
  absentMarkers?: string[];
  /** Final redirect target that means ABSENT (Sherlock `errorType: response_url`). */
  absentRedirectPrefix?: string;
  /** Username shape this platform accepts — a non-match is skipped, never probed
   *  (Sherlock `regexCheck`; probing an impossible username manufactures a false ABSENT). */
  usernameRegex?: string;
  /** Where this entry came from — hand-probed curated catalog vs the vendored Sherlock database. */
  source?: 'curated' | 'sherlock';
  /** Adult platform — catalogued but excluded from default sweeps. */
  adult?: boolean;
}

export const OSINT_SITES: OsintSite[] = [
  // --- developer / technical (strongest signals — clean API 404s) ---
  { name: 'GitHub', category: 'dev', urlTemplate: 'https://github.com/{u}', probeUrlTemplate: 'https://api.github.com/users/{u}', probeType: 'status', reliability: 'high', notes: 'GitHub REST API', fallbackProbeUrlTemplate: 'https://github.com/{u}', fallbackProbeType: 'body_contains', fallbackProbeValue: 'octolytics-dimension-user_login' },
  { name: 'GitLab', category: 'dev', urlTemplate: 'https://gitlab.com/{u}', probeUrlTemplate: 'https://gitlab.com/api/v4/users?username={u}', probeType: 'json_array_nonempty', reliability: 'high' },
  { name: 'Bitbucket', category: 'dev', urlTemplate: 'https://bitbucket.org/{u}/', probeUrlTemplate: 'https://api.bitbucket.org/2.0/users/{u}', probeType: 'status', reliability: 'high' },
  { name: 'npm', category: 'dev', urlTemplate: 'https://www.npmjs.com/~{u}', probeUrlTemplate: 'https://www.npmjs.com/~{u}', probeType: 'status', reliability: 'high' },
  { name: 'PyPI', category: 'dev', urlTemplate: 'https://pypi.org/user/{u}/', probeUrlTemplate: 'https://pypi.org/user/{u}/', probeType: 'status', reliability: 'medium' },
  { name: 'Docker Hub', category: 'dev', urlTemplate: 'https://hub.docker.com/u/{u}', probeUrlTemplate: 'https://hub.docker.com/u/{u}', probeType: 'status', reliability: 'medium' },
  { name: 'SourceForge', category: 'dev', urlTemplate: 'https://sourceforge.net/u/{u}/profile/', probeUrlTemplate: 'https://sourceforge.net/u/{u}/profile/', probeType: 'status', reliability: 'medium' },
  { name: 'Replit', category: 'dev', urlTemplate: 'https://replit.com/@{u}', probeUrlTemplate: 'https://replit.com/@{u}', probeType: 'status', reliability: 'medium' },
  { name: 'CodePen', category: 'dev', urlTemplate: 'https://codepen.io/{u}', probeUrlTemplate: 'https://codepen.io/{u}', probeType: 'status', reliability: 'high' },
  { name: 'HackerOne', category: 'dev', urlTemplate: 'https://hackerone.com/{u}', probeUrlTemplate: 'https://hackerone.com/{u}', probeType: 'status', reliability: 'medium' },
  { name: 'Bugcrowd', category: 'dev', urlTemplate: 'https://bugcrowd.com/{u}', probeUrlTemplate: 'https://bugcrowd.com/{u}', probeType: 'status', reliability: 'medium' },
  { name: 'Hacker News', category: 'dev', urlTemplate: 'https://news.ycombinator.com/user?id={u}', probeUrlTemplate: 'https://hn.algolia.com/api/v1/users/{u}', probeType: 'status', reliability: 'high', notes: 'Algolia public API' },
  { name: 'dev.to', category: 'dev', urlTemplate: 'https://dev.to/{u}', probeUrlTemplate: 'https://dev.to/{u}', probeType: 'status', reliability: 'high' },
  { name: 'Medium', category: 'blog', urlTemplate: 'https://medium.com/@{u}', probeUrlTemplate: 'https://medium.com/@{u}', probeType: 'status', reliability: 'medium' },
  { name: 'Hashnode', category: 'blog', urlTemplate: 'https://hashnode.com/@{u}', probeUrlTemplate: 'https://hashnode.com/@{u}', probeType: 'status', reliability: 'medium' },
  { name: 'Substack', category: 'blog', urlTemplate: 'https://{u}.substack.com', probeUrlTemplate: 'https://{u}.substack.com', probeType: 'status', reliability: 'medium' },
  { name: 'WordPress.com', category: 'blog', urlTemplate: 'https://{u}.wordpress.com', probeUrlTemplate: 'https://{u}.wordpress.com', probeType: 'status', reliability: 'high' },
  { name: 'Pastebin', category: 'dev', urlTemplate: 'https://pastebin.com/u/{u}', probeUrlTemplate: 'https://pastebin.com/u/{u}', probeType: 'status', reliability: 'high' },
  { name: 'Trello', category: 'dev', urlTemplate: 'https://trello.com/{u}', probeUrlTemplate: 'https://trello.com/{u}', probeType: 'status', reliability: 'medium' },
  { name: 'Keybase', category: 'dev', urlTemplate: 'https://keybase.io/{u}', probeUrlTemplate: 'https://keybase.io/{u}', probeType: 'status', reliability: 'high', notes: 'Keybase profiles list linked identities' },

  // --- mainstream social ---
  // MEASURED 2026-10-25 (KellyHeadley75 investigation — each platform probed with the live
  // handle, a never-registered control, AND a known-real handle): Reddit/Instagram/TikTok/
  // Facebook/Threads/Twitch/Pinterest are login- or challenge-walled from server vantages —
  // they answer 403/400 or an identical 200 app-shell for EXISTING and FAKE handles alike.
  // A status probe there cannot distinguish, so `unknown`/weak-FOUND is the honest verdict
  // and the search-engine lane (osint-searchdiscovery.ts) is the coverage for those platforms.
  { name: 'Reddit', category: 'social', urlTemplate: 'https://www.reddit.com/user/{u}', probeUrlTemplate: 'https://www.reddit.com/user/{u}/about.json', probeType: 'status', reliability: 'high', notes: 'about.json gives clean 404s — but 403s datacenter AND Tor IPs (measured 2026-10-25); unknown is honest, search lane covers' },
  { name: 'Instagram', category: 'social', urlTemplate: 'https://www.instagram.com/{u}/', probeUrlTemplate: 'https://www.instagram.com/{u}/', probeType: 'status', reliability: 'low', notes: '200 app-shell for existing AND fake handles, no og markers to datacenter IPs (measured 2026-10-25) — FOUND weak; search lane is the real coverage' },
  { name: 'TikTok', category: 'video', urlTemplate: 'https://www.tiktok.com/@{u}', probeUrlTemplate: 'https://www.tiktok.com/@{u}', probeType: 'status', reliability: 'low', notes: '200-challenges real and control alike; oembed refuses keyless (measured 2026-10-25) — rely on the search lane' },
  { name: 'X (Twitter)', category: 'social', urlTemplate: 'https://x.com/{u}', probeUrlTemplate: 'https://syndication.twitter.com/srv/timeline-profile/screen-name/{u}', probeType: 'body_contains', probeValue: '"headerProps":{"screenName"', reliability: 'medium', notes: 'syndication embed oracle — x.com itself serves the logged-out 404 shell for real AND fake; the embed echoes headerProps only for a handle that exists (measured 2026-10-25: jack/NASA echo it, target and control omit it)' },
  { name: 'Threads', category: 'social', urlTemplate: 'https://www.threads.net/@{u}', probeUrlTemplate: 'https://www.threads.net/@{u}', probeType: 'status', reliability: 'low', notes: '200 app-shell for real and control (measured 2026-10-25) — FOUND weak' },
  { name: 'Facebook', category: 'social', urlTemplate: 'https://www.facebook.com/{u}', probeUrlTemplate: 'https://www.facebook.com/{u}', probeType: 'status', reliability: 'low', notes: 'answers 400 to unauthenticated probes from datacenter AND Tor vantages (measured 2026-10-25) — unknown is honest; search lane covers' },
  { name: 'Mastodon (social)', category: 'social', urlTemplate: 'https://mastodon.social/@{u}', probeUrlTemplate: 'https://mastodon.social/@{u}', probeType: 'status', reliability: 'high' },
  { name: 'Bluesky', category: 'social', urlTemplate: 'https://bsky.app/profile/{u}', probeUrlTemplate: 'https://public.api.bsky.app/xrpc/app.bsky.actor.getProfiles?actors={u}', probeType: 'json_field', probeValue: 'profiles.0.did', reliability: 'high', notes: 'public AppView API' },
  { name: 'Telegram', category: 'messaging', urlTemplate: 'https://t.me/{u}', probeUrlTemplate: 'https://t.me/{u}', probeType: 'body_contains', probeValue: 'tgme_page_title', reliability: 'high', notes: 'soft-404 page stays 200 — body-detect needed' },
  { name: 'Pinterest', category: 'social', urlTemplate: 'https://www.pinterest.com/{u}/', probeUrlTemplate: 'https://www.pinterest.com/{u}/', probeType: 'status', reliability: 'low', notes: '200 app-shell for real and control (measured 2026-10-25) — FOUND weak; search lane covers' },
  { name: 'Tumblr', category: 'blog', urlTemplate: 'https://{u}.tumblr.com', probeUrlTemplate: 'https://{u}.tumblr.com', probeType: 'status', reliability: 'high' },
  { name: 'VK', category: 'social', urlTemplate: 'https://vk.com/{u}', probeUrlTemplate: 'https://vk.com/{u}', probeType: 'status', reliability: 'low', notes: 'auth wall' },
  { name: 'Truth Social', category: 'social', urlTemplate: 'https://truthsocial.com/@{u}', probeUrlTemplate: 'https://truthsocial.com/@{u}', probeType: 'status', reliability: 'medium' },
  { name: 'Gab', category: 'social', urlTemplate: 'https://gab.com/{u}', probeUrlTemplate: 'https://gab.com/{u}', probeType: 'status', reliability: 'medium' },
  { name: 'Linktree', category: 'social', urlTemplate: 'https://linktr.ee/{u}', probeUrlTemplate: 'https://linktr.ee/{u}', probeType: 'status', reliability: 'high', notes: 'link hubs often reveal the full footprint' },
  { name: 'about.me', category: 'social', urlTemplate: 'https://about.me/{u}', probeUrlTemplate: 'https://about.me/{u}', probeType: 'status', reliability: 'medium' },
  { name: 'Gravatar', category: 'social', urlTemplate: 'https://gravatar.com/{u}', probeUrlTemplate: 'https://gravatar.com/{u}', probeType: 'status', reliability: 'medium', notes: 'profiles can list linked accounts' },
  { name: 'Imgur', category: 'social', urlTemplate: 'https://imgur.com/user/{u}', probeUrlTemplate: 'https://imgur.com/user/{u}', probeType: 'status', reliability: 'medium' },
  { name: '9GAG', category: 'social', urlTemplate: 'https://9gag.com/u/{u}', probeUrlTemplate: 'https://9gag.com/u/{u}', probeType: 'status', reliability: 'medium' },
  { name: 'Duolingo', category: 'social', urlTemplate: 'https://www.duolingo.com/profile/{u}', probeUrlTemplate: 'https://www.duolingo.com/profile/{u}', probeType: 'status', reliability: 'medium' },

  // --- streaming / video ---
  { name: 'Twitch', category: 'video', urlTemplate: 'https://www.twitch.tv/{u}', probeUrlTemplate: 'https://www.twitch.tv/{u}', probeType: 'status', reliability: 'low', notes: '200 app-shell for real and control from datacenter vantage (measured 2026-10-25: summit1g 200 with title, control 200 shell) — FOUND weak' },
  { name: 'YouTube', category: 'video', urlTemplate: 'https://www.youtube.com/@{u}', probeUrlTemplate: 'https://www.youtube.com/@{u}', probeType: 'status', reliability: 'high', notes: 'handle pages 404 cleanly when unclaimed (measured 2026-10-25: live handle 200 with og:title, control 404)' },
  { name: 'Vimeo', category: 'video', urlTemplate: 'https://vimeo.com/{u}', probeUrlTemplate: 'https://vimeo.com/{u}', probeType: 'status', reliability: 'high', notes: 'profile pages 404 cleanly when unclaimed (measured 2026-10-25: staff account 200, target+control 404)' },
  { name: 'Rumble', category: 'video', urlTemplate: 'https://rumble.com/user/{u}', probeUrlTemplate: 'https://rumble.com/user/{u}', probeType: 'status', reliability: 'medium' },
  { name: 'Odysee', category: 'video', urlTemplate: 'https://odysee.com/@{u}', probeUrlTemplate: 'https://odysee.com/@{u}', probeType: 'status', reliability: 'medium' },

  // --- music / audio ---
  { name: 'SoundCloud', category: 'music', urlTemplate: 'https://soundcloud.com/{u}', probeUrlTemplate: 'https://soundcloud.com/{u}', probeType: 'status', reliability: 'high', notes: 'clean 404 oracle (measured 2026-10-25: known-real artist 200, target+control 404)' },
  { name: 'Last.fm', category: 'music', urlTemplate: 'https://www.last.fm/user/{u}', probeUrlTemplate: 'https://www.last.fm/user/{u}', probeType: 'status', reliability: 'high' },
  { name: 'Bandcamp', category: 'music', urlTemplate: 'https://{u}.bandcamp.com', probeUrlTemplate: 'https://{u}.bandcamp.com', probeType: 'status', reliability: 'high' },
  { name: 'Mixcloud', category: 'music', urlTemplate: 'https://www.mixcloud.com/{u}/', probeUrlTemplate: 'https://www.mixcloud.com/{u}/', probeType: 'status', reliability: 'medium' },

  // --- art / photography ---
  { name: 'DeviantArt', category: 'art', urlTemplate: 'https://www.deviantart.com/{u}', probeUrlTemplate: 'https://www.deviantart.com/{u}', probeType: 'status', reliability: 'medium' },
  { name: 'ArtStation', category: 'art', urlTemplate: 'https://www.artstation.com/{u}', probeUrlTemplate: 'https://www.artstation.com/{u}', probeType: 'status', reliability: 'high' },
  { name: 'Behance', category: 'art', urlTemplate: 'https://www.behance.net/{u}', probeUrlTemplate: 'https://www.behance.net/{u}', probeType: 'status', reliability: 'medium' },
  { name: 'Dribbble', category: 'art', urlTemplate: 'https://dribbble.com/{u}', probeUrlTemplate: 'https://dribbble.com/{u}', probeType: 'status', reliability: 'medium' },
  { name: '500px', category: 'art', urlTemplate: 'https://500px.com/p/{u}', probeUrlTemplate: 'https://500px.com/p/{u}', probeType: 'status', reliability: 'medium' },
  { name: 'Flickr', category: 'art', urlTemplate: 'https://www.flickr.com/people/{u}', probeUrlTemplate: 'https://www.flickr.com/people/{u}', probeType: 'status', reliability: 'medium' },
  { name: 'Unsplash', category: 'art', urlTemplate: 'https://unsplash.com/@{u}', probeUrlTemplate: 'https://unsplash.com/@{u}', probeType: 'status', reliability: 'medium' },
  { name: 'Redbubble', category: 'art', urlTemplate: 'https://www.redbubble.com/people/{u}/shop', probeUrlTemplate: 'https://www.redbubble.com/people/{u}/shop', probeType: 'status', reliability: 'medium' },

  // --- gaming ---
  { name: 'Steam', category: 'gaming', urlTemplate: 'https://steamcommunity.com/id/{u}', probeUrlTemplate: 'https://steamcommunity.com/id/{u}', probeType: 'body_contains', probeValue: 'Invalid search term', reliability: 'medium', notes: 'ABSENT when that soft-404 string appears' },
  { name: 'chess.com', category: 'gaming', urlTemplate: 'https://www.chess.com/member/{u}', probeUrlTemplate: 'https://api.chess.com/pub/player/{u}', probeType: 'status', reliability: 'high', notes: 'public player API' },
  { name: 'Lichess', category: 'gaming', urlTemplate: 'https://lichess.org/@/{u}', probeUrlTemplate: 'https://lichess.org/@/{u}', probeType: 'status', reliability: 'high' },
  { name: 'HackerRank', category: 'gaming', urlTemplate: 'https://www.hackerrank.com/profile/{u}', probeUrlTemplate: 'https://www.hackerrank.com/profile/{u}', probeType: 'status', reliability: 'medium' },
  { name: 'LeetCode', category: 'gaming', urlTemplate: 'https://leetcode.com/{u}/', probeUrlTemplate: 'https://leetcode.com/{u}/', probeType: 'status', reliability: 'medium' },
  { name: 'Minecraft (NameMC)', category: 'gaming', urlTemplate: 'https://namemc.com/profile/{u}', probeUrlTemplate: 'https://namemc.com/profile/{u}', probeType: 'status', reliability: 'medium' },
  { name: 'speedrun.com', category: 'gaming', urlTemplate: 'https://speedrun.com/users/{u}', probeUrlTemplate: 'https://speedrun.com/api/v1/users?lookup={u}', probeType: 'json_array_nonempty', reliability: 'high' },

  // --- money / support ---
  { name: 'Cash App', category: 'money', urlTemplate: 'https://cash.app/${u}', probeUrlTemplate: 'https://cash.app/${u}', probeType: 'status', reliability: 'high', notes: 'cashtag pages 404 cleanly when unclaimed (measured 2026-10-25: live cashtag 200 + embedded `var profile` JSON with display_name/is_verified_account/country, control 404)' },
  { name: 'Venmo', category: 'money', urlTemplate: 'https://venmo.com/u/{u}', probeUrlTemplate: 'https://venmo.com/u/{u}', probeType: 'status', reliability: 'high', notes: 'profile pages 404 cleanly when unclaimed (measured 2026-10-25: @venmo 200, target+control 404)' },
  { name: 'Patreon', category: 'money', urlTemplate: 'https://www.patreon.com/{u}', probeUrlTemplate: 'https://www.patreon.com/{u}', probeType: 'status', reliability: 'medium' },
  { name: 'Ko-fi', category: 'money', urlTemplate: 'https://ko-fi.com/{u}', probeUrlTemplate: 'https://ko-fi.com/{u}', probeType: 'status', reliability: 'medium' },
  { name: 'Buy Me a Coffee', category: 'money', urlTemplate: 'https://buymeacoff.ee/{u}', probeUrlTemplate: 'https://buymeacoff.ee/{u}', probeType: 'status', reliability: 'medium' },
];

// =============================================================================
// SHERLOCK MERGE — the curated catalog above plus the vendored Sherlock database
// (tools/sherlock/data.json). Curated entries win on name collision because they
// carry API probes + identity corroboration a generic page check cannot.
// Cached once per process; the database is ~480 entries and read from disk.
// =============================================================================
let mergedCatalogCache: ReturnType<typeof buildSherlockMergedCatalog> | null = null;

export function getMergedSiteCatalog() {
  if (!mergedCatalogCache) mergedCatalogCache = buildSherlockMergedCatalog(OSINT_SITES);
  return mergedCatalogCache;
}

// Steam's probe is inverted (the marker string means ABSENT) — encode via a
// dedicated probeType so the classifier stays dumb and correct.
type EffectiveProbeType = OsintSite['probeType'] | 'body_missing';

interface ResolvedSite extends OsintSite {
  effectiveProbeType: EffectiveProbeType;
}

function resolveSite(site: OsintSite): ResolvedSite {
  if (site.name === 'Steam') return { ...site, effectiveProbeType: 'body_missing' };
  return { ...site, effectiveProbeType: site.probeType };
}

export function normalizeUsername(raw: string): string {
  return raw.trim().replace(/^@+/, '').replace(/\/+$/, '');
}

export function validateUsername(username: string): string | null {
  const u = normalizeUsername(username);
  if (!u || u.length > 64 || /[/\\?#@\s]/.test(u)) return null;
  return u;
}

function dig(obj: unknown, path: string): unknown {
  let cur: unknown = obj;
  for (const part of path.split('.')) {
    if (cur === null || typeof cur !== 'object') return undefined;
    cur = (cur as Record<string, unknown>)[part];
  }
  return cur;
}

export type IdentityMatch = 'name-match' | 'name-mismatch' | 'handle-only';

export interface ProfileHint {
  displayName?: string;
  bio?: string;
  imageUrl?: string;
  /** Public contact/location fields the platform exposes on the profile itself. */
  email?: string;
  blog?: string;
  twitter?: string;
  location?: string;
}

export interface UsernameHit {
  site: string;
  category: OsintSiteCategory;
  url: string;
  status: 'found' | 'absent' | 'unknown';
  confidence: 'high' | 'medium' | 'low';
  probeStatus?: number;
  note?: string;
  /** Profile details pulled from the platform's public API on a FOUND hit. */
  profile?: ProfileHint;
  /** Is this account corroborated as the subject, or just a claimed handle? */
  identity?: IdentityMatch;
}

/** Cheap public profile lookups for identity corroboration on FOUND hits. Each spec
 *  is URL + parser so the corroborator can run it via egress AND fall back to Tor. */
const PROFILE_APIS: Record<string, (u: string) => { url: string; parse: (j: unknown) => ProfileHint | null }> = {
  GitHub: (u) => ({
    url: `https://api.github.com/users/${encodeURIComponent(u)}`,
    parse: (j) => {
      const r = j as Record<string, string | null>;
      if (!r || (!r.name && !r.avatar_url && !r.email)) return null;
      return {
        displayName: (r.name as string) || undefined,
        bio: (r.bio as string) || undefined,
        imageUrl: (r.avatar_url as string) || undefined,
        email: (r.email as string) || undefined,
        blog: (r.blog as string) || undefined,
        twitter: (r.twitter_username as string) ? `https://x.com/${r.twitter_username}` : undefined,
        location: (r.location as string) || undefined,
      };
    },
  }),
  Reddit: (u) => ({
    url: `https://www.reddit.com/user/${encodeURIComponent(u)}/about.json`,
    parse: (j) => {
      const data = (j as { data?: { name?: string; title?: string; icon_img?: string } })?.data;
      return data ? { displayName: data.title || data.name || undefined, imageUrl: data.icon_img || undefined } : null;
    },
  }),
  'chess.com': (u) => ({
    url: `https://api.chess.com/pub/player/${encodeURIComponent(u)}`,
    parse: (j) => {
      const r = j as { name?: string; avatar?: string };
      return r ? { displayName: r.name || undefined, imageUrl: r.avatar || undefined } : null;
    },
  }),
  'dev.to': (u) => ({
    url: `https://dev.to/api/users/by_username?url=${encodeURIComponent(u)}`,
    parse: (j) => {
      const r = j as { username?: string; name?: string; profile_image?: string; summary?: string };
      return r?.username ? { displayName: r.name || undefined, imageUrl: r.profile_image || undefined, bio: r.summary || undefined } : null;
    },
  }),
  Lichess: (u) => ({
    url: `https://lichess.org/api/user/${encodeURIComponent(u)}`,
    parse: (j) => {
      const r = j as { profile?: { fullName?: string; bio?: string }; lastName?: string; firstName?: string };
      if (!r) return null;
      const fullName = r.profile?.fullName || [r.firstName, r.lastName].filter(Boolean).join(' ') || undefined;
      return { displayName: fullName || undefined, bio: r.profile?.bio || undefined };
    },
  }),
  'Hacker News': (u) => ({
    url: `https://hn.algolia.com/api/v1/users/${encodeURIComponent(u)}`,
    parse: (j) => ((j as { id?: string })?.id ? {} : null),
  }),
};

async function corroborate(siteName: string, username: string): Promise<ProfileHint | null> {
  const spec = PROFILE_APIS[siteName];
  if (!spec) return null;
  const { url, parse } = spec(username);
  try {
    const j = await fetchJson<unknown>(url);
    const hint = j ? parse(j) : null;
    if (hint) return hint;
  } catch { /* fall through to Tor */ }
  const tor = await torStatus();
  if (tor.available) {
    try {
      const page = await torFetchAny(url);
      if (page.status === 200) return parse(JSON.parse(page.body));
    } catch { /* fall through to direct */ }
  }
  if (directAllowed()) {
    try {
      const res = await directFetch(url, {
        headers: { 'user-agent': UA, accept: 'application/json' },
        signal: AbortSignal.timeout(12_000),
      } as never);
      if (res.status === 200) return parse(await res.json());
    } catch { /* all paths failed — handle-only */ }
  }
  return null;
}

/** Corroborate a claimed handle against the subject's known name. Pure function.
 *  'name-match'    = display name/bio carries the subject's LAST name (full or
 *                    substring — initials-style 'jsmith' counts), or the full name.
 *  'name-mismatch' = profile has a display name that does NOT carry the last name
 *                    (e.g. subject 'Raul Glasgow', profile 'Raul Gutierrez' — a
 *                    first-name-only overlap is a DIFFERENT person, never a match).
 *  'handle-only'   = no name hints, ambiguous initial-only, or no name to compare. */
export function scoreIdentityMatch(hints: { name?: string }, profile?: ProfileHint | null): IdentityMatch {
  const hintName = (hints.name || '').toLowerCase().replace(/[^a-z ]/g, ' ').replace(/\s+/g, ' ').trim();
  if (!hintName || !hintName.includes(' ')) return 'handle-only'; // need a real full name to corroborate
  const hTokens = hintName.split(' ').filter((t) => t.length > 1);
  const lastName = hTokens[hTokens.length - 1];
  const dn = (profile?.displayName || '').toLowerCase().replace(/[^a-z ]/g, ' ').replace(/\s+/g, ' ').trim();
  const dTokens = dn ? dn.split(' ').filter((t) => t.length > 1) : [];
  const sub = (a: string, b: string) => a.includes(b) || b.includes(a);

  if (dTokens.length > 0) {
    if (hTokens.every((t) => dTokens.includes(t))) return 'name-match';
    // Last name present (exact, or substring of/into a real name fragment ≥3 chars —
    // initials like 't' never substring-match).
    if (dTokens.some((d) => d === lastName || (d.length >= 3 && (d.includes(lastName) || lastName.includes(d))))) return 'name-match';
    const firstOverlap = hTokens.slice(0, -1).some((t) => dTokens.some((d) => sub(d, t)));
    if (firstOverlap) return 'name-mismatch'; // shares a first name only — different person (initial-only ambiguity excluded too)
    return 'name-mismatch';
  }
  const bio = (profile?.bio || '').toLowerCase();
  if (bio && hTokens.every((t) => bio.includes(t))) return 'name-match';
  return dn ? 'name-mismatch' : 'handle-only';
}

interface ProbeOutcome { status: number; body?: string; via: 'egress' | 'tor'; url: string; finalUrl?: string; note?: string }

function classifyOutcome(site: ResolvedSite, outcome: ProbeOutcome): Pick<UsernameHit, 'status' | 'probeStatus' | 'note'> {
  const ok = outcome.status >= 200 && outcome.status < 300;
  let status: UsernameHit['status'] = 'unknown';
  if (site.effectiveProbeType === 'status' && !site.absentMarkers && !site.absentRedirectPrefix) {
    if (ok) status = 'found';
    else if (outcome.status === 404 || outcome.status === 410) status = 'absent';
  } else if (ok) {
    const body = outcome.body ?? '';
    // Sherlock `errorType: message` — a 2xx whose body carries ANY known error
    // marker means the profile does not exist (soft-404). Checked before the
    // generic marker probes so a curated body_contains site still behaves.
    if (site.absentMarkers?.length) {
      status = site.absentMarkers.some((m) => body.includes(m)) ? 'absent' : 'found';
    } else if (site.absentRedirectPrefix) {
      // Sherlock `errorType: response_url` — the site redirects a missing profile
      // to a known error page, so the FINAL url is the signal, not the status.
      const finalUrl = outcome.finalUrl || outcome.url;
      status = finalUrl.startsWith(site.absentRedirectPrefix) ? 'absent' : 'found';
    } else {
      const has = site.probeValue ? body.includes(site.probeValue) : false;
      if (site.effectiveProbeType === 'body_contains') status = has ? 'found' : 'absent';
      else if (site.effectiveProbeType === 'body_missing') status = has ? 'absent' : 'found';
      else if (site.effectiveProbeType === 'json_array_nonempty') {
        try { status = Array.isArray(JSON.parse(body || '[]')) && JSON.parse(body).length > 0 ? 'found' : 'absent'; } catch { status = 'unknown'; }
      } else if (site.effectiveProbeType === 'json_field') {
        try { status = dig(JSON.parse(body || '{}'), site.probeValue || '') ? 'found' : 'absent'; } catch { status = 'unknown'; }
      }
    }
  } else if (outcome.status === 404 || outcome.status === 410) {
    status = 'absent';
  }
  const note = outcome.via === 'tor' ? 'probe via Tor circuit' : outcome.note;
  return { status, probeStatus: outcome.status, note };
}

async function probeEgress(url: string, readBody: boolean): Promise<ProbeOutcome> {
  const res = await osintFetch(url);
  const body = readBody ? (await res.text().catch(() => '')).slice(0, 300_000) : undefined;
  return { status: res.status, body, url, finalUrl: res.url || url, via: 'egress' };
}

async function probeViaTor(url: string): Promise<ProbeOutcome | null> {
  const tor = await torStatus();
  if (!tor.available) return null;
  try {
    const page = await torFetchAny(url);
    return { status: page.status, body: page.body.slice(0, 300_000), url, finalUrl: page.finalUrl || url, via: 'tor' };
  } catch {
    return null;
  }
}

/** Last-resort path for third-party OSINT lookups: connect DIRECT (real IP visible
 *  to the data platform — not a mission target). Kill-switch: T3MP3ST_OSINT_ALLOW_DIRECT=0. */
function directAllowed(): boolean {
  return !/^(0|false|no|off)$/i.test(process.env.T3MP3ST_OSINT_ALLOW_DIRECT ?? '1');
}

async function probeDirect(url: string, readBody: boolean): Promise<ProbeOutcome | null> {
  if (!directAllowed()) return null;
  try {
    const res = await directFetch(url, {
      headers: { 'user-agent': UA, accept: 'text/html,application/json;q=0.9,*/*;q=0.8' },
      signal: AbortSignal.timeout(15_000),
      redirect: 'follow',
    } as never);
    const body = readBody ? (await res.text().catch(() => '')).slice(0, 300_000) : undefined;
    return { status: res.status, body, url, finalUrl: res.url || url, via: 'egress', note: '⚠ direct connection (real IP seen by platform) — set T3MP3ST_OSINT_ALLOW_DIRECT=0 to disable' };
  } catch {
    return null;
  }
}

/** Same egress → Tor → direct ladder the site probes use, exported for the search-engine
 *  discovery lane (osint-searchdiscovery.ts) — it must ride the identical transport, not a
 *  bare global fetch that skips the operator's proxy posture. Never throws: status 0 = dead.
 *  `init` carries method/body for POST form endpoints (e.g. the BOP inmate locator). The Tor
 *  leg is GET-only (torFetchAny has no POST), so a bodied request escalates egress → direct. */
export interface EgressProbeResult { status: number; body: string; via: 'egress' | 'tor' | 'direct' | 'none'; note?: string }

export async function egressProbe(url: string, timeoutMs = 20_000, init: { method?: string; body?: string; headers?: Record<string, string> } = {}): Promise<EgressProbeResult> {
  // Mirror probeSite's escalation rule: 403/429/5xx from the egress is an UNCLEAR verdict
  // (WAFs answer those to scripted clients), never an answer. Measured live 2026-10-25:
  // cash.app 403'd the shared egress and 200'd straight through Tor — accepting the 403
  // killed the cashtag bootstrap and, with it, the name that unlocks the search lane.
  const clear = (s: number) => s !== 403 && s !== 429 && s < 500;
  let egress: EgressProbeResult | null = null;
  try {
    const res = await osintFetch(url, { signal: AbortSignal.timeout(timeoutMs), ...init, headers: { ...(init.headers || {}) } });
    const body = (await res.text().catch(() => '')).slice(0, 300_000);
    const r: EgressProbeResult = { status: res.status, body, via: 'egress' };
    if (clear(res.status)) return r;
    egress = r;
  } catch { /* fall through to Tor */ }
  const bodied = Boolean(init.body);
  if (!bodied) {
    const tor = await probeViaTor(url);
    if (tor && clear(tor.status)) return { status: tor.status, body: tor.body || '', via: 'tor', note: tor.note };
  }
  if (directAllowed()) {
    try {
      const res = await directFetch(url, {
        signal: AbortSignal.timeout(timeoutMs),
        redirect: 'follow',
        ...init,
        headers: { 'user-agent': UA, 'accept-language': 'en-US,en;q=0.9', ...(init.headers || {}) },
      } as never);
      const body = (await res.text().catch(() => '')).slice(0, 300_000);
      return { status: res.status, body, via: 'direct', note: 'direct connection (real IP seen)' };
    } catch { /* all paths dead */ }
  }
  return egress ?? { status: 0, body: '', via: 'none' };
}

/** Extract a display name from a GitHub profile HTML page (fallback path when the API is rate-limited). */
function githubDisplayNameFromHtml(html: string, username: string): string | undefined {
  const title = html.match(/<title>([^<]+)<\/title>/)?.[1] || '';
  const m = title.match(new RegExp(`${username} \\(([^)]+)\\)`, 'i'));
  return m?.[1] || undefined;
}

async function probeSite(site: ResolvedSite, username: string, hints?: { name?: string }): Promise<UsernameHit> {
  const enc = encodeURIComponent(username).replace(/%40/g, '@');
  const url = site.probeUrlTemplate.replaceAll('{u}', enc);
  const humanUrl = site.urlTemplate.replaceAll('{u}', enc);
  const base: UsernameHit = {
    site: site.name,
    category: site.category,
    url: humanUrl,
    status: 'unknown',
    confidence: site.reliability,
  };

  // Sherlock `regexCheck` — a username this platform can never accept would
  // answer with a guaranteed-miss page. Probing it manufactures a false ABSENT,
  // so the site is left UNPROBED and reported as unknown with the reason.
  if (site.usernameRegex) {
    let shapeOk = true;
    try { shapeOk = new RegExp(site.usernameRegex).test(username); } catch { shapeOk = true; }
    if (!shapeOk) {
      base.note = `not probed — "${username}" cannot exist on this platform (username shape)`;
      return base;
    }
  }

  // A body is needed whenever the classifier reads it — including the Sherlock
  // soft-404 marker list, which rides on a 2xx response.
  const needsBody = (t: OsintSite['probeType'] | 'body_missing') =>
    t !== 'status' || Boolean(site.absentMarkers?.length) || Boolean(site.absentRedirectPrefix);

  // — Pass 1: primary probe over normal egress —
  let outcome: ProbeOutcome | null = null;
  try {
    const first = await probeEgress(url, needsBody(site.effectiveProbeType));
    if (first.status === 403 || first.status === 429 || first.status >= 500) outcome = null; // unclear — escalate
    else outcome = first;
  } catch {
    outcome = null;
  }

  // — Pass 2: fallback probe (e.g. HTML page when the JSON API is rate-limited) —
  let usedFallback = false;
  if (!outcome && site.fallbackProbeUrlTemplate) {
    try {
      const fbUrl = site.fallbackProbeUrlTemplate.replaceAll('{u}', enc);
      const res = await osintFetch(fbUrl, { signal: AbortSignal.timeout(18_000) });
      if (res.status === 200 || res.status === 404 || res.status === 410) {
        const text = res.status === 200 ? (await res.text().catch(() => '')).slice(0, 300_000) : '';
        usedFallback = true;
        outcome = { status: res.status, body: text, url: fbUrl, finalUrl: res.url || fbUrl, via: 'egress', note: 'API rate-limited — classified via HTML page' };
      }
    } catch { /* fallback failed — escalate to Tor */ }
  }

  // — Pass 3: primary probe over the Tor circuit (fresh exit beats WAF blocks) —
  if (!outcome) {
    outcome = (await probeViaTor(site.fallbackProbeUrlTemplate?.replaceAll('{u}', enc) || url))
      || (await probeViaTor(url));
  }

  // — Pass 4: direct connection (real IP) — accuracy lever for platforms that
  //   rate-limit/block the shared proxy and Tor exits. Marked on the hit. —
  if (!outcome && directAllowed()) {
    try {
      const probeUrl = (usedFallback ? site.fallbackProbeUrlTemplate : site.probeUrlTemplate)?.replaceAll('{u}', enc) || url;
      const bodyNeeded = needsBody((usedFallback ? site.fallbackProbeType : site.effectiveProbeType) || 'status');
      outcome = await probeDirect(probeUrl, bodyNeeded);
    } catch { /* direct failed too */ }
  }

  if (!outcome) {
    base.note = 'unreachable via egress, Tor and direct (set T3MP3ST_OSINT_ALLOW_DIRECT=1 — default on)';
    return base;
  }

  // — Classify —
  const eff: ResolvedSite = usedFallback
    ? { ...site, effectiveProbeType: (site.fallbackProbeType || site.effectiveProbeType) as EffectiveProbeType, probeValue: site.fallbackProbeValue || site.probeValue }
    : site;
  const classified = classifyOutcome(eff, outcome);
  Object.assign(base, classified);

  // — Corroborate identity on FOUND hits —
  if (base.status === 'found') {
    let profile: ProfileHint | null = null;
    if (usedFallback && site.name === 'GitHub' && outcome.body) {
      const dn = githubDisplayNameFromHtml(outcome.body, username);
      if (dn) profile = { displayName: dn };
    }
    if (!profile && PROFILE_APIS[site.name]) {
      profile = await corroborate(site.name, username);
    }
    if (profile) base.profile = profile;
    base.identity = scoreIdentityMatch(hints || {}, profile);
  }
  return base;
}

export interface SweepResult {
  username: string;
  found: UsernameHit[];
  absent: number;
  unknown: UsernameHit[];
  checked: number;
  /** Per-site probe results (found/absent/unknown) — the sources-consulted audit trail. */
  details: UsernameHit[];
  durationMs: number;
  /** Sites left unprobed because the username cannot exist there (Sherlock regexCheck). */
  skippedByShape: string[];
}

/** Concurrent username sweep across the public-profile catalog (Sherlock-style, keyless).
 *  `customSites` (test/harness hook) probes caller-supplied site specs instead of the
 *  catalog — used by the unit tests to exercise the classifier against a local stub.
 *
 *  `catalog` selects the breadth: 'curated' (hand-probed, fastest, cleanest signals),
 *  'sherlock' (the vendored Sherlock database only), or 'full' (curated + Sherlock).
 *  Adult platforms are catalogued but excluded unless 'adult' is asked for explicitly. */
export async function runUsernameSweep(
  usernameRaw: string,
  opts: {
    sites?: string[];
    categories?: OsintSiteCategory[];
    limit?: number;
    customSites?: OsintSite[];
    hints?: { name?: string };
    catalog?: 'curated' | 'sherlock' | 'full';
    includeAdult?: boolean;
  } = {}
): Promise<SweepResult> {
  const started = Date.now();
  const username = validateUsername(usernameRaw);
  if (!username) throw new Error(`Invalid username: ${usernameRaw}`);

  let sites: ResolvedSite[];
  if (opts.customSites?.length) {
    sites = opts.customSites.map(resolveSite);
  } else {
    const mode = opts.catalog || 'full';
    if (mode === 'curated') {
      sites = OSINT_SITES.map(resolveSite);
    } else {
      const merged = getMergedSiteCatalog();
      const pool = mode === 'sherlock' ? merged.catalog.filter((s) => s.source === 'sherlock') : merged.catalog;
      sites = pool.map(resolveSite);
    }
    if (!opts.includeAdult && !opts.categories?.includes('adult')) {
      sites = sites.filter((s) => !s.adult && s.category !== 'adult');
    }
    if (opts.sites?.length) {
      const wanted = new Set(opts.sites.map((s) => s.toLowerCase()));
      sites = sites.filter((s) => wanted.has(s.name.toLowerCase()));
    }
    if (opts.categories?.length) {
      const cats = new Set(opts.categories);
      sites = sites.filter((s) => cats.has(s.category));
    }
    if (opts.limit && opts.limit > 0) sites = sites.slice(0, opts.limit);
  }
  if (sites.length === 0) throw new Error('No sites to probe — check the site filter');

  const results: UsernameHit[] = [];
  for (let i = 0; i < sites.length; i += SWEEP_CONCURRENCY) {
    const batch = sites.slice(i, i + SWEEP_CONCURRENCY);
    results.push(...(await Promise.all(batch.map((s) => probeSite(s, username, opts.hints)))));
  }

  const found = results.filter((r) => r.status === 'found');
  const unknown = results.filter((r) => r.status === 'unknown');
  return {
    username,
    found,
    absent: results.filter((r) => r.status === 'absent').length,
    unknown,
    checked: results.length,
    details: results,
    durationMs: Date.now() - started,
    skippedByShape: results
      .filter((r) => r.status === 'unknown' && r.note?.includes('cannot exist on this platform'))
      .map((r) => r.site),
  };
}

// =============================================================================
// EMAIL INTEL — Gravatar identity + breach exposure (all keyless)
// =============================================================================

export interface GravatarProfile {
  hash: string;
  exists: boolean;
  avatarUrl: string;
  displayName?: string;
  about?: string;
  location?: string;
  links?: { title?: string; url: string }[];
  accounts?: { shortname: string; url: string; username?: string }[];
}

interface GravatarEntry {
  entry?: {
    hash?: string;
    displayName?: string;
    aboutMe?: string;
    currentLocation?: string;
    links?: { title?: string; url?: string }[];
    accounts?: { shortname?: string; url?: string; username?: string }[];
  }[];
}

export async function gravatarProfile(email: string): Promise<GravatarProfile> {
  const hash = createHash('md5').update(email.trim().toLowerCase()).digest('hex');
  const profile: GravatarProfile = {
    hash,
    exists: false,
    avatarUrl: `https://www.gravatar.com/avatar/${hash}?s=256`,
  };
  try {
    const avatarCheck = await osintFetch(`https://www.gravatar.com/avatar/${hash}?d=404&s=1`);
    profile.exists = avatarCheck.ok;
  } catch {
    /* network hiccup — leave exists=false but try the profile JSON anyway */
  }
  const data = await fetchJson<GravatarEntry>(`https://www.gravatar.com/${hash}.json`);
  const entry = data?.entry?.[0];
  if (entry) {
    profile.displayName = entry.displayName;
    profile.about = entry.aboutMe;
    profile.location = entry.currentLocation;
    profile.links = (entry.links || []).filter((l): l is { title?: string; url: string } => Boolean(l.url));
    profile.accounts = (entry.accounts || []).filter((a): a is { shortname: string; url: string; username?: string } => Boolean(a.url));
  }
  return profile;
}

export interface BreachSummary {
  service: string;
  found: number | 'unknown';
  fields?: string[];
  sources?: string[];
  note?: string;
}

interface LeakcheckPublicResponse { success?: boolean; found?: number; fields?: string[]; sources?: { name: string; date: string }[]; error?: string; message?: string }
interface XposedornotResponse { exposed?: string; breaches?: string[][]; breach?: string[] }

/** LeakCheck PUBLIC API — free, no key. Returns WHICH breaches an identifier is in
 *  and WHAT data classes were exposed, never the values. Live-verified: it also
 *  answers phone numbers (the docs only list email/hash/username), so we do not
 *  refuse those — the response shape is identical. Rate limit is 1 req/sec.
 *
 *  This deliberately runs the egress → Tor → direct fallback chain rather than a
 *  bare osintFetch: the bare path rides the armed SOCKS dispatcher and dies with
 *  "TypeError: fetch failed" whenever that proxy is unreachable, which silently
 *  turned this (and every other bare-fetch free lane) into a false "unknown".
 *  Live-verified on :3333 with the proxy down — the fallback answered with real
 *  data while the bare fetch failed. */
export async function leakcheckPublic(query: string): Promise<BreachSummary> {
  let r: { status: number; body: LeakcheckPublicResponse | null } | null = null;
  try { r = await osintJsonWithFallbackStatus(`${leakcheckBase('public')}?check=${encodeURIComponent(query)}`); } catch { r = null; }
  if (!r || !r.body) return { service: 'LeakCheck public', found: 'unknown', note: 'public API unreachable via egress, Tor and direct' };
  if (r.status === 429) return { service: 'LeakCheck public', found: 'unknown', note: 'rate-limited — the public lane allows 1 request/second' };
  const j = r.body;
  if (j.success === false) return { service: 'LeakCheck public', found: 'unknown', note: `public API rejected the query${j.error ? `: ${j.error}` : ''}` };
  if (!j.found) return { service: 'LeakCheck public', found: 0, note: 'no breach source lists this identifier' };
  return {
    service: 'LeakCheck public',
    found: j.found,
    fields: j.fields || [],
    sources: (j.sources || []).slice(0, 25).map((s) => `${s.name} (${s.date})`),
    note: 'public API: breach sources + exposed field names only — full records need a LeakCheck Pro key (Pro v2 lane)',
  };
}

export async function xposedOrNot(email: string): Promise<BreachSummary> {
  const r = await osintFetch(`https://api.xposedornot.com/v1/check-email/${encodeURIComponent(email)}`);
  const j = (await r.json().catch(() => ({}))) as XposedornotResponse;
  const list = j.breaches?.[0] ?? j.breach ?? [];
  if (j.exposed === 'Not Found' || !Array.isArray(list) || list.length === 0) {
    return { service: 'XposedOrNot', found: 0 };
  }
  return { service: 'XposedOrNot', found: list.length, sources: list.slice(0, 25) };
}

export async function pwnedPasswordCount(password: string): Promise<number> {
  const sha1 = createHash('sha1').update(password).digest('hex').toUpperCase();
  const r = await osintFetch(`https://api.pwnedpasswords.com/range/${sha1.slice(0, 5)}`);
  const text = await r.text();
  for (const line of text.split('\n')) {
    const [suffix, count] = line.trim().split(':');
    if (suffix === sha1.slice(5)) return parseInt(count, 10) || 0;
  }
  return 0;
}

// --- NEW keyless lanes: Hudson Rock (live infostealer infections) + HIBP catalogue ---
// Hudson Rock's free cybercrime-intelligence feed: real infostealer infection records
// (family, date, computer name, IP, OS, installed software) — a live-compromise class
// the static dump lanes can't see. HIBP's breach catalogue (haveibeenpwned.com/api/v3/
// breaches) is keyless and answers "was this domain ever breached" with pwn counts.

export interface InfostealerHit {
  family?: string;
  date?: string;
  computerName?: string;
  ip?: string;
  os?: string;
  software?: string[];
  url?: string;
}
export interface HudsonRockResult {
  service: 'Hudson Rock';
  infected: boolean;
  infections: InfostealerHit[];
  corporateServices: number;
  userServices: number;
  note?: string;
}

export function parseHudsonRock(j: unknown): HudsonRockResult {
  const o = (j || {}) as Record<string, unknown>;
  const raw = Array.isArray(o.stealers) ? (o.stealers as Record<string, unknown>[]) : [];
  const pick = (r: Record<string, unknown>, ...keys: string[]): string | undefined => {
    for (const k of keys) { const v = r[k]; if (typeof v === 'string' && v.trim()) return v.trim(); }
    return undefined;
  };
  const strArray = (r: Record<string, unknown>, ...keys: string[]): string[] | undefined => {
    for (const k of keys) if (Array.isArray(r[k])) return (r[k] as unknown[]).filter((x): x is string => typeof x === 'string').slice(0, 12);
    return undefined;
  };
  const infections: InfostealerHit[] = raw.slice(0, 10).map((r) => ({
    family: pick(r, 'stealer_family', 'stealerFamily', 'family', 'malware'),
    date: pick(r, 'date_compromised', 'dateCompromised', 'date', 'compromise_date'),
    computerName: pick(r, 'computer_name', 'computerName', 'hostname'),
    ip: pick(r, 'ip_address', 'ipAddress', 'ip'),
    os: pick(r, 'operating_system', 'operatingSystem', 'os'),
    software: strArray(r, 'installed_software', 'installedSoftware'),
    url: pick(r, 'url', 'c2_url', 'malicious_url'),
  }));
  return {
    service: 'Hudson Rock',
    infected: infections.length > 0,
    infections,
    corporateServices: typeof o.total_corporate_services === 'number' ? o.total_corporate_services : 0,
    userServices: typeof o.total_user_services === 'number' ? o.total_user_services : 0,
    note: infections.length === 0 && typeof o.message === 'string' ? o.message.slice(0, 160) : undefined,
  };
}

export async function hudsonRockEmail(emailRaw: string): Promise<HudsonRockResult> {
  const email = emailRaw.trim().toLowerCase();
  if (!EMAIL_RE.test(email)) throw new Error(`Invalid email address: ${emailRaw}`);
  const j = await osintJsonWithFallback<unknown>(`https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=${encodeURIComponent(email)}`);
  if (!j) return { service: 'Hudson Rock', infected: false, infections: [], corporateServices: 0, userServices: 0, note: 'lane unavailable (egress/Tor/direct all failed)' };
  return parseHudsonRock(j);
}

export interface HibpCatalogEntry {
  name: string; title: string; domain?: string; breachDate?: string; addedDate?: string;
  modifiedDate?: string; pwnCount?: number; description?: string; dataClasses?: string[]; isVerified?: boolean;
}

export function parseHibpCatalog(j: unknown): HibpCatalogEntry[] {
  if (!Array.isArray(j)) return [];
  return (j as Record<string, unknown>[]).slice(0, 800).map((e) => ({
    name: String(e.Name || ''),
    title: String(e.Title || e.Name || ''),
    domain: typeof e.Domain === 'string' ? e.Domain : undefined,
    breachDate: typeof e.BreachDate === 'string' ? e.BreachDate : undefined,
    addedDate: typeof e.AddedDate === 'string' ? e.AddedDate : undefined,
    modifiedDate: typeof e.ModifiedDate === 'string' ? e.ModifiedDate : undefined,
    pwnCount: typeof e.PwnCount === 'number' ? e.PwnCount : undefined,
    description: typeof e.Description === 'string' ? e.Description.slice(0, 400) : undefined,
    dataClasses: Array.isArray(e.DataClasses) ? (e.DataClasses as unknown[]).filter((x): x is string => typeof x === 'string') : undefined,
    isVerified: typeof e.IsVerified === 'boolean' ? e.IsVerified : undefined,
  }));
}

const hibpCatalogCache = new Map<string, { at: number; entries: HibpCatalogEntry[] }>();

/** HIBP breach catalogue — keyless, 24h cache. Optional domain filter (?Domain=). */
export async function hibpBreachCatalog(domainRaw?: string): Promise<{ domain: string | null; total: number; entries: HibpCatalogEntry[]; note?: string }> {
  const domain = (domainRaw || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  if (domainRaw && domain && !/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) throw new Error(`Invalid domain: ${domainRaw}`);
  const key = domain || '*';
  const hit = hibpCatalogCache.get(key);
  if (hit && Date.now() - hit.at < 86_400_000) return { domain: domain || null, total: hit.entries.length, entries: hit.entries };
  const j = await osintJsonWithFallback<unknown>(
    `https://haveibeenpwned.com/api/v3/breaches${domain ? `?Domain=${encodeURIComponent(domain)}` : ''}`,
    {},
    { 'user-agent': 'T3MP3ST-OSINT/1.0' }
  );
  if (!j) return { domain: domain || null, total: 0, entries: [], note: 'lane unavailable (HIBP unreachable)' };
  const entries = parseHibpCatalog(j);
  hibpCatalogCache.set(key, { at: Date.now(), entries });
  return { domain: domain || null, total: entries.length, entries };
}

export interface EmailIntelResult {
  email: string;
  valid: boolean;
  gravatar: GravatarProfile;
  breaches: BreachSummary[];
  infostealer: HudsonRockResult;
  domain: { name: string; mxRecords: string[]; aRecord?: string; acceptsMail: boolean } | null;
}

const EMAIL_RE = /^[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$/;

export async function emailIntel(emailRaw: string): Promise<EmailIntelResult> {
  const email = emailRaw.trim().toLowerCase();
  if (!EMAIL_RE.test(email)) throw new Error(`Invalid email address: ${emailRaw}`);
  const [, domain] = email.split('@');

  const [gravatar, lc, xo, hr, mx, a] = await Promise.all([
    gravatarProfile(email),
    leakcheckPublic(email).catch((e): BreachSummary => ({ service: 'LeakCheck public', found: 'unknown', note: String(e).slice(0, 100) })),
    xposedOrNot(email).catch((e): BreachSummary => ({ service: 'XposedOrNot', found: 'unknown', note: String(e).slice(0, 100) })),
    hudsonRockEmail(email).catch((e): HudsonRockResult => ({ service: 'Hudson Rock', infected: false, infections: [], corporateServices: 0, userServices: 0, note: String(e).slice(0, 100) })),
    dns.resolveMx(domain).catch(() => [] as { exchange: string; priority: number }[]),
    dns.resolve4(domain).then((r) => r[0]).catch(() => undefined),
  ]);

  const hrSummary: BreachSummary = {
    service: 'Hudson Rock (infostealers)',
    found: hr.infected ? hr.infections.length : 0,
    sources: [...new Set(hr.infections.map((i) => i.family).filter((f): f is string => Boolean(f)))],
    note: hr.infected ? `LIVE infostealer infection on record (${hr.corporateServices} corporate / ${hr.userServices} user services exposed)` : hr.note,
  };

  return {
    email,
    valid: true,
    gravatar,
    breaches: [xo, lc, hrSummary],
    infostealer: hr,
    domain: {
      name: domain,
      mxRecords: mx.map((m) => m.exchange).slice(0, 5),
      aRecord: a,
      acceptsMail: mx.length > 0,
    },
  };
}

// =============================================================================
// DARK WEB / DUMP DATABASES — free lanes live, deep lanes key-gated
// =============================================================================

interface DumpRecord {
  service: string;
  found: number;
  records?: {
    email?: string; username?: string; password?: string; hash?: string; source?: string; date?: string;
    /** Identity fields the licensed dump services return when the source dump had them. */
    dob?: string; age?: string; address?: string; city?: string; state?: string; country?: string; phone?: string;
    zip?: string; name?: string;
  }[];
  note?: string;
}

// --- runtime dump-lane keys (Settings-persisted; env fallback) ----------------
// Keys arm LeakCheck v2 / DeHashed / Snusbase instantly from the UI — no restart.
// Stored via the server's settings DB (memory/db-settings.json, gitignored) and
// masked in every GET. No Tor dump-site harvesters: licensed services only.

type DumpKeyService = 'leakcheck' | 'dehashed' | 'snusbase';
const DUMP_KEY_SERVICES: DumpKeyService[] = ['leakcheck', 'dehashed', 'snusbase'];
const dumpKeys: Partial<Record<DumpKeyService, string>> = {};
const DUMP_ENV: Record<DumpKeyService, string> = {
  leakcheck: 'T3MP3ST_LEAKCHECK_KEY',
  dehashed: 'T3MP3ST_DEHASHED_KEY',
  snusbase: 'T3MP3ST_SNUSBASE_KEY',
};
// LeakCheck key variable names, in the order they are consulted. `LEAKCHECKIO`
// is deliberately NOT here: in practice operators set it to the API BASE URL
// (https://leakcheck.io/api/v2), not to a key — treating it as one armed the
// lane with a URL, and every query then failed with "Invalid X-API-Key" while
// the panel cheerfully reported the lane ARMED. The base URLs are honoured
// separately below, where they belong.
const DUMP_ENV_ALIASES: Partial<Record<DumpKeyService, string[]>> = {
  leakcheck: ['LEAKCHECKIO_API_KEY', 'LEAKCHECK_APIKEY', 'LEAKCHECK_KEY'],
};
// A pasted/env key that is actually a URL is a configuration mistake, not a key.
// LeakCheck keys are ≥40 chars with no scheme, so reject anything URL-shaped
// rather than arming a lane that can only ever return "Invalid X-API-Key".
function isPlausibleKey(v: string | undefined): v is string {
  if (!v) return false;
  const t = v.trim();
  return t.length >= 8 && !/^https?:\/\//i.test(t) && !/\s/.test(t);
}

/** Base URL overrides. `LEAKCHECKIO` / `LEAKCHECK_PUBLIC_API` are what operators
 *  actually set those names to — a self-hosted or proxied LeakCheck endpoint. */
function leakcheckBase(kind: 'pro' | 'public'): string {
  const raw = (kind === 'pro'
    ? process.env.LEAKCHECKIO || process.env.LEAKCHECK_BASE_URL
    : process.env.LEAKCHECK_PUBLIC_API) || '';
  const t = raw.trim();
  if (!/^https?:\/\//i.test(t)) return kind === 'pro' ? 'https://leakcheck.io/api/v2' : 'https://leakcheck.io/api/public';
  return t.replace(/\/+$/, '');
}

export function setDumpKey(service: DumpKeyService, key: string | undefined): void {
  if (key && key.trim()) dumpKeys[service] = key.trim();
  else delete dumpKeys[service];
}

export function getDumpKey(service: DumpKeyService): string | undefined {
  const fromEnv = (v?: string) => (isPlausibleKey(v) ? v.trim() : undefined);
  const primary = fromEnv(process.env[DUMP_ENV[service]]);
  if (dumpKeys[service]) return dumpKeys[service];
  if (primary) return primary;
  for (const alias of DUMP_ENV_ALIASES[service] || []) {
    const v = fromEnv(process.env[alias]);
    if (v) return v;
  }
  return undefined;
}

export function dumpKeyStatus(): Record<DumpKeyService, boolean> {
  return {
    leakcheck: Boolean(getDumpKey('leakcheck')),
    dehashed: Boolean(getDumpKey('dehashed')),
    snusbase: Boolean(getDumpKey('snusbase')),
  };
}

export function isDumpKeyService(v: string): v is DumpKeyService {
  return (DUMP_KEY_SERVICES as string[]).includes(v);
}

/** JSON fetch with the full fallback chain (egress → Tor → direct). The dump APIs
 *  are third-party data platforms, not mission targets — the direct leg keeps them
 *  usable when the shared proxy exit is blocked, and it is marked/kill-switched.
 *  Any transport whose response parses as JSON wins (API-level errors like
 *  "invalid key" arrive as JSON too — callers interpret the payload). */
async function osintJsonWithFallback<T>(url: string, init: RequestInit = {}, headers: Record<string, string> = {}): Promise<T | null> {
  return (await osintJsonWithFallbackStatus<T>(url, init, headers))?.body ?? null;
}

/** Same chain, but the HTTP status is preserved. The public LeakCheck lane needs
 *  it to tell a 429 rate-limit apart from a 200 with zero findings — a lane that
 *  reports "clean" because it was throttled is worse than no lane at all. */
async function osintJsonWithFallbackStatus<T>(url: string, init: RequestInit = {}, headers: Record<string, string> = {}): Promise<{ status: number; body: T | null } | null> {
  const tryParse = (raw: string): T | null => {
    const t = raw.trim();
    if (!t.startsWith('{') && !t.startsWith('[')) return null;
    try { return JSON.parse(t) as T; } catch { return null; }
  };
  try {
    const res = await osintFetch(url, { ...init, headers });
    const j = tryParse(await res.text().catch(() => ''));
    if (j) return { status: res.status, body: j };
  } catch { /* fall through */ }
  const tor = await torStatus();
  if (tor.available) {
    try {
      const page = await torFetchAny(url);
      const j = tryParse(page.body);
      if (j) return { status: page.status || 200, body: j };
    } catch { /* fall through */ }
  }
  if (directAllowed()) {
    try {
      const res = await directFetch(url, {
        headers: { 'user-agent': UA, accept: 'application/json', ...headers },
        signal: AbortSignal.timeout(15_000),
      } as never);
      const j = tryParse(await res.text().catch(() => ''));
      if (j) return { status: res.status, body: j };
    } catch { /* all paths failed */ }
  }
  return null;
}

/** The `source` object every Pro v2 row carries. Field names are snake_case and
 *  were verified live against api.leakcheck.io — the previous implementation read
 *  a `sources` STRING that the API never sends, so every record silently lost its
 *  breach attribution. */
export interface LeakcheckProSource {
  name: string;
  breach_date: string | null;
  unverified?: number;
  passwordless?: number;
  compilation?: number;
}
export interface LeakcheckProRow {
  email?: string; username?: string; password?: string;
  first_name?: string; last_name?: string; name?: string;
  dob?: string; phone?: string;
  address?: string; city?: string; state?: string; zip?: string; country?: string;
  ip?: string; origin?: string; collected?: string;
  source?: LeakcheckProSource;
  fields?: string[];
}
export interface LeakcheckProResult {
  found: number;
  /** Queries left on the account — the API returns this on every success. */
  quota?: number;
  rows: LeakcheckProRow[];
  /** Distinct breach sources, most-hit first, with their per-source row counts. */
  sources: { name: string; count: number; date?: string; unverified?: boolean; compilation?: boolean }[];
  fields: string[];
  note?: string;
}

/** LeakCheck Pro API v2 — full records. Key-gated.
 *  Docs: https://docs.leakcheck.io/pro-api/lookup — GET /api/v2/query/{query}
 *  with the X-API-Key header. Note: the live API IGNORES `limit` (returns the whole
 *  match set) and returns 0 rows for any `offset` on the current plan, so this
 *  deliberately sends neither and caps client-side. */
export async function leakcheckPro(
  queryRaw: string,
  kind: 'auto' | 'email' | 'username' | 'phone' | 'domain' | 'hash' | 'keyword' = 'auto',
  opts: { maxRows?: number } = {}
): Promise<LeakcheckProResult> {
  const query = queryRaw.trim();
  const key = getDumpKey('leakcheck');
  const empty: LeakcheckProResult = { found: 0, rows: [], sources: [], fields: [] };
  if (!key) return { ...empty, note: 'not configured — set T3MP3ST_LEAKCHECK_KEY (or LEAKCHECKIO / LEAKCHECK_APIKEY), or paste a key into ARM DUMP LANES' };
  if (query.length < 3) return { ...empty, note: 'query must be at least 3 characters' };

  // `auto` only works for email/username/phone/hash; anything else must be explicit.
  const type = kind === 'auto' ? '' : `?type=${encodeURIComponent(kind)}`;
  const r = await osintJsonWithFallbackStatus<{
    success?: boolean; found?: number; quota?: number; error?: string; message?: string;
    result?: LeakcheckProRow[];
  }>(`${leakcheckBase('pro')}/query/${encodeURIComponent(query)}${type}`, {}, { 'X-API-Key': key, accept: 'application/json' });
  if (!r || !r.body) return { ...empty, note: 'LeakCheck Pro API unreachable via egress, Tor and direct' };
  const j = r.body;
  // 401/403/429 carry no useful body on some edges — name the status instead of
  // reporting "0 records" for what is really an auth, plan or throttle refusal.
  if (r.status === 429) return { ...empty, note: 'rate-limited — the Pro v2 lane allows 3 requests/second' };
  if (r.status === 401) return { ...empty, note: 'HTTP 401 — the configured LeakCheck key was rejected (check T3MP3ST_LEAKCHECK_KEY / LEAKCHECKIO)' };
  if (j.success === false || j.error) {
    const err = String(j.error || j.message || 'request rejected');
    // 403 "Active plan required" is the free-tier case — say so rather than
    // letting it read like a broken lane. 422 means auto-detection failed.
    const note = /^active plan/i.test(err)
      ? `${err} — this key is on a plan without Pro v2 record access; the PUBLIC lane still returns sources + exposed field names`
      : /could not determine/i.test(err)
        ? `${err} — pass an explicit type (email / username / phone / domain / hash)`
        : err;
    return { ...empty, note };
  }

  const all = Array.isArray(j.result) ? j.result : [];
  const max = opts.maxRows && opts.maxRows > 0 ? opts.maxRows : 100;
  const rows = all.slice(0, max);
  const bySource = new Map<string, { name: string; count: number; date?: string; unverified?: boolean; compilation?: boolean }>();
  const fieldSet = new Set<string>();
  for (const r of all) {
    for (const f of r.fields || []) fieldSet.add(f);
    const s = r.source;
    if (!s?.name) continue;
    const cur = bySource.get(s.name) || { name: s.name, count: 0, date: s.breach_date || undefined, unverified: !!s.unverified, compilation: !!s.compilation };
    cur.count += 1;
    bySource.set(s.name, cur);
  }
  return {
    found: j.found ?? all.length,
    quota: typeof j.quota === 'number' ? j.quota : undefined,
    rows,
    sources: [...bySource.values()].sort((a, b) => b.count - a.count),
    fields: [...fieldSet].sort(),
  };
}

/** LeakCheck v2 — full records (incl. password fields when the dump has them). Key-gated. */
async function leakcheckDeep(query: string, kind: 'email' | 'username' | 'phone' | 'domain'): Promise<DumpRecord | null> {
  const key = getDumpKey('leakcheck');
  if (!key) return null;
  const pro = await leakcheckPro(query, kind, { maxRows: 50 });
  if (pro.note) return { service: 'LeakCheck Pro v2 (keyed)', found: 0, note: pro.note };
  return {
    service: 'LeakCheck Pro v2 (keyed)',
    found: pro.found,
    records: pro.rows.map((rec) => ({
      email: rec.email, username: rec.username, password: rec.password, hash: undefined,
      name: [rec.first_name, rec.last_name].filter(Boolean).join(' ') || rec.name || undefined,
      dob: rec.dob, address: rec.address, city: rec.city, state: rec.state,
      zip: rec.zip, country: rec.country, phone: rec.phone,
      // source is an OBJECT upstream — take its name, with the date for context.
      source: rec.source?.name + (rec.source?.breach_date ? ` (${rec.source.breach_date})` : ''),
      date: rec.collected || rec.source?.breach_date || undefined,
    })),
  };
}

/** DeHashed — deep-web breach search. Key-gated (basic auth user:key). */
async function dehashedDeep(query: string, kind: 'email' | 'username' | 'phone'): Promise<DumpRecord | null> {
  const key = getDumpKey('dehashed');
  if (!key) return null;
  const j = await osintJsonWithFallback<{ total?: number; entries?: Record<string, string | null>[] }>(
    `https://api.dehashed.com/search?query=${encodeURIComponent(`${kind}:"${query}"`)}&size=50`,
    {},
    { authorization: `Basic ${Buffer.from(key).toString('base64')}` }
  );
  if (!j) return { service: 'DeHashed (keyed)', found: 0, note: 'API unreachable via egress, Tor and direct' };
  const str = (v: string | null | undefined): string | undefined => (typeof v === 'string' && v.trim() ? v.trim() : undefined);
  return {
    service: 'DeHashed (keyed)',
    found: j.total ?? 0,
    records: (j.entries || []).slice(0, 50).map((e) => ({
      email: str(e.email), username: str(e.username), password: str(e.password), hash: str(e.hashed_password),
      dob: str(e.date_of_birth) || str(e.dob), age: str(e.age), address: str(e.address), city: str(e.city),
      state: str(e.state), country: str(e.country), phone: str(e.phone),
      source: str(e.database),
    })),
  };
}

/** Snusbase — dump database. Key-gated. */
async function snusbaseDeep(query: string, kind: 'email' | 'username' | 'phone'): Promise<DumpRecord | null> {
  const key = getDumpKey('snusbase');
  if (!key) return null;
  const j = await osintJsonWithFallback<{ result?: Record<string, string>[] }>(
    `https://api.snusbase.com/v2/user/search?type=${kind}&term=${encodeURIComponent(query)}`,
    {},
    { auth: key }
  );
  if (!j) return { service: 'Snusbase (keyed)', found: 0, note: 'API unreachable via egress, Tor and direct' };
  const records = (j.result || []).slice(0, 50);
  return {
    service: 'Snusbase (keyed)',
    found: records.length,
    records: records.map((e) => ({
      email: e.email, username: e.username, password: e.password, hash: e.passhash || e.hash,
      dob: e.dob || e.date_of_birth, address: e.address, city: e.city, state: e.state,
      country: e.country, phone: e.phone,
      source: e.database,
    })),
  };
}

export interface DumpLaneResult {
  query: string;
  kind: 'email' | 'username' | 'phone' | 'password';
  free: BreachSummary[];
  deep: (DumpRecord | { service: string; status: 'key-required'; note: string })[];
  credentials: Credential[];
}

/**
 * Full dump-database pass on a subject. Free lanes (LeakCheck public, XposedOrNot,
 * Pwned Passwords) always run; the deep dump lanes run when the operator configured
 * keys. Password material that comes back is minted as Credential records so it lands
 * in the Evidence Vault credential ledger.
 */
export async function dumpDatabaseLookup(
  queryRaw: string,
  kind: 'email' | 'username' | 'phone' | 'password'
): Promise<DumpLaneResult> {
  const query = queryRaw.trim();
  const free: BreachSummary[] = [];
  const deep: DumpLaneResult['deep'] = [];
  const credentials: Credential[] = [];

  if (kind === 'password') {
    const count = await pwnedPasswordCount(query);
    free.push({
      service: 'HIBP Pwned Passwords',
      found: count,
      note: count > 0
        ? `Password appears in ${count} breached records — NEVER use it in an engagement guess without authorization`
        : 'Password not present in the Pwned Passwords corpus',
    });
  } else {
    free.push(await leakcheckPublic(query).catch((e): BreachSummary => ({ service: 'LeakCheck public', found: 'unknown', note: String(e).slice(0, 100) })));
    if (kind === 'email') {
      free.push(await xposedOrNot(query).catch((e): BreachSummary => ({ service: 'XposedOrNot', found: 'unknown', note: String(e).slice(0, 100) })));
    }
    const lanes: Promise<DumpRecord | null>[] = [];
    if (kind === 'phone') {
      lanes.push(leakcheckDeep(query, kind));
      lanes.push(snusbaseDeep(query, kind));
    } else {
      lanes.push(leakcheckDeep(query, kind));
      lanes.push(dehashedDeep(query, kind));
      lanes.push(snusbaseDeep(query, kind));
    }
    const settled = await Promise.all(lanes.map((p) => p.catch(() => null)));
    const gate: Record<string, string> = {
      'LeakCheck Pro v2 (keyed)': 'T3MP3ST_LEAKCHECK_KEY / LEAKCHECKIO / LEAKCHECK_APIKEY',
      'DeHashed (keyed)': 'T3MP3ST_DEHASHED_KEY',
      'Snusbase (keyed)': 'T3MP3ST_SNUSBASE_KEY',
    };
    for (const rec of settled) {
      if (rec) deep.push(rec);
    }
    // Report key-gated lanes that did NOT run so the panel is explicit about coverage.
    for (const [service, envVar] of Object.entries(gate)) {
      const already = settled.some((s) => s && s.service === service);
      const applies = service !== 'DeHashed (keyed)' || kind !== 'phone';
      if (!already && applies) {
        deep.push({ service, status: 'key-required', note: `set ${envVar} in the server environment to unlock this dump lane` });
      }
    }
    for (const rec of settled) {
      if (!rec?.records) continue;
      for (const r of rec.records) {
        const secret = r.password || r.hash;
        if (!secret) continue;
        credentials.push({
          id: `cred_osint_${createHash('md5').update(`${rec.service}:${r.email || r.username || query}:${secret}`).digest('hex').slice(0, 12)}`,
          type: r.password ? 'password' : 'hash',
          username: r.username || r.email,
          secret,
          domain: r.email?.split('@')[1],
          source: `osint:${rec.service}${r.source ? ` (${r.source})` : ''}`,
          discoveredAt: Date.now(),
          notes: `dump-record for ${query} — provenance ${rec.service}`,
        });
      }
    }
  }

  return { query, kind, free, deep, credentials };
}

// =============================================================================
// PHONE INTEL — normalization, country routing, deep-link generation
// =============================================================================

const COUNTRY_PREFIXES: [string, string, number][] = [
  ['1', 'US/Canada (NANP)', 10], ['7', 'Russia/Kazakhstan', 10], ['20', 'Egypt', 10], ['27', 'South Africa', 9],
  ['30', 'Greece', 10], ['31', 'Netherlands', 9], ['32', 'Belgium', 9], ['33', 'France', 9], ['34', 'Spain', 9],
  ['36', 'Hungary', 9], ['39', 'Italy', 10], ['40', 'Romania', 9], ['41', 'Switzerland', 9], ['43', 'Austria', 10],
  ['44', 'United Kingdom', 10], ['45', 'Denmark', 8], ['46', 'Sweden', 9], ['47', 'Norway', 8], ['48', 'Poland', 9],
  ['49', 'Germany', 10], ['51', 'Peru', 9], ['52', 'Mexico', 10], ['53', 'Cuba', 8], ['54', 'Argentina', 10],
  ['55', 'Brazil', 11], ['56', 'Chile', 9], ['57', 'Colombia', 10], ['58', 'Venezuela', 10], ['60', 'Malaysia', 9],
  ['61', 'Australia', 9], ['62', 'Indonesia', 10], ['63', 'Philippines', 10], ['64', 'New Zealand', 9],
  ['65', 'Singapore', 8], ['66', 'Thailand', 9], ['81', 'Japan', 10], ['82', 'South Korea', 10],
  ['84', 'Vietnam', 9], ['86', 'China', 11], ['90', 'Turkey', 10], ['91', 'India', 10], ['92', 'Pakistan', 10],
  ['93', 'Afghanistan', 9], ['94', 'Sri Lanka', 9], ['95', 'Myanmar', 9], ['98', 'Iran', 10],
  ['211', 'South Sudan', 9], ['212', 'Morocco', 9], ['213', 'Algeria', 9], ['216', 'Tunisia', 8],
  ['218', 'Libya', 9], ['220', 'Gambia', 7], ['233', 'Ghana', 9], ['234', 'Nigeria', 10], ['250', 'Rwanda', 9],
  ['254', 'Kenya', 9], ['255', 'Tanzania', 9], ['256', 'Uganda', 9], ['260', 'Zambia', 9], ['263', 'Zimbabwe', 9],
  ['264', 'Namibia', 9], ['267', 'Botswana', 8], ['291', 'Eritrea', 7],
  ['350', 'Gibraltar', 8], ['351', 'Portugal', 9], ['352', 'Luxembourg', 9], ['353', 'Ireland', 9],
  ['355', 'Albania', 9], ['356', 'Malta', 8], ['357', 'Cyprus', 8], ['358', 'Finland', 9], ['359', 'Bulgaria', 9],
  ['370', 'Lithuania', 8], ['371', 'Latvia', 8], ['372', 'Estonia', 8], ['373', 'Moldova', 8],
  ['374', 'Armenia', 8], ['375', 'Belarus', 9], ['380', 'Ukraine', 9], ['381', 'Serbia', 9],
  ['385', 'Croatia', 9], ['386', 'Slovenia', 8], ['387', 'Bosnia', 8], ['389', 'North Macedonia', 8],
  ['420', 'Czechia', 9], ['421', 'Slovakia', 9], ['423', 'Liechtenstein', 7], ['501', 'Belize', 7],
  ['502', 'Guatemala', 8], ['503', 'El Salvador', 8], ['504', 'Honduras', 8], ['505', 'Nicaragua', 8],
  ['506', 'Costa Rica', 8], ['507', 'Panama', 8], ['509', 'Haiti', 8], ['590', 'Guadeloupe', 9],
  ['591', 'Bolivia', 8], ['592', 'Guyana', 7], ['593', 'Ecuador', 9], ['594', 'French Guiana', 9],
  ['595', 'Paraguay', 9], ['596', 'Martinique', 9], ['597', 'Suriname', 7], ['598', 'Uruguay', 8],
  ['670', 'East Timor', 8], ['672', 'Norfolk Island', 6], ['673', 'Brunei', 7], ['675', 'Papua New Guinea', 8],
  ['676', 'Tonga', 7], ['679', 'Fiji', 7], ['682', 'Cook Islands', 5], ['685', 'Samoa', 7],
  ['687', 'New Caledonia', 6], ['689', 'French Polynesia', 8], ['690', 'Tokelau', 5], ['691', 'Micronesia', 7],
  ['692', 'Marshall Islands', 7], ['850', 'North Korea', 10], ['852', 'Hong Kong', 8], ['853', 'Macau', 8],
  ['855', 'Cambodia', 9], ['856', 'Laos', 9], ['880', 'Bangladesh', 10], ['886', 'Taiwan', 9],
  ['960', 'Maldives', 7], ['961', 'Lebanon', 8], ['962', 'Jordan', 9], ['963', 'Syria', 9],
  ['964', 'Iraq', 10], ['965', 'Kuwait', 8], ['966', 'Saudi Arabia', 9], ['967', 'Yemen', 9],
  ['968', 'Oman', 8], ['970', 'Palestine', 9], ['971', 'UAE', 9], ['972', 'Israel', 9],
  ['973', 'Bahrain', 8], ['974', 'Qatar', 8], ['975', 'Bhutan', 8], ['976', 'Mongolia', 8],
  ['977', 'Nepal', 10], ['992', 'Tajikistan', 9], ['993', 'Turkmenistan', 8], ['994', 'Azerbaijan', 9],
  ['995', 'Georgia', 9], ['996', 'Kyrgyzstan', 9], ['998', 'Uzbekistan', 9],
];

export interface PhoneIntelResult {
  input: string;
  e164: string;
  digits: string;
  countryCode: string;
  country: string;
  /** ISO-3166 alpha-2 when we can infer it (FR, US, GB …), '' otherwise. */
  countryIso: string;
  expectedLength: number;
  lengthValid: boolean;
  /** Loose validity — length + country prefix known + NANP area sane. True libphonenumber validity needs the optional lib. */
  valid: boolean;
  /** National number without the country prefix. */
  national: string;
  /** PhoneInfoga "rawLocal" — national number (no country prefix). */
  rawLocal: string;
  /** Pretty international form: +CC national (spaced groups of 2-4). */
  international: string;
  /** Local form (international without the +CC, or national spaced). */
  local: string;
  carrier: string;
  lineType: string;
  location: string;
  nanp: { areaCode: string; exchange: string; validAreaCode: boolean } | null;
  searchLinks: { label: string; url: string }[];
  /** Enriched only by phoneInfogaScan / the /phone endpoint with scan=true. */
  ovh?: PhoneInfogaOvhResult | null;
  numverify?: PhoneInfogaNumverifyResult | null;
  dorks?: PhoneInfogaDork[];
}

export interface PhoneInfogaDork {
  category: 'social' | 'disposable' | 'reputation' | 'individuals' | 'general';
  label: string;
  query: string;
  url: string;
}
export interface PhoneInfogaOvhResult {
  supported: boolean;
  found: boolean;
  country: string;
  number?: string;
  numberRange?: string;
  city?: string;
  zipCode?: string;
  note?: string;
}
export interface PhoneInfogaNumverifyResult {
  configured: boolean;
  valid?: boolean;
  carrier?: string;
  lineType?: string;
  location?: string;
  countryName?: string;
  error?: string;
  raw?: Record<string, unknown>;
}
export interface PhoneInfogaScanResult extends PhoneIntelResult {
  ovh: PhoneInfogaOvhResult | null;
  numverify: PhoneInfogaNumverifyResult | null;
  dorks: PhoneInfogaDork[];
  scanNote: string;
  /** Present only when a remote instance was reachable (T3MP3ST_PHONEINFOGA_URL). */
  remote?: PhoneInfogaRemoteResult | null;
}

export function phoneIntel(phoneRaw: string): PhoneIntelResult {
  const raw = phoneRaw.trim();
  const hadPlus = raw.startsWith('+') || raw.startsWith('00');
  const digits = raw.replace(/[^\d]/g, '').replace(/^00/, '');
  if (digits.length < 6 || digits.length > 15) throw new Error(`Invalid phone number: ${phoneRaw}`);

  // NANP: 10-digit numbers (no country code) are ambiguous — the operator should
  // confirm +1, but we report the US/Canada parse as the primary reading. The
  // assumed '1' has to be reflected in the E.164 form we emit.
  let cc: string | null = null;
  let country = 'unknown';
  let iso = '';
  let expected = 10;
  let national = digits;
  let e164 = `+${digits}`;

  if (hadPlus || digits.length > 10) {
    for (const len of [3, 2, 1]) {
      const prefix = digits.slice(0, len);
      const hit = COUNTRY_PREFIXES.find(([p]) => p === prefix);
      if (hit) { cc = hit[0]; country = hit[1]; expected = hit[2]; national = digits.slice(len); break; }
    }
    if (!cc) { country = `unknown (+${digits.slice(0, 2)}…)`; national = digits; }
  } else {
    cc = '1'; country = 'US/Canada (NANP, assumed — no country code given)'; expected = 10; national = digits;
    e164 = `+1${digits}`;
  }
  iso = cc ? phoneCountryIso(cc) : '';
  const nanp = cc === '1' && national.length === 10
    ? {
        areaCode: national.slice(0, 3),
        exchange: national.slice(3, 6),
        validAreaCode: !/^[01]/.test(national.slice(0, 3)) && national.slice(1, 3) !== '11',
      }
    : null;

  const lenValid = national.length === expected;
  const valid = lenValid && cc !== null && country !== 'unknown' && (nanp ? nanp.validAreaCode : true) && national.length >= 6;
  const spaced = national.replace(/(\d{2,4})(?=\d)/g, '$1 ').trim();
  const international = cc && cc !== '?' ? `+${cc} ${spaced}` : `+${digits.slice(0, 2)} ${spaced}`;
  const local = spaced;
  const rawLocal = national;
  const bare = encodeURIComponent(digits);
  const nationalEnc = encodeURIComponent(national);
  const rawPlus = encodeURIComponent(e164);
  // Search links — keep the original set for backward compat, add international/rawLocal variants
  const searchLinks = [
    { label: 'Google', url: `https://www.google.com/search?q=%22${bare}%22` },
    { label: 'Google (international)', url: `https://www.google.com/search?q=%22${encodeURIComponent(international)}%22` },
    { label: 'Bing', url: `https://www.bing.com/search?q=%22${bare}%22` },
    { label: 'Yandex', url: `https://yandex.com/search/?text=%22${bare}%22` },
    { label: 'Truecaller', url: `https://www.truecaller.com/search/global/${digits}` },
    { label: 'Sync.me', url: `https://sync.me/search/?number=${digits}` },
    { label: 'WhatsApp check', url: `https://wa.me/${digits}` },
    { label: 'Telegram check', url: `https://t.me/+${digits}` },
    { label: 'Facebook search', url: `https://www.facebook.com/search/top?q=%22${bare}%22` },
    { label: 'LinkedIn posts', url: `https://www.linkedin.com/search/results/content/?keywords=%22${bare}%22` },
  ];
  void nationalEnc; void rawPlus;
  return {
    input: raw,
    e164,
    digits,
    countryCode: cc || '?',
    country,
    countryIso: iso,
    expectedLength: expected,
    lengthValid: lenValid,
    valid,
    national,
    rawLocal,
    international,
    local,
    carrier: '',
    lineType: '',
    location: '',
    nanp,
    searchLinks,
  };
}

// Minimal CC → ISO-3166 alpha-2 map — enough for the OVH scanner (FR/BE/GB/ES/CH)
// Plus the common countries callers will hit. Unknown CC returns '' (unknown).
const CC_TO_ISO: Record<string, string> = {
  '1': 'US', '7': 'RU', '20': 'EG', '27': 'ZA', '30': 'GR', '31': 'NL', '32': 'BE', '33': 'FR',
  '34': 'ES', '36': 'HU', '39': 'IT', '40': 'RO', '41': 'CH', '43': 'AT', '44': 'GB', '45': 'DK',
  '46': 'SE', '47': 'NO', '48': 'PL', '49': 'DE', '51': 'PE', '52': 'MX', '53': 'CU', '54': 'AR',
  '55': 'BR', '56': 'CL', '57': 'CO', '58': 'VE', '60': 'MY', '61': 'AU', '62': 'ID', '63': 'PH',
  '64': 'NZ', '65': 'SG', '66': 'TH', '81': 'JP', '82': 'KR', '84': 'VN', '86': 'CN', '90': 'TR',
  '91': 'IN', '92': 'PK', '93': 'AF', '94': 'LK', '95': 'MM', '98': 'IR', '212': 'MA', '213': 'DZ',
  '216': 'TN', '233': 'GH', '234': 'NG', '351': 'PT', '352': 'LU', '353': 'IE', '380': 'UA',
  '420': 'CZ', '421': 'SK', '852': 'HK', '853': 'MO', '880': 'BD', '886': 'TW', '971': 'AE',
  '972': 'IL', '966': 'SA', '678': 'VU',
};
function phoneCountryIso(cc: string): string { return CC_TO_ISO[cc] || ''; }

// =============================================================================
// PHONEINFOGA — ported scanners (sundowndev/phoneinfoga, GPL-3.0)
// =============================================================================
// The Go original ships 5 scanners. We port all five to TS without a Go runtime:
//   • local        → phoneIntel() (formatting, validity, country, NANP — above)
//   • googlesearch → phoneInfogaDorks() (50 search-engine dorks across 5 categories)
//   • ovh          → phoneInfogaOvhCheck() (free OVH Telecom VoIP range lookup)
//   • numverify    → phoneInfogaNumverify() (optional, key-gated carrier/lineType)
//   • googlecse    → optional Google Custom Search enrichment (key-gated, best-effort)
//
// Design choices vs the Go port:
//   - No nyaruka/phonenumbers dependency is added; we reuse phoneIntel's own
//     country routing so the module stays dependency-free. Formats are derived
//     as: E164="+CCnational", International="+CC national (spaced)", RawLocal="national".
//     This matches the Go FormatNumber regex `[\W_]+` behaviour without pulling Go.
//   - Dork generation is string-template based like the Go Report() methods, not a
//     dorkgen library — same queries, fewer allocations, no extra dep.
//   - OVH and Numverify ride osintFetch (SOCKS-aware). Numverify/GoogleCSE are
//     honest no-ops when their env keys are absent.
//   - Licensed under GPL-3.0 attribution: this file ports sundowndev/phoneinfoga's
//     scanner report templates, dork lists, and OVH matching logic verbatim.

function gq(q: string): string { return `https://www.google.com/search?q=${encodeURIComponent(q)}`; }

export function phoneInfogaDorks(phoneRaw: string): PhoneInfogaDork[] {
  let intel: PhoneIntelResult;
  try { intel = phoneIntel(phoneRaw); } catch { return []; }
  const e164 = intel.e164;                // +CCnational
  const intl = intel.international;        // +CC national (spaced)
  const raw = intel.rawLocal;              // national only
  const national = intel.national;
  // Go's intl sometimes renders with spaces/dashes; we also emit a spaced local
  const spacedLocal = intl.replace(/^\+\d+\s*/, '').trim();
  const out: PhoneInfogaDork[] = [];
  const push = (category: PhoneInfogaDork['category'], label: string, query: string) => {
    out.push({ category, label, query, url: gq(query) });
  };

  // ── Social media (5) — PhoneInfoga: getSocialMediaDorks()
  push('social', 'Facebook — phone in text', `site:facebook.com intext:"${e164}"`);
  push('social', 'Twitter / X — phone in text', `site:twitter.com intext:"${e164}"`);
  push('social', 'LinkedIn — phone in text', `site:linkedin.com intext:"${e164}"`);
  push('social', 'Instagram — phone in text', `site:instagram.com intext:"${e164}"`);
  push('social', 'VK — phone in text', `site:vk.com intext:"${e164}"`);

  // ── Disposable providers (21-22) — getDisposableProvidersDorks(). Each site + "E.164 OR International"
  const disposableSites = [
    'hs3x.com', 'receive-sms-now.com', 'smslisten.com', 'smsnumbersonline.com', 'freesmscode.com',
    'catchsms.com', 'smstibo.com', 'smsreceiving.com', 'getfreesmsnumber.com', 'sellaite.com',
    'receive-sms-online.info', 'receivesmsonline.com', 'receive-a-sms.com', 'sms-receive.net',
    'receivefreesms.com', 'receive-sms.com', 'receivetxt.com', 'freephonenum.com',
    'freesmsverification.com', 'receive-sms-online.com', 'smslive.co',
  ];
  for (const site of disposableSites) {
    push('disposable', `Disposable — ${site}`, `site:${site} ("${e164}" OR "${intl}")`);
  }

  // ── Reputation (10) — getReputationDorks()
  push('reputation', 'Who called — who called (intitle)', `intitle:"who called" "${e164}"`);
  push('reputation', 'whosenumber.info', `site:whosenumber.info "${e164}"`);
  push('reputation', 'Phone fraud — intitle', `intext:"Phone Fraud" intitle:"${e164}"`);
  push('reputation', 'findwhocallsme.com', `site:findwhocallsme.com intext:"${e164}"`);
  push('reputation', 'yellowpages.ca — phone', `site:yellowpages.ca "${e164}"`);
  push('reputation', 'phonenumbers.ie', `site:phonenumbers.ie intext:"${intl}"`);
  push('reputation', 'who-calledme.com', `site:who-calledme.com "${intl}"`);
  push('reputation', 'usphonesearch.net', `site:usphonesearch.net "${e164}"`);
  push('reputation', 'whocalled.us — phone inurl', `site:whocalled.us inurl:"${e164}"`);
  push('reputation', 'quinumero.info', `site:quinumero.info intext:"${e164}"`);

  // ── Individuals (7) — getIndividualsDorks()
  push('individuals', 'numinfo.net — individuals', `site:numinfo.net "${e164}"`);
  push('individuals', 'sync.me — individuals', `site:sync.me "${intl}"`);
  push('individuals', 'whocallsyou.de', `site:whocallsyou.de "${e164}"`);
  push('individuals', 'Pastebin — phone', `site:pastebin.com "${e164}"`);
  push('individuals', 'whycall.me', `site:whycall.me "${e164}"`);
  push('individuals', 'locatefamily.com', `site:locatefamily.com "${e164}"`);
  push('individuals', 'spytox.com — phone + name/address', `site:spytox.com "${e164}" intext:("name" OR "address")`);

  // ── General (2 doc-oriented) — getGeneralDorks()
  // Go's general dorks: ("E164" OR "local-spaced") + doc extensions, and raw national.
  push('general', 'Documents mentioning phone (general)', `("${e164}" OR "${spacedLocal || raw}") (ext:doc OR ext:docx OR ext:odt OR ext:pdf OR ext:rtf OR ext:sxw OR ext:psw OR ext:ppt OR ext:pptx OR ext:pps OR ext:csv OR ext:txt OR ext:xls)`);
  push('general', 'Documents mentioning national number', `"${national}" (ext:doc OR ext:docx OR ext:odt OR ext:pdf OR ext:rtf OR ext:sxw OR ext:psw OR ext:ppt OR ext:pptx OR ext:pps OR ext:csv)`);

  return out;
}

export function phoneInfogaDorkStats(dorks: PhoneInfogaDork[]): Record<string, number> {
  const m: Record<string, number> = {};
  for (const d of dorks) m[d.category] = (m[d.category] || 0) + 1;
  return m;
}

// ── OVH scanner ────────────────────────────────────────────────────────────
// Mirrors suppliers/ovh.go + lib/remote/ovh_scanner.go
// API: GET https://api.ovh.com/1.0/telephony/number/detailedZones?country={cc lower}
// Response: [{ prefix:"33xxxx", city:"Paris", zipCode:"75000", number:"33..xxxx" ... }]
// Matching: six-digit prefix (first 6 national digits + "xxxx") membership.
const OVH_SUPPORTED = new Map<string, string>([
  ['33', 'fr'], ['32', 'be'], ['44', 'gb'], ['34', 'es'], ['41', 'ch'],
]);

export async function phoneInfogaOvhCheck(phoneRaw: string): Promise<PhoneInfogaOvhResult> {
  let intel: PhoneIntelResult;
  try { intel = phoneIntel(phoneRaw); } catch (e: unknown) {
    return { supported: false, found: false, country: '', note: e instanceof Error ? e.message : String(e) };
  }
  const mapped = OVH_SUPPORTED.get(intel.countryCode);
  if (!mapped) {
    return { supported: false, found: false, country: intel.countryIso || intel.countryCode, note: `OVH detailedZones only covers FR/BE/GB/ES/CH (got ${intel.countryCode || '?'})` };
  }
  const national = intel.national.replace(/\D/g, '');
  if (national.length < 6) return { supported: true, found: false, country: mapped, note: 'National number too short for OVH prefix check (need ≥6 digits)' };
  const prefix = national.slice(0, 6) + 'xxxx';
  try {
    const url = `https://api.ovh.com/1.0/telephony/number/detailedZones?country=${mapped}`;
    const res = await osintFetch(url, { headers: { accept: 'application/json' } });
    if (!res.ok) {
      return { supported: true, found: false, country: mapped, note: `OVH API HTTP ${res.status}` };
    }
    const data = (await res.json()) as Array<{ number?: string; city?: string; zipCode?: string; prefix?: string }>;
    const hit = Array.isArray(data) ? data.find((r) => r.number === prefix || r.prefix === prefix) : null;
    if (hit) {
      return { supported: true, found: true, country: mapped, number: hit.number || prefix, numberRange: hit.number || prefix, city: hit.city || '', zipCode: hit.zipCode || '' };
    }
    return { supported: true, found: false, country: mapped, note: 'No OVH VoIP range matched (number is not OVH-allocated under this prefix)' };
  } catch (e: unknown) {
    return { supported: true, found: false, country: mapped, note: e instanceof Error ? e.message : String(e) };
  }
}

// ── Numverify scanner ──────────────────────────────────────────────────────
// Mirrors suppliers/numverify.go + lib/remote/numverify_scanner.go
// Endpoint: https://api.apilayer.com/number_verification/validate?number={e164}
// Header: Apikey: {T3MP3ST_NUMVERIFY_KEY | NUMVERIFY_API_KEY}
function numverifyKey(): string {
  return (process.env.T3MP3ST_NUMVERIFY_KEY || process.env.NUMVERIFY_API_KEY || '').trim();
}

export async function phoneInfogaNumverify(phoneRaw: string): Promise<PhoneInfogaNumverifyResult> {
  const key = numverifyKey();
  if (!key) return { configured: false, error: 'Numverify not configured — set T3MP3ST_NUMVERIFY_KEY (or NUMVERIFY_API_KEY) to enable carrier/line-type enrichment' };
  let e164: string;
  try { e164 = phoneIntel(phoneRaw).e164; } catch (e: unknown) {
    return { configured: true, error: e instanceof Error ? e.message : String(e) };
  }
  try {
    const url = `https://api.apilayer.com/number_verification/validate?number=${encodeURIComponent(e164)}`;
    const res = await osintFetch(url, { headers: { Apikey: key, accept: 'application/json' } });
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      return { configured: true, error: `Numverify HTTP ${res.status}${body ? `: ${body.slice(0, 300)}` : ''}` };
    }
    const j = (await res.json()) as Record<string, unknown>;
    if (j.valid === false && j.error) {
      const er = j.error as Record<string, unknown>;
      return { configured: true, error: String(er.info || er.type || JSON.stringify(er)).slice(0, 300) };
    }
    return {
      configured: true,
      valid: j.valid as boolean | undefined,
      carrier: (j.carrier as string) || '',
      lineType: (j.line_type as string) || '',
      location: (j.location as string) || '',
      countryName: (j.country_name as string) || (j.country as string) || '',
      raw: j,
    };
  } catch (e: unknown) {
    return { configured: true, error: e instanceof Error ? e.message : String(e) };
  }
}

// ── Remote PhoneInfoga instance adapter ────────────────────────────────────
// PhoneInfoga ships a REST API (web/docs/swagger.yaml — v2). Operators can point
// T3MP3ST at a self-hosted instance (DOCKER_HOST mode) and we drive its endpoints
// instead of / in addition to the in-process port. Config:
//   T3MP3ST_PHONEINFOGA_URL   e.g. http://127.0.0.1:5000
//   T3MP3ST_PHONEINFOGA_TOKEN bearer token when the instance sits behind auth
// Swagger routes we speak (v2 first, v1 deprecated routes as fallback):
//   GET  /api/v2/scanners                       → [{ name, description }]
//   POST /api/v2/numbers  {number}              → number.Number (libphonenumber truth)
//   POST /api/v2/scanners/{scanner}/dryrun      → { success, error } (config check, no network)
//   POST /api/v2/scanners/{scanner}/run         → { result: {...} }
//   GET  /api/numbers/{number}/scan/{scanner}   → v1 fallback (local|googlesearch|ovh|numverify)
export interface PhoneInfogaRemoteScanner { name: string; description: string }
export interface PhoneInfogaRemoteResult {
  configured: boolean;
  reachable: boolean;
  baseUrl: string;
  version?: string;
  scanners?: PhoneInfogaRemoteScanner[];
  /** Scanner name → raw result payload, or the error string that scanner returned. */
  results?: Record<string, unknown>;
  /** Scanner → dry-run verdict from the remote instance. */
  dryRuns?: Record<string, string>;
  error?: string;
}

function phoneInfogaBaseUrl(): string {
  return (process.env.T3MP3ST_PHONEINFOGA_URL || '').trim().replace(/\/+$/, '');
}
function phoneInfogaHeaders(): Record<string, string> {
  const h: Record<string, string> = { 'content-type': 'application/json' };
  const token = (process.env.T3MP3ST_PHONEINFOGA_TOKEN || '').trim();
  if (token) h.authorization = `Bearer ${token}`;
  return h;
}
async function phoneInfogaFetchJson(url: string, init: RequestInit = {}): Promise<{ ok: boolean; status: number; body: any }> {
  try {
    const r = await osintFetch(url, {
      ...init,
      headers: { accept: 'application/json', ...(init.headers || {}) },
    });
    const text = await r.text().catch(() => '');
    let body: any = null;
    try { body = text ? JSON.parse(text) : null; } catch { body = text; }
    return { ok: r.ok, status: r.status, body };
  } catch (e: unknown) {
    return { ok: false, status: 0, body: null, error: e instanceof Error ? e.message : String(e) } as any;
  }
}

/** GET /api/v2/scanners + GET /api/ (health: version/commit/demo). */
export async function phoneInfogaRemoteInfo(): Promise<PhoneInfogaRemoteResult> {
  const base = phoneInfogaBaseUrl();
  if (!base) return { configured: false, reachable: false, baseUrl: '', error: 'not configured — set T3MP3ST_PHONEINFOGA_URL to drive a self-hosted PhoneInfoga instance' };
  const [health, scanners] = await Promise.all([
    phoneInfogaFetchJson(`${base}/api/`),
    phoneInfogaFetchJson(`${base}/api/v2/scanners`, { headers: phoneInfogaHeaders() }),
  ]);
  const version = health.ok && health.body ? String(health.body.version || health.body.commit || '') : '';
  const list: PhoneInfogaRemoteScanner[] = Array.isArray(scanners.body?.scanners)
    ? scanners.body.scanners
    : Array.isArray(scanners.body) ? scanners.body : [];
  return {
    configured: true,
    reachable: health.ok || scanners.ok,
    baseUrl: base,
    version,
    scanners: list,
    error: health.ok || scanners.ok ? undefined : (scanners.body?.error || health.body?.error || `HTTP ${scanners.status || health.status}`),
  };
}

/** POST /api/v2/numbers — the remote instance's libphonenumber parse. */
export async function phoneInfogaRemoteNumber(phoneRaw: string): Promise<{ ok: boolean; result?: Record<string, unknown>; error?: string }> {
  const base = phoneInfogaBaseUrl();
  if (!base) return { ok: false, error: 'T3MP3ST_PHONEINFOGA_URL not set' };
  const r = await phoneInfogaFetchJson(`${base}/api/v2/numbers`, {
    method: 'POST', headers: phoneInfogaHeaders(), body: JSON.stringify({ number: phoneRaw }),
  });
  if (!r.ok) return { ok: false, error: String(r.body?.error || r.body || `HTTP ${r.status}`) };
  return { ok: true, result: r.body as Record<string, unknown> };
}

/** POST /api/v2/scanners/{scanner}/dryrun — config check on the remote side. */
export async function phoneInfogaRemoteDryRun(phoneRaw: string, scanner: string): Promise<{ ok: boolean; success: boolean; error?: string }> {
  const base = phoneInfogaBaseUrl();
  if (!base) return { ok: false, success: false, error: 'T3MP3ST_PHONEINFOGA_URL not set' };
  const r = await phoneInfogaFetchJson(`${base}/api/v2/scanners/${encodeURIComponent(scanner)}/dryrun`, {
    method: 'POST', headers: phoneInfogaHeaders(), body: JSON.stringify({ number: phoneRaw, options: {} }),
  });
  return { ok: r.ok, success: !!r.body?.success, error: r.body?.error ? String(r.body.error) : (r.ok ? undefined : `HTTP ${r.status}`) };
}

/** POST /api/v2/scanners/{scanner}/run — executes ONE scanner remotely.
 *  v1 fallback: GET /api/numbers/{number}/scan/{scanner} (deprecated but shipped). */
export async function phoneInfogaRemoteRun(phoneRaw: string, scanner: string): Promise<{ ok: boolean; result?: unknown; error?: string }> {
  const base = phoneInfogaBaseUrl();
  if (!base) return { ok: false, error: 'T3MP3ST_PHONEINFOGA_URL not set' };
  const r = await phoneInfogaFetchJson(`${base}/api/v2/scanners/${encodeURIComponent(scanner)}/run`, {
    method: 'POST', headers: phoneInfogaHeaders(), body: JSON.stringify({ number: phoneRaw, options: {} }),
  });
  if (r.ok) return { ok: true, result: r.body?.result ?? r.body };
  // v1 fallback for instances still on the pre-v2 handlers
  const v1 = await phoneInfogaFetchJson(`${base}/api/numbers/${encodeURIComponent(phoneRaw)}/scan/${encodeURIComponent(scanner)}`, { headers: phoneInfogaHeaders() });
  if (v1.ok) return { ok: true, result: v1.body?.result ?? v1.body };
  return { ok: false, error: String(r.body?.error || v1.body?.error || `HTTP ${r.status || v1.status}`) };
}

/** Google-search scanner run on the remote instance — returns the categorized
 *  dork arrays in the swagger shape (social_media/disposable_providers/reputation/
 *  individuals/general) so the UI can merge them with the local dork set. */
export async function phoneInfogaRemoteGoogleDorks(phoneRaw: string): Promise<Record<string, Array<{ dork: string; url: string; number: string }>>> {
  const run = await phoneInfogaRemoteRun(phoneRaw, 'googlesearch');
  if (!run.ok || !run.result || typeof run.result !== 'object') return {};
  const r = run.result as Record<string, any>;
  const out: Record<string, Array<{ dork: string; url: string; number: string }>> = {};
  for (const [k, v] of Object.entries(r)) {
    if (Array.isArray(v)) out[k] = v.filter((x: any) => x && (x.dork || x.url)).map((x: any) => ({ dork: String(x.dork || ''), url: String(x.url || ''), number: String(x.number || '') }));
  }
  return out;
}

/** Full remote run across every scanner the instance advertises (or the default set). */
export async function phoneInfogaRemoteScan(phoneRaw: string, opts: { scanners?: string[]; dryRun?: boolean } = {}): Promise<PhoneInfogaRemoteResult> {
  const info = await phoneInfogaRemoteInfo();
  if (!info.configured || !info.reachable) return info;
  const wanted = opts.scanners?.length ? opts.scanners : (info.scanners || []).map((s) => s.name);
  const results: Record<string, unknown> = {};
  const dryRuns: Record<string, string> = {};
  const number = await phoneInfogaRemoteNumber(phoneRaw);
  if (number.ok && number.result) results.local = number.result;
  for (const scanner of wanted) {
    if (scanner === 'local') continue;
    if (opts.dryRun) {
      const d = await phoneInfogaRemoteDryRun(phoneRaw, scanner);
      dryRuns[scanner] = d.success ? 'ready' : (d.error || 'not ready');
      continue;
    }
    const run = await phoneInfogaRemoteRun(phoneRaw, scanner);
    results[scanner] = run.ok ? run.result : (run.error || 'failed');
  }
  return { ...info, results, dryRuns: Object.keys(dryRuns).length ? dryRuns : undefined };
}

// ── Composite PhoneInfoga scan ─────────────────────────────────────────────
// Runs every scanner that doesn't require a paid key locally, plus optional
// key-gated enrichments best-effort. A single call powers the OSINT Phone tab
// and the new osint_phone_scan agent tool.
export async function phoneInfogaScan(phoneRaw: string, opts: { remote?: boolean } = {}): Promise<PhoneInfogaScanResult> {
  const base = phoneIntel(phoneRaw);
  const dorks = phoneInfogaDorks(phoneRaw);
  const [ovh, numverify] = await Promise.all([
    phoneInfogaOvhCheck(phoneRaw),
    phoneInfogaNumverify(phoneRaw),
  ]);
  // Optional: run a self-hosted PhoneInfoga REST instance (swagger v2) alongside
  // the in-process port. Unconfigured = a null lane, never a failure.
  let remote: PhoneInfogaRemoteResult | null = null;
  if (opts.remote !== false && phoneInfogaBaseUrl()) {
    try {
      remote = await phoneInfogaRemoteScan(phoneRaw);
    } catch (e: unknown) {
      remote = { configured: true, reachable: false, baseUrl: phoneInfogaBaseUrl(), error: e instanceof Error ? e.message : String(e) };
    }
  }
  // Fold numverify enrichments into the top-level intel when present
  const numCarrier = numverify?.carrier || '';
  const numLineType = numverify?.lineType || '';
  const numLocation = numverify?.location || '';
  // Remote numverify scanner result (swagger shape: line_type / location)
  const rNum = remote?.results?.numverify as Record<string, any> | undefined;
  const carrier = (numCarrier || rNum?.carrier || base.carrier || '').trim();
  const lineType = (numLineType || rNum?.line_type || base.lineType || '').trim();
  const location = (numLocation || rNum?.location || base.location || '').trim();
  let valid = numverify?.valid !== undefined ? !!numverify.valid : base.valid;
  if (numverify?.valid === undefined && rNum && typeof rNum.valid === 'boolean') valid = rNum.valid;
  // Remote OVH scanner result (swagger shape: found / number_range / city / zip_code)
  const rOvh = remote?.results?.ovh as Record<string, any> | undefined;
  if (rOvh && typeof rOvh.found === 'boolean') {
    ovh.found = rOvh.found;
    ovh.supported = true;
    ovh.numberRange = rOvh.number_range || ovh.numberRange;
    ovh.city = rOvh.city || ovh.city;
    ovh.zipCode = rOvh.zip_code || ovh.zipCode;
    ovh.note = rOvh.found ? 'OVH VoIP range MATCHED (remote instance)' : 'OVH VoIP range checked, no match (remote instance)';
  }
  // Merge remote googlesearch dorks into the local set (dedupe by query)
  const rDorks = remote?.results?.googlesearch as Record<string, any> | undefined;
  if (rDorks && typeof rDorks === 'object') {
    const catMap: Record<string, PhoneInfogaDork['category']> = {
      social_media: 'social', disposable_providers: 'disposable', reputation: 'reputation',
      individuals: 'individuals', general: 'general',
    };
    const seen = new Set(dorks.map((d) => d.query));
    for (const [key, cat] of Object.entries(catMap)) {
      const arr = rDorks[key];
      if (!Array.isArray(arr)) continue;
      for (const item of arr as Array<any>) {
        const query = String(item?.dork || item?.query || '');
        if (!query || seen.has(query)) continue;
        seen.add(query);
        dorks.push({ category: cat, label: `Remote — ${query.slice(0, 70)}`, query, url: String(item?.url || gq(query)) });
      }
    }
  }
  let scanNote = 'Local formatting + Google dorks (free) always run.';
  if (ovh?.supported) scanNote += ovh.found ? ' OVH VoIP range MATCHED.' : ' OVH VoIP range checked (no match).';
  else scanNote += ` OVH: ${ovh?.note || 'unsupported country'}.`;
  scanNote += numverify?.configured ? (numverify.error ? ` Numverify: ${numverify.error.slice(0, 120)}.` : ` Numverify: carrier=${carrier || '?'} line=${lineType || '?'}.`) : ' Numverify: not configured (set T3MP3ST_NUMVERIFY_KEY to enrich).';
  if (remote?.configured) scanNote += remote.reachable
    ? ` Remote instance ${remote.baseUrl} reachable (${remote.version || 'version unknown'}, ${remote.scanners?.length || 0} scanners) — results folded in.`
    : ` Remote instance ${remote.baseUrl} configured but UNREACHABLE: ${remote.error || 'no response'}.`;
  else if (remote?.error) scanNote += ` Remote: ${remote.error}.`;
  scanNote += ' Does NOT track phone in real time, does NOT get precise location, does NOT hack phone.';
  return {
    ...base,
    carrier,
    lineType,
    location,
    valid,
    ovh: ovh || null,
    numverify: numverify || null,
    dorks,
    remote,
    scanNote,
  };
}

// =============================================================================
// USERNAME PERMUTATION GENERATOR
// =============================================================================

export function usernamePermutations(
  first: string,
  last: string,
  extras: { middle?: string; birthYear?: string; keywords?: string[]; numbers?: boolean; max?: number } = {}
): string[] {
  const f = first.toLowerCase().replace(/[^a-z0-9]/g, '');
  const l = last.toLowerCase().replace(/[^a-z0-9]/g, '');
  if (!f || !l) throw new Error('Both first and last name are required');
  const m = (extras.middle || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  const year = (extras.birthYear || '').replace(/\D/g, '').slice(-4);
  const base = new Set<string>();
  const add = (...parts: (string | undefined)[]) => {
    const joined = parts.filter(Boolean).join('');
    if (joined.length >= 3) base.add(joined);
  };

  add(f, l); add(l, f); add(f, '.', l); add(l, '.', f); add(f, '_', l); add(l, '_', f);
  add(f, '-', l); add(l, '-', f); add(f[0], l); add(f, l[0]); add(f[0], '.', l); add(f, '.', l[0]);
  if (m) { add(f, m[0], l); add(f, '.', m, '.', l); add(f, m, l); }
  for (const k of extras.keywords || []) {
    const kw = k.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (!kw) continue;
    add(f, kw); add(kw, f); add(f, '.', kw); add(f, '_', kw); add(l, kw); add(kw, l);
  }

  const out = new Set<string>(base);
  if (extras.numbers !== false) {
    for (const b of base) {
      out.add(`${b}1`); out.add(`${b}123`); out.add(`${b}69`); out.add(`${b}007`);
      if (year) { out.add(`${b}${year}`); out.add(`${b}${year.slice(2)}`); }
    }
  }
  const max = extras.max && extras.max > 0 ? extras.max : 200;
  return [...out].sort((a, b) => a.length - b.length).slice(0, max);
}

// =============================================================================
// DORK GENERATORS — deep links the operator can fire in a browser
// =============================================================================

export interface DorkLink { label: string; url: string }

export function personDorks(params: { name?: string; email?: string; username?: string; phone?: string; domain?: string }): DorkLink[] {
  const links: DorkLink[] = [];
  const q = (s: string) => encodeURIComponent(s);
  const engines: [string, string][] = [
    ['Google', 'https://www.google.com/search?q='],
    ['Bing', 'https://www.bing.com/search?q='],
    ['DuckDuckGo', 'https://duckduckgo.com/?q='],
    ['Yandex', 'https://yandex.com/search/?text='],
    ['Brave', 'https://search.brave.com/search?q='],
  ];

  if (params.name) {
    for (const [label, base] of engines) links.push({ label: `${label}: name`, url: `${base}${q(`"${params.name}"`)}` });
    // Venmo public pages are only OSINT-accessible passively (search-engine index).
    // No Venmo endpoints are queried — account enumeration on a financial platform is out of scope.
    links.push({ label: 'Venmo: public pages (indexed)', url: `https://www.google.com/search?q=${q(`site:venmo.com "${params.name}"`)}` });
    links.push({ label: 'Google: name + CV/resume', url: `https://www.google.com/search?q=${q(`"${params.name}" (CV OR resume OR "curriculum vitae")`)}` });
    links.push({ label: 'Google: name + docs', url: `https://www.google.com/search?q=${q(`"${params.name}" (filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xls)`)}` });
    links.push({ label: 'LinkedIn people', url: `https://www.linkedin.com/search/results/people/?keywords=${q(params.name)}` });
    links.push({ label: 'Facebook', url: `https://www.facebook.com/public/${q(params.name)}` });
    links.push({ label: 'TruePeopleSearch', url: `https://www.truepeoplesearch.com/results?name=${q(params.name)}` });
    links.push({ label: 'FastPeopleSearch', url: `https://www.fastpeoplesearch.com/name/${q(params.name.replace(/\s+/g, '-'))}` });
    links.push({ label: 'Whitepages', url: `https://www.whitepages.com/name/${q(params.name.replace(/\s+/g, '-'))}` });
    links.push({ label: 'Spokeo', url: `https://www.spokeo.com/${q(params.name.replace(/\s+/g, '-'))}` });
    links.push({ label: "That'sThem", url: `https://thatsthem.com/name/${q(params.name.replace(/\s+/g, '-'))}` });
    // Federal custody + licensed-clinician records — both have live API lanes now
    // (src/tools/osint-people.ts); these dorks are the manual cross-check the lane cites.
    const [first, ...rest] = params.name.trim().split(/\s+/);
    const last = rest[rest.length - 1] || '';
    links.push({ label: 'BOP federal inmate locator (current federal custody)', url: `https://www.bop.gov/inmateloc/` });
    if (first && last) links.push({ label: 'CMS NPI registry (clinicians)', url: `https://npiregistry.cms.hhs.gov/api/?version=2.1&enumeration_type=NPI-1&first_name=${q(first)}&last_name=${q(last)}&limit=20` });
  }
  if (params.email) {
    for (const [label, base] of engines) links.push({ label: `${label}: email`, url: `${base}${q(`"${params.email}"`)}` });
    links.push({ label: 'GitHub commits (email → code)', url: `https://github.com/search?q=${q(params.email)}&type=code` });
    links.push({ label: 'Gravatar', url: `https://gravatar.com/${createHash('md5').update(params.email.toLowerCase()).digest('hex')}` });
    links.push({ label: 'Have I Been Pwned', url: `https://haveibeenpwned.com/account/${q(params.email)}` });
  }
  if (params.username) {
    const u = params.username.replace(/^@/, '');
    for (const [label, base] of engines) links.push({ label: `${label}: username`, url: `${base}${q(`"${u}"`)}` });
    links.push({ label: 'Venmo: profile (public page)', url: `https://venmo.com/u/${q(u)}` });
    links.push({ label: 'Venmo: indexed mentions', url: `https://www.google.com/search?q=${q(`site:venmo.com "${u}"`)}` });
    links.push({ label: 'Namechk (handle check)', url: `https://namechk.com/check/${q(u)}` });
    links.push({ label: 'KnowEm (aggregator)', url: `https://knowem.com/checkusernames.php?u=${q(u)}` });
    links.push({ label: 'InstantUsername', url: `https://instantusername.com/#/${q(u)}` });
    links.push({ label: 'WhatsMyName (web)', url: `https://whatsmyname.app/?q=${q(u)}` });
    links.push({ label: 'Reddit search', url: `https://www.reddit.com/search/?q=${q(u)}` });
  }
  if (params.phone) {
    const d = params.phone.replace(/\D/g, '');
    links.push({ label: 'Google: phone', url: `https://www.google.com/search?q=${q(`"${d}"`)}` });
    links.push({ label: 'Truecaller', url: `https://www.truecaller.com/search/global/${d}` });
    links.push({ label: 'Sync.me', url: `https://sync.me/search/?number=${d}` });
  }
  if (params.domain) {
    const dom = params.domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    for (const [label, base] of engines) links.push({ label: `${label}: domain`, url: `${base}${q(`site:${dom}`)}` });
    links.push({ label: 'crt.sh (cert transparency)', url: `https://crt.sh/?q=${q(`%.${dom}`)}` },
    );
    links.push({ label: 'Wayback Machine', url: `https://web.archive.org/web/*/${dom}/*` });
    links.push({ label: 'URLScan', url: `https://urlscan.io/domain/${dom}` });
    links.push({ label: 'Shodan', url: `https://www.shodan.io/search?query=hostname%3A${q(dom)}` });
  }
  return links;
}

// =============================================================================
// PERSON LOCATOR — the composite dossier
// =============================================================================

export interface LocatorInput {
  subject?: string;
  name?: string;
  email?: string;
  username?: string;
  phone?: string;
  domain?: string;
  /** Parsed from a subject that was a URL. */
  url?: string;
  /** Sweep breadth. The locator defaults to the fast hand-probed catalog; 'full'
   *  adds the ~430 vendored Sherlock platforms at roughly 3 minutes instead of ~30s. */
  catalog?: 'curated' | 'sherlock' | 'full';
  includeAdult?: boolean;
  /** Live per-module progress callback (the server bridges it to SSE so the UI can
   *  glow the module currently in use). */
  onModule?: (m: LocateModuleStatus & { phase: 'start' | 'end' }) => void;
  /** Optional chat bridge to the operator's configured backbone (local gemma4
   *  when useLocal is on). Enables the UNVERIFIED LLM assist over mined pages. */
  llmChat?: (system: string, user: string) => Promise<string>;
  llmModel?: string;
}

/** One row of the locate run ledger — every module reports ok / skip / error with
 *  timing, so a full locate visibly runs EVERY applicable lane and a failing one
 *  is isolated instead of silently vanishing. */
export interface LocateModuleStatus {
  name: string;
  status: 'running' | 'ok' | 'skip' | 'error';
  ms: number;
  note?: string;
  found?: number;
}

/** Module-ledger factory for the full locate: every stage runs through `run`,
 *  which records ok / skip(reason) / error + timing, isolates failures (one dead
 *  lane never aborts the run), and emits start/end so the UI can glow the module
 *  currently in use. */
export function createModuleLedger(onModule?: (m: LocateModuleStatus & { phase: 'start' | 'end' }) => void) {
  const log: LocateModuleStatus[] = [];
  async function run(
    name: string,
    applicable: boolean,
    skipNote: string,
    fn: () => Promise<{ found?: number; note?: string } | void>,
  ): Promise<void> {
    const row: LocateModuleStatus = { name, status: 'running', ms: 0 };
    if (applicable) {
      log.push(row);
      onModule?.({ ...row, phase: 'start' });
    }
    const t0 = Date.now();
    if (!applicable) {
      const skip: LocateModuleStatus = { name, status: 'skip', ms: 0, note: skipNote };
      log.push(skip);
      onModule?.({ ...skip, phase: 'start' });
      onModule?.({ ...skip, phase: 'end' });
      return;
    }
    try {
      const r = (await fn()) || {};
      row.status = 'ok';
      row.ms = Date.now() - t0;
      if (r.found !== undefined) row.found = r.found;
      if (r.note) row.note = r.note;
    } catch (e) {
      row.status = 'error';
      row.ms = Date.now() - t0;
      row.note = String(e instanceof Error ? e.message : e).slice(0, 140);
    }
    onModule?.({ ...row, phase: 'end' });
  }
  return { log, run };
}

export interface OsintDossier {
  subject: string;
  parsed: { email?: string; username?: string; phone?: string; domain?: string; url?: string };
  name?: string;
  socialAccounts: UsernameHit[];
  /** Profile-corroborated mismatches (a different person owns the handle) — excluded
   *  from results/presence and reported separately so they never pollute the dossier. */
  excludedAccounts: UsernameHit[];
  /** Contact core — the primary locator output. */
  emails: string[];
  phones: string[];
  addresses: string[];
  /** Demographics from dump records (keyed lanes). */
  ages: number[];
  dobs: string[];
  gravatar?: GravatarProfile;
  emailIntel?: EmailIntelResult;
  phone?: PhoneIntelResult;
  dumpLanes: DumpLaneResult[];
  photos: string[];
  locations: string[];
  /** City-level public location signals geocoded for the Geo Intel Map (OSINT layer). */
  geoPoints: GeoPoint[];
  /** Every source probed during the locate — found/absent/unknown audit trail. */
  sourcesChecked: { name: string; status: 'found' | 'absent' | 'unknown'; confidence: string; url?: string }[];
  /** Sanctions / watchlist / wanted-notice screening (name subjects). */
  screening?: ScreeningResult;
  /** Search-result mining runs (per query) — the RESULT PAGES are fetched and parsed,
   *  so mined counts reflect real page text (emails/phones/addresses), not SERP links.
   *  `hits` keeps per-page provenance (page + what was mined from it). */
  searchExtraction: {
    query: string; via: string; found: number; pagesFetched: number;
    emails: number; phones: number; addresses: number;
    hits: { url: string; title: string; emails: string[]; phones: string[]; addresses: string[] }[];
  }[];
  /** Public-records person records (browser-rendered page mining). */
  /** ShadowDragon Step 3 — cross-platform verification signals (same avatar, shared bio). */
  socialSignals: SocialCorrelationSignal[];
  /** ShadowDragon Step 5 — Wayback recovery of deleted profile pages, mined for contacts. */
  historicalRecovery: { url: string; snapshotCount: number; recoveredAt?: string; recoveredUrl?: string; emails: string[]; phones: string[]; addresses: string[] }[];
  peopleRecords: PersonRecord[];
  /** Per-module run ledger for the full locate (ok/skip/error + timing). */
  modules: LocateModuleStatus[];
  /** Dark-web leak-site monitor result (ransomware victim posts for the subject). */
  darkWeb?: LeakMonitorResult;
  /** LLM second-opinion extraction (operator's configured backbone — local gemma4
   *  when useLocal is on). UNVERIFIED by design — kept out of the confident lists. */
  llmAssisted?: LlmAssistedContacts & { sources: string[] };
  /** LLM-directed search plan + ranked pages (the model DIRECTED these searches;
   *  the deterministic layer executed and validated every result). */
  searchPlan?: SearchDirectorResult;
  /** Aggressive multi-round director: which playbook method ran in which round. */
  directorCoverage?: DirectorMethodRun[];
  /** Gaps the director still names after its last round (drives the next plan). */
  directorGaps?: string[];
  /** Operator-ready markdown report (the DETAILED REPORT section). */
  report: string;
  identities: { source: string; detail: string }[];
  dorks: DorkLink[];
  presenceScore: number;
  ranAt: number;
  durationMs: number;
}

// =============================================================================
// GEO INTEL — IP geolocation + text geocoding (keyless public sources)
// =============================================================================
// Serves the Geo Intel Map: engagement-target IPs, egress/proxy exit, DFIR IOC
// infrastructure, and coarse OSINT location signals (city-level public data —
// Gravatar location text, NANP area regions). This is infrastructure geography,
// NOT a person-tracker: no GPS/device/telephony positioning is wired anywhere.

export interface GeoPoint {
  kind: 'egress' | 'target' | 'dfir' | 'osint';
  key: string;
  label: string;
  detail?: string;
  lat?: number;
  lon?: number;
  city?: string;
  region?: string;
  country?: string;
  org?: string;
  geoNote?: string;
}

export interface IpGeoResult {
  ip: string;
  resolved?: boolean;
  privateLan?: boolean;
  lat?: number;
  lon?: number;
  city?: string;
  region?: string;
  country?: string;
  org?: string;
  note?: string;
}

// RFC1918 + loopback + link-local + IETF documentation ranges (192.0.2/198.51.100/203.0.113)
// — the last three are fake-IP convention, never real geolocation targets.
const PRIVATE_IP_RE = /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|0\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|::1|f[cd][0-9a-f]{2}:)/i;

export function isPrivateIp(host: string): boolean {
  return PRIVATE_IP_RE.test(host.trim());
}

interface IpwhoResponse {
  ip?: string; success?: boolean; message?: string;
  latitude?: number; longitude?: number;
  city?: string; region?: string; country?: string;
  connection?: { org?: string; isp?: string };
}

/** Keyless IP geolocation — ipwho.is (HTTPS, no key), ip-api.com as fallback. */
export async function ipGeo(ipRaw: string): Promise<IpGeoResult> {
  const ip = ipRaw.trim();
  if (isPrivateIp(ip) || ip === 'localhost') {
    return { ip, resolved: true, privateLan: true, note: 'private/loopback — no public geolocation (local LAN asset)' };
  }
  try {
    const j = await fetchJson<IpwhoResponse>(`https://ipwho.is/${encodeURIComponent(ip)}`);
    if (j && j.success !== false && typeof j.latitude === 'number' && typeof j.longitude === 'number') {
      return {
        ip,
        resolved: true,
        lat: j.latitude,
        lon: j.longitude,
        city: j.city,
        region: j.region,
        country: j.country,
        org: j.connection?.org || j.connection?.isp,
      };
    }
  } catch { /* fall through to the backup source */ }
  try {
    const fields = 'status,message,country,regionName,city,lat,lon,isp,query';
    const r = await osintFetch(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=${fields}`);
    const j = (await r.json().catch(() => ({}))) as Record<string, unknown>;
    if (j.status === 'success' && typeof j.lat === 'number' && typeof j.lon === 'number') {
      return {
        ip, resolved: true,
        lat: j.lat as number, lon: j.lon as number,
        city: j.city as string, region: j.regionName as string, country: j.country as string,
        org: j.isp as string,
      };
    }
    return { ip, resolved: false, note: (j.message as string) || 'no geolocation returned' };
  } catch (error) {
    return { ip, resolved: false, note: `geolocation failed: ${error instanceof Error ? error.message.slice(0, 80) : 'network error'}` };
  }
}

export async function ipGeoMany(ips: string[]): Promise<IpGeoResult[]> {
  const unique = [...new Set(ips.map((i) => i.trim()).filter(Boolean))].slice(0, 25);
  const out: IpGeoResult[] = [];
  for (let i = 0; i < unique.length; i += 5) {
    out.push(...(await Promise.all(unique.slice(i, i + 5).map(ipGeo))));
  }
  return out;
}

/** Resolve hostnames to IPv4 before geolocating. */
export async function geoForHost(host: string): Promise<IpGeoResult & { host: string }> {
  const h = host.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h) || h === 'localhost' || isPrivateIp(h)) {
    return { host: h, ...(await ipGeo(h)) };
  }
  try {
    const addr = (await dns.resolve4(h))[0];
    const geo = await ipGeo(addr);
    return { host: h, ...geo, ip: addr };
  } catch {
    return { host: h, ...(await ipGeo(h)), note: 'DNS resolution failed — attempted direct geolocation' };
  }
}

// --- text geocoding (Nominatim / OpenStreetMap — keyless, 1 req/s policy) ---

interface NominatimPlace { lat?: string; lon?: string; display_name?: string; type?: string }

const geocodeCache = new Map<string, { lat: number; lon: number; label: string } | null>();
const geocodeLastCall = { at: 0 };

/** Keyless text geocoding (city/place text → coordinates) via OpenStreetMap Nominatim.
 *  Throttled to 1 req/s and cached for the process lifetime per the usage policy. */
export async function geocodeText(query: string): Promise<{ lat: number; lon: number; label: string } | null> {
  const q = query.trim().slice(0, 200);
  if (!q) return null;
  if (geocodeCache.has(q)) return geocodeCache.get(q) ?? null;
  const wait = 1100 - (Date.now() - geocodeLastCall.at);
  if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  geocodeLastCall.at = Date.now();
  try {
    const r = await osintFetch(
      `https://nominatim.openstreetmap.org/search?q=${encodeURIComponent(q)}&format=json&limit=1`,
      { headers: { 'user-agent': 'T3MP3ST-GeoIntel/1.0 (authorized security testing platform)' } }
    );
    const places = (await r.json().catch(() => [])) as NominatimPlace[];
    const hit = places[0]?.lat && places[0]?.lon
      ? { lat: parseFloat(places[0].lat!), lon: parseFloat(places[0].lon!), label: places[0].display_name || q }
      : null;
    geocodeCache.set(q, hit);
    return hit;
  } catch {
    return null;
  }
}

// =============================================================================
// DARK WEB DIRECT — onion search + leak-site monitoring (keyless public lanes)
// =============================================================================
// Two direct lanes instead of paid dump APIs:
//   1. Ransomware leak-site monitor — ransomware.live (keyless public aggregator of
//      the ransomware groups' own victim posts). Defender-oriented threat intel.
//   2. Onion search — Ahmia (public search engine indexing onion sites). Clearnet
//      path first; when a local Tor SOCKS daemon is running (9050 / Tor Browser
//      9150), queries Ahmia's own onion address and fetches .onion pages DIRECTLY
//      through the Tor circuit via curl --socks5-hostname.
// This searches/fetches PUBLIC dark-web content. It does not buy, download, or
// traffic in stolen-data dumps — record-level breach data stays behind the keyed
// lanes or the operator's own authorization.

import { execFile as execFileCb } from 'child_process';
import { promisify } from 'util';
import * as net from 'net';
const execFileP = promisify(execFileCb);

const AHMIA_ONION = 'http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion';
const ONION_RE = /^https?:\/\/[a-z2-7]{16,56}\.onion(\/|$)/i;

export interface TorStatus {
  available: boolean;
  port?: number;
  source?: 'tor-daemon' | 'tor-browser';
  note: string;
}

let torStatusCache: { at: number; status: TorStatus } | null = null;

/** Detect a local Tor SOCKS daemon (9050) or Tor Browser (9150). Cached 60s. */
export async function torStatus(force = false): Promise<TorStatus> {
  if (!force && torStatusCache && Date.now() - torStatusCache.at < 60_000) return torStatusCache.status;
  const probe = (port: number) => new Promise<boolean>((resolve) => {
    const sock = net.connect({ port, host: '127.0.0.1', timeout: 800 });
    sock.once('connect', () => { sock.destroy(); resolve(true); });
    sock.once('timeout', () => { sock.destroy(); resolve(false); });
    sock.once('error', () => resolve(false));
  });
  let status: TorStatus;
  if (await probe(9050)) status = { available: true, port: 9050, source: 'tor-daemon', note: 'Tor SOCKS live on 127.0.0.1:9050 — direct .onion access armed' };
  else if (await probe(9150)) status = { available: true, port: 9150, source: 'tor-browser', note: 'Tor Browser SOCKS live on 127.0.0.1:9150 — direct .onion access armed' };
  else status = { available: false, note: 'no local Tor on 9050/9150 — start Tor (daemon or Tor Browser) to fetch .onion pages directly; search still works over clearnet where reachable' };
  torStatusCache = { at: Date.now(), status };
  return status;
}

/** Fetch a page through the local Tor circuit (curl --socks5-hostname — remote DNS,
 *  the .onion resolution happens inside Tor). Requires torStatus().available. */
export async function onionFetch(urlRaw: string, maxBytes = 400_000): Promise<{ url: string; status: number; body: string }> {
  const url = urlRaw.trim();
  if (!ONION_RE.test(url)) throw new Error('not a .onion URL — onion fetch only handles hidden services');
  const tor = await torStatus();
  if (!tor.available) throw new Error(tor.note);
  let stdout = '';
  try {
    const out = await execFileP(
      'curl',
      ['--socks5-hostname', `127.0.0.1:${tor.port}`, '-sL', '--max-time', '30', '-A', UA, '-w', '\\n__T3MP3ST_STATUS__%{http_code}', url],
      { timeout: 35_000, maxBuffer: 16 * 1024 * 1024 }
    );
    stdout = out.stdout;
  } catch (e) {
    const err = e as { code?: number | string; stderr?: string; killed?: boolean };
    if (err.killed) throw new Error(`onion fetch timed out through the Tor circuit: ${url}`);
    const tail = (err.stderr || '').trim().slice(-120);
    throw new Error(`onion fetch failed (curl exit ${err.code ?? '?'}) — hidden service down, stale address, or circuit congestion${tail ? `: ${tail}` : ''}`);
  }
  const marker = stdout.lastIndexOf('__T3MP3ST_STATUS__');
  const body = (marker >= 0 ? stdout.slice(0, marker) : stdout).slice(0, maxBytes);
  const status = marker >= 0 ? parseInt(stdout.slice(marker + 18).trim(), 10) || 0 : 0;
  return { url, status, body };
}

export interface OnionResult { title: string; url: string; snippet: string }

/** Parse Ahmia result HTML (tolerant — result blocks are <li class="result"> with an
 *  onion anchor, optional <p> snippet and <cite> URL). Exported for unit tests. */
export function parseAhmiaResults(html: string, max = 25): OnionResult[] {
  const results: OnionResult[] = [];
  const seen = new Set<string>();
  const blocks = html.split(/<li[^>]*class="[^"]*result[^"]*"/i).slice(1);
  for (const block of blocks) {
    const anchor = block.match(/<a[^>]+href="(https?:\/\/[a-z2-7]{16,56}\.onion[^"]*)"[^>]*>([\s\S]*?)<\/a>/i);
    if (!anchor) continue;
    const url = anchor[1].replace(/&amp;/g, '&');
    if (seen.has(url)) continue;
    const title = anchor[2].replace(/<[^>]+>/g, '').trim().slice(0, 160) || url;
    const snippetMatch = block.match(/<p[^>]*>([\s\S]*?)<\/p>/i);
    const snippet = snippetMatch ? snippetMatch[1].replace(/<[^>]+>/g, '').trim().slice(0, 300) : '';
    seen.add(url);
    results.push({ title, url, snippet });
    if (results.length >= max) break;
  }
  return results;
}

export interface AhmiaSearchResult {
  query: string;
  via: 'tor' | 'clearnet';
  results: OnionResult[];
  note?: string;
}

/** Onion search via Ahmia. Prefers the Tor circuit (Ahmia's own onion address —
 *  immune to clearnet exit blocking); falls back to clearnet ahmia.fi and reports
 *  honestly when the exit is redirected away (exit-IP reputation). */
export async function ahmiaSearch(queryRaw: string): Promise<AhmiaSearchResult> {
  const query = queryRaw.trim().slice(0, 200);
  if (!query) throw new Error('query required');
  const tor = await torStatus();
  if (tor.available) {
    try {
      const page = await onionFetch(`${AHMIA_ONION}/search/?q=${encodeURIComponent(query)}`);
      const results = parseAhmiaResults(page.body);
      return { query, via: 'tor', results, note: results.length ? undefined : 'search executed over Tor — no results parsed for this query' };
    } catch (e) {
      // fall through to clearnet with the Tor failure noted
      const clear = await ahmiaClearnet(query).catch(() => null);
      if (clear) return { ...clear, note: `Tor fetch failed (${String(e).slice(0, 80)}); clearnet fallback used` };
      throw e;
    }
  }
  return ahmiaClearnet(query);
}

async function ahmiaClearnet(query: string): Promise<AhmiaSearchResult> {
  try {
    const res = await osintFetch(`https://ahmia.fi/search/?q=${encodeURIComponent(query)}`, { redirect: 'manual' });
    if (res.status >= 300 && res.status < 400) {
      return {
        query, via: 'clearnet', results: [],
        note: `ahmia.fi redirected this proxy exit away from search (HTTP ${res.status}) — exit-IP reputation. Start a local Tor daemon (port 9050) and the same search runs DIRECT over the Tor circuit.`,
      };
    }
    const html = await res.text();
    const results = parseAhmiaResults(html);
    return { query, via: 'clearnet', results };
  } catch (error) {
    throw new Error(`Ahmia clearnet search failed: ${error instanceof Error ? error.message.slice(0, 100) : 'network error'}`);
  }
}

// --- ransomware leak-site monitor (ransomware.live — keyless public API) ---

export interface LeakVictim {
  victim: string;
  domain?: string;
  group: string;
  country?: string;
  activity?: string;
  attackDate?: string;
  discovered?: string;
  postUrl?: string;
  description?: string;
}

interface RwVictimRecord {
  victim?: string; domain?: string; group?: string; country?: string; activity?: string;
  attackdate?: string; discovered?: string; url?: string; claim_url?: string; description?: string;
}

function toLeakVictim(r: RwVictimRecord): LeakVictim {
  return {
    victim: r.victim || '(unnamed)',
    domain: r.domain || undefined,
    group: r.group || 'unknown',
    country: r.country || undefined,
    activity: r.activity || undefined,
    attackDate: r.attackdate || undefined,
    discovered: r.discovered || undefined,
    postUrl: r.url || r.claim_url || undefined,
    description: (r.description || '').replace(/\s+/g, ' ').slice(0, 240) || undefined,
  };
}

export interface LeakMonitorResult {
  keyword: string;
  found: number;
  searched: 'api-index' | 'recent-scan';
  victims: LeakVictim[];
  note?: string;
}

/** Check ransomware leak sites for a keyword (target domain, company name, …).
 *  Uses the ransomware.live search API, falls back to a local filter over the
 *  recent-victims feed. This is the free alternative to paid dark-web monitoring. */
export async function ransomwareLeakSearch(keywordRaw: string): Promise<LeakMonitorResult> {
  const keyword = keywordRaw.trim().toLowerCase().slice(0, 120);
  if (!keyword) throw new Error('keyword required (target domain or company name)');
  const kw = keyword.replace(/^https?:\/\//, '').replace(/^www\./, '');

  const search = await fetchJson<RwVictimRecord[]>(`https://api.ransomware.live/v2/searchvictims/${encodeURIComponent(kw)}`);
  if (search && Array.isArray(search)) {
    const victims = search.slice(0, 40).map(toLeakVictim);
    return { keyword: kw, found: victims.length, searched: 'api-index', victims };
  }

  const recent = await fetchJson<RwVictimRecord[]>('https://api.ransomware.live/v2/recentvictims');
  const feed = Array.isArray(recent) ? recent : [];
  const victims = feed
    .filter((r) => `${r.victim || ''} ${r.domain || ''} ${r.group || ''}`.toLowerCase().includes(kw))
    .slice(0, 40)
    .map(toLeakVictim);
  return {
    keyword: kw, found: victims.length, searched: 'recent-scan', victims,
    note: 'keyword index unreachable — scanned the latest victim feed only',
  };
}

function parseSubject(subject: string, input: LocatorInput): LocatorInput {
  const s = subject.trim();
  const out: LocatorInput = { ...input };
  if (EMAIL_RE.test(s)) out.email = s.toLowerCase();
  else if (/^https?:\/\//i.test(s)) {
    out.url = s;
    try {
      const u = new URL(s);
      out.domain = u.hostname.replace(/^www\./, '');
      const seg = u.pathname.split('/').filter(Boolean);
      if (seg.length) {
        // Profile URLs: github.com/USER, reddit.com/user/USER, x.com/@USER, t.me/USER ...
        const raw = seg[0] === 'user' || seg[0] === 'users' ? seg[1] : seg[0];
        const handle = raw?.startsWith('@') ? raw.slice(1) : raw;
        if (handle && !/^(api|blog|help|about|login|signup|settings|notifications|messages|search|explore)$/i.test(handle)) {
          out.username = decodeURIComponent(handle);
        }
      }
    } catch { /* malformed URL — domain stays unset */ }
  } else if (/^[\w.-]+\.[a-z]{2,}$/i.test(s)) out.domain = s.toLowerCase();
  else if (/^\+?\d[\d\s().-]{6,}$/.test(s)) out.phone = s;
  else if (s.includes('@') && s.length > 1) out.username = s.replace(/^@/, '');
  else if (!s.includes(' ')) out.username = s;
  else out.name = s;
  return out;
}

/** Operator-ready markdown report for a dossier — the DETAILED REPORT section:
 *  identifiers, every found record with its source, breach exposure, identity and
 *  location signals, the full sources-consulted audit, and honest next steps. */
export function buildDossierReport(d: OsintDossier): string {
  const L: string[] = [];
  L.push(`# OSINT DOSSIER — ${d.subject}`);
  L.push('');
  L.push(`Generated ${new Date(d.ranAt).toISOString()} · presence ${d.presenceScore}/100 · runtime ${(d.durationMs / 1000).toFixed(1)}s`);
  L.push('');
  L.push('## 1. IDENTIFIERS');
  const ids = Object.entries(d.parsed).filter(([, v]) => v);
  if (d.name) ids.push(['name', d.name]);
  if (ids.length === 0) L.push('- none detected in the subject string');
  for (const [k, v] of ids) L.push(`- **${k}:** ${v}`);
  // Subject assessment — corroboration up front, not buried in a list.
  const matched = d.socialAccounts.filter((h) => h.identity === 'name-match');
  const mismatched = d.excludedAccounts || [];
  if (d.name || d.socialAccounts.length > 0) {
    L.push('');
    if (matched.length > 0) {
      const strongest = matched[0];
      L.push(`- **assessment:** ${matched.length} account(s) corroborate the subject's name — strongest signal: ${strongest.site} ("${strongest.profile?.displayName || 'name match'}"). ${mismatched.length} handle(s) belonged to different people and were EXCLUDED from these results.`);
    } else if (d.socialAccounts.length > 0) {
      L.push(`- **assessment:** ${d.socialAccounts.length} handle(s) claimed but NONE corroborated against a name — treat every hit as unverified (same handle ≠ same person).`);
    } else {
      L.push('- **assessment:** no corroborated accounts found');
    }
  }
  L.push('');

  L.push(`## 2. CONTACT — EMAILS · PHONES · ADDRESSES`);
  if (d.emails.length > 0) {
    L.push(`- **emails (${d.emails.length}):**`);
    for (const e of d.emails) L.push(`  - ${e}`);
  } else {
    L.push('- **emails:** none recovered — arm the dump-lane keys (DeHashed/LeakCheck v2) or check the public-records workbench');
  }
  if (d.phones.length > 0) {
    L.push(`- **phones (${d.phones.length}):**`);
    for (const p of d.phones) L.push(`  - ${p}`);
  } else {
    L.push('- **phones:** none recovered — same levers (keyed dump records carry phone fields; public-records links below)');
  }
  if (d.addresses.length > 0) {
    L.push(`- **addresses (${d.addresses.length}):**`);
    for (const a of d.addresses) L.push(`  - ${a}`);
  } else {
    L.push('- **addresses:** none in keyed dump records — address history lives in the public-records workbench (browser) and keyed dump records');
  }
  L.push('');

  L.push(`## 3. SOCIAL FOOTPRINT — ${d.socialAccounts.length} account(s) for this subject (swept from the contact/identifier results above)`);
  if (d.socialAccounts.length === 0) L.push('- no public profiles found for the handles swept');
  for (const h of d.socialAccounts) {
    const ident = h.identity === 'name-match' ? '✓ IDENTITY MATCH' : 'handle-only';
    const contacts = [h.profile?.email, h.profile?.blog, h.profile?.twitter, h.profile?.location].filter(Boolean).join(' · ');
    L.push(`- [${h.confidence}] **${h.site}** — ${h.url}${h.profile?.displayName ? ` — "${h.profile.displayName}"` : ''} _(${ident})_${contacts ? `\n  - contact/location: ${contacts}` : ''}`);
  }
  if (mismatched.length > 0) {
    L.push('');
    L.push(`### EXCLUDED — different people (${mismatched.length}, not part of this dossier)`);
    for (const h of mismatched) L.push(`- ${h.site}: ${h.url}${h.profile?.displayName ? ` — owned by "${h.profile.displayName}"` : ''}`);
  }
  L.push('');

  L.push('## 4. BREACH / DUMP EXPOSURE');
  let breach = false;
  for (const lane of d.dumpLanes) {
    for (const f of lane.free) {
      L.push(`- ${lane.kind} \`${lane.query}\` — **${f.service}**: ${f.found === 'unknown' ? 'unknown' : `${f.found} record(s)`}${f.sources?.length ? ` — sources: ${f.sources.slice(0, 6).join('; ')}` : ''}${f.note ? ` — _${f.note}_` : ''}`);
      breach = true;
    }
    for (const dep of lane.deep) {
      if ('status' in dep) L.push(`- ${lane.kind} \`${lane.query}\` — ${dep.service}: **not run** — ${dep.note}`);
      else {
        L.push(`- ${lane.kind} \`${lane.query}\` — ${dep.service}: **${dep.found} record(s)**`);
        for (const r of (dep.records || []).slice(0, 10)) {
          L.push(`  - ${r.email || r.username || '?'}${r.password ? ` — password material recovered (${r.source || 'unknown dump'})` : r.hash ? ` — hash recovered (${r.source || 'unknown dump'})` : ''}`);
        }
      }
      breach = true;
    }
    if (lane.credentials.length > 0) L.push(`- ${lane.kind} \`${lane.query}\` — **${lane.credentials.length} credential(s) forwarded to the Evidence Vault**`);
  }
  if (!breach) L.push('- no breach lanes ran for this subject (no email/username/phone identifier present)');
  L.push('');

  L.push('## 5. IDENTITY SIGNALS');
  let ident = false;
  if (d.emailIntel?.gravatar?.exists) {
    const g = d.emailIntel.gravatar;
    L.push(`- Gravatar: **${g.displayName || '(no display name)'}**${g.location ? ` @ ${g.location}` : ''}${g.accounts?.length ? ` — linked accounts: ${g.accounts.map((a) => a.shortname).join(', ')}` : ''}`);
    ident = true;
  }
  for (const i of d.identities) {
    L.push(`- ${i.source}: ${i.detail}`);
    ident = true;
  }
  if (!ident) L.push('- none');
  L.push('');

  L.push('## 6. LOCATION SIGNALS (city-level, public data only)');
  if (d.locations.length === 0) L.push('- none');
  for (const loc of d.locations) L.push(`- ${loc}`);
  L.push('');

  if (d.screening) {
    L.push(`## 6b. SANCTIONS / WATCHLIST SCREENING — ${d.screening.name}`);
    for (const s of d.screening.sources) {
      if (s.status === 'ok' && s.matches.length > 0) {
        L.push(`- **${s.source}: ${s.matches.length} MATCH(ES)**${s.via ? ` (via ${s.via})` : ''}`);
        for (const m of s.matches.slice(0, 10)) L.push(`  - ${m.name} — ${m.detail}`);
      } else if (s.status === 'ok') {
        L.push(`- ${s.source}: no matches${s.via ? ` (via ${s.via})` : ''}`);
      } else {
        L.push(`- ${s.source}: ${s.status.toUpperCase()} — ${s.note || ''}`);
      }
    }
    L.push('');
  }

  const found = d.sourcesChecked.filter((s) => s.status === 'found');
  const absent = d.sourcesChecked.filter((s) => s.status === 'absent');
  const unknownS = d.sourcesChecked.filter((s) => s.status === 'unknown');
  L.push(`## 7. SOURCES CONSULTED — ${d.sourcesChecked.length} platform probe(s)`);
  L.push(`- **found (${found.length}):** ${found.map((s) => s.name).join(', ') || '—'}`);
  L.push(`- **checked, no profile (${absent.length}):** ${absent.length > 0 ? absent.map((s) => s.name).join(', ') : '—'}`);
  L.push(`- **unknown — blocked or rate-limited (${unknownS.length}):** ${unknownS.map((s) => s.name).join(', ') || '—'}`);
  L.push('- breach lanes consulted: LeakCheck public, XposedOrNot, HIBP Pwned Passwords (+ LeakCheck v2 / DeHashed / Snusbase when operator keys are configured)');
  L.push('');

  if (d.name) {
    const personName = d.name;
    const slug = personName.replace(/\s+/g, '-');
    const sp = personName.replace(/\s+/g, '+');
    L.push(`## 7b. PUBLIC RECORDS WORKBENCH — ${personName}`);
    L.push('These hold legal public-record data (address history, age/DOB range, relatives, phones). They WAF-block server-side access — open them in YOUR browser:');
    L.push(`- TruePeopleSearch: https://www.truepeoplesearch.com/results?name=${sp}`);
    L.push(`- FastPeopleSearch: https://www.fastpeoplesearch.com/name/${slug}`);
    L.push(`- Whitepages: https://www.whitepages.com/name/${slug}`);
    L.push(`- That'sThem: https://thatsthem.com/name/${slug}`);
    L.push(`- Spokeo: https://www.spokeo.com/${slug}`);
    L.push(`- LinkedIn (professional footprint): https://www.linkedin.com/search/results/people/?keywords=${sp}`);
    L.push(`- Voter/property/court records: search your state's voter file + county property appraiser + PACER (federal) for "${personName}"`);
    L.push('- Identity-record fields (DOB, address history) ALSO surface in the dump lanes above when their source dumps contained them and the operator key is armed — that is the licensed route to record-level data.');
    L.push('- There is NO legal keyless source for SSN-level identity data, and stolen "fullz" dumps are off-limits. This dossier stops at what public + licensed sources return.');
    L.push('');
  }

  L.push('## 8. RECOMMENDED NEXT STEPS');
  const steps: string[] = [];
  if (d.socialAccounts.length > 0) steps.push('Review the highest-confidence profiles first; screenshots + archive before engaging.');
  if (d.photos.length > 0) steps.push('Reverse-image search the recovered avatar(s) for cross-platform matches.');
  if (d.dumpLanes.some((l) => l.free.some((f) => typeof f.found === 'number' && f.found > 0))) steps.push('Breach exposure confirmed — configure dump-lane keys (T3MP3ST_LEAKCHECK_KEY / DEHASHED / SNUSBASE) for record-level detail, then pursue ONLY within your authorization.');
  if (d.sourcesChecked.some((s) => s.status === 'unknown')) steps.push('Some platforms returned unknown (login-wall / rate-limit) — re-run through residential egress or check manually.');
  if (d.phone) steps.push(`Phone ${d.phone.e164}: fire the Truecaller/Sync.me deep-links for carrier and reverse-lookup data.`);
  steps.push('Hand the dossier handles to a recon operator (tools: osint_username_sweep, osint_breach_lookup) for continuous monitoring.');
  if (d.screening) steps.push('Screening sources marked BLOCKED resist datacenter/Tor egress — check them from your own browser (links in PUBLIC RECORDS / dorks), or arm a residential exit and re-run.');
  for (const s of steps) L.push(`- ${s}`);
  L.push('');
  L.push('_Public-source OSINT only. City-level geography. No device positioning, no intrusion — engage recovered credentials strictly within your authorization._');
  return L.join('\n');
}

/**
 * The full human-lookup chain: parse the subject, sweep socials, pull Gravatar
 * identity + linked accounts, run breach/dump lanes on every identifier, resolve
 * phone country, and generate operator deep-links. All keyless unless the operator
 * configured dump-lane keys.
 */
export async function locatePerson(input: LocatorInput): Promise<OsintDossier> {
  const started = Date.now();
  const parsedInput = input.subject ? parseSubject(input.subject, input) : input;
  const { email, phone, domain } = parsedInput;
  let username = parsedInput.username ? validateUsername(parsedInput.username) : null;
  if (!username && email) username = validateUsername(email.split('@')[0]) || null;

  const socialAccounts: UsernameHit[] = [];
  const dumpLanes: DumpLaneResult[] = [];
  const emails: string[] = email ? [email.toLowerCase()] : [];
  const phones: string[] = phone ? [phone.trim()] : [];
  const addresses: string[] = [];
  const ages: number[] = [];
  const dobs: string[] = [];
  const photos: string[] = [];
  const locations: string[] = [];
  const identities: { source: string; detail: string }[] = [];
  const sourcesChecked: OsintDossier['sourcesChecked'] = [];
  const srcRank = { found: 3, unknown: 2, absent: 1 } as const;
  const mergeChecked = (details: UsernameHit[], tag?: string): void => {
    for (const d of details) {
      const name = tag ? `${d.site} [${tag}]` : d.site;
      const entry = { name, status: d.status, confidence: d.confidence, url: d.url };
      const existing = sourcesChecked.find((s) => s.name === name);
      if (!existing) sourcesChecked.push(entry);
      else if (srcRank[d.status] > srcRank[existing.status]) sourcesChecked[sourcesChecked.indexOf(existing)] = entry;
    }
  };

  // Assembled up front so the parallel jobs below can fill it in — the phone lane
  // awaits inline, which means the .then() callbacks of other jobs can fire before
  // this function reaches any later declaration.
  const dossier: OsintDossier = {
    subject: input.subject || username || email || phone || domain || input.name || '(no subject)',
    parsed: { email, username: username || undefined, phone, domain },
    name: parsedInput.name,
    socialAccounts: [],
    excludedAccounts: [],
    dumpLanes,
    emails,
    phones,
    addresses,
    ages,
    dobs,
    photos,
    locations,
    geoPoints: [],
    sourcesChecked,
    searchExtraction: [],
    socialSignals: [],
    historicalRecovery: [],
    modules: [],
    peopleRecords: [],
    report: '',
    identities,
    dorks: [],
    presenceScore: 0,
    ranAt: Date.now(),
    durationMs: 0,
  };

  // ─────────────────────────────────────────────────────────────────
  // WAVE 1 — IDENTITY CORE: contact data first (emails, phones, addresses,
  // breach/dump exposure, screening). Socials are deliberately LAST and
  // derive from whatever wave 1 confirms.
  // ─────────────────────────────────────────────────────────────────
  // Every stage runs through runModule(): a failing lane is recorded as
  // 'error' and the locate continues; a full run visibly exercises every
  // module (ok / skip-with-reason / error) and reports timing.
  const { log: moduleLog, run: runModule } = createModuleLedger(input.onModule);
  const jobs: Promise<void>[] = [];

  if (email) {
    jobs.push(runModule('EMAIL INTEL', true, '', async () => {
      const intel = await emailIntel(email);
      dossier.gravatar = intel.gravatar;
      dossier.emailIntel = intel;
      if (intel.gravatar.exists) {
        photos.push(intel.gravatar.avatarUrl);
        if (intel.gravatar.displayName) identities.push({ source: 'Gravatar', detail: `display name: ${intel.gravatar.displayName}` });
        if (intel.gravatar.location) locations.push(intel.gravatar.location);
      }
      return { found: intel.breaches.reduce((a, b) => a + (typeof b.found === 'number' ? b.found : 0), 0) + (intel.infostealer.infected ? intel.infostealer.infections.length : 0) };
    }));
    jobs.push(runModule('DUMP LANES', true, '', async () => {
      const r = await dumpDatabaseLookup(email, 'email');
      dumpLanes.push(r);
      const armed = r.deep.filter((d) => 'found' in d).length;
      return { found: r.free.reduce((a, f) => a + (typeof f.found === 'number' ? f.found : 0), 0), note: armed ? `${armed} keyed lane(s) returned records` : r.deep.length ? 'keyed lanes returned no records (key-required or plan-limited)' : undefined };
    }));
  } else {
    jobs.push(runModule('EMAIL INTEL', false, 'no email identifier parsed', async () => undefined));
    jobs.push(runModule('DUMP LANES', false, 'no email identifier parsed (username/phone lanes run below)', async () => undefined));
  }
  if (phone) {
    jobs.push(runModule('PHONE INTEL', true, '', async () => {
      const pi = phoneIntel(phone);
      dossier.phone = pi;
      if (pi.nanp && pi.nanp.validAreaCode) locations.push(`NANP area code ${pi.nanp.areaCode} (region lookup: npa ${pi.nanp.areaCode})`);
      dumpLanes.push(await dumpDatabaseLookup(pi.e164, 'phone').catch(() => ({ query: pi.e164, kind: 'phone' as const, free: [], deep: [], credentials: [] })));
      return { found: 1 };
    }));
  } else {
    jobs.push(runModule('PHONE INTEL', false, 'no phone identifier parsed', async () => undefined));
  }
  if (username) {
    jobs.push(runModule('DUMP LANES (USERNAME)', true, '', async () => {
      const r = await dumpDatabaseLookup(username, 'username');
      dumpLanes.push(r);
      return { found: r.free.reduce((a, f) => a + (typeof f.found === 'number' ? f.found : 0), 0) };
    }));
  }
  if (domain) {
    jobs.push(runModule('DOMAIN / MX', true, '', async () => {
      const mx = await dns.resolveMx(domain);
      if (mx.length) identities.push({ source: `MX ${domain}`, detail: `mail handled by ${mx.map((m) => m.exchange).join(', ')}` });
      return { found: mx.length };
    }));
    jobs.push(runModule('BREACH CATALOG', true, '', async () => {
      const c = await hibpBreachCatalog(domain);
      if (c.total > 0) identities.push({ source: 'HIBP breach catalogue', detail: `${c.total} breach(es) touching ${domain}: ${c.entries.slice(0, 6).map((e) => e.name).join(', ')}` });
      return { found: c.total, note: c.note };
    }));
    jobs.push(runModule('DARK WEB MONITOR', true, '', async () => {
      const leak = await ransomwareLeakSearch(domain);
      dossier.darkWeb = leak;
      if (leak.victims?.length) identities.push({ source: 'dark web leak sites', detail: `${leak.victims.length} ransomware victim post(s) for ${domain}` });
      return { found: leak.victims?.length || 0 };
    }));
  } else {
    jobs.push(runModule('DOMAIN / MX', false, 'no domain parsed', async () => undefined));
    jobs.push(runModule('BREACH CATALOG', false, 'no domain parsed', async () => undefined));
    jobs.push(runModule('DARK WEB MONITOR', false, 'no domain parsed', async () => undefined));
  }
  if (parsedInput.name && parsedInput.name.includes(' ')) {
    jobs.push(runModule('SCREENING', true, '', async () => {
      dossier.screening = await screenSubject(parsedInput.name!);
      const hits = dossier.screening.sources.filter((s) => /hit|listed|found|match/i.test(s.status)).length;
      return { found: hits, note: `${dossier.screening.sources.length} source(s) screened` };
    }));
    jobs.push(runModule('PUBLIC RECORDS', true, '', async () => {
      const result = await peopleRecordSearch(parsedInput.name!);
      dossier.peopleRecords = result.records;
      for (const rec of result.records) {
        if (rec.age && !ages.includes(rec.age)) ages.push(rec.age);
        if (rec.city && !locations.some((l) => l.includes(rec.city!))) locations.push(rec.city + ' (public records)');
        for (const a of rec.pastAddresses.slice(0, 4)) {
          const key = a.toLowerCase();
          if (!addresses.some((x) => x.toLowerCase().includes(key))) addresses.push(a + ' (public records)');
        }
        for (const aka of rec.akas.slice(0, 4)) {
          identities.push({ source: 'public records AKA', detail: aka });
        }
      }
      return { found: result.records.length };
    }));
  } else {
    jobs.push(runModule('SCREENING', false, 'needs a full name (first + last)', async () => undefined));
    jobs.push(runModule('PUBLIC RECORDS', false, 'needs a full name (first + last)', async () => undefined));
  }

  await Promise.all(jobs);

  // Wave 1 harvest: dump records carry the subject's other identifiers — other email
  // addresses, phone numbers, street addresses, and usernames. These are the locator's
  // primary output and drive wave 2.
  const derivedHandles: { handle: string; source: string }[] = [];
  for (const lane of dumpLanes) {
    for (const dep of lane.deep) {
      if ('status' in dep) continue;
      for (const r of dep.records || []) {
        if (r.email && !emails.includes(r.email.toLowerCase())) {
          emails.push(r.email.toLowerCase());
          identities.push({ source: dep.service, detail: `email in dump records: ${r.email.toLowerCase()}` });
        }
        if (r.phone && !phones.includes(r.phone)) {
          phones.push(r.phone);
          identities.push({ source: dep.service, detail: `phone in dump records: ${r.phone}` });
        }
        const addr = [r.address, r.city, r.state, r.country].filter(Boolean).join(', ');
        if (r.address && !addresses.some((a) => a.includes(r.address!))) {
          addresses.push(addr);
          identities.push({ source: dep.service, detail: `address in dump records: ${addr}` });
        }
        if (r.dob && !dobs.includes(r.dob)) dobs.push(r.dob);
        if (r.age) { const a = parseInt(r.age, 10); if (!isNaN(a) && !ages.includes(a)) ages.push(a); }
        const u = validateUsername(r.username || '');
        if (u && !derivedHandles.some((c) => c.handle === u)) derivedHandles.push({ handle: u, source: dep.service });
      }
    }
  }

  // Wave 1.5 — search extraction: mine engine results for contact data.
  const searchQueries: { q: string; kind: string }[] = [];
  if (parsedInput.name) searchQueries.push({ q: `"${parsedInput.name}"`, kind: 'name' });
  if (email) searchQueries.push({ q: `"${email}"`, kind: 'email' });
  if (phone) searchQueries.push({ q: `"${phone}"`, kind: 'phone' });
  await runModule('SEARCH MINING', searchQueries.length > 0, 'no name/email/phone to search', async () => {
    let pages = 0;
    for (const { q, kind } of searchQueries.slice(0, 3)) {
      const extraction = await searchExtract(q, {
        llmAssist: input.llmChat ? async (system, user) => (input.llmChat!(system, user)) : undefined,
      }).catch(() => null);
      if (!extraction) continue;
      pages += extraction.mined.filter((m) => m.fetched).length;
      if (extraction.extracted.llmAssisted) {
        dossier.llmAssisted = dossier.llmAssisted || { emails: [], phones: [], addresses: [], model: input.llmModel, pages: 0, sources: [] };
        const a = extraction.extracted.llmAssisted;
        dossier.llmAssisted.emails = MERGE_UNIQUE(dossier.llmAssisted.emails, a.emails);
        dossier.llmAssisted.phones = MERGE_UNIQUE(dossier.llmAssisted.phones, a.phones);
        dossier.llmAssisted.addresses = MERGE_UNIQUE(dossier.llmAssisted.addresses, a.addresses);
        dossier.llmAssisted.pages += a.pages;
        dossier.llmAssisted.sources.push(kind);
      }
      dossier.searchExtraction.push({
        query: q, via: extraction.via, found: extraction.results.length,
        pagesFetched: extraction.mined.filter((m) => m.fetched).length,
        emails: extraction.extracted.emails.length,
        phones: extraction.extracted.phones.length,
        addresses: extraction.extracted.addresses.length,
        hits: extraction.mined
          .filter((m) => m.fetched && (m.emails.length || m.phones.length || m.addresses.length))
          .slice(0, 6)
          .map((m) => ({
            url: m.url, title: m.title.slice(0, 120),
            emails: m.emails.slice(0, 6), phones: m.phones.slice(0, 4), addresses: m.addresses.slice(0, 4),
          })),
      });
      for (const e of extraction.extracted.emails) {
        if (!emails.includes(e)) {
          emails.push(e);
          identities.push({ source: `search:${kind}`, detail: `email mined from search results: ${e}` });
        }
      }
      for (const p of extraction.extracted.phones) {
        if (!phones.includes(p)) {
          phones.push(p);
          identities.push({ source: `search:${kind}`, detail: `phone mined from search results: ${p}` });
        }
      }
      for (const a of extraction.extracted.addresses) {
        if (!addresses.some((x) => x.toLowerCase() === a.toLowerCase())) {
          addresses.push(a);
          identities.push({ source: `search:${kind}`, detail: `address mined from search result pages: ${a}` });
        }
      }
      for (const sUrl of extraction.extracted.socialUrls) {
        const handleMatch = sUrl.match(/(?:github\.com|t\.me)\/([A-Za-z0-9_-]+)/);
        const u = handleMatch ? validateUsername(handleMatch[1]) : null;
        if (u && !derivedHandles.some((c) => c.handle === u)) derivedHandles.push({ handle: u, source: `search (${kind})` });
      }
    }
    return { found: pages, note: `${searchQueries.slice(0, 3).length} query(ies), ${pages} page(s) fetched+parsed` };
  });

  // ─────────────────────────────────────────────────────────────────
  // WAVE 2 — SOCIAL FOOTPRINT, derived from the identity core. Handle
  // priority: explicit subject handle → email local-part → dump-record
  // usernames → Gravatar linked usernames → name permutations (last).
  // ─────────────────────────────────────────────────────────────────
  const sweepT0 = Date.now();
  const candidates: { handle: string; source: string; primary: boolean }[] = [];
  if (username) candidates.push({ handle: username, source: 'subject handle', primary: true });
  if (email && email.split('@')[0] !== username) {
    const lp = validateUsername(email.split('@')[0]);
    if (lp) candidates.push({ handle: lp, source: 'email local-part', primary: false });
  }
  for (const dh of derivedHandles) {
    if (!candidates.some((c) => c.handle.toLowerCase() === dh.handle.toLowerCase())) {
      candidates.push({ handle: dh.handle, source: dh.source, primary: false });
    }
  }
  for (const acct of dossier.gravatar?.accounts || []) {
    const u = validateUsername(acct.username || '');
    if (u && !candidates.some((c) => c.handle.toLowerCase() === u.toLowerCase())) {
      candidates.push({ handle: u, source: 'Gravatar linked account', primary: false });
    }
  }
  const primaryCandidates = candidates.slice(0, 4);

  if (primaryCandidates.length > 0) {
    for (const cand of primaryCandidates) {
      const sweep = await runUsernameSweep(cand.handle, { hints: { name: parsedInput.name }, catalog: input.catalog || 'curated' }).catch(() => null);
      if (!sweep) continue;
      const tag = cand.primary ? undefined : cand.handle;
      mergeChecked(sweep.details, tag);
      for (const hit of sweep.found) {
        const tagged: UsernameHit = tag ? { ...hit, site: `${hit.site} [${tag}]` } : hit;
        socialAccounts.push(tagged);
        identities.push({
          source: `${hit.site} (via ${cand.source})`,
          detail: `handle "${cand.handle}" claimed: ${hit.url}${hit.identity === 'name-match' ? ` — corroborated: "${hit.profile?.displayName || 'name match'}"` : ''}`,
        });
      }
      // A corroborated match on a derived handle confirms the handle chain.
      if (sweep.found.some((h) => h.identity === 'name-match')) {
        identities.push({ source: 'corroboration', detail: `handle "${cand.handle}" (${cand.source}) corroborated as the subject — accounts above are the same person` });
      }
    }
  } else if (parsedInput.name && !email && !phone && !domain) {
    // Name-only subject: hunt handle variants of the real name across the
    // high-reliability subset of the catalog (the whole point of a name lookup).
    const words = (parsedInput.name || '').trim().split(/\s+/).filter(Boolean);
    if (words.length >= 2) {
      let perms: string[] = [];
      try {
        perms = usernamePermutations(words[0], words[words.length - 1], { max: 12 });
      } catch { /* no perms */ }
      for (let i = 0; i < perms.length; i += 3) {
        const chunk = perms.slice(i, i + 3);
        const sweeps = await Promise.all(
          // Permutation fan-out stays on the curated catalog: 12 permutations ×
          // the full 490-site surface would take tens of minutes for a name-only subject.
          chunk.map((perm) => runUsernameSweep(perm, { limit: 20, hints: { name: parsedInput.name }, catalog: 'curated' }).catch(() => null))
        );
        for (const sweep of sweeps) {
          if (!sweep) continue;
          mergeChecked(sweep.details, sweep.username);
          for (const hit of sweep.found) {
            socialAccounts.push({ ...hit, site: `${hit.site} [${sweep.username}]` });
            identities.push({ source: hit.site, detail: `handle "${sweep.username}" (from name) claimed: ${hit.url}` });
          }
        }
      }
    }
  }

  // Dedupe accounts (perm/secondary sweeps can double-hit), then SPLIT: corroborated
  // mismatches (a different person owns the handle) are excluded from the dossier's
  // results entirely — they get their own disclosure section, never mixed into hits.
  const seenUrls = new Set<string>();
  const uniqueAccounts = socialAccounts.filter((h) => (seenUrls.has(h.url) ? false : (seenUrls.add(h.url), true)));
  const excluded = uniqueAccounts.filter((h) => h.identity === 'name-mismatch');
  const kept = uniqueAccounts.filter((h) => h.identity !== 'name-mismatch');
  dossier.excludedAccounts = excluded.sort((a, b) => a.site.localeCompare(b.site));

  // Profile enrichment: public contact/location fields the platforms expose.
  for (const h of kept) {
    const p = h.profile;
    if (!p) continue;
    if (p.email && !emails.includes(p.email.toLowerCase())) {
      emails.push(p.email.toLowerCase());
      identities.push({ source: h.site, detail: `public email on profile: ${p.email.toLowerCase()}` });
    }
    if (p.blog) identities.push({ source: h.site, detail: `profile blog: ${p.blog}` });
    if (p.twitter) identities.push({ source: h.site, detail: `profile twitter: ${p.twitter}` });
    if (p.location && !locations.includes(p.location)) locations.push(`${p.location} (self-declared on ${h.site})`);
    if (p.imageUrl && !photos.includes(p.imageUrl)) photos.push(p.imageUrl);
  }

  const weight = (h: UsernameHit) =>
    (h.confidence === 'high' ? 2 : h.confidence === 'medium' ? 1 : 0.5) +
    (h.identity === 'name-match' ? 2 : 0);
  const foundWeight = kept.reduce((acc, h) => acc + Math.max(weight(h), 0), 0);
  dossier.presenceScore = Math.min(100, Math.round((foundWeight / 40) * 100));

  // City-level public signals (Gravatar location text, NANP area notes) → map points.
  // Coarse geography only — this is footprint mapping, not device positioning.
  for (const loc of locations.slice(0, 3)) {
    const text = loc.replace(/^NANP area code \d+ \(region lookup: npa (\d+)\)$/, 'area code $1 region, North America');
    const geo = await geocodeText(text).catch(() => null);
    if (geo) {
      dossier.geoPoints.push({
        kind: 'osint',
        key: `osint:${loc}`,
        label: loc,
        detail: geo.label,
        lat: geo.lat,
        lon: geo.lon,
      });
    }
  }

  dossier.socialAccounts = kept.sort((a, b) => weight(b) - weight(a));
  moduleLog.push({
    name: 'SOCIAL SWEEP', status: 'ok',
    ms: Date.now() - (sweepT0 || started),
    found: dossier.socialAccounts.length,
    note: dossier.socialAccounts.length
      ? `${kept.filter((h) => h.identity === 'name-match').length} corroborated · ${kept.filter((h) => h.identity === 'name-mismatch').length} mismatch (excluded)`
      : 'no accounts found',
  });

  // ── ShadowDragon Step 3 — cross-platform correlation on the FOUND accounts ──
  // Two signals beyond name-match: the same profile image reused across
  // platforms, and shared bio wording (city/employer/school). Fingerprints are
  // computed for a bounded set of accounts that expose a public avatar.
  await runModule('CORRELATION', dossier.socialAccounts.length >= 2, 'needs 2+ found accounts', async () => {
    const withImages = dossier.socialAccounts
      .filter((a) => a.profile?.imageUrl)
      .slice(0, 10);
    const fps = await Promise.all(withImages.map(async (a) => ({
      site: a.site, url: a.url, bio: a.profile?.bio || a.profile?.displayName || null,
      avatarFingerprint: await avatarFingerprint(a.profile!.imageUrl!).catch(() => null),
    })));
    dossier.socialSignals = correlateSocialSignals([
      ...fps,
      ...dossier.socialAccounts.map((a) => ({ site: a.site, url: a.url, bio: a.profile?.bio || a.profile?.displayName || null, avatarFingerprint: null })),
    ]);
    for (const sig of dossier.socialSignals) {
      identities.push({
        source: 'correlation',
        detail: sig.kind === 'avatar'
          ? `same profile image across ${sig.accounts.length} platforms (${sig.accounts.map((a) => a.site).join(', ')}) — strongest cross-platform link`
          : `shared bio term "${sig.value}" across ${sig.accounts.map((a) => a.site).join(', ')}`,
      });
    }
    return { found: dossier.socialSignals.length };
  });

  // ── ShadowDragon Step 5 — historical recovery on corroborated profiles ──
  // Deleted bios/pages are archived; the Wayback snapshot body is mined for
  // contact data. Bounded to the top corroborated accounts (skip handle-only).
  const recoveryTargets = dossier.socialAccounts.filter((a) => a.identity !== 'handle-only').slice(0, 3);
  await runModule('HISTORICAL RECOVERY', recoveryTargets.length > 0, 'no corroborated profile to recover', async () => {
    let snapshots = 0;
    for (const acct of recoveryTargets) {
      const rec = await historicalProfileRecovery(acct.url).catch(() => null);
      if (!rec || rec.snapshots.length === 0) continue;
      snapshots += rec.snapshots.length;
      dossier.historicalRecovery.push({
        url: rec.url, snapshotCount: rec.snapshots.length,
        recoveredAt: rec.recoveredAt, recoveredUrl: rec.recoveredUrl,
        emails: rec.mined.emails.slice(0, 8), phones: rec.mined.phones.slice(0, 5), addresses: rec.mined.addresses.slice(0, 5),
      });
      for (const e of rec.mined.emails) {
        if (!emails.includes(e)) { emails.push(e); identities.push({ source: `wayback:${acct.site}`, detail: `email in archived snapshot ${rec.recoveredAt}: ${e}` }); }
      }
      for (const p of rec.mined.phones) {
        if (!phones.includes(p)) { phones.push(p); identities.push({ source: `wayback:${acct.site}`, detail: `phone in archived snapshot ${rec.recoveredAt}: ${p}` }); }
      }
      for (const a of rec.mined.addresses) {
        if (!addresses.some((x) => x.toLowerCase() === a.toLowerCase())) { addresses.push(a); identities.push({ source: `wayback:${acct.site}`, detail: `address in archived snapshot ${rec.recoveredAt}: ${a}` }); }
      }
    }
    return { found: dossier.historicalRecovery.length, note: `${snapshots} snapshot(s) across ${dossier.historicalRecovery.length} profile(s)` };
  });

  // ── LLM SEARCH DIRECTOR — the model plans, ranks and directs the searches.
  // Runs after the deterministic passes so it can plan against what we already
  // have. It proposes queries/URLs; this code executes them, re-validates every
  // contact through the same extractors, and files the plan + page ranking in
  // the dossier so the operator can audit what the model decided.
  await runModule('SEARCH DIRECTOR', Boolean(input.llmChat), 'no LLM configured — deterministic search only', async () => {
    const domains = new Set<string>();
    for (const u of [...emails, ...dossier.socialAccounts.map((a) => a.url)]) {
      const m = String(u).match(/https?:\/\/([^/]+)/) || String(u).match(/@([^@.]+\.[^@]+)/);
      if (m) domains.add(m[1].toLowerCase());
    }
    const director = await llmDirectSearch(input.llmChat!, {
      subject: dossier.subject,
      name: dossier.name,
      email,
      phone,
      domain,
      known: {
        emails, phones, addresses,
        domains: [...domains].slice(0, 10),
        accounts: dossier.socialAccounts.map((a) => a.site).join(', ') || 'none',
      },
    }, { model: input.llmModel });
    dossier.searchPlan = director;
    for (const e of director.found.emails) {
      if (!emails.includes(e)) { emails.push(e); identities.push({ source: 'llm-directed search', detail: `email found by LLM-planned query: ${e}` }); }
    }
    for (const p of director.found.phones) {
      if (!phones.includes(p)) { phones.push(p); identities.push({ source: 'llm-directed search', detail: `phone found by LLM-planned query: ${p}` }); }
    }
    for (const a of director.found.addresses) {
      if (!addresses.some((x) => x.toLowerCase() === a.toLowerCase())) { addresses.push(a); identities.push({ source: 'llm-directed search', detail: `address found by LLM-planned fetch: ${a}` }); }
    }
    const uniq = [...new Set(director.found.emails.filter((e) => !parsedInput.email || e !== parsedInput.email))];
    return {
      found: uniq.length + director.found.phones.length + director.found.addresses.length,
      note: `${director.plan.length} planned step(s), ${director.pagesFetched} page(s) fetched, ${director.verdicts.length} page(s) ranked`,
    };
  });

  // ── AGGRESSIVE DIRECTOR — playbook-driven multi-round people search. The LLM
  // sees a versioned method playbook + current coverage each round and picks the
  // next 1-3 methods/parameters; this code executes them against PUBLIC sources,
  // validates every result, and loops until the budget ends or gaps close.
  let directorResult: AggressiveSearchResult | null = null;
  await runModule('AGGRESSIVE DIRECTOR', Boolean(input.llmChat), 'no LLM configured — deterministic lanes only', async () => {
    const known = {
      emails: [...emails], phones: [...phones], addresses: [...addresses],
      handles: dossier.socialAccounts.map((a) => a.url),
      urls: dossier.socialAccounts.map((a) => a.url),
      accounts: dossier.socialAccounts.map((a) => a.site).join(', ') || 'none',
    };
    directorResult = await aggressivePeopleSearch(input.llmChat!, {
      subject: dossier.subject, name: dossier.name, email, username: username || undefined, phone, domain,
      known,
    }, { model: input.llmModel, maxRounds: 3 });
    dossier.directorCoverage = directorResult.runs;
    dossier.directorGaps = directorResult.remainingGaps;
    for (const e of directorResult.found.emails) {
      if (!emails.includes(e)) { emails.push(e); identities.push({ source: 'aggressive director', detail: `email via directed method: ${e}` }); }
    }
    for (const p of directorResult.found.phones) {
      if (!phones.includes(p)) { phones.push(p); identities.push({ source: 'aggressive director', detail: `phone via directed method: ${p}` }); }
    }
    for (const a of directorResult.found.addresses) {
      if (!addresses.some((x) => x.toLowerCase() === a.toLowerCase())) { addresses.push(a); identities.push({ source: 'aggressive director', detail: `address via directed method: ${a}` }); }
    }
    for (const l of directorResult.found.locations) {
      if (!locations.some((x) => x.toLowerCase() === l.toLowerCase())) locations.push(l);
    }
    for (const h of directorResult.found.handles) {
      if (!derivedHandles.some((c) => c.handle === h)) derivedHandles.push({ handle: h, source: 'aggressive director' });
    }
    return {
      found: directorResult.found.emails.length + directorResult.found.phones.length + directorResult.found.addresses.length + directorResult.found.handles.length,
      note: `${directorResult.rounds} round(s), ${directorResult.runs.length} method run(s) — ${directorResult.runs.map((r) => r.method).join(', ')}${directorResult.remainingGaps.length ? ` · gaps: ${directorResult.remainingGaps.slice(0, 2).join('; ')}` : ''}`,
    };
  });

  await runModule('OPERATOR DORKS', true, '', async () => {
    const base = personDorks({
      name: dossier.name,
      email,
      username: username || undefined,
      phone,
      domain,
    });
    // Google-Dork technique layer (Recorded Future top-20 operators + GHDB categories).
    // Every dork is a *search-engine query* the operator fires in THEIR browser —
    // no automated scraping, no Google bot. The dossier carries the ready-to-click URLs.
    const gDorks = buildGoogleDorks({
      name: dossier.name,
      email: email || undefined,
      username: username || undefined,
      phone: phone || undefined,
      domain: domain || undefined,
      keyword: dossier.name || domain || username || undefined,
      limit: 80,
    }).map((d) => ({
      label: `DORK [${d.category}] ${d.label} (${d.operators.join(' ')})`,
      url: d.engines[0]?.url || `https://www.google.com/search?q=${encodeURIComponent(d.query)}`,
    }));
    // Deduplicate against the base links, then merge (new operator technique last so
    // the original deep-links stay first and stable for existing harness asserts).
    const seen = new Set(base.map((b) => b.url));
    dossier.dorks = [...base, ...gDorks.filter((d) => !seen.has(d.url))];
    return { found: dossier.dorks.length };
  });

  dossier.modules = moduleLog;
  dossier.parsed.url = parsedInput.url;
  dossier.durationMs = Date.now() - started;
  dossier.report = buildDossierReport(dossier);
  return dossier;
}

/** Fetch any URL through the local Tor circuit (clearnet or .onion) — used by the
 *  screening lane as the second path when a source WAF-blocks our primary egress. */
export async function torFetchAny(urlRaw: string, maxBytes = 400_000): Promise<{ url: string; finalUrl: string; status: number; body: string }> {
  const url = urlRaw.trim();
  if (!/^https?:\/\//i.test(url)) throw new Error('http(s) URL required');
  const tor = await torStatus();
  if (!tor.available) throw new Error(tor.note);
  let stdout = '';
  try {
    const out = await execFileP(
      'curl',
      ['--socks5-hostname', `127.0.0.1:${tor.port}`, '-sL', '--max-time', '40', '-A', UA, '-H', 'Accept: application/json,text/html;q=0.9,*/*;q=0.8', '-w', '\\n__T3MP3ST_STATUS__%{http_code} %{url_effective}', url],
      { timeout: 45_000, maxBuffer: 32 * 1024 * 1024 }
    );
    stdout = out.stdout;
  } catch (e) {
    const err = e as { code?: number | string; stderr?: string; killed?: boolean };
    if (err.killed) throw new Error(`tor fetch timed out: ${url}`);
    const tail = (err.stderr || '').trim().slice(-120);
    throw new Error(`tor fetch failed (curl exit ${err.code ?? '?'})${tail ? `: ${tail}` : ''}`);
  }
  const marker = stdout.lastIndexOf('__T3MP3ST_STATUS__');
  const body = (marker >= 0 ? stdout.slice(0, marker) : stdout).slice(0, maxBytes);
  const tail = marker >= 0 ? stdout.slice(marker + 18).trim() : '0';
  const sp = tail.indexOf(' ');
  const status = parseInt(sp >= 0 ? tail.slice(0, sp) : tail, 10) || 0;
  // %{url_effective} — the post-redirect URL, which is the signal for sites that
  // bounce a missing profile onto an error page (Sherlock errorType: response_url).
  const finalUrl = sp >= 0 ? tail.slice(sp + 1).trim() : url;
  return { url, finalUrl: finalUrl || url, status, body };
}

/** Fetch with automatic Tor fallback: primary egress first, Tor circuit when the
 *  source WAF-blocks it (403/000). Returns the winning body + which path answered. */
async function fetchWithTorFallback(url: string, init: RequestInit = {}): Promise<{ body: string; via: 'egress' | 'tor'; status: number }> {
  try {
    const res = await osintFetch(url, init);
    if (res.status !== 403) return { body: await res.text(), via: 'egress', status: res.status };
  } catch { /* fall through to Tor */ }
  const tor = await torStatus();
  if (tor.available) {
    const page = await torFetchAny(url);
    return { body: page.body, via: 'tor', status: page.status };
  }
  return { body: '', via: 'egress', status: 403 };
}

// --- subject screening — sanctions / watchlists / wanted notices (legal, public) ---

export interface ScreeningHit {
  source: string;
  kind: 'match' | 'notice';
  name: string;
  detail: string;
  url?: string;
}

export interface ScreeningSourceStatus {
  source: string;
  status: 'ok' | 'blocked' | 'unconfigured' | 'no-results';
  via?: 'egress' | 'tor';
  matches: ScreeningHit[];
  note?: string;
}

export interface ScreeningResult {
  name: string;
  sources: ScreeningSourceStatus[];
}

function normalizeName(n: string): string {
  return n.toLowerCase().replace(/[^a-z\s]/g, '').replace(/\s+/g, ' ').trim();
}

/** Screen a person across legal public sources: Interpol Red Notices and OFAC-type
 *  sanctions lists. Sources that WAF-block datacenter/Tor egress are reported as
 *  blocked — honestly — instead of pretending the check ran. */
export async function screenSubject(nameRaw: string): Promise<ScreeningResult> {
  const name = nameRaw.trim();
  if (!name || !name.includes(' ')) throw new Error('full name required (first + last)');
  const [firstName, ...rest] = name.split(/\s+/);
  const lastName = rest.join(' ');
  const sources: ScreeningSourceStatus[] = [];

  // Interpol Red Notices — public API
  try {
    const url = `https://ws-public.interpol.int/notices/v1/red?forename=${encodeURIComponent(firstName)}&name=${encodeURIComponent(lastName)}&limit=10`;
    const { body, via, status } = await fetchWithTorFallback(url, { headers: { accept: 'application/json' } });
    if (status !== 200) {
      sources.push({ source: 'Interpol Red Notices', status: 'blocked', matches: [], note: `HTTP ${status} — source blocks datacenter/Tor egress; check https://www.interpol.int/en/How-we-work/Notices/View-Red-Notices in your browser` });
    } else {
      const j = JSON.parse(body) as { total?: number; _embedded?: { notices?: Array<{ forename?: string; name?: string; date_of_birth?: string; nationalities?: string[]; _links?: { self?: { href?: string } } }> } };
      const notices = j._embedded?.notices || [];
      sources.push({
        source: 'Interpol Red Notices', status: notices.length ? 'ok' : 'no-results', via,
        matches: notices.slice(0, 10).map((n) => ({
          source: 'Interpol Red Notice', kind: 'notice' as const,
          name: `${n.forename || ''} ${n.name || ''}`.trim(),
          detail: `wanted notice${n.date_of_birth ? ` · DOB ${n.date_of_birth}` : ''}${n.nationalities?.length ? ` · ${n.nationalities.join(', ')}` : ''}`,
          url: n._links?.self?.href,
        })),
      });
    }
  } catch (e) {
    sources.push({ source: 'Interpol Red Notices', status: 'blocked', matches: [], note: String(e).slice(0, 120) });
  }

  // OFAC SDN list — official CSV export
  try {
    const { body, via, status } = await fetchWithTorFallback('https://www.treasury.gov/ofac/downloads/sdn.csv');
    if (status !== 200 || !body.startsWith('#') === false && body.length < 100) {
      sources.push({ source: 'OFAC SDN', status: 'blocked', matches: [], note: `export unreachable (HTTP ${status}) — browse https://ofac.treasury.gov/specially-designated-nationals-and-blocked-persons-list` });
    } else {
      const norm = normalizeName(name);
      const matches: ScreeningHit[] = [];
      for (const line of body.split('\n')) {
        if (line.startsWith('#') || !line.trim()) continue;
        const cols = line.split(',').map((c) => c.replace(/"/g, '').trim());
        const listName = normalizeName(cols[1] || '');
        if (!listName) continue;
        const tokens = norm.split(' ');
        if (tokens.every((t) => listName.includes(t)) && listName.length < norm.length + 40) {
          matches.push({
            source: 'OFAC SDN', kind: 'match', name: cols[1],
            detail: `${cols[2] || 'entity'}${cols[3] ? ` · program ${cols[3]}` : ''}${cols[5] ? ` · ${cols[5].slice(0, 140)}` : ''}`,
          });
          if (matches.length >= 10) break;
        }
      }
      sources.push({ source: 'OFAC SDN', status: matches.length ? 'ok' : 'no-results', via, matches });
    }
  } catch (e) {
    sources.push({ source: 'OFAC SDN', status: 'blocked', matches: [], note: String(e).slice(0, 120) });
  }

  // OpenSanctions — hosted API is keyed; report as unconfigured rather than pretending
  sources.push({
    source: 'OpenSanctions (full screening)', status: 'unconfigured', matches: [],
    note: 'hosted API needs a key (api.opensanctions.org) — free bulk datasets exist at data.opensanctions.org for air-gapped import',
  });

  return { name, sources };
}

// =============================================================================
// =============================================================================
// SEARCH EXTRACTION — mine search-engine results for contact data (keyless)
// =============================================================================
// Bing HTML SERP parses server-side (DDG/Mojeek serve challenges to datacenter
// exits; Bing answered 200 with real results). Titles + snippets are mined for
// emails, phones, social profile URLs — passive search-data extraction.

export interface SearchResultItem { title: string; url: string; snippet: string }

/** Bing wraps every SERP link in a /ck/a redirect carrying the destination base64url-
 *  encoded in `u` (optionally prefixed "a1"). Decode to the real URL so the mined
 *  pages are the actual destinations, not Bing's JS redirect stubs. */
export function decodeBingRedirect(url: string): string {
  if (!/bing\.com\/ck\/a/i.test(url)) return url;
  try {
    const u = new URL(url).searchParams.get('u');
    if (!u) return url;
    let b64 = u.startsWith('a1') ? u.slice(2) : u;
    b64 = b64.replace(/-/g, '+').replace(/_/g, '/');
    const pad = b64.length % 4 ? '='.repeat(4 - (b64.length % 4)) : '';
    const decoded = Buffer.from(b64 + pad, 'base64').toString('utf8');
    return /^https?:\/\//i.test(decoded) ? decoded : url;
  } catch {
    return url;
  }
}

/** Parse Bing SERP HTML into result items (exported for unit tests). */
export function parseBingResults(html: string, max = 20): SearchResultItem[] {
  const out: SearchResultItem[] = [];
  const blocks = html.split('<li class="b_algo').slice(1);
  for (const block of blocks) {
    const anchor = block.match(/<h2[^>]*><a[^>]+href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/);
    if (!anchor) continue;
    const url = decodeBingRedirect(anchor[1].replace(/&amp;/g, '&'));
    if (!/^https?:\/\//i.test(url)) continue;
    const title = anchor[2].replace(/<[^>]+>/g, '').trim().slice(0, 200);
    const pMatch = block.match(/<p[^>]*>([\s\S]*?)<\/p>/);
    const snippet = pMatch ? pMatch[1].replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim().slice(0, 400) : '';
    out.push({ title, url, snippet });
    if (out.length >= max) break;
  }
  return out;
}

export interface ExtractedContacts {
  emails: string[];
  phones: string[];
  addresses: string[];
  socialUrls: string[];
  /** Optional LLM second opinion — kept OUT of the authoritative lists on purpose. */
  llmAssisted?: LlmAssistedContacts;
}

const EMAIL_RE_GLOBAL = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi;
const PHONE_RE_GLOBAL = /(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}/g;
const SOCIAL_URL_RE = /https?:\/\/(?:www\.)?(github\.com|t\.me|twitter\.com|x\.com|instagram\.com|facebook\.com|linkedin\.com|tiktok\.com|youtube\.com|reddit\.com|soundcloud\.com|keybase\.io)\/[A-Za-z0-9_.\-/@]+/g;
// US-style street addresses, optionally with city/state/ZIP tail on the same line.
const ADDRESS_RE_GLOBAL = /\b(?:P\.?\s?O\.?\s?Box\s+\d+|\d{1,6}\s+(?:[A-Z0-9][A-Za-z0-9'.-]*\s+){0,6}(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Drive|Dr|Lane|Ln|Court|Ct|Circle|Cir|Way|Place|Pl|Terrace|Ter|Parkway|Pkwy|Highway|Hwy|Square|Sq|Trail|Trl))\b(?:[^<\n]{0,60}?\b[A-Z][A-Za-z.\- ]{1,24},\s*(?:AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC)\s+\d{5}(?:-\d{4})?)?/g;

const ADDRESS_JUNK = /(?:v?\d+\.\d+\.\d+|\b(?:lorem|ipsum|example|placeholder|your\s+company|n\/a)\b|copyright|all rights reserved|privacy policy)/i;

/** Extract contact signals from arbitrary text (titles/snippets/URLs/page bodies). */
export function extractContacts(text: string): ExtractedContacts {
  const emails = new Set<string>();
  const phones = new Set<string>();
  const addresses = new Set<string>();
  const phoneKeys = new Set<string>();
  const socials = new Set<string>();
  for (const m of text.match(EMAIL_RE_GLOBAL) || []) {
    const e = m.toLowerCase().replace(/\.$/, '');
    if (/\.(png|jpe?g|gif|css|js|woff2?)$/.test(e)) continue;
    if (/(example\.com|sentry\.io|noreply|no-reply@|@2x)/.test(e)) continue;
    emails.add(e);
  }
  for (const m of text.match(PHONE_RE_GLOBAL) || []) {
    // Version strings / coords, not phones: mixed separators ("762-139.6503")
    // or triple dot-groups ("377.728.2818").
    if (m.includes('-') && m.includes('.')) continue;
    if (/^\d{2,4}\.\d{2,4}\.\d{3,5}$/.test(m.trim())) continue;
    const digits = m.replace(/\D/g, '');
    if (digits.length === 11 && digits.startsWith('1')) { if (!phoneKeys.has(digits)) { phoneKeys.add(digits); phones.add(m.trim()); } }
    else if (digits.length === 10 && !/^(19|20)\d{2}/.test(digits)) { if (!phoneKeys.has(digits)) { phoneKeys.add(digits); phones.add(m.trim()); } }
  }
  for (const m of text.match(ADDRESS_RE_GLOBAL) || []) {
    const a = m.replace(/\s+/g, ' ').replace(/[.,;)]+$/, '').trim();
    if (a.length < 6 || a.length > 120) continue;
    if (ADDRESS_JUNK.test(a)) continue;
    // Needs at least one street number and a street suffix — kills CSS/JS/version noise.
    if (!/^\s*(?:P\.?\s?O\.?\s?Box\s+\d+|\d{1,6}\s)/i.test(a)) continue;
    addresses.add(a);
  }
  for (const m of text.match(SOCIAL_URL_RE) || []) {
    const clean = m.replace(/[.,)]+$/, '');
    if (clean.split('/').filter(Boolean).length >= 2) socials.add(clean);
  }
  return { emails: [...emails], phones: [...phones], addresses: [...addresses], socialUrls: [...socials] };
}

/** Strip a fetched HTML page down to visible-ish text for contact mining. */
export function htmlToText(html: string, maxChars = 200_000): string {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<\/(?:p|div|li|tr|h[1-6]|br|section|article)>/gi, '\n')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&#(\d+);/g, (_, d) => String.fromCharCode(Number(d)))
    .replace(/[ \t]+/g, ' ')
    .slice(0, maxChars);
}

export interface MinedPage {
  url: string;
  title: string;
  fetched: boolean;
  emails: string[];
  phones: string[];
  addresses: string[];
  socialUrls: string[];
  /** Bounded visible-text snippet (first ~2k chars) — feeds the optional LLM assist. */
  text?: string;
}

const SEARCH_PAGE_FETCHERS: Array<(url: string) => Promise<string | null>> = [
  async (url) => {
    const res = await osintFetch(url, { signal: AbortSignal.timeout(8000), headers: { 'accept-language': 'en-US,en' } });
    return res.status === 200 ? await res.text() : null;
  },
  async (url) => {
    const tor = await torStatus();
    if (!tor.available) return null;
    const page = await torFetchAny(url);
    return page.status === 200 ? page.body : null;
  },
  async (url) => {
    if (!directAllowed()) return null;
    const res = await directFetch(url, { signal: AbortSignal.timeout(8000) } as never);
    return res.status === 200 ? await res.text() : null;
  },
];

/** Fetch one search-result page through the egress→Tor→direct chain and mine its
 *  content for emails / phones / addresses / socials. Mines BOTH the cleaned text
 *  AND the raw HTML — contact data usually lives in mailto:/tel: attributes and
 *  JSON-LD blocks that text-stripping removes. */
export async function mineResultPage(url: string, title: string, fetchers = SEARCH_PAGE_FETCHERS): Promise<MinedPage> {
  const empty: MinedPage = { url, title, fetched: false, emails: [], phones: [], addresses: [], socialUrls: [] };
  for (const f of fetchers) {
    const html = await f(url).catch(() => null);
    if (!html) continue;
    const exText = extractContacts(htmlToText(html));
    const exRaw = extractContacts(html);
    return {
      url, title, fetched: true,
      emails: MERGE_UNIQUE(exText.emails, exRaw.emails).slice(0, 12),
      phones: MERGE_UNIQUE(exText.phones, exRaw.phones).slice(0, 8),
      addresses: MERGE_UNIQUE(exText.addresses, exRaw.addresses).slice(0, 8),
      socialUrls: MERGE_UNIQUE(exText.socialUrls, exRaw.socialUrls).slice(0, 10),
      text: htmlToText(html, 2200),
    };
  }
  return empty;
}

const MERGE_UNIQUE = (a: string[], b: string[]): string[] => [...a, ...b.filter((x) => !a.includes(x))];

// =============================================================================
// SHADOWDRAGON 5-STEP METHOD — Step 3 (correlation) + Step 5 (historical recovery)
// Step 3 adds the strongest verification signals beyond name-match: the SAME
// profile image reused across platforms, and overlapping bio tokens (city /
// employer / school wording). Three or more agreeing signals = high confidence.
// Step 5 recovers what a subject deleted: Wayback CDX snapshot listing + the
// archived page body — old bios/pages classically leak emails, phones and
// addresses. Public archive data only; nothing behind a login is touched.
// =============================================================================

export interface ArchiveSnapshot { timestamp: string; url: string; status: string; digest?: string }

/** Parse Wayback CDX JSON (row 0 is the header) into snapshot records. */
export function parseCdxSnapshots(json: unknown): ArchiveSnapshot[] {
  if (!Array.isArray(json) || json.length < 2) return [];
  const header = (json[0] as unknown[]).map((h) => String(h));
  const iTs = header.indexOf('timestamp');
  const iUrl = header.indexOf('original');
  const iSt = header.indexOf('statuscode');
  const iDg = header.indexOf('digest');
  if (iTs === -1 || iUrl === -1) return [];
  const out: ArchiveSnapshot[] = [];
  for (const row of json.slice(1)) {
    if (!Array.isArray(row)) continue;
    const status = iSt !== -1 ? String(row[iSt]) : '';
    if (status && status !== '200') continue;
    out.push({
      timestamp: String(row[iTs] || ''),
      url: String(row[iUrl] || ''),
      status: status || '200',
      digest: iDg !== -1 && row[iDg] ? String(row[iDg]) : undefined,
    });
  }
  return out.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
}

export interface HistoricalRecovery {
  url: string;
  snapshots: ArchiveSnapshot[];
  recoveredAt?: string;
  recoveredUrl?: string;
  recoveredText?: string;
  mined: ExtractedContacts;
  note?: string;
}

/** Wayback CDX lane: list snapshots for a profile/page URL, fetch the most recent
 *  one and mine its body (emails/phones/addresses/socials) — deleted-page recovery. */
export async function historicalProfileRecovery(urlRaw: string, opts: { limit?: number; fetchRaw?: (u: string) => Promise<string | null> } = {}): Promise<HistoricalRecovery> {
  const url = urlRaw.trim();
  if (!/^https?:\/\//i.test(url)) throw new Error(`URL required (http/https): ${urlRaw}`);
  const fetchRaw = opts.fetchRaw || (async (u: string) => {
    try {
      const res = await osintFetch(u, { signal: AbortSignal.timeout(15_000) });
      return res.status === 200 ? await res.text() : null;
    } catch { return null; }
  });
  const limit = Math.max(1, Math.min(opts.limit ?? 25, 100));
  const cdxUrl = `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(url)}&output=json&fl=timestamp,original,statuscode,digest&filter=statuscode:200&collapse=digest&limit=${limit}`;
  const cdxText = await fetchRaw(cdxUrl);
  if (!cdxText) return { url, snapshots: [], mined: { emails: [], phones: [], addresses: [], socialUrls: [] }, note: 'Wayback CDX unreachable' };
  let snapshots: ArchiveSnapshot[] = [];
  try { snapshots = parseCdxSnapshots(JSON.parse(cdxText)); } catch { /* malformed */ }
  if (snapshots.length === 0) {
    return { url, snapshots: [], mined: { emails: [], phones: [], addresses: [], socialUrls: [] }, note: 'no archived snapshots for this URL' };
  }
  const latest = snapshots[snapshots.length - 1];
  const wbUrl = `https://web.archive.org/web/${latest.timestamp}id_/${latest.url}`;
  const pageText = await fetchRaw(wbUrl);
  const mined = pageText ? extractContacts(htmlToText(pageText)) : { emails: [], phones: [], addresses: [], socialUrls: [] };
  const recoveredText = pageText ? htmlToText(pageText).replace(/\s+/g, ' ').trim().slice(0, 600) : undefined;
  return {
    url, snapshots,
    recoveredAt: latest.timestamp,
    recoveredUrl: wbUrl,
    recoveredText: recoveredText && recoveredText.length > 40 ? recoveredText : undefined,
    mined,
    note: pageText ? undefined : 'snapshot listed but body fetch failed (rate limit or JS-only page)',
  };
}

export function avatarFingerprintBytes(buf: Uint8Array): string {
  return createHash('sha256').update(buf).digest('hex').slice(0, 16);
}

/** Fingerprint a public profile image (bytes hash) — identical hashes on different
 *  platforms = the same photo reused = the strongest single identity link. */
export async function avatarFingerprint(imageUrl: string, opts: { fetcher?: (u: string) => Promise<ArrayBuffer | null> } = {}): Promise<string | null> {
  if (!/^https?:\/\//i.test(imageUrl)) return null;
  const fetcher = opts.fetcher || (async (u: string) => {
    const legs: Array<() => Promise<{ status: number; arrayBuffer: () => Promise<ArrayBuffer> } | null>> = [
      async () => { const r = await osintFetch(u, { signal: AbortSignal.timeout(8000) }); return r.status === 200 ? r : null; },
      async () => { if (!directAllowed()) return null; const r = await directFetch(u, { signal: AbortSignal.timeout(8000) } as never); return r.status === 200 ? r : null; },
    ];
    for (const leg of legs) { const r = await leg().catch(() => null); if (r) return r; }
    return null;
  });
  try {
    const fetched = await fetcher(imageUrl);
    if (!fetched) return null;
    // Default fetcher yields a structural Response-like; injected test fetchers yield ArrayBuffer.
    const buf = fetched instanceof ArrayBuffer ? fetched : await (fetched as { arrayBuffer: () => Promise<ArrayBuffer> }).arrayBuffer();
    return avatarFingerprintBytes(new Uint8Array(buf.slice(0, 1_500_000)));
  } catch { return null; }
}

const BIO_STOPWORDS = new Set(['about', 'their', 'there', 'these', 'those', 'with', 'from', 'have', 'been', 'were', 'they', 'them', 'your', 'what', 'when', 'will', 'would', 'could', 'should', 'and', 'the', 'for', 'you', 'not', 'but', 'all', 'can', 'just', 'like', 'more', 'than', 'then', 'some', 'only', 'over', 'into', 'also', 'here', 'that', 'this', 'was', 'are', 'our', 'out', 'get', 'has', 'his', 'her', 'him', 'she']);

export function bioTokens(bio?: string | null): Set<string> {
  const out = new Set<string>();
  for (const t of (bio || '').toLowerCase().replace(/[^a-z0-9\s]/g, ' ').split(/\s+/)) {
    if (t.length >= 4 && !BIO_STOPWORDS.has(t) && !/^\d+$/.test(t)) out.add(t);
  }
  return out;
}

export interface SocialCorrelationSignal { kind: 'avatar' | 'bio'; value: string; accounts: { site: string; url: string }[] }

/** Step-3 correlation across FOUND accounts: identical avatar bytes, or shared bio
 *  tokens (city / employer / school wording), spanning DIFFERENT platforms. */
export function correlateSocialSignals(accounts: { site: string; url: string; avatarFingerprint?: string | null; bio?: string | null }[]): SocialCorrelationSignal[] {
  const out: SocialCorrelationSignal[] = [];
  const byAvatar = new Map<string, { site: string; url: string }[]>();
  for (const a of accounts) {
    if (!a.avatarFingerprint) continue;
    const list = byAvatar.get(a.avatarFingerprint) || [];
    list.push({ site: a.site, url: a.url });
    byAvatar.set(a.avatarFingerprint, list);
  }
  for (const [fp, list] of byAvatar) {
    if (new Set(list.map((x) => x.site)).size >= 2) out.push({ kind: 'avatar', value: fp, accounts: list });
  }
  const tokenSites = new Map<string, Map<string, { site: string; url: string }>>();
  for (const a of accounts) {
    for (const tok of bioTokens(a.bio)) {
      const sites = tokenSites.get(tok) || new Map<string, { site: string; url: string }>();
      if (!sites.has(a.site)) sites.set(a.site, { site: a.site, url: a.url });
      tokenSites.set(tok, sites);
    }
  }
  for (const [tok, sites] of tokenSites) {
    if (sites.size >= 2) out.push({ kind: 'bio', value: tok, accounts: [...sites.values()].slice(0, 6) });
  }
  return out.sort((a, b) => (a.kind === b.kind ? 0 : a.kind === 'avatar' ? -1 : 1)).slice(0, 20);
}

/** LLM-assisted extraction — OPTIONAL second opinion over mined page text.
 *  Deliberately segregated from the deterministic regex layer: the model is
 *  asked for strict JSON, every value is re-validated with the same format
 *  filters the regex lane uses, and results are labelled UNVERIFIED because an
 *  LLM can invent a perfectly-formatted email. Runs on the operator's configured
 *  backbone (local gemma4 when useLocal is on). */
export interface LlmAssistedContacts { emails: string[]; phones: string[]; addresses: string[]; model?: string; pages: number }

export function parseLlmContactJson(raw: string): { emails: string[]; phones: string[]; addresses: string[] } {
  // tolerate fenced blocks + leading prose
  const fenced = raw.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const body = fenced ? fenced[1] : raw;
  const start = body.indexOf('{');
  const end = body.lastIndexOf('}');
  if (start === -1 || end <= start) return { emails: [], phones: [], addresses: [] };
  let j: Record<string, unknown>;
  try { j = JSON.parse(body.slice(start, end + 1)) as Record<string, unknown>; } catch { return { emails: [], phones: [], addresses: [] }; }
  const arr = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);
  // Validate through the same extractors so garbage/hallucinated shapes die.
  const emails = extractContacts(arr(j.emails).join(' ')).emails;
  const phones = extractContacts(arr(j.phones).join(' ')).phones;
  const addresses = extractContacts(arr(j.addresses).join(' ')).addresses;
  return { emails, phones, addresses };
}

const LLM_EXTRACT_SYSTEM = [
  'You extract contact details from raw web-page text. Return ONLY a JSON object',
  'with keys "emails" (array of strings), "phones" (array of strings), "addresses" (array of strings).',
  'Copy values VERBATIM from the text — never invent, complete, or guess one.',
  'If a class is absent, return an empty array. No prose, no markdown outside one JSON object.',
].join(' ');

/** Run the assist across the first N successfully-fetched mined pages (bounded). */
export async function llmAssistAcross(
  mined: MinedPage[],
  chat: (system: string, user: string) => Promise<string>,
  opts: { maxPages?: number; chars?: number; model?: string } = {},
): Promise<LlmAssistedContacts> {
  const maxPages = Math.max(0, Math.min(opts.maxPages ?? 2, 4));
  const chars = opts.chars ?? 1600;
  const pages = mined.filter((m) => m.fetched).slice(0, maxPages);
  const emails: string[] = []; const phones: string[] = []; const addresses: string[] = [];
  for (const m of pages) {
    // Re-fetch is avoided: the regex lane already validated what the page text
    // The assist reasons over the page's own visible text (bounded slice kept by
    // the miner), not a re-fetch — and never over the regex list alone.
    const prompt = [
      `Page: ${m.title || m.url}`,
      `URL: ${m.url}`,
      'Page text (may be truncated):',
      (m.text || m.title || '').slice(0, chars),
      'Regex pre-pass already found (verify/extend; copy verbatim, do not invent):',
      `emails: ${m.emails.join(', ') || 'none'} | phones: ${m.phones.join(', ') || 'none'} | addresses: ${m.addresses.join(', ') || 'none'}`,
    ].join('\n');
    const raw = await chat(LLM_EXTRACT_SYSTEM, prompt).catch(() => '');
    if (!raw) continue;
    const parsed = parseLlmContactJson(raw);
    emails.push(...parsed.emails); phones.push(...parsed.phones); addresses.push(...parsed.addresses);
  }
  return {
    emails: [...new Set(emails)].slice(0, 10),
    phones: [...new Set(phones)].slice(0, 6),
    addresses: [...new Set(addresses)].slice(0, 6),
    model: opts.model,
    pages: pages.length,
  };
}

// =============================================================================
// LLM SEARCH DIRECTOR — the model PLANS and RANKS the searches; the deterministic
// layer executes and re-validates everything. The LLM never becomes the source of
// truth: every proposed query/URL is sanitized here, every fetched page is mined
// with the same format-validating extractors, and the plan itself is kept in a
// SEPARATE dossier section so the operator can see what the model decided.
// =============================================================================

export interface LlmSearchPlanStep { query: string; intent: string; priority: number }
export interface LlmPageVerdict { url: string; priority: number; reason: string }
export interface SearchDirectorResult {
  model?: string;
  rounds: number;
  plan: LlmSearchPlanStep[];
  pagesFetched: number;
  verdicts: LlmPageVerdict[];
  /** What the directed searches actually FOUND (deterministically validated). */
  found: { emails: string[]; phones: string[]; addresses: string[] };
}

/** SSRF-style guard for LLM-proposed DIRECT fetches: public http(s) only. */
export function isPublicSearchUrl(urlRaw: string): boolean {
  let u: URL;
  try { u = new URL(urlRaw); } catch { return false; }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return false;
  const h = u.hostname.toLowerCase();
  if (h === 'localhost' || h.endsWith('.local') || h.endsWith('.internal') || h === 'metadata.google.internal') return false;
  if (/^127\./.test(h) || /^10\./.test(h) || /^192\.168\./.test(h) || /^169\.254\./.test(h) || /^172\.(1[6-9]|2\d|3[01])\./.test(h)) return false;
  if (h === '0.0.0.0' || h === '::1' || h.startsWith('[')) return false;
  return h.includes('.') || h.length > 3; // require a dotted public host
}

const PLAN_SYSTEM = [
  'You are the search director for an OSINT investigation. Given the subject facts and what has already been found, decide the NEXT searches.',
  'Return ONLY JSON: {"plan":[{"query":"<search string>","intent":"<why>","priority":<1-100>}],"pages":[{"url":"<public https URL>","priority":<1-100>,"reason":"<why>"}]}',
  'Rules: at most 6 plan steps and 6 pages. Queries are plain search strings (quotes and site:/filetype: operators are fine). Pages must be public https URLs you are confident belong to the subject (profiles, contact pages, company pages). Never invent a URL you were not given or cannot infer; prefer fewer high-confidence steps. No prose.',
].join(' ');

const VERDICT_SYSTEM = [
  'You rank fetched web pages by how likely each is to belong to the subject.',
  'Return ONLY JSON: {"verdicts":[{"url":"<exact url as given>","priority":<1-100>,"reason":"<max 12 words>"}]}',
  'Rank every given URL exactly once. No prose.',
].join(' ');

/** Tolerant parse + SANITIZE of the director plan (caps, string hygiene, SSRF guard). */
export function parseLlmSearchPlan(raw: string): { plan: LlmSearchPlanStep[]; pages: LlmPageVerdict[] } {
  const fenced = raw.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const body = fenced ? fenced[1] : raw;
  const s = body.indexOf('{'); const e = body.lastIndexOf('}');
  if (s === -1 || e <= s) return { plan: [], pages: [] };
  let j: Record<string, unknown>;
  try { j = JSON.parse(body.slice(s, e + 1)) as Record<string, unknown>; } catch { return { plan: [], pages: [] }; }
  const plan: LlmSearchPlanStep[] = [];
  for (const item of (Array.isArray(j.plan) ? j.plan : []).slice(0, 6)) {
    const o = item as Record<string, unknown>;
    const query = String(o.query || '').replace(/\s+/g, ' ').trim().slice(0, 140);
    if (query.length < 3) continue;
    plan.push({ query, intent: String(o.intent || '').slice(0, 140), priority: Math.max(1, Math.min(100, Number(o.priority) || 50)) });
  }
  const pages: LlmPageVerdict[] = [];
  for (const item of (Array.isArray(j.pages) ? j.pages : []).slice(0, 6)) {
    const o = item as Record<string, unknown>;
    const url = String(o.url || '').trim();
    if (!isPublicSearchUrl(url)) continue; // drop anything non-public / malformed
    pages.push({ url, priority: Math.max(1, Math.min(100, Number(o.priority) || 50)), reason: String(o.reason || '').slice(0, 80) });
  }
  plan.sort((a, b) => b.priority - a.priority);
  pages.sort((a, b) => b.priority - a.priority);
  return { plan, pages };
}

export function parseLlmPageVerdicts(raw: string, allowedUrls: string[]): LlmPageVerdict[] {
  const fenced = raw.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const body = fenced ? fenced[1] : raw;
  const s = body.indexOf('{'); const e = body.lastIndexOf('}');
  if (s === -1 || e <= s) return [];
  let j: Record<string, unknown>;
  try { j = JSON.parse(body.slice(s, e + 1)) as Record<string, unknown>; } catch { return []; }
  const allowed = new Set(allowedUrls);
  const out: LlmPageVerdict[] = [];
  for (const item of (Array.isArray(j.verdicts) ? j.verdicts : [])) {
    const o = item as Record<string, unknown>;
    const url = String(o.url || '').trim();
    if (!allowed.has(url)) continue; // model can only RANK pages we actually fetched
    out.push({ url, priority: Math.max(1, Math.min(100, Number(o.priority) || 50)), reason: String(o.reason || '').slice(0, 80) });
  }
  return out.sort((a, b) => b.priority - a.priority);
}

/** The director pass: plan → execute (queries + direct public pages) → rank. */
/** The AGGRESSIVE director executor: up to `maxRounds` LLM planning rounds; each
 *  round the model picks 1-3 playbook methods with parameters, the engine runs
 *  them against public sources, and every result is validated by the existing
 *  extractors. (Method implementations + parsing live in osint-aggressive.ts.) */
export async function aggressivePeopleSearch(
  chat: (system: string, user: string) => Promise<string>,
  input: {
    subject: string; name?: string; email?: string; username?: string; phone?: string; domain?: string;
    known: { emails: string[]; phones: string[]; addresses: string[]; handles: string[]; urls: string[]; accounts: string };
  },
  opts: { model?: string; maxRounds?: number } = {},
): Promise<AggressiveSearchResult> {
  const maxRounds = Math.max(1, Math.min(opts.maxRounds ?? 3, 5));
  const runs: DirectorMethodRun[] = [];
  const allPicks: DirectorPick[] = [];
  const found = { emails: [] as string[], phones: [] as string[], addresses: [] as string[], locations: [] as string[], handles: [] as string[], urls: [] as string[] };
  found.emails.push(...input.known.emails); found.phones.push(...input.known.phones);
  found.addresses.push(...input.known.addresses); found.urls.push(...input.known.urls);
  let gaps: string[] = [];
  const doneKeys = new Set<string>();
  const dirT0 = Date.now();
  const DIR_BUDGET_MS = 150_000;

  const merge = (src: { emails?: string[]; phones?: string[]; addresses?: string[]; socialUrls?: string[] }) => {
    found.emails.push(...(src.emails || []));
    found.phones.push(...(src.phones || []));
    found.addresses.push(...(src.addresses || []));
    found.urls.push(...(src.socialUrls || []));
  };

  for (let round = 1; round <= maxRounds; round++) {
    const brief = buildDirectorBrief({
      subject: input.subject, name: input.name, email: input.email, username: input.username, phone: input.phone, domain: input.domain,
      known: { ...found, accounts: input.known.accounts },
      ran: runs,
    });
    const raw = await chat(DIRECTOR_SYSTEM, brief).catch(() => '');
    const director = parseDirectorPicks(raw);
    let picks = director.picks;   // reassigned below when a pick is refused
    gaps = director.gaps;
    if (picks.length === 0) {
      // Model flakiness must never idle an aggressive search: fall back to the
      // first playbook methods that have not produced a run yet.
      const { OSINT_PLAYBOOK: PB } = await import('./osint-aggressive.js');
      const ranAny = new Set(runs.map((r) => r.method));
      // Wave 1 already covered these lanes — the fallback must not re-run the
      // slowest of them (public records alone is ~70s).
      const WAVE1_DONE = new Set(['breach_dump', 'people_records', 'screening', 'web_search', 'username_sweep']);
      const FAST_FIRST: DirectorMethodId[] = ['contact_page', 'breach_catalog', 'darkweb_monitor', 'infostealer', 'historical', 'geolocation', 'associates'];
      picks = FAST_FIRST.filter((id) => !ranAny.has(id) && !WAVE1_DONE.has(id)).slice(0, 2)
        .map((id) => ({ method: id, reason: 'deterministic fallback (model returned no usable picks)' }));
      if (!picks.length) picks = PB.filter((m) => !ranAny.has(m.id)).slice(0, 2).map((m) => ({ method: m.id, reason: 'deterministic fallback (slow lane)' }));
      if (picks.length === 0) break;
    }
    let ranAny = false;
    const perMethod = new Map<string, number>();
    for (const pick of picks) {
      // The LLM may COMBINE known identifiers but never INVENT one: a query or
      // url carrying an email/phone/url outside the known set is refused (small
      // local models fabricate plausible contacts; executing those searches
      // poisons the dossier with invented evidence).
      const knownAll = { emails: [...input.known.emails, ...found.emails], phones: [...input.known.phones, ...found.phones], urls: [...input.known.urls, ...found.urls], handles: [...input.known.handles, ...found.handles] };
      if (pick.query) {
        const bad = queryHasUnknownIdentifier(pick.query, knownAll);
        if (bad) { runs.push({ method: pick.method, round, status: 'skip', found: 0, note: 'refused — query contains unverified identifier (' + bad + ')' }); continue; }
      }
      if (pick.url) {
        let host = ''; try { host = new URL(pick.url).hostname.toLowerCase(); } catch (_) { /* unparseable URL — host stays empty and the pick is refused below */ }
        const hostKnown = knownAll.urls.some((u) => { try { return new URL(u).hostname.toLowerCase() === host; } catch (_) { return false; } });
        if (!hostKnown) { runs.push({ method: pick.method, round, status: 'skip', found: 0, note: 'refused — url host not previously surfaced' }); continue; }
      }
      const used = perMethod.get(pick.method) || 0;
      if (used >= 2) { runs.push({ method: pick.method, round, status: 'skip', found: 0, note: 'skipped — method already picked twice this round (diversity)' }); continue; }
      perMethod.set(pick.method, used + 1);
      const param = pick.query || pick.url || pick.username || '';
      if (param && doneKeys.has(`${pick.method}::${param}`)) continue; // never re-run the same ask
      if (param) doneKeys.add(`${pick.method}::${param}`);
      if (Date.now() - dirT0 > DIR_BUDGET_MS) { runs.push({ method: pick.method, round, status: 'skip', found: 0, note: 'skipped — director time budget exhausted' }); continue; }
      ranAny = true;
      allPicks.push(pick);
      const before = found.emails.length + found.phones.length + found.addresses.length;
      const run = await runDirectorMethod(pick, round, input, found, merge);
      run.found = found.emails.length + found.phones.length + found.addresses.length - before + (run.note?.startsWith('accounts:') ? 1 : 0);
      runs.push(run);
    }
    if (!ranAny) break;
    // Early exit: the model says nothing is left to chase.
    if (gaps.length === 0 && round >= 2) break;
  }
  return {
    model: opts.model,
    rounds: runs.length ? Math.max(...runs.map((r) => r.round)) : 0,
    picks: allPicks,
    runs,
    found: {
      emails: [...new Set(found.emails)].slice(0, 25),
      phones: [...new Set(found.phones)].slice(0, 15),
      addresses: [...new Set(found.addresses)].slice(0, 15),
      locations: [...new Set(found.locations)].slice(0, 10),
      handles: [...new Set(found.handles)].slice(0, 15),
      urls: [...new Set(found.urls)].slice(0, 20),
    },
    remainingGaps: gaps,
  };
}

/** Execute one playbook method (public sources only). */
async function runDirectorMethod(
  pick: DirectorPick,
  round: number,
  input: { subject: string; name?: string; email?: string; username?: string; phone?: string; domain?: string; known: { emails: string[]; phones: string[]; addresses: string[]; handles: string[]; urls: string[]; accounts: string } },
  found: { emails: string[]; phones: string[]; addresses: string[]; locations: string[]; handles: string[]; urls: string[] },
  merge: (src: { emails?: string[]; phones?: string[]; addresses?: string[]; socialUrls?: string[] }) => void,
): Promise<DirectorMethodRun> {
  const t0 = Date.now();
  const ok = (n: number, note?: string): DirectorMethodRun => ({ method: pick.method, round, status: 'ok', found: n, note });
  const bad = (e: unknown): DirectorMethodRun => ({ method: pick.method, round, status: 'error', found: 0, note: String(e instanceof Error ? e.message : e).slice(0, 100) });
  const skip = (why: string): DirectorMethodRun => ({ method: pick.method, round, status: 'skip', found: 0, note: why });
  try {
    switch (pick.method) {
      case 'web_search': {
        const r = await searchExtract(pick.query || input.subject, { maxPages: 4 });
        merge(r.extracted);
        return ok(r.mined.filter((m) => m.fetched).length, `query "${(pick.query || '').slice(0, 40)}" · ${r.via} · ${r.results.length} results`);
      }
      case 'contact_page': {
        if (!pick.url) return skip('no url given');
        const m = await mineResultPage(pick.url, pick.reason || pick.url);
        if (!m.fetched) return skip('fetch failed');
        merge(m);
        return ok(m.emails.length + m.phones.length + m.addresses.length, `fetched ${pick.url.slice(0, 50)}`);
      }
      case 'username_sweep': {
        const candidates = pick.username ? [pick.username] : (input.name ? directorHandleCandidates(input.name) : []).slice(0, 2);
        if (candidates.length === 0) return skip('no handle candidates');
        let hits = 0;
        for (const c of candidates) {
          const sw = await runUsernameSweep(c);
          hits += sw.found.length;
          for (const h of sw.found) found.handles.push(h.url);
        }
        return ok(hits, `accounts: ${hits} for ${candidates.join(', ')}`);
      }
      case 'breach_dump': {
        const q = pick.query || pick.username || input.email || input.username || input.phone;
        if (!q) return skip('no identifier');
        const kind = q.includes('@') ? 'email' : (q.replace(/\D/g, '').length >= 7 ? 'phone' : 'username');
        const r = await dumpDatabaseLookup(q, kind);
        const n = r.free.reduce((a, f) => a + (typeof f.found === 'number' ? f.found : 0), 0);
        if (kind === 'email') found.emails.push(q);
        return ok(n, `free-lane records for ${q} (${kind})`);
      }
      case 'infostealer': {
        const e = pick.query && pick.query.includes('@') ? pick.query : input.email;
        if (!e) return skip('no email');
        const r = await hudsonRockEmail(e);
        if (r.infected) for (const i of r.infections) { if (i.ip) found.phones.push(i.ip); }
        return ok(r.infected ? r.infections.length : 0, r.infected ? `${r.infections.length} infection(s)` : 'no infection on record');
      }
      case 'breach_catalog': {
        const d = pick.query || input.domain || (input.email ? input.email.split('@')[1] : '');
        if (!d) return skip('no domain');
        const c = await hibpBreachCatalog(d);
        return ok(c.total, c.total ? `${c.total} breach(es) touching ${d}` : `no breaches recorded for ${d}`);
      }
      case 'people_records': {
        if (!input.name) return skip('needs full name');
        const r = await peopleRecordSearch(input.name);
        for (const rec of r.records) {
          if (rec.city) found.locations.push(rec.city);
          for (const a of rec.pastAddresses) found.addresses.push(a);
          for (const aka of rec.akas) found.handles.push(aka);
        }
        return ok(r.records.length, `${r.records.length} record(s) via ${r.via}`);
      }
      case 'screening': {
        if (!input.name) return skip('needs full name');
        const s = await screenSubject(input.name);
        return ok(s.sources.length, `${s.sources.length} source(s) screened`);
      }
      case 'darkweb_monitor': {
        const kw = pick.query || input.domain || input.name;
        if (!kw) return skip('no keyword');
        const l = await ransomwareLeakSearch(kw);
        return ok(l.victims.length, l.victims.length ? `${l.victims.length} victim post(s) for ${kw}` : `no leak-site posts for ${kw}`);
      }
      case 'historical': {
        const url = pick.url || found.urls[0] || input.known.urls[0];
        if (!url) return skip('no URL recovered yet');
        const rec = await historicalProfileRecovery(url);
        if (rec.snapshots.length === 0) return skip('no snapshots');
        merge(rec.mined);
        return ok(rec.mined.emails.length + rec.mined.phones.length + rec.mined.addresses.length, `${rec.snapshots.length} snapshot(s) of ${url.slice(0, 40)}`);
      }
      case 'geolocation': {
        const q = pick.query || found.addresses[0] || found.locations[0];
        if (!q) return skip('no location string yet');
        const g = await geocodeText(q);
        if (g) found.locations.push(g.label);
        return ok(g ? 1 : 0, g ? `geocoded "${q.slice(0, 40)}"` : `no geocode for "${q.slice(0, 40)}"`);
      }
      case 'associates': {
        const name = input.name;
        if (!name) return skip('needs full name');
        // Classic missing-persons pivot: mine relatives/associates mentions, then
        // back-search the strongest as new leads.
        const r = await searchExtract(`"${name}" relatives OR family OR "associated with" OR colleague`, { maxPages: 3 });
        merge(r.extracted);
        return ok(r.mined.filter((m) => m.fetched).length, `associates pivot via web search`);
      }
      default:
        return skip('method not implemented');
    }
  } catch (e) {
    return bad(e);
  } finally {
    void t0;
  }
}

export async function llmDirectSearch(
  chat: (system: string, user: string) => Promise<string>,
  ctx: {
    subject: string;
    name?: string; email?: string; phone?: string; domain?: string;
    known: { emails: string[]; phones: string[]; addresses: string[]; domains: string[]; accounts: string };
  },
  opts: { model?: string; perQueryPages?: number } = {},
): Promise<SearchDirectorResult> {
  const ctxLine = [
    `Subject: ${ctx.subject}`,
    ctx.name ? `Name: ${ctx.name}` : '',
    ctx.email ? `Email: ${ctx.email}` : '',
    ctx.phone ? `Phone: ${ctx.phone}` : '',
    `Already found — emails: ${ctx.known.emails.join(', ') || 'none'}`,
    `phones: ${ctx.known.phones.join(', ') || 'none'}`,
    `addresses: ${ctx.known.addresses.join(', ') || 'none'}`,
    `domains seen: ${ctx.known.domains.join(', ') || 'none'}`,
    `social accounts: ${ctx.known.accounts || 'none'}`,
    'Plan the searches most likely to surface PUBLIC contact data (emails, phones, addresses) for this subject that we do not already have.',
  ].filter(Boolean).join('\n');

  const rawPlan = await chat(PLAN_SYSTEM, ctxLine).catch(() => '');
  const { plan, pages } = parseLlmSearchPlan(rawPlan);
  if (plan.length === 0 && pages.length === 0) return { model: opts.model, rounds: 1, plan: [], pagesFetched: 0, verdicts: [], found: { emails: [], phones: [], addresses: [] } };

  // Execute the plan in priority order — deterministic execution, LLM direction.
  let pagesFetched = 0;
  const fetchedUrls: string[] = [];
  const found = { emails: [] as string[], phones: [] as string[], addresses: [] as string[] };
  for (const step of plan.slice(0, 6)) {
    const r = await searchExtract(step.query, { maxPages: Math.max(1, Math.min(opts.perQueryPages ?? 3, 5)) }).catch(() => null);
    if (!r) continue;
    pagesFetched += r.mined.filter((m) => m.fetched).length;
    fetchedUrls.push(...r.mined.filter((m) => m.fetched).map((m) => m.url));
    found.emails.push(...r.extracted.emails); found.phones.push(...r.extracted.phones); found.addresses.push(...r.extracted.addresses);
  }
  for (const p of pages.slice(0, 6)) {
    const m = await mineResultPage(p.url, p.reason || p.url).catch(() => null);
    if (m && m.fetched) { pagesFetched++; fetchedUrls.push(m.url); found.emails.push(...m.emails); found.phones.push(...m.phones); found.addresses.push(...m.addresses); }
  }

  // Rank what we actually fetched (the model can only order real URLs).
  const uniq = [...new Set(fetchedUrls)].slice(0, 14);
  const verdicts = uniq.length
    ? parseLlmPageVerdicts(await chat(VERDICT_SYSTEM, `Pages fetched:\n${uniq.join('\n')}`).catch(() => ''), uniq)
    : [];

  return {
    model: opts.model, rounds: 1, plan, pagesFetched, verdicts,
    found: {
      emails: [...new Set(found.emails)].slice(0, 15),
      phones: [...new Set(found.phones)].slice(0, 8),
      addresses: [...new Set(found.addresses)].slice(0, 8),
    },
  };
}


/** Run a Bing search, then PARSE the linked result pages themselves for contact data —
 *  addresses, phones and emails mined from full page text, not just SERP snippets. */
export async function searchExtract(queryRaw: string, opts: { maxPages?: number; llmAssist?: (system: string, user: string) => Promise<string> } = {}): Promise<{
  query: string;
  via: string;
  results: SearchResultItem[];
  extracted: ExtractedContacts;
  mined: MinedPage[];
}> {
  const query = queryRaw.trim().slice(0, 200);
  if (!query) throw new Error('query required');
  const attempts: Array<() => Promise<string | null>> = [
    async () => {
      const res = await osintFetch(`https://www.bing.com/search?q=${encodeURIComponent(query)}&count=20`, {
        headers: { 'accept-language': 'en-US,en' },
        signal: AbortSignal.timeout(15_000),
      });
      return res.status === 200 ? await res.text() : null;
    },
    async () => {
      const tor = await torStatus();
      if (!tor.available) return null;
      const page = await torFetchAny(`https://www.bing.com/search?q=${encodeURIComponent(query)}&count=20`);
      return page.status === 200 ? page.body : null;
    },
  ];
  for (const attempt of attempts) {
    const html = await attempt().catch(() => null);
    if (!html) continue;
    const results = parseBingResults(html);
    if (results.length === 0) continue;
    // Cheap pre-pass: snippets sometimes carry a contact line.
    const snippetExtract = extractContacts(results.map((r) => `${r.title} ${r.snippet} ${r.url}`).join('\n'));
    // The real pass: fetch and mine the top result pages' full text (bounded, parallel).
    const maxPages = Math.max(0, Math.min(opts.maxPages ?? 8, 12));
    const targets = results.slice(0, maxPages);
    const mined = await Promise.all(targets.map((r) => mineResultPage(r.url, r.title).catch(() => ({ url: r.url, title: r.title, fetched: false, emails: [], phones: [], addresses: [], socialUrls: [] } as MinedPage))));
    const extracted: ExtractedContacts = {
      emails: MERGE_UNIQUE(snippetExtract.emails, mined.flatMap((m) => m.emails)),
      phones: MERGE_UNIQUE(snippetExtract.phones, mined.flatMap((m) => m.phones)),
      addresses: MERGE_UNIQUE(snippetExtract.addresses, mined.flatMap((m) => m.addresses)),
      socialUrls: MERGE_UNIQUE(snippetExtract.socialUrls, mined.flatMap((m) => m.socialUrls)),
    };
    // Optional LLM assist (operator's configured backbone — local gemma4 when
    // useLocal is on). The regex layer stays authoritative: LLM findings land in
    // a SEPARATE `llmAssisted` bucket, format-validated and labelled unverified,
    // because models hallucinate contact-shaped strings.
    if (opts.llmAssist) {
      const assisted = await llmAssistAcross(mined, opts.llmAssist).catch(() => null);
      if (assisted && (assisted.emails.length || assisted.phones.length || assisted.addresses.length)) {
        extracted.llmAssisted = assisted;
      }
    }
    return { query, via: 'bing', results, extracted, mined };
  }
  return { query, via: 'blocked', results: [], extracted: { emails: [], phones: [], addresses: [], socialUrls: [] }, mined: [] };
}

// =============================================================================
// PEOPLE RECORDS — agent-driven browser scrubbing of public-records pages
// =============================================================================
// The agent renders public pages with a REAL Chromium (Playwright) — the same
// public data a person sees in their browser — and mines the text for structured
// records: age, city, address history, relatives, aliases. Public-record data,
// no login bypass, no stolen dumps. Source URL is kept on every record.

import * as fsPs from 'fs';
import * as pathPs from 'path';

export interface PersonRecord {
  name: string;
  age?: number;
  city?: string;
  pastAddresses: string[];
  relatives: string[];
  akas: string[];
  sourceUrl: string;
}

const peopleLaunchLock: Promise<void> | null = null;

function resolveChromiumExe(): string | null {
  const base = pathPs.join(process.env.LOCALAPPDATA || '', 'ms-playwright');
  if (!fsPs.existsSync(base)) return null;
  const dirs = fsPs.readdirSync(base).filter((d) => d.startsWith('chromium-')).sort().reverse();
  for (const dir of dirs) {
    for (const sub of ['chrome-win64', 'chrome-win']) {
      const exe = pathPs.join(base, dir, sub, 'chrome.exe');
      if (fsPs.existsSync(exe)) return exe;
    }
  }
  return null;
}

/** Parse FastPeopleSearch innerText into structured person records (exported for tests). */
export function parseFastPeopleSearch(text: string, sourceUrl: string, max = 10): PersonRecord[] {
  const records: PersonRecord[] = [];
  const blocks = text.split(/VIEW FREE DETAILS/).map((b) => b.trim()).filter(Boolean);
  const cityRe = /^[A-Za-z .'-]+, [A-Z]{2}$/;
  for (const block of blocks) {
    const lines = block.split(/\n+/).map((l) => l.trim()).filter((l) => l && !/^FastPeopleSearch$/.test(l) && !/FREE public records found/.test(l));
    let name = '';
    let pending = '';
    let age: number | undefined;
    let city = '';
    const pastAddresses: string[] = [];
    const relatives: string[] = [];
    const akas: string[] = [];
    for (const line of lines) {
      const ageCity = line.match(/^(?:(.{2,60}?)\s+)?Age (\d{1,3}) \u2022 (.+)$/);
      if (ageCity) {
        if (ageCity[1]) name = ageCity[1];
        else if (!name && pending) name = pending;
        age = parseInt(ageCity[2], 10);
        city = ageCity[3].split(/\s*\u2022\s*/)[0];
        continue;
      }
      const past = line.match(/^Past Addresses:\s*(.+)$/);
      if (past) { pastAddresses.push(...past[1].split(/\s*\u2022\s*/).map((s) => s.trim()).filter(Boolean)); continue; }
      const rel = line.match(/^Relatives:\s*(.+)$/);
      if (rel) { relatives.push(...rel[1].split(/\s*\u2022\s*/).map((s) => s.trim()).filter(Boolean)); continue; }
      const aka = line.match(/^AKA:\s*(.+)$/);
      if (aka) { akas.push(...aka[1].split(/\s*\u2022\s*/).map((s) => s.trim()).filter(Boolean)); continue; }
      if (!name && cityRe.test(line) && !city) { city = line; continue; }
      if (!name && line.length <= 60 && !/^(Find |Names |VIEW)/.test(line)) pending = line;
    }
    if (!name && pending) name = pending;
    if (!name && !city) continue;
    if (/(©|copyright|all rights reserved)/i.test(name)) continue;
    records.push({ name: name || city, age, city: city || undefined, pastAddresses, relatives, akas, sourceUrl });
    if (records.length >= max) break;
  }
  return records;
}

/** Parse TruePeopleSearch innerText into structured records.
 *  Layout: header rows, then per-record: name line, 'Age [N|Unknown] • City, ST',
 *  optional 'Used to live in A, B, C', optional 'Related to A, B', 'View Details'. */
export function parseTruePeopleSearch(text: string, sourceUrl: string, max = 10): PersonRecord[] {
  const records: PersonRecord[] = [];
  const lines = text.split(/\n+/).map((l) => l.trim()).filter(Boolean);
  let pending = '';
  let cur: PersonRecord | null = null;
  const finish = () => {
    if (cur && (cur.name || cur.city)) {
      if (!/(©|copyright)/i.test(cur.name)) records.push(cur);
    }
    cur = null;
  };
  for (const line of lines) {
    if (/^TruePeopleSearch$/.test(line) || /^(Name|Phone|Address|Email|Neighbors)$/.test(line)) continue;
    if (/records? found for/i.test(line)) continue;
    const ageN = line.match(/^Age (\d{1,3})\s*•\s*(.+)$/i);
    const ageUnknown = line.match(/^Age Unknown\s*•\s*(.+)$/i);
    if (ageN || ageUnknown) {
      finish();
      cur = {
        name: pending,
        age: ageN ? parseInt(ageN[1], 10) : undefined,
        city: (ageN ? ageN[2] : ageUnknown![1]).trim(),
        pastAddresses: [], relatives: [], akas: [], sourceUrl,
      };
      pending = '';
      continue;
    }
    const usedTo = line.match(/^Used to live in\s*(.+)$/i);
    if (usedTo && cur) { cur.pastAddresses.push(...usedTo[1].split(/,\s*/).map((s) => s.trim()).filter(Boolean)); continue; }
    const related = line.match(/^Related to\s*(.+)$/i);
    if (related && cur) { cur.relatives.push(...related[1].split(/,\s*/).map((s) => s.trim()).filter(Boolean)); continue; }
    if (/^View Details/i.test(line)) { finish(); continue; }
    if (!cur) pending = line;
  }
  finish();
  return records.slice(0, max);
}

/** Per-name result cache — public-records sites throttle frequent queries; a cached
 *  hit is always better than a soft-blocked empty one. 10 min TTL. */
const peopleCache = new Map<string, { at: number; records: PersonRecord[] }>();
const PEOPLE_CACHE_TTL = 10 * 60 * 1000;

/** Render the public-records page for a name in a real browser and mine it. */
export async function peopleRecordSearch(fullNameRaw: string): Promise<{ name: string; via: string; records: PersonRecord[]; note?: string }> {
  const fullName = fullNameRaw.trim().replace(/s+/g, ' ');
  if (!fullName || !fullName.includes(' ')) throw new Error('full name required (first + last)');
  const exe = resolveChromiumExe();
  if (!exe) throw new Error('playwright chromium not installed — run: npx playwright install chromium');
  const cacheKey0 = fullName.toLowerCase();
  const cached = peopleCache.get(cacheKey0);
  if (cached && Date.now() - cached.at < PEOPLE_CACHE_TTL) {
    return { name: fullName, via: 'fastpeoplesearch (rendered)', records: cached.records, note: 'cached (source throttles frequent queries)' };
  }
  const run = async (): Promise<PersonRecord[]> => {
    const { chromium } = await import('playwright');
    const browser = await chromium.launch({ headless: true, executablePath: exe });
    try {
      const page = await browser.newPage({
        userAgent: UA,
        viewport: { width: 1366, height: 900 },
      });
      const slug = fullName.toLowerCase().replace(/\s+/g, '-');
      // Source 1: TruePeopleSearch — renders for datacenter exits more reliably.
      const tpsUrl = `https://www.truepeoplesearch.com/results?name=${encodeURIComponent(fullName)}`;
      await page.goto(tpsUrl, { timeout: 30_000, waitUntil: 'domcontentloaded' });
      await page.waitForTimeout(6_000);
      let tpsText = (await page.evaluate('document.body.innerText.slice(0, 60000)')) as string;
      let parsed = parseTruePeopleSearch(tpsText, tpsUrl, 10);
      if (parsed.length > 0) return parsed;
      // TPS late render / soft block — one retry window.
      await page.waitForTimeout(5_000);
      tpsText = (await page.evaluate('document.body.innerText.slice(0, 60000)')) as string;
      parsed = parseTruePeopleSearch(tpsText, tpsUrl, 10);
      if (parsed.length > 0) return parsed;
      // Source 2: FastPeopleSearch.
      const fpsUrl = `https://www.fastpeoplesearch.com/name/${slug}`;
      await page.goto(fpsUrl, { timeout: 30_000, waitUntil: 'domcontentloaded' });
      await page.waitForTimeout(4_000);
      let fpsText = (await page.evaluate('document.body.innerText.slice(0, 60000)')) as string;
      parsed = parseFastPeopleSearch(fpsText, fpsUrl, 10);
      if (parsed.length === 0) {
        await page.waitForTimeout(6_000);
        fpsText = (await page.evaluate('document.body.innerText.slice(0, 60000)')) as string;
        parsed = parseFastPeopleSearch(fpsText, fpsUrl, 10);
      }
      return parsed;
    } finally {
      await browser.close().catch(() => undefined);
    }
  };
  // One browser launch at a time.
  const records = peopleLaunchLock
    ? await peopleLaunchLock.then(run)
    : await run();
  const cacheKey = fullName.toLowerCase();
  peopleCache.set(cacheKey, { at: Date.now(), records });
  return { name: fullName, via: 'fastpeoplesearch (rendered)', records };
}

// AGENT-RUNNABLE TOOLS (registered into the arsenal, category 'osint')
// =============================================================================

function fmtSweep(sweep: SweepResult): string {
  const lines = sweep.found.map((h) => {
    const ident = h.identity === 'name-match' ? ' [✓ IDENTITY MATCH]' : h.identity === 'name-mismatch' ? ' [≠ name mismatch — likely someone else]' : '';
    const dn = h.profile?.displayName ? ` — "${h.profile.displayName}"` : '';
    return `  [${h.confidence}] ${h.site}${ident}: ${h.url}${dn}`;
  });
  const corroborated = sweep.found.filter((h) => h.identity === 'name-match').length;
  const mismatched = sweep.found.filter((h) => h.identity === 'name-mismatch').length;
  return [
    `Username sweep for "${sweep.username}": ${sweep.found.length} found (${corroborated} corroborated as subject, ${mismatched} mismatched) / ${sweep.absent} absent / ${sweep.unknown.length} unknown (${sweep.checked} sites, ${sweep.durationMs}ms)`,
    ...lines,
    sweep.skippedByShape.length
      ? `  ${sweep.skippedByShape.length} site(s) not probed — the username cannot exist there (Sherlock regexCheck): ${sweep.skippedByShape.join(', ')}`
      : '',
    sweep.unknown.length ? `  unknown: ${sweep.unknown.map((u) => u.site).join(', ')}` : '',
  ].filter(Boolean).join('\n');
}

export const OSINT_TOOLS: CustomTool[] = [
  {
    name: 'osint_username_sweep',
    description: 'Sweep a username across ~490 public social/developer/gaming sites (curated probes + the vendored Sherlock platform database, keyless). Returns claimed accounts.',
    category: 'osint',
    parameters: [
      { name: 'username', type: 'string', description: 'Username to sweep (no @)', required: true },
      { name: 'sites', type: 'string', description: 'Comma-separated site names to limit the sweep (default: all)', required: false },
      { name: 'name', type: 'string', description: 'Known full name of the subject — enables identity corroboration on hits (recommended)', required: false },
      { name: 'catalog', type: 'string', description: 'Catalog breadth: "curated" (fast, hand-probed), "sherlock" (vendored database only), "full" (default — both)', required: false },
      { name: 'includeAdult', type: 'boolean', description: 'Include adult platforms (excluded by default)', required: false },
    ],
    handler: async (context) => {
      const username = context.parameters.username as string;
      const sites = (context.parameters.sites as string | undefined)?.split(',').map((s) => s.trim()).filter(Boolean);
      const name = context.parameters.name as string | undefined;
      const catalogRaw = String(context.parameters.catalog || 'full').toLowerCase();
      const catalog = (['curated', 'sherlock', 'full'].includes(catalogRaw) ? catalogRaw : 'full') as 'curated' | 'sherlock' | 'full';
      const includeAdult = context.parameters.includeAdult === true;
      try {
        const sweep = await runUsernameSweep(username, { sites, hints: { name }, catalog, includeAdult });
        const findings = sweep.found.slice(0, 20).map((h) => ({
          title: `Social Account Found — ${h.site} (${sweep.username})`,
          severity: 'info' as const,
          details: `Username "${sweep.username}" is claimed on ${h.site}: ${h.url} (probe ${h.probeStatus ?? '?'}, confidence ${h.confidence})`,
        }));
        return {
          success: true,
          output: fmtSweep(sweep),
          findings,
        };
      } catch (error) {
        return { success: false, error: `Username sweep failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'osint_email_lookup',
    description: 'Email intelligence: Gravatar identity (name, location, linked accounts, photo), breach exposure (XposedOrNot + LeakCheck public), and mail-domain MX/A records.',
    category: 'osint',
    parameters: [
      { name: 'email', type: 'string', description: 'Email address to investigate', required: true },
    ],
    handler: async (context) => {
      const email = context.parameters.email as string;
      try {
        const intel = await emailIntel(email);
        const lines = [
          `Email intel for ${intel.email}:`,
          `Gravatar: ${intel.gravatar.exists ? 'EXISTS' : 'none'}${intel.gravatar.displayName ? ` — ${intel.gravatar.displayName}` : ''}${intel.gravatar.location ? ` (${intel.gravatar.location})` : ''}`,
          ...(intel.gravatar.accounts || []).map((a) => `  linked account: ${a.shortname}: ${a.username || ''} ${a.url}`),
          `Domain ${intel.domain?.name ?? '?'}: ${intel.domain?.acceptsMail ? `mail (MX: ${intel.domain.mxRecords.join(', ')})` : 'no MX'}${intel.domain?.aRecord ? `, A ${intel.domain.aRecord}` : ''}`,
          ...intel.breaches.map((b) => `Breaches ${b.service}: ${b.found === 'unknown' ? 'unknown' : b.found}${b.sources?.length ? ` (${b.sources.slice(0, 5).join('; ')})` : ''}`),
        ];
        const findings = [];
        if (intel.gravatar.exists) {
          findings.push({
            title: `Gravatar Identity — ${intel.email}`,
            severity: 'info' as const,
            details: `Gravatar exists${intel.gravatar.displayName ? ` for ${intel.gravatar.displayName}` : ''}${intel.gravatar.location ? `, location ${intel.gravatar.location}` : ''}; avatar ${intel.gravatar.avatarUrl}${intel.gravatar.accounts?.length ? `; linked accounts: ${intel.gravatar.accounts.map((a) => `${a.shortname}=${a.username || a.url}`).join(', ')}` : ''}`,
          });
        }
        for (const b of intel.breaches) {
          if (typeof b.found === 'number' && b.found > 0) {
            findings.push({
              title: `Breach Exposure — ${intel.email} (${b.service})`,
              severity: 'medium' as const,
              details: `${b.found} exposed records${b.sources?.length ? ` from: ${b.sources.slice(0, 8).join(', ')}` : ''}${b.fields?.length ? `; fields: ${b.fields.join(', ')}` : ''}`,
            });
          }
        }
        return { success: true, output: lines.filter(Boolean).join('\n'), findings };
      } catch (error) {
        return { success: false, error: `Email lookup failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'osint_phone_lookup',
    description: 'Phone number intelligence (PhoneInfoga — sundowndev/phoneinfoga, GPL-3.0): E.164 / international / local formatting, country/carrier routing, NANP validation, OVH VoIP hint + 50 categorized Google dorks (social / disposable / reputation / individuals / general) and reverse-lookup deep links. Does NOT track phone in real time, does NOT get precise location, does NOT hack phone.',
    category: 'osint',
    parameters: [
      { name: 'phone', type: 'string', description: 'Phone number (any common format, e.g. +33 6 12 34 56 78)', required: true },
    ],
    handler: async (context) => {
      const phone = context.parameters.phone as string;
      try {
        const intel = phoneIntel(phone);
        const dorks = phoneInfogaDorks(phone);
        const byStats = phoneInfogaDorkStats(dorks);
        const lines = [
          `Phone intel for ${intel.input} (PhoneInfoga — sundowndev/phoneinfoga, GPL-3.0):`,
          `E.164: ${intel.e164} | International: ${intel.international} | Local: ${intel.local} | National: ${intel.national}`,
          `Country: ${intel.country} (CC +${intel.countryCode}, ISO ${intel.countryIso || '?'}) — expected ${intel.expectedLength} national digits, got ${intel.national.length} — valid: ${intel.valid ? 'yes' : 'no'}`,
          intel.nanp ? `NANP area ${intel.nanp.areaCode}, exchange ${intel.nanp.exchange}, area valid: ${intel.nanp.validAreaCode}` : '',
          `Dorks: ${dorks.length} (social ${byStats.social || 0} · disposable ${byStats.disposable || 0} · reputation ${byStats.reputation || 0} · individuals ${byStats.individuals || 0} · general ${byStats.general || 0})`,
          ...intel.searchLinks.slice(0, 6).map((l) => `  ${l.label}: ${l.url}`),
          `  + ${dorks.length} PhoneInfoga dorks via osint_phone_scan`,
        ];
        return {
          success: true,
          output: lines.filter(Boolean).join('\n'),
          findings: [{
            title: `Phone Parsed — ${intel.e164}`,
            severity: 'info' as const,
            details: `${intel.country}; length ${intel.lengthValid ? 'valid' : 'UNEXPECTED'}; ${intel.valid ? 'valid' : 'invalid'}${intel.nanp ? `; NANP area ${intel.nanp.areaCode} (valid: ${intel.nanp.validAreaCode})` : ''} — ${dorks.length} PhoneInfoga dorks ready`,
          }],
        };
      } catch (error) {
        return { success: false, error: `Phone lookup failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'osint_phone_scan',
    description: 'Full PhoneInfoga scan (sundowndev/phoneinfoga, GPL-3.0): local formatting + country validity, OVH VoIP range check (free, FR/BE/GB/ES/CH), Numverify carrier/line-type/location enrichment (key-gated, T3MP3ST_NUMVERIFY_KEY), 50 categorized Google dorks (social/disposable/reputation/individuals/general), and — when T3MP3ST_PHONEINFOGA_URL points at a self-hosted PhoneInfoga REST instance (swagger v2) — that instance\'s scanner results folded in. Does NOT claim verified subscriber data, does NOT track phone in real time.',
    category: 'osint',
    parameters: [
      { name: 'phone', type: 'string', description: 'Phone number (any common format, e.g. +1 202 555 0143)', required: true },
      { name: 'remote', type: 'boolean', description: 'Also run the configured self-hosted PhoneInfoga REST instance (T3MP3ST_PHONEINFOGA_URL). Default true; ignored when unset.', required: false },
    ],
    handler: async (context) => {
      const phone = context.parameters.phone as string;
      const wantRemote = context.parameters.remote === undefined ? true : context.parameters.remote === true;
      try {
        const scan = await phoneInfogaScan(phone, { remote: wantRemote });
        const lines = [
          `PhoneInfoga scan for ${scan.input} (sundowndev/phoneinfoga, GPL-3.0):`,
          `E.164: ${scan.e164} | International: ${scan.international} | National: ${scan.national} | Local: ${scan.local}`,
          `Country: ${scan.country} (CC +${scan.countryCode}, ISO ${scan.countryIso || '?'}) — ${scan.valid ? 'valid' : 'invalid'} (expected ${scan.expectedLength}, got ${scan.national.length})${scan.nanp ? ` — NANP area ${scan.nanp.areaCode} valid:${scan.nanp.validAreaCode}` : ''}`,
          scan.carrier || scan.lineType || scan.location ? `Carrier: ${scan.carrier || '?'} | Line: ${scan.lineType || '?'} | Location: ${scan.location || '?'}` : 'Carrier/line/location: needs Numverify key (T3MP3ST_NUMVERIFY_KEY)',
          scan.ovh ? (scan.ovh.found ? `OVH VoIP: MATCH — ${scan.ovh.city || ''} ${scan.ovh.zipCode || ''} range ${scan.ovh.numberRange || scan.ovh.number || ''}` : `OVH VoIP: ${scan.ovh.supported ? 'checked — no OVH range match' : scan.ovh.note || 'unsupported country'}`) : 'OVH: not checked',
          scan.numverify?.configured ? (scan.numverify.error ? `Numverify: ${scan.numverify.error.slice(0, 200)}` : `Numverify: valid=${scan.numverify.valid} carrier=${scan.numverify.carrier || '?'} line=${scan.numverify.lineType || '?'}`) : 'Numverify: not configured',
          `Dorks: ${scan.dorks.length} generated — use pane or copy queries to search engine`,
          ...scan.dorks.slice(0, 12).map((d) => `  [${d.category}] ${d.label}: ${d.query}`),
          scan.dorks.length > 12 ? `  … +${scan.dorks.length - 12} more dorks` : '',
          ...(scan.remote?.configured
            ? [scan.remote.reachable
              ? `Remote instance ${scan.remote.baseUrl}: v${scan.remote.version || '?'}, scanners ${(scan.remote.scanners || []).map((s) => s.name).join(', ') || '?'}; ran ${Object.keys(scan.remote.results || {}).join(', ') || 'none'}`
              : `Remote instance ${scan.remote.baseUrl}: UNREACHABLE (${scan.remote.error || 'no response'})`]
            : []),
          scan.scanNote,
        ];
        const findings: Array<{ title: string; severity: 'info'|'low'|'medium'|'high'|'critical'; details: string }> = [{
          title: `PhoneInfoga Scan — ${scan.e164}`,
          severity: 'info',
          details: `${scan.country} ${scan.valid ? 'valid' : 'invalid'}${scan.carrier ? ` carrier ${scan.carrier}` : ''}${scan.lineType ? ` (${scan.lineType})` : ''}${scan.ovh?.found ? ` OVH VoIP ${scan.ovh.city || ''} ${scan.ovh.zipCode || ''}` : ''} — ${scan.dorks.length} dorks`,
        }];
        if (scan.ovh?.found) {
          findings.push({ title: `OVH VoIP Range — ${scan.e164}`, severity: 'info', details: `Number matches OVH allocated range ${scan.ovh.numberRange} — ${scan.ovh.city || ''} ${scan.ovh.zipCode || ''} (${scan.ovh.country})` });
        }
        return { success: true, output: lines.filter(Boolean).join('\n'), findings };
      } catch (error) {
        return { success: false, error: `Phone scan failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'osint_breach_lookup',
    description: 'Breach/dump exposure check for an email, username, phone — or a raw password (HIBP Pwned Passwords, k-anonymity). Free lanes always run; keyed dump lanes (LeakCheck v2/DeHashed/Snusbase) run when operator keys are configured.',
    category: 'osint',
    parameters: [
      { name: 'query', type: 'string', description: 'Email, username, phone (E.164), or password', required: true },
      { name: 'kind', type: 'string', description: 'Query type', required: false, enum: ['email', 'username', 'phone', 'password'], default: 'email' },
    ],
    handler: async (context) => {
      const query = context.parameters.query as string;
      const kind = (context.parameters.kind as 'email' | 'username' | 'phone' | 'password') || (query.includes('@') ? 'email' : 'username');
      try {
        const result = await dumpDatabaseLookup(query, kind);
        const lines = [
          `Dump-database lookup (${kind}) for "${result.query}":`,
          ...result.free.map((f) => `  ${f.service}: ${f.found === 'unknown' ? 'unknown' : f.found}${f.sources?.length ? ` (${f.sources.slice(0, 5).join('; ')})` : ''}${f.note ? ` — ${f.note}` : ''}`),
          ...result.deep.map((d) => 'status' in d
            ? `  ${d.service}: NOT RUN — ${d.note}`
            : `  ${d.service}: ${d.found} records${d.records?.length ? `\n${d.records.slice(0, 10).map((r) => `    ${r.email || r.username || '?'}${r.password ? ' :PASSWORD:' : ''}${r.hash ? ' :HASH:' : ''} ${r.password || r.hash || ''} (${r.source || '?'})`).join('\n')}` : ''}`),
        ];
        const findings = [];
        for (const f of result.free) {
          if (typeof f.found === 'number' && f.found > 0) {
            findings.push({
              title: `Breach Exposure — ${result.query} (${f.service})`,
              severity: 'medium' as const,
              details: `${f.found} records${f.sources?.length ? ` from ${f.sources.slice(0, 8).join(', ')}` : ''}${f.fields?.length ? `; leaked fields: ${f.fields.join(', ')}` : ''}`,
            });
          }
        }
        return {
          success: true,
          output: lines.join('\n'),
          findings,
          credentials: result.credentials.length ? result.credentials : undefined,
        };
      } catch (error) {
        return { success: false, error: `Breach lookup failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'osint_infostealer_check',
    description: 'Check an email against Hudson Rock\'s free cybercrime-intelligence feed for LIVE infostealer infections (malware family, compromise date, computer name, IP, OS, installed software). Keyless — a live-compromise class static dump lanes cannot see.',
    category: 'osint',
    parameters: [
      { name: 'email', type: 'string', description: 'Email address to check', required: true },
    ],
    handler: async (context) => {
      const email = context.parameters.email as string;
      try {
        const r = await hudsonRockEmail(email);
        const lines = [
          `Infostealer check — ${email}:`,
          r.infected
            ? `  INFECTED — ${r.infections.length} infection record(s); corporate services on record: ${r.corporateServices}, user services: ${r.userServices}`
            : `  no infostealer infection on record${r.note ? ` — ${r.note}` : ''}`,
          ...r.infections.map((i) => `  ${i.family || '?'} · ${i.date || '?'} · host=${i.computerName || '?'} · ip=${i.ip || '?'}${i.os ? ` · os=${i.os}` : ''}${i.software?.length ? ` · software=${i.software.slice(0, 6).join(', ')}` : ''}`),
        ];
        const findings = r.infected
          ? [{
            title: `Infostealer Infection — ${email}`,
            severity: 'high' as const,
            details: r.infections.map((i) => `${i.family || 'stealer'} on ${i.computerName || '?'} (${i.ip || '?'}) at ${i.date || '?'}`).join('; '),
          }]
          : [];
        return { success: true, output: lines.join('\n'), findings };
      } catch (error) {
        return { success: false, error: `Infostealer check failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'osint_historical_recovery',
    description: 'Step-5 historical recovery: list Wayback Machine snapshots for a profile/page URL and mine the newest archived copy for emails, phones, addresses and social links — recovers contact data from deleted bios/pages. Public archive data only.',
    category: 'osint',
    parameters: [
      { name: 'url', type: 'string', description: 'Profile or page URL to recover (e.g. https://github.com/handle)', required: true },
    ],
    handler: async (context) => {
      const url = context.parameters.url as string;
      try {
        const rec = await historicalProfileRecovery(url);
        if (rec.snapshots.length === 0) {
          return { success: true, output: 'No archived snapshots for ' + url + (rec.note ? ' (' + rec.note + ')' : '') };
        }
        const m = rec.mined;
        const lines = [
          'Historical recovery — ' + url + ': ' + rec.snapshots.length + ' snapshot(s), oldest ' + rec.snapshots[0].timestamp + ', newest ' + rec.recoveredAt,
          '  mined from archived copy: ' + m.emails.length + ' email(s), ' + m.phones.length + ' phone(s), ' + m.addresses.length + ' address(es), ' + m.socialUrls.length + ' social link(s)',
          ...m.emails.slice(0, 8).map((e) => '    ✉ ' + e),
          ...m.phones.slice(0, 5).map((p) => '    ☎ ' + p),
          ...m.addresses.slice(0, 5).map((a) => '    📍 ' + a),
        ];
        const findings = (m.emails.length || m.phones.length || m.addresses.length)
          ? [{ title: 'Archived contact data recovered — ' + url, severity: 'medium' as const, details: lines.slice(1).join('; ') }]
          : [];
        return { success: true, output: lines.join(String.fromCharCode(10)), findings };
      } catch (error) {
        return { success: false, error: 'Historical recovery failed: ' + (error instanceof Error ? error.message : String(error)) };
      }
    },
  },
  {
    name: 'osint_leakcheck',
    description: 'LeakCheck.io breach lookup (leakcheck.io, docs.leakcheck.io): the free PUBLIC lane returns which breach sources list an identifier and which data classes were exposed; the Pro v2 lane (key-gated via T3MP3ST_LEAKCHECK_KEY / LEAKCHECKIO) returns full records plus per-breach attribution, exposure flags and the remaining query quota. Searches by email, username, phone, domain or hash. A hit means a breach lists this identifier — it does not prove the account is still active.',
    category: 'osint',
    parameters: [
      { name: 'query', type: 'string', description: 'Email, username, phone (E.164 digits), domain, or SHA-256 hash', required: true },
      { name: 'type', type: 'string', description: 'Search type: auto (default), email, username, phone, domain, hash, keyword', required: false, enum: ['auto', 'email', 'username', 'phone', 'domain', 'hash', 'keyword'], default: 'auto' },
      { name: 'pro', type: 'boolean', description: 'Run the Pro v2 lane too (needs a configured key). Default true when a key is present.', required: false },
    ],
    handler: async (context) => {
      const query = String(context.parameters.query || '').trim();
      const typeRaw = String(context.parameters.type || 'auto').toLowerCase();
      const type = (['auto', 'email', 'username', 'phone', 'domain', 'hash', 'keyword'] as const).includes(typeRaw as any)
        ? typeRaw as 'auto' | 'email' | 'username' | 'phone' | 'domain' | 'hash' | 'keyword'
        : 'auto';
      if (!query) return { success: false, error: 'query required' };
      try {
        const pub = await leakcheckPublic(query);
        const wantPro = context.parameters.pro === undefined ? Boolean(getDumpKey('leakcheck')) : context.parameters.pro === true;
        const pro = wantPro ? await leakcheckPro(query, type, { maxRows: 50 }) : null;
        const lines = [`LeakCheck lookup for ${query} (type=${type}):`];
        if (pub.found === 'unknown') lines.push(`  public: ${pub.note}`);
        else if (!pub.found) lines.push('  public: no breach source lists this identifier');
        else {
          lines.push(`  public: ${pub.found} breach source(s); exposed fields: ${(pub.fields || []).join(', ') || '?'}`);
          for (const s of pub.sources || []) lines.push(`    · ${s}`);
        }
        if (pro) {
          lines.push(pro.note ? `  Pro v2: ${pro.note}`
            : `  Pro v2: ${pro.found} record(s)${pro.quota !== undefined ? `, ${pro.quota} queries left on the account` : ''}`);
          if (!pro.note && pro.found) {
            for (const s of pro.sources.slice(0, 15)) lines.push(`    · ${s.name} × ${s.count}${s.date ? ` (${s.date})` : ''}${s.unverified ? ' [UNVERIFIED]' : ''}${s.compilation ? ' [compilation]' : ''}`);
          }
        }
        const findings: Array<{ title: string; severity: 'info' | 'low' | 'medium' | 'high' | 'critical'; details: string }> = [];
        if (pub.found !== 'unknown' && pub.found > 0) {
          findings.push({
            title: `Breach Exposure — ${query} (LeakCheck public)`,
            severity: (pub.fields || []).some((f) => /password|passwd/.test(f)) ? 'medium' : 'low',
            details: `${pub.found} breach source(s); exposed data classes: ${(pub.fields || []).join(', ') || 'unspecified'}. Sources: ${(pub.sources || []).slice(0, 10).join('; ')}`,
          });
        }
        if (pro && !pro.note && pro.found > 0) {
          const withPw = pro.rows.filter((r) => r.password).length;
          findings.push({
            title: `LeakCheck Pro Records — ${query}`,
            severity: withPw > 0 ? 'high' : 'medium',
            details: `${pro.found} record(s) across ${pro.sources.length} breach source(s); ${withPw} row(s) carry password material. Top sources: ${pro.sources.slice(0, 6).map((s) => `${s.name}×${s.count}`).join('; ')}`,
          });
        }
        return { success: true, output: lines.join('\n'), findings };
      } catch (error) {
        return { success: false, error: `LeakCheck lookup failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'osint_breach_catalog',
    description: 'Query the HIBP breach catalogue (keyless): every known breach touching a domain, with dates, account counts and leaked data classes. Pass "all" for the full universe. Answers "was this domain ever breached" with zero account keys.',
    category: 'osint',
    parameters: [
      { name: 'domain', type: 'string', description: 'Breached domain to query (e.g. adobe.com), or "all" for the full catalogue', required: true },
    ],
    handler: async (context) => {
      const raw = String(context.parameters.domain || '').trim();
      const domain = !raw || raw.toLowerCase() === 'all' ? undefined : raw;
      try {
        const c = await hibpBreachCatalog(domain);
        const lines = [
          `HIBP breach catalogue${c.domain ? ` for ${c.domain}` : ''} — ${c.total} breach(es)${c.note ? ` (${c.note})` : ''}:`,
          ...c.entries.slice(0, 25).map((e) => `  ${e.name} · ${e.breachDate || '?'} · ${e.pwnCount ? e.pwnCount.toLocaleString() : '?'} accounts${e.dataClasses?.length ? ` · leaked: ${e.dataClasses.slice(0, 8).join(', ')}` : ''}`),
          c.total > 25 ? `  … ${c.total - 25} more (ask again with a domain filter to narrow)` : '',
        ];
        const findings = c.total > 0
          ? [{
            title: `Breach Catalogue — ${c.domain || 'all known breaches'} (${c.total} entries)`,
            severity: 'info' as const,
            details: c.entries.slice(0, 10).map((e) => `${e.name} (${e.breachDate || '?'}, ${e.pwnCount || '?'} accounts)`).join('; '),
          }]
          : [];
        return { success: true, output: lines.filter(Boolean).join('\n'), findings };
      } catch (error) {
        return { success: false, error: `Breach catalogue failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'osint_person_locate',
    description: 'Full person locator: auto-parses an email/username/phone/URL/name, sweeps socials, pulls Gravatar identity + linked accounts, runs breach/dump lanes on every identifier, and returns a scored dossier.',
    category: 'osint',
    parameters: [
      { name: 'subject', type: 'string', description: 'Anything: email, @handle, phone, profile URL, domain, or full name', required: true },
      { name: 'name', type: 'string', description: 'Known full name (improves dork generation)', required: false },
      { name: 'catalog', type: 'string', description: 'Sweep breadth: "curated" (default, fast), "sherlock" (vendored database only), "full" (both — ~490 sites, minutes not seconds)', required: false },
    ],
    handler: async (context) => {
      const subject = context.parameters.subject as string;
      const name = context.parameters.name as string | undefined;
      const catalogRaw = String(context.parameters.catalog || 'curated').toLowerCase();
      const catalog = (['curated', 'sherlock', 'full'].includes(catalogRaw) ? catalogRaw : 'curated') as 'curated' | 'sherlock' | 'full';
      try {
        const dossier = await locatePerson({ subject, name, catalog });
        const lines = [
          `LOCATOR DOSSIER — ${dossier.subject} (${dossier.durationMs}ms, presence ${dossier.presenceScore}/100)`,
          `Parsed: ${Object.entries(dossier.parsed).filter(([, v]) => v).map(([k, v]) => `${k}=${v}`).join(' ') || 'nothing'}`,
          `Socials (${dossier.socialAccounts.length}):`,
          ...dossier.socialAccounts.map((h) => `  [${h.confidence}] ${h.site}: ${h.url}`),
          dossier.gravatar?.exists ? `Gravatar: ${dossier.gravatar.displayName || '(no name)'}${dossier.gravatar.location ? ` @ ${dossier.gravatar.location}` : ''}` : 'Gravatar: none',
          dossier.phone ? `Phone: ${dossier.phone.e164} (${dossier.phone.country})` : '',
          ...dossier.dumpLanes.map((lane) => `Dump lane (${lane.kind}): ` + lane.free.map((f) => `${f.service}=${f.found}`).join(', ') + lane.deep.map((d) => `; ${d.service}=${'status' in d ? d.status : d.found}`).join('')),
          ...dossier.identities.map((i) => `  identity: ${i.source}: ${i.detail}`),
          ...dossier.dorks.slice(0, 8).map((d) => `  dork ${d.label}: ${d.url}`),
        ];
        const findings = [];
        if (dossier.socialAccounts.length > 0) {
          findings.push({
            title: `OSINT Dossier — ${dossier.subject} (${dossier.socialAccounts.length} accounts)`,
            severity: 'info' as const,
            details: dossier.socialAccounts.map((h) => `${h.site}: ${h.url}`).join('\n'),
          });
        }
        const credentials = dossier.dumpLanes.flatMap((l) => l.credentials);
        return {
          success: true,
          output: lines.filter(Boolean).join('\n'),
          findings,
          credentials: credentials.length ? credentials : undefined,
        };
      } catch (error) {
        return { success: false, error: `Person locate failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'osint_username_permutate',
    description: 'Generate username permutations from a real name (first.last, flast, first_last, year suffixes…) for hunting handle variants across platforms.',
    category: 'osint',
    parameters: [
      { name: 'first', type: 'string', description: 'First name', required: true },
      { name: 'last', type: 'string', description: 'Last name', required: true },
      { name: 'middle', type: 'string', description: 'Middle name/initial', required: false },
      { name: 'birthYear', type: 'string', description: 'Birth year (4 digits) for suffix variants', required: false },
      { name: 'numbers', type: 'boolean', description: 'Add numeric suffix variants (default true)', required: false },
    ],
    handler: async (context) => {
      try {
        const perms = usernamePermutations(
          context.parameters.first as string,
          context.parameters.last as string,
          {
            middle: context.parameters.middle as string | undefined,
            birthYear: context.parameters.birthYear as string | undefined,
            numbers: context.parameters.numbers as boolean | undefined,
          }
        );
        return {
          success: true,
          output: `${perms.length} username permutations:\n${perms.join('\n')}`,
        };
      } catch (error) {
        return { success: false, error: `Permutation failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'osint_people_records',
    description: 'Render the public-records page for a full name in a real browser (Playwright Chromium) and mine structured person records: age, city, address history, relatives, aliases. Pass the subject full name.',
    category: 'osint',
    parameters: [
      { name: 'name', type: 'string', description: 'Full name (first + last)', required: true },
    ],
    handler: async (context) => {
      const name = context.parameters.name as string;
      try {
        const result = await peopleRecordSearch(name);
        const lines = [
          `Public records for "${result.name}" (${result.via}): ${result.records.length} record(s)`,
          ...result.records.map((r) => `  ${r.name}${r.age ? `, age ${r.age}` : ''}${r.city ? ` — ${r.city}` : ''}\n    addresses: ${r.pastAddresses.join(' | ') || '—'}\n    relatives: ${r.relatives.join(', ') || '—'}\n    akas: ${r.akas.join(', ') || '—'}\n    source: ${r.sourceUrl}`),
        ];
        const findings = result.records.slice(0, 5).map((r) => ({
          title: `Public Record — ${r.name}${r.city ? `, ${r.city}` : ''}`,
          severity: 'info' as const,
          details: `age ${r.age ?? '?'}; addresses: ${r.pastAddresses.join(' | ') || '—'}; relatives: ${r.relatives.join(', ') || '—'}; akas: ${r.akas.join(', ') || '—'}; source: ${r.sourceUrl}`,
        }));
        return { success: true, output: lines.join('\n'), findings };
      } catch (error) {
        return { success: false, error: `People records failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'osint_darkweb_leak_monitor',
    description: 'Ransomware leak-site monitor: check the ransomware groups\' own victim posts (ransomware.live, keyless) for a target domain or company name. The free alternative to paid dark-web monitoring.',
    category: 'osint',
    parameters: [
      { name: 'keyword', type: 'string', description: 'Target domain or company name to look for on leak sites', required: true },
    ],
    handler: async (context) => {
      const keyword = context.parameters.keyword as string;
      try {
        const result = await ransomwareLeakSearch(keyword);
        const lines = [
          `Leak-site monitor (${result.searched}) for "${result.keyword}": ${result.found} victim post(s)`,
          ...result.victims.slice(0, 15).map((v) => `  [${v.group}] ${v.victim}${v.domain ? ` (${v.domain})` : ''}${v.attackDate ? ` — attacked ${v.attackDate.slice(0, 10)}` : ''}${v.postUrl ? ` — ${v.postUrl}` : ''}${v.description ? `\n      ${v.description}` : ''}`),
          result.note ? `  note: ${result.note}` : '',
        ];
        const findings = result.victims.slice(0, 10).map((v) => ({
          title: `Leak-Site Victim Post — ${v.victim} (${v.group})`,
          severity: 'medium' as const,
          details: `${v.victim}${v.domain ? ` (${v.domain})` : ''} listed by ransomware group ${v.group}${v.attackDate ? `, attacked ${v.attackDate.slice(0, 10)}` : ''}${v.description ? ` — ${v.description}` : ''}${v.postUrl ? ` Post: ${v.postUrl}` : ''}`,
        }));
        return { success: true, output: lines.filter(Boolean).join('\n'), findings };
      } catch (error) {
        return { success: false, error: `Leak monitor failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'osint_onion_search',
    description: 'Search onion (Tor hidden-service) sites via Ahmia, the public onion search engine. Runs DIRECT over a local Tor circuit when one is up (9050/9150), otherwise over clearnet ahmia.fi — reports honestly if the exit is blocked.',
    category: 'osint',
    parameters: [
      { name: 'query', type: 'string', description: 'Search terms for the onion index', required: true },
    ],
    handler: async (context) => {
      const query = context.parameters.query as string;
      try {
        const result = await ahmiaSearch(query);
        const lines = [
          `Onion search "${result.query}" via ${result.via}: ${result.results.length} result(s)`,
          ...result.results.map((r) => `  ${r.title}\n    ${r.url}${r.snippet ? `\n    ${r.snippet}` : ''}`),
          result.note ? `  note: ${result.note}` : '',
        ];
        return { success: true, output: lines.filter(Boolean).join('\n') };
      } catch (error) {
        return { success: false, error: `Onion search failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'osint_onion_fetch',
    description: 'Fetch a .onion page directly through the local Tor circuit (curl --socks5-hostname). Requires a running Tor daemon or Tor Browser. Public hidden-service content only.',
    category: 'osint',
    parameters: [
      { name: 'url', type: 'string', description: 'Full .onion URL', required: true },
    ],
    handler: async (context) => {
      const url = context.parameters.url as string;
      try {
        const page = await onionFetch(url);
        return {
          success: true,
          output: `GET ${page.url} → HTTP ${page.status}\n\n${page.body.slice(0, 4000)}`,
        };
      } catch (error) {
        return { success: false, error: `Onion fetch failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'osint_google_dorks',
    description: 'Build Google Dork queries as an OSINT search technique — the Recorded Future top-20 operator catalog (site: filetype: intitle: inurl: intext: cache: related: before: after: AROUND(X) etc.) across 8 categories: people, documents, credentials & configs, admin portals, directory listings, infrastructure & sensitive endpoints, social & reputation, temporal/cache. Returns raw dork strings + ready-to-click engine URLs. The operator fires the search in their own browser — no automated scraping.',
    category: 'osint',
    parameters: [
      { name: 'name', type: 'string', description: 'Person full name (for people dorks)', required: false },
      { name: 'email', type: 'string', description: 'Email address', required: false },
      { name: 'username', type: 'string', description: 'Handle / username', required: false },
      { name: 'phone', type: 'string', description: 'Phone number', required: false },
      { name: 'domain', type: 'string', description: 'Target domain or host (e.g. example.com)', required: false },
      { name: 'keyword', type: 'string', description: 'Free keyword (company, topic, product) — powers social/paste/AROUND dorks', required: false },
      { name: 'category', type: 'string', description: 'Category filter: people | documents | credentials | admin | directory | infrastructure | social | temporal (omit = all)', required: false },
      { name: 'severity', type: 'string', description: 'Severity filter: info | low | medium | high | critical', required: false },
      { name: 'operator', type: 'string', description: 'Operator filter (e.g. filetype, site, intitle, inurl)', required: false },
      { name: 'limit', type: 'number', description: 'Max dorks to return (1-200, default 40)', required: false },
    ],
    handler: async (context) => {
      const p = context.parameters as Record<string, unknown>;
      try {
        const { buildGoogleDorks: _b } = await import('./google-dorks.js');
        const dorks = _b({
          name: typeof p.name === 'string' ? p.name : undefined,
          email: typeof p.email === 'string' ? p.email : undefined,
          username: typeof p.username === 'string' ? p.username : undefined,
          phone: typeof p.phone === 'string' ? p.phone : undefined,
          domain: typeof p.domain === 'string' ? p.domain : undefined,
          keyword: typeof p.keyword === 'string' ? p.keyword : undefined,
          category: typeof p.category === 'string' ? p.category as never : undefined,
          severity: typeof p.severity === 'string' ? p.severity as never : undefined,
          operator: typeof p.operator === 'string' ? p.operator : undefined,
          limit: typeof p.limit === 'number' ? p.limit : typeof p.limit === 'string' ? parseInt(p.limit as string, 10) : undefined,
        });
        if (!dorks.length) return { success: true, output: 'No dorks matched the filter/context — try broader inputs (add a domain or keyword).', findings: [] };
        const lines = [
          `Google Dorks — ${dorks.length} quer${dorks.length === 1 ? 'y' : 'ies'} (operator technique, not an automated search):`,
          ...dorks.slice(0, 80).map((d) => `  [${d.category}/${d.severity}] ${d.label}\n    query:  ${d.query}\n    Google: ${d.engines[0]?.url || ''}`),
          dorks.length > 80 ? `  … +${dorks.length - 80} more` : '',
        ];
        const findings = dorks.slice(0, 5).filter((d) => d.severity === 'critical' || d.severity === 'high').map((d) => ({
          title: `Google Dork — ${d.label}`,
          severity: d.severity === 'critical' ? 'critical' as const : d.severity === 'high' ? 'high' as const : 'medium' as const,
          details: `${d.description} — query: ${d.query}`,
        }));
        return { success: true, output: lines.filter(Boolean).join('\n'), findings: findings.length ? findings : undefined };
      } catch (error) {
        return { success: false, error: `Google dorks failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
];
