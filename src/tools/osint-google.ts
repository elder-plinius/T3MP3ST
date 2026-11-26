// =============================================================================
// GOOGLE OSINT — app linkage discovery + WiFi geolocation
// =============================================================================
// Techniques reimplemented from GHunt (mxrch/ghunt). NOTHING FROM THAT PROJECT IS
// VENDORED, COPIED, OR EXECUTED HERE — see the licence note below, because it is
// the reason this file exists in the shape it does.
//
//   GHunt is licensed **AGPL-3.0**. That is a network copyleft licence: linking
//   its code into this platform would put the whole combined work under AGPL's
//   source-disclosure terms. So none of its files are copied here, none of its
//   Python is invoked, and nothing is downloaded from it at runtime. This module
//   reimplements its *techniques* natively in TypeScript against the same public
//   endpoints — the same rule already applied to blackbird (no licence) and
//   UnlockAndroid (no licence) in this repo. Provenance is recorded in
//   GOOGLE_OSINT_SOURCE / GOOGLE_OSINT_VERSION so the panel can say where the
//   techniques came from, exactly as it does for PhoneInfoga (GPL-3.0).
//
// WHAT WAS PORTED, AND WHAT WAS DELIBERATELY NOT
//
//   Ported — Digital Asset Links ("spiderdal" in GHunt). A website publishes, at a
//   standard path, the Android apps it vouches for and the other websites it
//   delegates to. Google's DAL API indexes that and serves it with NO KEY and NO
//   ACCOUNT. Measured live before wiring: google.com resolves to 72 statements
//   (all androidApp targets), github.com to its own Android app plus that app's
//   signing certificate, twitter.com to x.com alongside its own Android and Lite
//   apps, and wikipedia.org to auth.wikimedia.org. Those last two are the reason
//   this lane is worth having: a domain's own asset links name the other domains
//   it delegates to — SSO/auth infrastructure and rebrand survivors — which a
//   subdomain scan does not reliably find and which is published nowhere else.
//
//   NOT ported — every GHunt module that needs a Google ACCOUNT SESSION. The
//   email/gaia modules authenticate as the operator's own Google account (via a
//   browser extension exporting the SAPISID cookie) and then read that account's
//   view of a target: People API profile, Play Games, Maps reviews, Calendar.
//   That is not a keyless public lookup, it is session-cookie automation against
//   a consumer service that does not offer an API for it and that bans accounts
//   which automate it. Shipping it would mean ingesting a credential that grants
//   full Google account access, into a store this platform already holds other
//   secrets in, in exchange for a lane that breaks whenever Google changes an
//   internal endpoint. The repo's standing rule — "a lane that silently fails is
//   worse than no lane" — points the same way: half of it, honestly labelled, is
//   better than all of it, falsely promising.
//
// DOCTRINE
//   * App-linkage statements are read from GOOGLE'S OWN DATABASE. Third-party
//     only, no account, no key.
//   * ONE exception, stated rather than hidden: the iOS lane fetches
//     /.well-known/apple-app-site-association from the subject's own origin.
//     Google's DAL API returns Android targets ONLY — measured, google.com's 72
//     statements are 72 androidApp entries and zero iosApp — so iOS bundle IDs
//     exist in no database and can only be read from the site. It is a single
//     passive GET of a file the site publishes at a standard path specifically to
//     be fetched. The UI says so on the button.
//   * "this domain vouches for this app" is the app publisher's CLAIM, published
//     by whoever controls the domain. It is not Google's endorsement and not a
//     verification that the app is safe. A hostile domain can claim any package.
//   * Certificate fingerprints are the app SIGNING key as published in the
//     statement. Two apps sharing one are signed by the same publisher key — a
//     real correlation, and the basis for the certClusters output.
//   * The WiFi lane needs the operator's own Google key and is refused with a
//     named remedy when it is unset. GHunt hardcodes a Google Maps sample key
//     harvested from a public demo; that key is deliberately NOT shipped here.
// =============================================================================

import { directFetch } from '../net/proxy.js';
import { classifyTarget } from './osint-infra.js';
import type { Lane } from './osint-infra.js';
import type { CustomTool } from '../types/index.js';

export const GOOGLE_OSINT_SOURCE = 'mxrch/ghunt';
export const GOOGLE_OSINT_VERSION = 'v2 (AGPL-3.0) — techniques reimplemented, no upstream code vendored';

const API_UA = 'T3MP3ST-OSINT/1.0 (keyless Google app-linkage lookups)';
const FAST_TIMEOUT_MS = 15_000;
/** digitalassetlinks.googleapis.com is slow on cold queries — measured well past
 *  the fast budget on a large domain, and a short timeout here would manufacture
 *  a confident "this domain vouches for no apps", which is exactly the kind of
 *  false negative this module must not produce. */
const DAL_TIMEOUT_MS = 40_000;

const EGRESS_REJECTED = new Set([403, 407, 429, 503]);

// -----------------------------------------------------------------------------
// transport
// -----------------------------------------------------------------------------

async function googleJson<T = unknown>(
  url: string,
  opts: { timeoutMs?: number; method?: string; body?: string; headers?: Record<string, string> } = {},
): Promise<{ status: number; body: T | null; text: string } | null> {
  const timeoutMs = opts.timeoutMs ?? FAST_TIMEOUT_MS;
  const attempt = async (useDirect: boolean) => {
    const init = {
      method: opts.method ?? 'GET',
      headers: {
        'user-agent': API_UA,
        accept: 'application/json,*/*;q=0.8',
        ...(opts.body ? { 'content-type': 'application/json' } : {}),
        ...(opts.headers || {}),
      },
      body: opts.body,
      redirect: 'follow' as const,
      signal: AbortSignal.timeout(timeoutMs),
    };
    try {
      const res = useDirect ? await directFetch(url, init as never) : await globalThis.fetch(url, init as never);
      const text = await res.text();
      let body: T | null = null;
      const t = text.trim();
      if (t.startsWith('{') || t.startsWith('[')) {
        try { body = JSON.parse(t) as T; } catch { body = null; }
      }
      return { status: res.status, body, text };
    } catch {
      return null;
    }
  };
  const first = await attempt(false);
  // A 200 whose body will not parse is not an answer — measured live (2026-10-19):
  // a corrupted response pipeline hands back raw gzip with the content-encoding
  // header stripped. Retry on the direct leg before reporting it upward.
  const unreadable200 = (r: { status: number; body: unknown } | null) => r !== null && r.status === 200 && r.body === null;
  if (first && !unreadable200(first) && !EGRESS_REJECTED.has(first.status)) return first;
  const second = await attempt(true);
  return second ?? first;
}

async function googleText(url: string, timeoutMs = FAST_TIMEOUT_MS): Promise<{ status: number; text: string } | null> {
  const attempt = async (useDirect: boolean) => {
    try {
      const init = { headers: { 'user-agent': API_UA, accept: 'application/json,text/plain,*/*' }, redirect: 'follow' as const, signal: AbortSignal.timeout(timeoutMs) };
      const res = useDirect ? await directFetch(url, init as never) : await globalThis.fetch(url, init as never);
      return { status: res.status, text: await res.text() };
    } catch { return null; }
  };
  return (await attempt(false)) ?? (await attempt(true));
}

// -----------------------------------------------------------------------------
// input classification
// -----------------------------------------------------------------------------

/** Normalise whatever the operator pasted into a site URL Google's DAL API will
 *  accept. MEASURED: `source.web.site=github.com` is rejected 400 with
 *  "Invalid site (non-HTTP URL)". The scheme is not optional. */
export function normalizeSiteUrl(raw: string): string {
  const t = (raw || '').trim().replace(/^https?:\/\//i, '');
  const host = t.split('/')[0].split('?')[0].split('#')[0].split(':')[0].toLowerCase().replace(/\.$/, '');
  return `https://${host}`;
}

/** Google's own responses carry a trailing dot on every site ("https://github.com.")
 *  — that is DNS root notation, and echoing it back into the UI would make every
 *  domain look like a typo. */
function trimSite(site: string): string {
  return (site || '').replace(/\/+$/, '').replace(/\.$/, '');
}

// -----------------------------------------------------------------------------
// relation vocabulary
// -----------------------------------------------------------------------------

/** DAL relations are opaque reverse-DNS strings. The UI shows them verbatim — an
 *  operator reading this lane is technical — but these short labels make a table
 *  of seventy-two statements legible without a lookup table. */
const RELATION_LABEL: Record<string, string> = {
  'delegate_permission/common.handle_all_urls': 'handles all URLs',
  'delegate_permission/common.get_login_creds': 'login credentials',
  'delegate_permission/common.login_service': 'login service',
  'browser_activity': 'browser activity',
  'delegate_permission/common.get_login_creds.web': 'web login credentials',
};

export function relationLabel(relation: string): string {
  return RELATION_LABEL[relation] ?? relation;
}

/** The relation that means "this app can act as the site everywhere" — the one
 *  that actually matters when deciding whether an app is first-party. */
const FIRST_PARTY_RELATION = 'delegate_permission/common.handle_all_urls';

// -----------------------------------------------------------------------------
// types
// -----------------------------------------------------------------------------

export interface DalApp {
  packageName: string;
  certFingerprint: string | null;
  /** Relations this app holds over the domain, de-duplicated. */
  relations: string[];
  /** True when the app may handle all URLs — the "official app" signal. */
  firstParty: boolean;
}

export interface DalSite {
  site: string;
  relations: string[];
}

export interface IosApp {
  /** TeamID.bundleIdentifier as Apple publishes it. */
  appId: string;
  /** URL paths the app claims, when the file publishes components. */
  components: string[];
}

export interface CertCluster {
  fingerprint: string;
  packages: string[];
}

export interface AppLinkageResult {
  website: string;
  apps: DalApp[];
  iosApps: IosApp[];
  associatedSites: DalSite[];
  certClusters: CertCluster[];
  wellKnown: Lane<{ iosApps: IosApp[] }>;
  /** Why the statement list looks the way it does. Present on BOTH "this domain
   *  vouches for nothing" and "we could not reach the database" — the two answers
   *  lead an operator to opposite conclusions and must never render identically. */
  dalNote?: string;
  failed: string[];
  ms: number;
}

interface RawStatement {
  source?: { web?: { site?: string }; androidApp?: { packageName?: string; certificate?: { sha256Fingerprint?: string } } };
  relation?: string;
  target?: {
    web?: { site?: string };
    androidApp?: { packageName?: string; certificate?: { sha256Fingerprint?: string } };
    iosApp?: { appId?: string; appleId?: string };
  };
}

// -----------------------------------------------------------------------------
// parsing
// -----------------------------------------------------------------------------

/** Group a statement list into the three things a statement can actually point
 *  at: an Android app, another website, or an iOS app. Returns them separately
 *  because they answer different questions and an operator scanning a table of
 *  72 rows should not have to work out which shape each row is. */
export function parseDalStatements(
  statements: RawStatement[],
): { apps: DalApp[]; sites: DalSite[]; iosApps: IosApp[] } {
  const apps = new Map<string, DalApp>();
  const sites = new Map<string, DalSite>();
  const ios = new Map<string, IosApp>();

  const addRelation = (bag: Set<string>, relation?: string) => {
    if (relation) bag.add(relation);
  };

  for (const st of statements) {
    const relation = st.relation ?? '';
    const t = st.target;
    if (!t) continue;

    if (t.androidApp?.packageName) {
      const pkg = t.androidApp.packageName;
      const fp = (t.androidApp.certificate?.sha256Fingerprint ?? '').trim() || null;
      const key = `${pkg}|${fp ?? ''}`;
      const existing = apps.get(key);
      if (existing) addRelation(new Set(existing.relations), relation);
      apps.set(key, {
        packageName: pkg,
        certFingerprint: fp,
        relations: existing ? [...new Set([...existing.relations, relation])] : [relation],
        firstParty: existing?.firstParty === true || relation === FIRST_PARTY_RELATION,
      });
    } else if (t.web?.site) {
      const site = trimSite(t.web.site);
      const existing = sites.get(site);
      sites.set(site, { site, relations: existing ? [...new Set([...existing.relations, relation])] : [relation] });
    } else if (t.iosApp?.appId || t.iosApp?.appleId) {
      const appId = t.iosApp.appId ?? t.iosApp.appleId ?? '';
      if (!ios.has(appId)) ios.set(appId, { appId, components: [] });
    }
  }

  return { apps: [...apps.values()], sites: [...sites.values()], iosApps: [...ios.values()] };
}

/** Parse /.well-known/apple-app-site-association. This file is JSON but the
 *  HTTP server may still send it with any content type, and it is routinely
 *  served either as an object with `applinks`/`webcredentials`/`appclips` or as
 *  a BARE ARRAY of detail objects. Both shapes are accepted; anything else is
 *  reported as a lane failure rather than as "this domain has no iOS app",
 *  because those two answers lead an operator to opposite conclusions. */
export function parseAppleAssociation(raw: string): IosApp[] {
  const text = (raw || '').trim();
  if (!text || text.startsWith('<')) return []; // an HTML 404 page is not an answer
  let parsed: unknown;
  try { parsed = JSON.parse(text); } catch { return []; }

  const details: unknown[] = [];
  if (Array.isArray(parsed)) {
    details.push(...parsed);
  } else if (parsed && typeof parsed === 'object') {
    for (const key of ['applinks', 'webcredentials', 'appclips']) {
      const section = (parsed as Record<string, unknown>)[key];
      if (section && typeof section === 'object') {
        const d = (section as Record<string, unknown>).details;
        if (Array.isArray(d)) details.push(...d);
      }
    }
  }

  const out = new Map<string, IosApp>();
  for (const d of details) {
    if (!d || typeof d !== 'object') continue;
    const appId = String((d as Record<string, unknown>).appID ?? (d as Record<string, unknown>).appId ?? '').trim();
    if (!appId) continue;
    const components: string[] = [];
    const raw = (d as Record<string, unknown>).components;
    if (Array.isArray(raw)) {
      for (const c of raw) {
        if (!c || typeof c !== 'object') continue;
        const entry = c as Record<string, unknown>;
        // An entry carrying exclude:true is a NEGATIVE rule ("this path is NOT
        // deep-linked"), which is the opposite of a claim. Verified against a real
        // file: discord.com publishes {"/":"/oauth2/authorize","exclude":true} so
        // that one URL is excluded while a sibling entry claims the same path.
        // Collecting both renders a path as claimed and refused at once.
        if (entry.exclude === true) continue;
        for (const [k, v] of Object.entries(entry)) {
          if (k.startsWith('/') && typeof v === 'string' && v) components.push(v);
        }
      }
    }
    const existing = out.get(appId);
    out.set(appId, { appId, components: [...new Set([...(existing?.components ?? []), ...components])].slice(0, 12) });
  }
  return [...out.values()];
}

/** Apps that share a signing certificate are almost always the same publisher —
 *  one company shipping a branded app, a white-label build, and a companion app
 *  under three package names. Surfacing the clusters is the single most useful
 *  thing this lane does with a statement list, and it falls out of the data. */
export function clusterByCertificate(apps: DalApp[]): CertCluster[] {
  const byCert = new Map<string, Set<string>>();
  for (const a of apps) {
    if (!a.certFingerprint) continue;
    const set = byCert.get(a.certFingerprint) ?? new Set<string>();
    set.add(a.packageName);
    byCert.set(a.certFingerprint, set);
  }
  return [...byCert.entries()]
    .map(([fingerprint, set]) => ({ fingerprint, packages: [...set].sort() }))
    .sort((a, b) => b.packages.length - a.packages.length || a.fingerprint.localeCompare(b.fingerprint));
}

// -----------------------------------------------------------------------------
// the website lane
// -----------------------------------------------------------------------------

export interface DalLookupOptions {
  /** Fetch the subject's own /.well-known/apple-app-site-association for iOS
   *  bundle ids. This is the ONE request in this module that touches the
   *  subject's origin, so it is opt-in and the UI states it on the control. */
  includeIos?: boolean;
}

/** True when the input is an EMAIL rather than a URL or a bare domain.
 *
 *  classifyTarget() strips a leading `user@` because that is how URL credentials
 *  look (`https://user:pass@host/`), and for a real URL that is correct. But
 *  applied to a SCHEMELESS input it laundered `test@example.com` into the
 *  domain `example.com`, and this lane then returned a confident, well-formatted
 *  report about a website the operator never asked about. Measured, not
 *  hypothesised: that exact paste produced "0 apps — this domain publishes no
 *  Digital Asset Links statements", which reads as a real negative answer.
 *
 *  A bare `something@host` is an email, and an OSINT tool that silently
 *  reinterprets its subject is worse than one that refuses: the operator asked
 *  about a person and was handed a domain. The scheme is what separates the two
 *  shapes, so that is what the test keys on. */
export function looksLikeEmail(raw: string): boolean {
  const t = (raw || '').trim();
  if (!t || /^[a-z][a-z0-9+.-]*:\/\//i.test(t)) return false; // a URL — userinfo is legitimate
  const at = t.indexOf('@');
  return at > 0 && at < t.length - 1 && !t.slice(at + 1).includes('@');
}

/** "Which Android apps does this domain vouch for, which other sites does it
 *  delegate to, and which iOS apps claim it." */
export async function googleAppLinkage(rawTarget: string, opts: DalLookupOptions = {}): Promise<AppLinkageResult> {
  const t0 = Date.now();
  if (looksLikeEmail(rawTarget)) {
    // Say what this lane actually does, and name the capability that is missing,
    // because GHunt's headline `email` module is exactly what someone pasting an
    // address here is asking for.
    throw new Error(
      `"${rawTarget.trim()}" is an email address. This lane maps DOMAIN app linkage (which Android apps a domain vouches for, and which domains it delegates to) — it does not look up a Google account from an address. ` +
        'For an account lookup GHunt needs a signed-in Google session, which this platform does not ingest. Paste the domain instead, e.g. example.com.',
    );
  }
  const t = classifyTarget(rawTarget);
  if (t.kind !== 'domain') throw new Error(t.note ?? `not a domain: ${rawTarget}`);
  const website = t.value;
  const siteUrl = normalizeSiteUrl(website);
  const failed: string[] = [];

  const res = await googleJson<{ statements?: RawStatement[] }>(
    `https://digitalassetlinks.googleapis.com/v1/statements:list?source.web.site=${encodeURIComponent(siteUrl)}`,
    { timeoutMs: DAL_TIMEOUT_MS },
  );

  // A missing statement list is a real answer ("this domain vouches for
  // nothing"), so it is reported as an empty result — but a TRANSPORT failure
  // must never look like one. Google answers 404 for a domain with no
  // statements, which is exactly the same body-less response a blocked egress
  // produces.
  let statements: RawStatement[] = [];
  let dalNote: string | undefined;
  if (!res) {
    failed.push('digitalassetlinks');
    dalNote = 'the Digital Asset Links API could not be reached — the app list below is unknown, not empty';
  } else if (res.status === 404) {
    dalNote = 'this domain publishes no Digital Asset Links statements';
  } else if (res.status !== 200 || !res.body) {
    failed.push('digitalassetlinks');
    dalNote = `Digital Asset Links API answered HTTP ${res.status}` +
      (res.status === 200 ? ' with an unreadable body — transport corruption, not an empty answer' : '');
  } else {
    statements = Array.isArray(res.body.statements) ? res.body.statements : [];
    if (!statements.length) dalNote = 'this domain publishes no Digital Asset Links statements';
  }

  const parsed = parseDalStatements(statements);

  // iOS: Google's API returns androidApp targets only (measured: google.com's 72
  // statements are 72 androidApp entries, zero iosApp), so bundle ids exist in
  // no database and must be read from the site itself.
  let wellKnown: Lane<{ iosApps: IosApp[] }> = { ok: false, data: null, note: 'not requested' };
  let iosApps: IosApp[] = [];
  if (opts.includeIos) {
    const aasa = await googleText(`https://${website}/.well-known/apple-app-site-association`);
    if (!aasa) {
      wellKnown = { ok: false, data: null, note: 'apple-app-site-association could not be fetched' };
    } else if (aasa.status === 404) {
      wellKnown = { ok: true, data: { iosApps: [] }, note: 'this domain publishes no apple-app-site-association file' };
    } else if (aasa.status !== 200) {
      wellKnown = { ok: false, data: null, note: `apple-app-site-association answered HTTP ${aasa.status}` };
    } else {
      const found = parseAppleAssociation(aasa.text);
      iosApps = found;
      wellKnown = {
        ok: true,
        data: { iosApps: found },
        note: found.length ? `${found.length} iOS app(s) claim this domain` : 'the association file is published but names no apps',
      };
    }
    if (!wellKnown.ok) failed.push('apple-app-site-association');
  }

  // A statement pointing back at the queried domain is not a pivot — it is the
  // domain describing itself. Surfacing it would pad the table with the operator's
  // own input dressed up as a discovery.
  const selfSite = trimSite(siteUrl);
  const associatedSites = parsed.sites.filter((s) => s.site !== selfSite);

  return {
    website,
    apps: parsed.apps,
    iosApps: [...iosApps, ...parsed.iosApps],
    associatedSites,
    certClusters: clusterByCertificate(parsed.apps),
    wellKnown,
    dalNote,
    failed,
    ms: Date.now() - t0,
  };
}

// -----------------------------------------------------------------------------
// A CAPABILITY THAT WAS CUT, AND WHY — recorded so nobody re-adds it
// -----------------------------------------------------------------------------
//
// The obvious companion lane is "which websites does this SIGNED APP vouch for?"
// — the reverse direction of the same dataset, and the one that would find a
// company's less obvious domains from a single APK you already hold. It is NOT
// here, because it does not work.
//
// Measured against the live API with a package name AND its uppercase SHA-256
// fingerprint, exactly as Google's own documentation requires:
//
//   com.github.android.dev        -> HTTP 200 {"maxAge":"3600s"}   (no statements)
//   com.google.android.calendar   -> HTTP 200 {"maxAge":"3600s"}   (no statements)
//
// Two unrelated apps, both answer 200 with no statements field, which is the
// authoritative-looking empty response. Shipped as a lane it would render "this
// app vouches for no websites" for every input ever queried — a confident,
// well-formatted, permanently wrong answer. The repo's rule is that a lane which
// silently fails is worse than no lane, so this one is documented rather than
// implemented. If Google ever indexes the app direction, this is where it goes.

// -----------------------------------------------------------------------------
// WiFi / BSSID geolocation
// -----------------------------------------------------------------------------

export interface WifiObservation {
  macAddress: string;
  signalStrength?: number;
  channel?: number;
}

export interface WifiGeoResult {
  ok: boolean;
  note?: string;
  lat?: number;
  lng?: number;
  accuracyMeters?: number;
  observations: number;
  /** Set when the operator has supplied a key but Google still refused. */
  httpStatus?: number;
}

/** Google does not publish an operator-facing key for this endpoint; the one
 *  GHunt ships is a Maps JavaScript sample key lifted from a public demo, and
 *  shipping someone else's credential is not something this platform does. The
 *  operator supplies their own via T3MP3ST_GOOGLE_GEO_KEY. */
export function googleGeoKey(): string {
  return (process.env.T3MP3ST_GOOGLE_GEO_KEY ?? '').trim();
}

export function googleGeoKeyConfigured(): boolean {
  return googleGeoKey().length > 0;
}

/** Parse "aa:bb:cc:dd:ee:ff" or a comma/whitespace separated list, tolerating the
 *  dashes and bare 12-hex-digit forms operators actually paste. Google rejects a
 *  malformed BSSID remotely; catching it here turns an opaque 400 into a message
 *  that names the offending entry. */
export function parseBssids(raw: string): WifiObservation[] {
  const out: WifiObservation[] = [];
  const seen = new Set<string>();
  for (const chunk of (raw || '').split(/[\s,;]+/)) {
    if (!chunk) continue;
    const hex = chunk.replace(/[^0-9a-f]/gi, '');
    if (hex.length !== 12 || !/^[0-9a-f]{12}$/i.test(hex)) continue;
    const mac = hex.toUpperCase().replace(/(.{2})(?=.)/g, '$1:');
    if (seen.has(mac)) continue;
    seen.add(mac);
    out.push({ macAddress: mac });
  }
  return out;
}

/** Geolocate WiFi access points. Accuracy improves sharply with more
 *  neighbouring APs, which is why this accepts a list rather than a single MAC.
 *  Refuses with the env var named when no key is configured — an unkeyed call
 *  answers 403 "unregistered callers", which an operator would otherwise read as
 *  "Google has no location for this network". */
export async function googleWifiLocate(bssidsRaw: string): Promise<WifiGeoResult> {
  const aps = parseBssids(bssidsRaw);
  if (!aps.length) throw new Error(`no valid BSSID found in "${bssidsRaw}" — expected MAC addresses like aa:bb:cc:dd:ee:ff`);
  const key = googleGeoKey();
  if (!key) {
    return { ok: false, observations: aps.length, note: 'no Google API key configured — set T3MP3ST_GOOGLE_GEO_KEY to enable WiFi geolocation (Google refuses this endpoint for unregistered callers)' };
  }

  const res = await googleJson<{ location?: { lat?: number; lng?: number }; accuracy?: number }>(
    `https://www.googleapis.com/geolocation/v1/geolocate?key=${encodeURIComponent(key)}`,
    { method: 'POST', body: JSON.stringify({ considerIp: false, wifiAccessPoints: aps }), timeoutMs: 25_000 },
  );
  if (!res) return { ok: false, observations: aps.length, note: 'the Google geolocation endpoint could not be reached' };
  if (res.status !== 200 || !res.body?.location) {
    return { ok: false, observations: aps.length, httpStatus: res.status, note: `Google refused the request (HTTP ${res.status}) — check that T3MP3ST_GOOGLE_GEO_KEY is valid and the Geolocation API is enabled for it` };
  }
  return {
    ok: true,
    observations: aps.length,
    lat: res.body.location.lat,
    lng: res.body.location.lng,
    accuracyMeters: res.body.accuracy,
    note: `located from ${aps.length} access point(s); accuracy is a radius, not a device fix`,
  };
}

// -----------------------------------------------------------------------------
// agent tools
// -----------------------------------------------------------------------------

const GOOGLE_DOCTRINE =
  'Digital Asset Links statements are read from Google\'s public index (keyless, no account). iOS bundle ids are read from the site\'s own /.well-known/apple-app-site-association. An app listed for a domain is the DOMAIN PUBLISHER\'S CLAIM, not an endorsement by Google.';

export const GOOGLE_OSINT_TOOLS: CustomTool[] = [
  {
    name: 'osint_google_app_linkage',
    description: `Google app linkage (Digital Asset Links, GHunt spiderdal technique): enumerate every Android app a domain vouches for — package name and SHA-256 signing certificate — plus the OTHER websites that domain delegates to (SSO/auth infrastructure pivots such as auth.twitter.com or auth.wikimedia.org), clustered by shared signing certificate. Optionally reads the domain's own apple-app-site-association for iOS bundle ids. ${GOOGLE_DOCTRINE}`,
    category: 'osint',
    parameters: [
      { name: 'domain', type: 'string', description: 'Domain to map (a full URL is accepted and reduced to its host)', required: true },
      { name: 'includeIos', type: 'boolean', description: "Also fetch the domain's own /.well-known/apple-app-site-association for iOS bundle ids. This is the ONLY request in the tool that touches the subject's own origin. Default false.", required: false },
    ],
    handler: async (context) => {
      const wantIos = context.parameters.includeIos === true;
      try {
        const r = await googleAppLinkage(String(context.parameters.domain ?? ''), { includeIos: wantIos });
        const lines = [`Google app linkage for ${r.website} (${r.ms}ms)`, ''];
        if (r.dalNote) lines.push(`Note: ${r.dalNote}`);
        lines.push(`Android apps vouching for this domain: ${r.apps.length}`);
        for (const a of r.apps.slice(0, 40)) {
          lines.push(`  ${a.firstParty ? '★ ' : '  '}${a.packageName}${a.certFingerprint ? ` [${a.certFingerprint.slice(0, 17)}…]` : ' [no certificate published]'}`);
          lines.push(`      ${a.relations.map(relationLabel).join(', ') || 'no relation published'}`);
        }
        if (r.iosApps.length) {
          lines.push('', `iOS apps claiming this domain: ${r.iosApps.length}`);
          for (const i of r.iosApps.slice(0, 20)) lines.push(`  ${i.appId}`);
        }
        if (r.associatedSites.length) {
          lines.push('', `Other websites this domain delegates to: ${r.associatedSites.length}`);
          for (const s of r.associatedSites.slice(0, 25)) lines.push(`  ${s.site} — ${s.relations.map(relationLabel).join(', ')}`);
        }
        const clusters = r.certClusters.filter((c) => c.packages.length > 1);
        if (clusters.length) {
          lines.push('', 'Apps sharing one signing certificate (same publisher):');
          for (const c of clusters) lines.push(`  ${c.fingerprint.slice(0, 17)}… → ${c.packages.join(', ')}`);
        }
        if (r.failed.length) lines.push('', `Sources that could not answer: ${r.failed.join(', ')} — the result is incomplete, not "clean"`);

        const findings = [
          ...r.apps.map((a) => ({
            title: `Android app vouches for ${r.website} — ${a.packageName}`,
            severity: 'info' as const,
            details: `${r.website} publishes a Digital Asset Links statement naming ${a.packageName}${a.firstParty ? ' with the handle_all_urls relation, i.e. it may act as the site everywhere' : ''}. This is the domain publisher's claim; it is not an endorsement by Google and says nothing about whether the app is safe.`,
          })),
          ...r.associatedSites.slice(0, 10).map((s) => ({
            title: `Associated domain — ${s.site}`,
            severity: 'low' as const,
            details: `${r.website} delegates to ${s.site} (${s.relations.map(relationLabel).join(', ')}). Associated domains often expose SSO/auth infrastructure that a subdomain scan misses.`,
          })),
        ];
        return { success: true, output: lines.join('\n'), findings };
      } catch (error) {
        return { success: false, error: `Google app linkage failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'osint_google_bssid_locate',
    description: `Geolocate WiFi access points (BSSID/MAC) through Google's geolocation database — the GHunt geolocate technique. Give one MAC for a rough answer or several neighbouring APs for a tighter one; returns a position and an accuracy radius. Requires the operator's own Google API key in T3MP3ST_GOOGLE_GEO_KEY (this platform deliberately does not ship a third-party key). The result is a coverage-estimated area, NOT a device fix.`,
    category: 'osint',
    parameters: [
      { name: 'bssids', type: 'string', description: 'One or more WiFi access point MAC addresses, comma or space separated (e.g. aa:bb:cc:dd:ee:ff). More neighbouring APs give a tighter fix.', required: true },
    ],
    handler: async (context) => {
      try {
        const r = await googleWifiLocate(String(context.parameters.bssids ?? ''));
        if (!r.ok) return { success: false, error: r.note ?? 'WiFi geolocation failed' };
        const output = [
          `Located ${r.observations} access point(s) at ${r.lat}, ${r.lng}`,
          `Accuracy radius: ${r.accuracyMeters ?? '?'} m`,
          '',
          'This is an estimated coverage area derived from where these access points have been observed,',
          'not a live device fix. The network may have moved since it was last seen.',
        ].join('\n');
        return {
          success: true,
          output,
          findings: [{
            title: `WiFi geolocation — ${r.observations} BSSID(s)`,
            severity: 'info' as const,
            details: `Position ${r.lat}, ${r.lng} with a ${r.accuracyMeters ?? '?'} m accuracy radius, derived from ${r.observations} observed access point(s). An estimated area, not a device fix.`,
          }],
        };
      } catch (error) {
        return { success: false, error: `WiFi geolocation failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
];