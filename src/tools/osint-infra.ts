// =============================================================================
// OSINT INFRASTRUCTURE — domain / IP / certificate / routing intelligence
// =============================================================================
// The OSINT Framework's two largest categories are Domain Name (146 tools) and
// IP & MAC (56). This module closes that gap using ONLY public, keyless,
// registration-free services — each one probed live before being wired:
//
//   RDAP ......... https://rdap.org/domain/{d}      IANA bootstrap → authoritative
//   crt.sh ....... https://crt.sh/?q=%.{d}&output=json   Certificate Transparency
//   Shodan ....... https://internetdb.shodan.io/{ip}  ports · hostnames · CPE · CVEs
//   RIPEstat ..... https://stat.ripe.net/data/…       BGP prefix · ASN · abuse contact
//   DNS-over-HTTPS https://dns.google/resolve?name=  full RR set incl. TXT
//   urlscan.io ... https://urlscan.io/api/v1/search/  historical scans → contacts
//   OTX .......... https://otx.alienvault.com/…      reputation · pulses
//   blocklist.de . https://api.blocklist.de/api.php   attack / report counts
//   CIRCL ........ https://hashlookup.circl.lu/lookup known-FILE lookup (DFIR)
//
//   NOTE ON THE HASH LANE: CIRCL hashlookup identifies a file by hash against
//   the NIST Software Reference Library. It answers "what is this file, and is
//   it known-good software" — it is NOT a malware database. (The actual malware
//   database, abuse.ch MalwareBazaar, now requires an API key and is therefore
//   absent here.) Nothing in this module may claim a hash is malicious.
//
// DOCTRINE — identical to the people-side engine next door:
//   * Nothing here probes the TARGET. Every call is a lookup against a third-party
//     public database, exactly like the CVE/EPSS feed or a breach-catalogue query.
//     There is no port scan, no banner grab, no request to the subject's own host.
//   * "vulns" are Shodan's database matches for a CPE they observed on that IP.
//     They are not proof the box is exploitable today, and the UI says so.
//   * isPrivateIp() refuses RFC1918 / loopback / link-local / IETF-doc ranges, so
//     the platform cannot be pointed at the operator's own LAN by a stray target.
//   * Sources that turned out to be DEAD were dropped rather than shipped broken:
//     abuse.ch URLhaus/ThreatFox now answer 401 (auth became mandatory), grep.app
//     is behind a Vercel WAF checkpoint, OpenCorporates serves an hCaptcha
//     challenge, and Spamhaus DNSBL refuses cloud resolvers outright. None of them
//     are in this file because a lane that silently fails is worse than no lane.
// =============================================================================

import { directFetch } from '../net/proxy.js';
import { isPrivateIp } from './osint.js';
import type { CustomTool } from '../types/index.js';

/** These are all API endpoints, and an honest, identifying User-Agent is not
 *  just politeness — it is required for them to answer at all. Measured live:
 *  rdap.org's Cloudflare front-end returns **403** to a spoofed Chrome UA and
 *  **200** to this string, on the same URL, same transport, same second. Every
 *  one of the ten sources here was re-verified with it. */
const API_UA = 'T3MP3ST-OSINT/1.0 (keyless public infrastructure lookups)';
/** Most of these answer in well under a second. */
const FAST_TIMEOUT_MS = 12_000;
/** crt.sh is genuinely slow — 3.2s measured for a large domain, and it is
 *  frequently much worse. A short timeout here manufactures fake "no subdomains". */
const SLOW_TIMEOUT_MS = 45_000;

/** Statuses that mean "this transport is being rejected", not "the answer is no".
 *  Seeing one on the proxied attempt is a reason to try direct, not to report. */
const EGRESS_REJECTED = new Set([403, 407, 429, 503]);

// -----------------------------------------------------------------------------
// transport
// -----------------------------------------------------------------------------

export interface Lane<T> {
  ok: boolean;
  data: T | null;
  /** Operator-readable reason. Present on failure AND on a genuine "nothing here",
   *  because a lane that reports empty and a lane that was blocked must not look alike. */
  note?: string;
  ms?: number;
}

export interface InfraJsonResult<T> {
  status: number;
  body: T | null;
}

/** Proxied JSON GET, then a direct-transport retry. Returns the HTTP status
 *  alongside the body so a 404 ("this IP is not in any database") stays
 *  distinguishable from a transport failure ("the egress is blocked").
 *
 *  The direct retry is not a nicety: measured live, the SOCKS egress gets a
 *  Cloudflare 403 from rdap.org while direct transport gets a clean 200. A helper
 *  that returned the first response it got — any response — would have reported
 *  Cloudflare's error page as "no RDAP record" and quietly blanked the whole
 *  registration lane. So an egress-rejection status is treated as a failed
 *  attempt and falls through, while a genuine 404/400 is returned as the answer. */
export async function infraJson<T = unknown>(
  url: string,
  opts: { timeoutMs?: number; headers?: Record<string, string>; method?: string; body?: string } = {},
): Promise<InfraJsonResult<T> | null> {
  const timeoutMs = opts.timeoutMs ?? FAST_TIMEOUT_MS;
  const attempt = async (useDirect: boolean): Promise<InfraJsonResult<T> | null> => {
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
      const res = useDirect
        ? await directFetch(url, init as never)
        : await globalThis.fetch(url, init as never);
      const text = await res.text();
      let body: T | null = null;
      const t = text.trim();
      if (t.startsWith('{') || t.startsWith('[')) {
        try { body = JSON.parse(t) as T; } catch { body = null; }
      }
      return { status: res.status, body };
    } catch {
      return null;
    }
  };
  const first = await attempt(false);
  if (first && !EGRESS_REJECTED.has(first.status)) return first;
  const second = await attempt(true);
  return second ?? first;
}

/** Plain-text GET (blocklist.de answers HTML fragments, not JSON). */
async function infraText(url: string, timeoutMs = FAST_TIMEOUT_MS): Promise<{ status: number; text: string } | null> {
  const attempt = async (useDirect: boolean) => {
    try {
      const init = { headers: { 'user-agent': API_UA, accept: 'text/*,*/*' }, signal: AbortSignal.timeout(timeoutMs) };
      const res = useDirect ? await directFetch(url, init as never) : await globalThis.fetch(url, init as never);
      return { status: res.status, text: await res.text() };
    } catch { return null; }
  };
  return (await attempt(false)) ?? (await attempt(true));
}

// -----------------------------------------------------------------------------
// target classification
// -----------------------------------------------------------------------------

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const DOMAIN_RE = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/;

export type InfraTargetKind = 'ipv4' | 'domain' | 'invalid';

export interface InfraTarget {
  kind: InfraTargetKind;
  value: string;
  /** Why an input was refused, or a caveat on what was accepted. */
  note?: string;
}

export function isIpv4(v: string): boolean {
  const m = IPV4_RE.exec(v);
  if (!m) return false;
  return m.slice(1).every((o) => Number(o) <= 255);
}

/** Accepts a bare domain, a full URL, a host:port pair, or an IPv4 literal, and
 *  resolves it to one of the two shapes this module knows how to research.
 *
 *  A schemeless EMAIL is explicitly NOT one of those shapes and is refused with a
 *  reason rather than unwrapped into its domain — see the comment below. */
export function classifyTarget(raw: string): InfraTarget {
  const input = (raw || '').trim();
  if (!input) return { kind: 'invalid', value: '', note: 'empty target' };

  // A SCHEMELESS `user@host` with no port is an EMAIL, not a URL with credentials.
  // The `user@` strip below exists to unwrap `https://user:pass@host/`, and it also
  // legitimately supports the schemeless `user@host:port` form — but applied to a
  // plain `someone@example.com` it silently laundered an ADDRESS into the domain
  // `example.com`, after which this module returned a confident, well-formatted
  // report about a website the operator never asked about. For a recon tool that
  // is the worst failure available: a negative that reads as real. The port suffix
  // is exactly what separates the two shapes, which is why the existing
  // `user@host:port` behaviour is untouched by this check.
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(input)) {
    const at = input.indexOf('@');
    if (at > 0) {
      const hostPart = input.slice(at + 1).split(/[/?#]/)[0];
      const hostClean = hostPart.toLowerCase().replace(/\.$/, '');
      // DOMAIN_RE also matches an all-numeric dotted quad, so exclude IPs: a
      // `user@1.2.3.4` is not an email, and falling through lets the normal IPv4
      // path refuse it as private — a far more useful answer than "looks like an
      // email address".
      if (!hostPart.includes(':') && !isIpv4(hostClean) && DOMAIN_RE.test(hostClean)) {
        return {
          kind: 'invalid',
          value: input.toLowerCase(),
          note: 'this looks like an email address, not a domain — this module takes a domain, a URL, or a public IPv4',
        };
      }
    }
  }

  // Strip a scheme and anything after the authority.
  let v = input.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
  v = v.split('/')[0].split('?')[0].split('#')[0];
  // Drop credentials and port. A bare IPv6 literal has colons, so only split a
  // port when there is exactly one colon and the tail is numeric.
  v = v.replace(/^[^@]*@/, '');
  if (v.startsWith('[')) v = v.slice(1, v.indexOf(']') > 0 ? v.indexOf(']') : undefined);
  else if ((v.match(/:/g) || []).length === 1) v = v.split(':')[0];
  v = v.toLowerCase().replace(/\.$/, '');

  if (isIpv4(v)) {
    if (isPrivateIp(v)) {
      return { kind: 'invalid', value: v, note: 'private / loopback / reserved address — not a public target' };
    }
    return { kind: 'ipv4', value: v };
  }
  // An all-numeric label set is somebody's malformed IP, not a domain. Without
  // this it falls through to the domain pattern — "999.1.1.1" matches, because the
  // TLD "1" is alphanumeric — and then gets handed to RDAP and crt.sh, which
  // return confident nonsense. No real TLD is all-digits.
  if (/^[\d.]+$/.test(v) && v.includes('.')) {
    return { kind: 'invalid', value: v, note: 'not a valid IPv4 address (an octet is out of range or malformed)' };
  }
  if (DOMAIN_RE.test(v)) return { kind: 'domain', value: v };
  if (v.includes(':')) return { kind: 'invalid', value: v, note: 'IPv6 is not covered by this module' };
  return { kind: 'invalid', value: v, note: 'not a domain or IPv4 address' };
}

// -----------------------------------------------------------------------------
// RDAP — registration data (the modern replacement for `whois`)
// -----------------------------------------------------------------------------

export interface RdapEvent { action: string; date: string }
export interface RdapEntity { roles: string[]; name: string; email?: string; phone?: string }
export interface RdapResult {
  handle?: string;
  ldhName?: string;
  status: string[];
  events: RdapEvent[];
  registrar?: string;
  entities: RdapEntity[];
  nameservers: string[];
  secureDns?: boolean;
}

/** The vCard is a JSON array of alternating [key, …, value] rows. Registrars put
 *  the display name under `fn` and, separately, a `org` free-text row. */
function vcardField(entries: unknown, field: string): string | undefined {
  if (!Array.isArray(entries)) return undefined;
  for (const row of entries) {
    if (Array.isArray(row) && String(row[0]).toLowerCase() === field) {
      const v = row[3];
      if (typeof v === 'string' && v.trim()) return v.trim();
    }
  }
  return undefined;
}

export function parseRdap(j: unknown): RdapResult | null {
  if (!j || typeof j !== 'object') return null;
  const o = j as Record<string, unknown>;
  if (!o.objectClassName && !o.ldhName && !Array.isArray(o.entities)) return null;

  const entities: RdapEntity[] = [];
  for (const e of (Array.isArray(o.entities) ? o.entities : [])) {
    const eo = e as Record<string, unknown>;
    const rows = (eo.vcardArray as unknown[] | undefined)?.[1] as unknown;
    const name = vcardField(rows, 'fn') ?? vcardField(rows, 'org') ?? (typeof eo.handle === 'string' ? eo.handle : '');
    if (!name && !(eo.roles as string[] | undefined)?.length) continue;
    const emailRow = vcardField(rows, 'email');
    const telRow = vcardField(rows, 'tel');
    entities.push({
      roles: Array.isArray(eo.roles) ? eo.roles.map((r) => String(r)) : [],
      name: name || '(unnamed)',
      email: emailRow ? emailRow.replace(/^mailto:/i, '') : undefined,
      phone: telRow ? telRow.replace(/^tel:/i, '') : undefined,
    });
  }

  const events: RdapEvent[] = [];
  for (const ev of (Array.isArray(o.events) ? o.events : [])) {
    const eo = ev as Record<string, unknown>;
    if (eo.eventAction && eo.eventDate) events.push({ action: String(eo.eventAction), date: String(eo.eventDate) });
  }

  return {
    handle: typeof o.handle === 'string' ? o.handle : undefined,
    ldhName: typeof o.ldhName === 'string' ? o.ldhName : undefined,
    status: Array.isArray(o.status) ? o.status.map((s) => String(s)) : [],
    events,
    registrar: entities.find((e) => e.roles.includes('registrar'))?.name,
    entities,
    nameservers: (Array.isArray(o.nameservers) ? o.nameservers : [])
      .map((n) => (n as Record<string, unknown>)?.ldhName)
      .filter((n): n is string => typeof n === 'string'),
    secureDns: (o.secureDNS as Record<string, unknown> | undefined)?.delegationSigned === true ? true : undefined,
  };
}

export async function rdapDomain(domain: string): Promise<Lane<RdapResult>> {
  const t0 = Date.now();
  const r = await infraJson(`https://rdap.org/domain/${encodeURIComponent(domain)}`);
  if (!r) return { ok: false, data: null, note: 'RDAP unreachable through this egress', ms: Date.now() - t0 };
  if (r.status === 404) return { ok: true, data: null, note: 'no RDAP record — domain not registered (or the TLD has no RDAP service)', ms: Date.now() - t0 };
  if (r.status === 429) return { ok: false, data: null, note: 'RDAP rate-limited (429) — try again shortly', ms: Date.now() - t0 };
  if (r.status !== 200) return { ok: false, data: null, note: `RDAP HTTP ${r.status}`, ms: Date.now() - t0 };
  const parsed = parseRdap(r.body);
  return parsed
    ? { ok: true, data: parsed, ms: Date.now() - t0 }
    : { ok: false, data: null, note: 'RDAP response did not parse as a registration object', ms: Date.now() - t0 };
}

// -----------------------------------------------------------------------------
// crt.sh — Certificate Transparency → subdomain discovery
// -----------------------------------------------------------------------------

export interface CrtResult {
  total: number;
  subdomains: string[];
  /** ISO date of the earliest / latest certificate in the returned window. */
  firstSeen?: string;
  lastSeen?: string;
  issuers: string[];
}

/** A single crt.sh row's `name_value` holds every SAN on the certificate, separated
 *  by NEWLINES. Splitting on "," (the obvious move) silently collapses a cert's
 *  whole SAN list into one garbage hostname — so split on any whitespace. */
export function parseCrt(rows: unknown, domain: string): CrtResult {
  const base = domain.toLowerCase().replace(/\.$/, '');
  const out = new Set<string>();
  const issuers = new Set<string>();
  let first: string | undefined;
  let last: string | undefined;
  const list = Array.isArray(rows) ? rows : [];
  for (const row of list) {
    const o = row as Record<string, unknown>;
    if (typeof o.issuer_name === 'string' && o.issuer_name) issuers.add(o.issuer_name);
    for (const nb of [o.not_before, o.not_after]) {
      if (typeof nb !== 'string' || !nb) continue;
      if (!first || nb < first) first = nb;
      if (!last || nb > last) last = nb;
    }
    const nv = o.name_value;
    const names = Array.isArray(nv) ? nv.map(String) : typeof nv === 'string' ? nv.split(/\s+/) : [];
    for (const raw of names) {
      let n = raw.trim().toLowerCase().replace(/\.$/, '');
      if (!n) continue;
      if (n.startsWith('*.')) n = n.slice(2);
      if (!n || n.includes('*')) continue;
      // Keep the apex and anything genuinely under it. crt.sh can return entries
      // for a shared multi-tenant SAN bundle, and those are not this domain.
      if (n !== base && !n.endsWith(`.${base}`)) continue;
      if (!DOMAIN_RE.test(n)) continue;
      out.add(n);
    }
  }
  return {
    total: out.size,
    subdomains: [...out].sort(),
    firstSeen: first,
    lastSeen: last,
    issuers: [...issuers].slice(0, 5),
  };
}

export async function crtshSubdomains(domain: string, maxNames = 500): Promise<Lane<CrtResult>> {
  const t0 = Date.now();
  const r = await infraJson(`https://crt.sh/?q=${encodeURIComponent('%.' + domain)}&output=json`, { timeoutMs: SLOW_TIMEOUT_MS });
  if (!r) return { ok: false, data: null, note: 'crt.sh unreachable through this egress', ms: Date.now() - t0 };
  if (r.status === 502 || r.status === 503) {
    return { ok: false, data: null, note: 'crt.sh is up but overloaded (it is frequently 503 under load) — this is NOT a "no subdomains" answer', ms: Date.now() - t0 };
  }
  if (r.status !== 200) return { ok: false, data: null, note: `crt.sh HTTP ${r.status}`, ms: Date.now() - t0 };
  const parsed = parseCrt(r.body, domain);
  const trimmed = parsed.subdomains.slice(0, maxNames);
  return {
    ok: true,
    data: { ...parsed, subdomains: trimmed },
    note: parsed.total > trimmed.length ? `${parsed.total} names found, showing first ${trimmed.length}` : undefined,
    ms: Date.now() - t0,
  };
}

// -----------------------------------------------------------------------------
// Shodan InternetDB — exposed services, hostnames, CPEs, known CVEs
// -----------------------------------------------------------------------------

export interface InternetDbResult {
  ip: string;
  ports: number[];
  hostnames: string[];
  cpes: string[];
  vulns: string[];
  tags: string[];
}

export function parseInternetDb(j: unknown): InternetDbResult | null {
  if (!j || typeof j !== 'object') return null;
  const o = j as Record<string, unknown>;
  // The no-data answer is 200 + {"detail":"No information available"} — it is NOT
  // an object with the expected fields, and treating it as one would print an
  // empty host as though it had been scanned.
  if (typeof o.detail === 'string') return null;
  if (typeof o.ip !== 'string' && !Array.isArray(o.ports)) return null;
  const strArr = (v: unknown) => (Array.isArray(v) ? v.map((x) => String(x)).filter(Boolean) : []);
  return {
    ip: String(o.ip ?? ''),
    ports: (Array.isArray(o.ports) ? o.ports : []).map((p) => Number(p)).filter((p) => Number.isFinite(p)),
    hostnames: strArr(o.hostnames),
    cpes: strArr(o.cpes),
    vulns: strArr(o.vulns),
    tags: strArr(o.tags),
  };
}

export async function internetDb(ip: string): Promise<Lane<InternetDbResult>> {
  const t0 = Date.now();
  const r = await infraJson(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`);
  if (!r) return { ok: false, data: null, note: 'Shodan InternetDB unreachable', ms: Date.now() - t0 };
  if (r.status === 404) return { ok: true, data: null, note: 'Shodan has no record of this IP', ms: Date.now() - t0 };
  if (r.status === 429) return { ok: false, data: null, note: 'InternetDB rate-limited (429)', ms: Date.now() - t0 };
  if (r.status !== 200) return { ok: false, data: null, note: `InternetDB HTTP ${r.status}`, ms: Date.now() - t0 };
  const parsed = parseInternetDb(r.body);
  return parsed
    ? { ok: true, data: parsed, ms: Date.now() - t0 }
    : { ok: true, data: null, note: 'Shodan has no information for this IP', ms: Date.now() - t0 };
}

// -----------------------------------------------------------------------------
// RIPEstat — BGP routing, ASN ownership, abuse contact
// -----------------------------------------------------------------------------

export interface RipeResult {
  ip: string;
  prefix?: string;
  asn?: string;
  holder?: string;
  announced?: boolean;
  abuseEmail?: string;
  related?: { announced?: boolean; lessSpecific: string[]; moreSpecific: string[] };
}

/** Pure parser for the RIPEstat pair. Split out so the two field-name traps are
 *  pinned by tests rather than only by a live call:
 *    * the prefix lives in `resource` — there is NO `prefix` key on this endpoint;
 *    * `abuse_contacts` is an array of plain STRINGS for some RIRs
 *      ("abuse@linode.com") and of {email} objects for others. Reading `.email`
 *      unconditionally dropped the contact on the registries returning strings. */
export function parseRipe(
  ip: string,
  prefixData: Record<string, unknown> | undefined,
  abuseContacts: unknown,
): RipeResult | null {
  if (!prefixData) return null;
  const asns = (prefixData.asns as { asn?: number; holder?: string }[] | undefined) ?? [];
  const relatedPrefixes = prefixData.related_prefixes as { less_specific?: string[]; more_specific?: string[] } | undefined;
  const abuseEmail = (Array.isArray(abuseContacts) ? abuseContacts : [])
    .map((c) => (typeof c === 'string' ? c : typeof (c as { email?: unknown })?.email === 'string' ? (c as { email: string }).email : ''))
    .find((c) => c.includes('@'));
  return {
    ip,
    prefix: typeof prefixData.resource === 'string' ? prefixData.resource : undefined,
    asn: typeof asns[0]?.asn === 'number' ? `AS${asns[0].asn}` : undefined,
    holder: asns[0]?.holder,
    announced: typeof prefixData.announced === 'boolean' ? prefixData.announced : undefined,
    abuseEmail,
    related: relatedPrefixes
      ? { lessSpecific: relatedPrefixes.less_specific ?? [], moreSpecific: relatedPrefixes.more_specific ?? [] }
      : undefined,
  };
}

export async function ripeBgp(ip: string): Promise<Lane<RipeResult>> {
  const t0 = Date.now();
  const [prefixRes, abuseRes] = await Promise.all([
    infraJson<{ data?: Record<string, unknown> }>(`https://stat.ripe.net/data/prefix-overview/data.json?resource=${encodeURIComponent(ip)}`),
    infraJson<{ data?: { abuse_contacts?: unknown } }>(`https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=${encodeURIComponent(ip)}`),
  ]);
  if (!prefixRes || prefixRes.status !== 200) {
    return { ok: false, data: null, note: 'RIPEstat prefix lookup failed', ms: Date.now() - t0 };
  }
  const parsed = parseRipe(ip, prefixRes.body?.data, abuseRes?.body?.data?.abuse_contacts);
  return parsed
    ? { ok: true, data: parsed, ms: Date.now() - t0 }
    : { ok: false, data: null, note: 'RIPEstat returned no prefix data', ms: Date.now() - t0 };
}

// -----------------------------------------------------------------------------
// DNS-over-HTTPS — the full RR set (TXT is where the interesting leaks are)
// -----------------------------------------------------------------------------

export const DNS_TYPES: Record<string, number> = { A: 1, NS: 2, CNAME: 5, SOA: 6, MX: 15, TXT: 16, AAAA: 28 };

export interface DnsRecords {
  records: Record<string, string[]>;
  /** NXDOMAIN is a real answer; a missing/empty record set is not the same thing. */
  nxdomain: boolean;
  note?: string;
}

/** DoH returns TXT data wrapped in presentation quotes: "v=spf1 …". The quotes
 *  are not part of the value and must not be shown as one. */
export function parseDnsAnswers(j: unknown): { records: Record<string, string[]>; nxdomain: boolean } {
  const out: Record<string, string[]> = {};
  if (!j || typeof j !== 'object') return { records: out, nxdomain: false };
  const o = j as Record<string, unknown>;
  const byType: Record<number, string> = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 15: 'MX', 16: 'TXT', 28: 'AAAA' };
  for (const ans of (Array.isArray(o.Answer) ? o.Answer : [])) {
    const a = ans as Record<string, unknown>;
    const name = byType[Number(a.type)];
    const data = typeof a.data === 'string' ? a.data : '';
    if (!name || !data) continue;
    const value = name === 'TXT' ? data.replace(/^"|"$/g, '') : data;
    (out[name] ||= []).push(value);
  }
  return { records: out, nxdomain: Number(o.Status) === 3 };
}

export async function dnsRecords(domain: string, types: string[] = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']): Promise<Lane<DnsRecords>> {
  const t0 = Date.now();
  const wanted = types.filter((t) => DNS_TYPES[t]);
  const results = await Promise.all(
    wanted.map(async (t) => {
      const r = await infraJson<unknown>(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${DNS_TYPES[t]}`);
      return [t, r] as const;
    }),
  );
  const records: Record<string, string[]> = {};
  let answered = 0;
  let blocked = 0;
  let nxdomain = false;
  for (const [t, r] of results) {
    if (!r || r.status !== 200) { blocked++; continue; }
    if (r.body === null) { blocked++; continue; }
    answered++;
    const parsed = parseDnsAnswers(r.body);
    if (parsed.nxdomain) nxdomain = true;
    if (parsed.records[t]?.length) records[t] = [...new Set(parsed.records[t])].slice(0, 20);
  }
  if (answered === 0) {
    return { ok: false, data: null, note: `DNS-over-HTTPS unreachable (${blocked}/${wanted.length} queries failed)`, ms: Date.now() - t0 };
  }
  const note = nxdomain
    ? 'NXDOMAIN — this name does not resolve at all'
    : blocked > 0
      ? `${blocked}/${wanted.length} record types could not be read through this egress`
      : undefined;
  return { ok: true, data: { records, nxdomain }, note, ms: Date.now() - t0 };
}

// -----------------------------------------------------------------------------
// urlscan.io — historical scans: what a domain actually talked to
// -----------------------------------------------------------------------------

export interface UrlscanHit {
  id: string;
  url: string;
  title?: string;
  ip?: string;
  asn?: string;
  asnname?: string;
  server?: string;
  country?: string;
  status?: string;
  domain?: string;
  when?: number;
  requests?: number;
  uniqIPs?: number;
}

export interface UrlscanResult {
  total: number;
  hits: UrlscanHit[];
}

export function parseUrlscan(j: unknown, limit = 20): UrlscanResult {
  const out: UrlscanHit[] = [];
  if (!j || typeof j !== 'object') return { total: 0, hits: out };
  const o = j as Record<string, unknown>;
  const results = Array.isArray(o.results) ? o.results : [];
  for (const r of results) {
    const ro = r as Record<string, unknown>;
    const page = (ro.page ?? {}) as Record<string, unknown>;
    const stats = (ro.stats ?? {}) as Record<string, unknown>;
    const task = (ro.task ?? {}) as Record<string, unknown>;
    const url = typeof page.url === 'string' ? page.url : typeof task.url === 'string' ? task.url : '';
    if (!url) continue;
    out.push({
      id: String(ro._id ?? ''),
      url,
      title: typeof page.title === 'string' ? page.title : undefined,
      ip: typeof page.ip === 'string' ? page.ip : undefined,
      asn: typeof page.asn === 'string' ? page.asn : undefined,
      asnname: typeof page.asnname === 'string' ? page.asnname : undefined,
      server: typeof page.server === 'string' ? page.server : undefined,
      country: typeof page.country === 'string' ? page.country : undefined,
      status: typeof page.status === 'string' ? page.status : undefined,
      domain: typeof page.domain === 'string' ? page.domain : typeof page.apexDomain === 'string' ? page.apexDomain : undefined,
      when: typeof ro.sort === 'number' ? ro.sort : undefined,
      requests: typeof stats.requests === 'number' ? stats.requests : undefined,
      uniqIPs: typeof stats.uniqIPs === 'number' ? stats.uniqIPs : undefined,
    });
    if (out.length >= limit) break;
  }
  return { total: typeof o.total === 'number' ? o.total : out.length, hits: out };
}

export async function urlscanHistory(domain: string, limit = 20): Promise<Lane<UrlscanResult>> {
  const t0 = Date.now();
  // `page.domain:` — NOT the bare `domain:` operator. Measured live: querying
  // `domain:cloudflare.com` returns health-ade.com and example.com, because the
  // bare form matches pages *served on that network* (any Cloudflare customer),
  // not pages *on that domain*. The looser operator would have reported unrelated
  // third-party sites as this domain's scan history — a plausible-looking, badly
  // wrong answer, which is the worst failure mode this engine has.
  // urlscan takes several seconds even for a tiny query — measured 6.4s.
  const r = await infraJson(`https://urlscan.io/api/v1/search/?q=${encodeURIComponent(`page.domain:${domain}`)}&size=${Math.min(Math.max(limit, 1), 50)}`, { timeoutMs: 30_000 });
  if (!r) return { ok: false, data: null, note: 'urlscan.io unreachable through this egress', ms: Date.now() - t0 };
  if (r.status === 429) return { ok: false, data: null, note: 'urlscan.io rate-limited (429) — anonymous quota exhausted', ms: Date.now() - t0 };
  if (r.status === 401 || r.status === 403) return { ok: false, data: null, note: `urlscan.io refused (HTTP ${r.status})`, ms: Date.now() - t0 };
  if (r.status !== 200) return { ok: false, data: null, note: `urlscan.io HTTP ${r.status}`, ms: Date.now() - t0 };
  return { ok: true, data: parseUrlscan(r.body, limit), ms: Date.now() - t0 };
}

// -----------------------------------------------------------------------------
// AlienVault OTX — community reputation
// -----------------------------------------------------------------------------

export interface OtxPulse { name: string; created?: string; modified?: string; tags?: string[] }
export interface OtxResult {
  indicator: string;
  type: string;
  reputation: number | null;
  pulseCount: number;
  pulses: OtxPulse[];
  asn?: string;
  country?: string;
  latitude?: number;
  longitude?: number;
}

export function parseOtx(j: unknown, indicator: string): OtxResult | null {
  if (!j || typeof j !== 'object') return null;
  const o = j as Record<string, unknown>;
  const pi = (o.pulse_info ?? {}) as Record<string, unknown>;
  if (typeof o.indicator !== 'string' && typeof o.type !== 'string') return null;
  const pulses: OtxPulse[] = [];
  for (const p of (Array.isArray(pi.pulses) ? pi.pulses : [])) {
    const po = p as Record<string, unknown>;
    if (typeof po.name !== 'string') continue;
    pulses.push({
      name: po.name,
      created: typeof po.created === 'string' ? po.created : undefined,
      modified: typeof po.modified === 'string' ? po.modified : undefined,
      tags: Array.isArray(po.tags) ? po.tags.map((t) => String(t)).slice(0, 6) : [],
    });
  }
  return {
    indicator: typeof o.indicator === 'string' ? o.indicator : indicator,
    type: String(o.type ?? ''),
    // 0 is a real reputation value; null means "the API did not say".
    reputation: typeof o.reputation === 'number' ? o.reputation : null,
    pulseCount: typeof pi.count === 'number' ? pi.count : pulses.length,
    pulses: pulses.slice(0, 10),
    asn: typeof o.asn === 'string' ? o.asn : undefined,
    country: typeof o.country_name === 'string' ? o.country_name : undefined,
    latitude: typeof o.latitude === 'number' ? o.latitude : undefined,
    longitude: typeof o.longitude === 'number' ? o.longitude : undefined,
  };
}

export async function otxIndicator(indicator: string): Promise<Lane<OtxResult>> {
  const t0 = Date.now();
  const v = indicator.trim().toLowerCase();
  const kind = isIpv4(v) ? 'IPv4' : DOMAIN_RE.test(v) ? 'domain' : 'file';
  if (kind === 'file') return { ok: false, data: null, note: 'OTX covers IP and domain indicators only', ms: Date.now() - t0 };
  const r = await infraJson(`https://otx.alienvault.com/api/v1/indicators/${kind}/${encodeURIComponent(v)}/general`);
  if (!r) return { ok: false, data: null, note: 'OTX unreachable through this egress', ms: Date.now() - t0 };
  if (r.status === 404) return { ok: true, data: null, note: 'OTX has no indicator record for this value', ms: Date.now() - t0 };
  if (r.status !== 200) return { ok: false, data: null, note: `OTX HTTP ${r.status}`, ms: Date.now() - t0 };
  const parsed = parseOtx(r.body, v);
  return parsed
    ? { ok: true, data: parsed, ms: Date.now() - t0 }
    : { ok: false, data: null, note: 'OTX response did not parse', ms: Date.now() - t0 };
}

// -----------------------------------------------------------------------------
// blocklist.de — attack / report counters
// -----------------------------------------------------------------------------

export interface BlocklistDeResult { ip: string; attacks: number; reports: number; listed: boolean }

/** The service answers an HTML fragment, not JSON: "attacks: 0<br />reports: 0<br />". */
export function parseBlocklistDe(text: string, ip: string): BlocklistDeResult | null {
  if (typeof text !== 'string' || !text.trim()) return null;
  const attacks = /attacks:\s*(\d+)/i.exec(text);
  const reports = /reports:\s*(\d+)/i.exec(text);
  if (!attacks && !reports) return null;
  const a = attacks ? Number(attacks[1]) : 0;
  const r = reports ? Number(reports[1]) : 0;
  return { ip, attacks: a, reports: r, listed: a > 0 || r > 0 };
}

export async function blocklistDeIp(ip: string): Promise<Lane<BlocklistDeResult>> {
  const t0 = Date.now();
  const r = await infraText(`https://api.blocklist.de/api.php?ip=${encodeURIComponent(ip)}`);
  if (!r) return { ok: false, data: null, note: 'blocklist.de unreachable', ms: Date.now() - t0 };
  if (r.status !== 200) return { ok: false, data: null, note: `blocklist.de HTTP ${r.status}`, ms: Date.now() - t0 };
  const parsed = parseBlocklistDe(r.text, ip);
  return parsed
    ? { ok: true, data: parsed, ms: Date.now() - t0 }
    : { ok: false, data: null, note: 'blocklist.de returned an unrecognised response', ms: Date.now() - t0 };
}

// -----------------------------------------------------------------------------
// CIRCL hashlookup — known-file identification. Feeds the DFIR IOC pipeline.
// -----------------------------------------------------------------------------

export interface HashLookupResult {
  hash: string;
  fileName?: string;
  fileSize?: number;
  md5?: string;
  sha1?: string;
  sha256?: string;
  crc32?: string;
  ssdeep?: string;
  mimeType?: string;
  os?: string;
  osVersion?: string;
  /** 0-100. CIRCL's own confidence in this record. */
  trust?: number;
  /** Present when the file is listed in the NIST Software Reference Library —
   *  i.e. it is a KNOWN-GOOD piece of software, not a threat. */
  knownGood?: boolean;
}

/** Field names are load-bearing and were verified live against hashlookup.circl.lu.
 *  They are hyphenated (`SHA-1`, not `SHA1`) and there is no `FileType` key at all
 *  — the first draft of this parser read `SHA1`/`SHA256`/`FileType` and silently
 *  returned undefined for every one of them while still reporting a hit.
 *  `FileSize` arrives as a STRING ("3"), so it must be coerced, not type-tested. */
export function parseHashlookup(j: unknown, hash: string): HashLookupResult | null {
  if (!j || typeof j !== 'object') return null;
  const o = j as Record<string, unknown>;
  // Known-file answer carries a FileName; "not known" is an empty object.
  if (!o.FileName && !o.FileSize) return null;
  const os = (o.OpSystemCode ?? {}) as Record<string, unknown>;
  const str = (v: unknown) => (typeof v === 'string' && v.trim() ? v.trim() : undefined);
  const sizeRaw = o.FileSize;
  const size = typeof sizeRaw === 'number' ? sizeRaw : Number(String(sizeRaw ?? '').trim());
  return {
    hash,
    fileName: str(o.FileName),
    fileSize: Number.isFinite(size) ? size : undefined,
    md5: str(o.MD5),
    sha1: str(o['SHA-1']),
    sha256: str(o['SHA-256']),
    crc32: str(o.CRC32),
    ssdeep: str(o.SSDEEP),
    mimeType: str(o.mimetype),
    os: str(os.OpSystemName),
    osVersion: str(os.OpSystemVersion),
    trust: typeof o['hashlookup:trust'] === 'number' ? o['hashlookup:trust'] : undefined,
    knownGood: typeof o['nsrl-sha256'] === 'string' ? true : undefined,
  };
}

const HASH_RE = /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$|^[a-f0-9]{128}$/i;

export async function circlHash(hash: string): Promise<Lane<HashLookupResult>> {
  const t0 = Date.now();
  const h = hash.trim().toLowerCase();
  if (!HASH_RE.test(h)) {
    return { ok: false, data: null, note: 'not an MD5/SHA1/SHA256/SHA512 hash', ms: Date.now() - t0 };
  }
  const r = await infraJson(`https://hashlookup.circl.lu/lookup/${h.length === 32 ? 'md5' : h.length === 40 ? 'sha1' : h.length === 64 ? 'sha256' : 'sha512'}/${h}`);
  if (!r) return { ok: false, data: null, note: 'CIRCL hashlookup unreachable', ms: Date.now() - t0 };
  if (r.status === 404) return { ok: true, data: null, note: 'hash is not in the known-file database', ms: Date.now() - t0 };
  if (r.status !== 200) return { ok: false, data: null, note: `CIRCL hashlookup HTTP ${r.status}`, ms: Date.now() - t0 };
  const parsed = parseHashlookup(r.body, h);
  return parsed
    ? { ok: true, data: parsed, ms: Date.now() - t0 }
    : { ok: true, data: null, note: 'hash is not in the known-file database', ms: Date.now() - t0 };
}

// -----------------------------------------------------------------------------
// composites
// -----------------------------------------------------------------------------

export interface DomainInfraResult {
  kind: 'domain';
  domain: string;
  rdap: Lane<RdapResult>;
  crt: Lane<CrtResult>;
  dns: Lane<DnsRecords>;
  urlscan: Lane<UrlscanResult>;
  otx: Lane<OtxResult>;
  /** Sources that failed, so the operator sees coverage rather than a short answer. */
  failed: string[];
  ms: number;
}

export async function domainInfraScan(domain: string): Promise<DomainInfraResult> {
  const t0 = Date.now();
  const [rdap, crt, dns, urlscan, otx] = await Promise.all([
    rdapDomain(domain),
    crtshSubdomains(domain),
    dnsRecords(domain),
    urlscanHistory(domain, 15),
    otxIndicator(domain),
  ]);
  const lanes: Array<[string, Lane<unknown>]> = [
    ['rdap', rdap], ['crt', crt], ['dns', dns], ['urlscan', urlscan], ['otx', otx],
  ];
  return {
    kind: 'domain', domain,
    rdap, crt, dns, urlscan, otx,
    failed: lanes.filter(([, l]) => !l.ok).map(([n]) => n),
    ms: Date.now() - t0,
  };
}

export interface IpInfraResult {
  kind: 'ipv4';
  ip: string;
  shodan: Lane<InternetDbResult>;
  ripe: Lane<RipeResult>;
  otx: Lane<OtxResult>;
  blocklist: Lane<BlocklistDeResult>;
  failed: string[];
  ms: number;
}

export async function ipInfraScan(ip: string): Promise<IpInfraResult> {
  const t0 = Date.now();
  const [shodan, ripe, otx, blocklist] = await Promise.all([
    internetDb(ip),
    ripeBgp(ip),
    otxIndicator(ip),
    blocklistDeIp(ip),
  ]);
  const lanes: Array<[string, Lane<unknown>]> = [
    ['shodan', shodan], ['ripe', ripe], ['otx', otx], ['blocklist', blocklist],
  ];
  return {
    kind: 'ipv4', ip,
    shodan, ripe, otx, blocklist,
    failed: lanes.filter(([, l]) => !l.ok).map(([n]) => n),
    ms: Date.now() - t0,
  };
}

// -----------------------------------------------------------------------------
// agent tools
// -----------------------------------------------------------------------------

const INFRA_DOCTRINE =
  'All lookups are against third-party public databases (RDAP, crt.sh, Shodan InternetDB, RIPEstat, DNS-over-HTTPS, urlscan.io, OTX). Nothing here probes the target system.';

export const INFRA_TOOLS: CustomTool[] = [
  {
    name: 'osint_domain_infra',
    description: `Domain infrastructure intelligence: registration data (RDAP), Certificate Transparency subdomain discovery (crt.sh), the full DNS record set including TXT, and urlscan.io scan history. ${INFRA_DOCTRINE}`,
    category: 'osint',
    parameters: [
      { name: 'domain', type: 'string', description: 'Domain to investigate (a full URL is accepted and reduced to its host)', required: true },
    ],
    handler: async (context) => {
      const t = classifyTarget(String(context.parameters.domain ?? ''));
      if (t.kind !== 'domain') {
        return { success: false, error: `not a domain: ${t.note ?? t.value}` };
      }
      try {
        const r = await domainInfraScan(t.value);
        const lines = [`Domain infrastructure for ${r.domain} (${r.ms}ms)`, ''];
        if (r.rdap.data) {
          lines.push(`Registration: registrar ${r.rdap.data.registrar ?? '?'}, created ${r.rdap.data.events.find((e) => e.action === 'registration')?.date?.slice(0, 10) ?? '?'}, expires ${r.rdap.data.events.find((e) => e.action === 'expiration')?.date?.slice(0, 10) ?? '?'}`);
          lines.push(`  nameservers: ${r.rdap.data.nameservers.join(', ') || 'none published'}`);
        } else lines.push(`Registration: ${r.rdap.note ?? 'no data'}`);
        lines.push(`Subdomains (Certificate Transparency): ${r.crt.data ? r.crt.data.total : '?'}${r.crt.data?.subdomains.length ? ` — ${r.crt.data.subdomains.slice(0, 30).join(', ')}${r.crt.data.subdomains.length > 30 ? ' …' : ''}` : ''}${r.crt.data ? '' : ` (${r.crt.note})`}`);
        for (const [name, vals] of Object.entries(r.dns.data?.records ?? {})) {
          lines.push(`DNS ${name}: ${vals.slice(0, 6).join(' | ')}`);
        }
        if (r.urlscan.data?.hits.length) {
          lines.push(`urlscan history (${r.urlscan.data.total} scans):`);
          for (const h of r.urlscan.data.hits.slice(0, 5)) {
            lines.push(`  ${h.url} — ${h.status ?? '?'} ${h.ip ?? ''} ${h.asnname ?? ''}`.trim());
          }
        } else lines.push(`urlscan history: ${r.urlscan.note ?? 'no public scans'}`);
        if (r.otx.data) lines.push(`OTX: ${r.otx.data.pulseCount} pulse(s), reputation ${r.otx.data.reputation ?? 'n/a'}`);
        if (r.failed.length) lines.push(`Sources that could not answer: ${r.failed.join(', ')}`);

        const findings = (r.crt.data?.subdomains ?? []).slice(0, 25).map((s) => ({
          title: `Subdomain Discovered (CT) — ${s}`,
          severity: 'info' as const,
          details: `Certificate Transparency log entry for ${s} under ${r.domain}.`,
        }));
        return { success: true, output: lines.join('\n'), findings };
      } catch (error) {
        return { success: false, error: `Domain infrastructure scan failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'osint_ip_infra',
    description: `IP infrastructure intelligence: exposed services and known CVEs (Shodan InternetDB), BGP prefix/ASN ownership and abuse contact (RIPEstat), OTX threat reputation, and blocklist.de attack counters. ${INFRA_DOCTRINE}`,
    category: 'osint',
    parameters: [
      { name: 'ip', type: 'string', description: 'Public IPv4 address to investigate', required: true },
    ],
    handler: async (context) => {
      const t = classifyTarget(String(context.parameters.ip ?? ''));
      if (t.kind !== 'ipv4') {
        return { success: false, error: `not a public IPv4 address: ${t.note ?? t.value}` };
      }
      try {
        const r = await ipInfraScan(t.value);
        const lines = [`IP infrastructure for ${r.ip} (${r.ms}ms)`, ''];
        if (r.shodan.data) {
          lines.push(`Services: ports ${r.shodan.data.ports.join(', ') || 'none recorded'}`);
          if (r.shodan.data.hostnames.length) lines.push(`  hostnames: ${r.shodan.data.hostnames.slice(0, 8).join(', ')}`);
          if (r.shodan.data.vulns.length) lines.push(`  CVEs matched by CPE: ${r.shodan.data.vulns.join(', ')}`);
        } else lines.push(`Services: ${r.shodan.note ?? 'no data'}`);
        if (r.ripe.data) {
          lines.push(`Routing: ${r.ripe.data.prefix ?? '?'} announced by ${r.ripe.data.asn ?? '?'} (${r.ripe.data.holder ?? 'unknown holder'})`);
          if (r.ripe.data.abuseEmail) lines.push(`  abuse contact: ${r.ripe.data.abuseEmail}`);
        } else lines.push(`Routing: ${r.ripe.note ?? 'no data'}`);
        if (r.otx.data) lines.push(`OTX: ${r.otx.data.pulseCount} pulse(s), reputation ${r.otx.data.reputation ?? 'n/a'}`);
        if (r.blocklist.data) lines.push(`blocklist.de: ${r.blocklist.data.attacks} attack(s), ${r.blocklist.data.reports} report(s)`);
        if (r.failed.length) lines.push(`Sources that could not answer: ${r.failed.join(', ')}`);

        const findings = [
          ...(r.shodan.data?.vulns ?? []).map((cve) => ({
            title: `Known CVE matched on ${r.ip} — ${cve}`,
            severity: 'medium' as const,
            details: `Shodan InternetDB matched ${cve} against a CPE observed on ${r.ip}${r.shodan.data?.cpes.length ? ` (${r.shodan.data.cpes.slice(0, 3).join(', ')})` : ''}. This is a database match on an observed product version, NOT proof the host is exploitable — verify before acting.`,
          })),
          ...(r.blocklist.data?.listed
            ? [{
                title: `IP has abuse history — ${r.ip}`,
                severity: 'medium' as const,
                details: `blocklist.de reports ${r.blocklist.data.attacks} attack(s) and ${r.blocklist.data.reports} report(s).`,
              }]
            : []),
        ];
        return { success: true, output: lines.join('\n'), findings };
      } catch (error) {
        return { success: false, error: `IP infrastructure scan failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'osint_hash_lookup',
    description: 'Identify a file from its MD5/SHA1/SHA256/SHA512 hash against the CIRCL known-file database (keyless) — returns filename, size, mimetype, and the OS package it belongs to. NOTE: this is a known-good-file database (NIST NSRL), NOT a malware database — a hit means the file is recognized, never that it is malicious.',
    category: 'osint',
    parameters: [
      { name: 'hash', type: 'string', description: 'MD5, SHA1, SHA256 or SHA512 hash of the file', required: true },
    ],
    handler: async (context) => {
      try {
        const r = await circlHash(String(context.parameters.hash ?? ''));
        if (!r.ok) return { success: false, error: r.note ?? 'hash lookup failed' };
        if (!r.data) return { success: true, output: `Hash not found in the known-file database: ${context.parameters.hash}`, findings: [] };
        const d = r.data;
        const output = [
          `Known-file match for ${d.hash}:`,
          `  filename: ${d.fileName ?? '?'}`,
          `  size: ${d.fileSize ?? '?'} bytes`,
          `  type: ${d.mimeType ?? '?'}`,
          `  belongs to OS: ${d.os ?? 'unknown'}${d.osVersion && d.osVersion !== 'none' ? ` ${d.osVersion}` : ''}`,
          `  listed as known-good software (NIST NSRL): ${d.knownGood ? 'yes' : 'no'}`,
          '',
          'This database identifies files. A match says nothing about whether the',
          'file is malicious — use a malware sandbox for that.',
        ].join('\n');
        return {
          success: true,
          output,
          findings: [{
            title: `Known File Identified — ${d.fileName ?? d.hash}`,
            severity: 'info' as const,
            details: `CIRCL hashlookup matched ${d.hash} to "${d.fileName}"${d.mimeType ? ` (${d.mimeType})` : ''}${d.os ? `, shipped as part of ${d.os}` : ''}${d.knownGood ? ' — listed in the NIST Software Reference Library as known-good software' : ''}.`,
          }],
        };
      } catch (error) {
        return { success: false, error: `Hash lookup failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
];
