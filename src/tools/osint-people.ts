/**
 * PEOPLE-RECORDS LANES — public government and name-index lookups for a PERSON, not a handle.
 *
 * Everything here was measured live on 2026-10-26 before being wired:
 *
 *  • BOP FEDERAL INMATE LOCATOR — the bop.gov/inmateloc UI POSTs form fields to
 *    `/PublicInfo/execute/inmateloc` and consumes JSON. Proven from this box: Elizabeth
 *    Holmes returns a full record (name/sex/race/age/register number/facility/projected
 *    release), number search works with the exact IRN form, an unknown name answers
 *    `{"InmateLocator":[]}` (an HONEST zero), a last-name-only query answers
 *    `Exceptions: "Validation failed, no valid field values"`, and `Captcha:true` exists as
 *    a state the operator must be told about, never laundered into "no results".
 *  • CMS NPI REGISTRY — the official public clinician registry (npiregistry.cms.hhs.gov,
 *    keyless). The v1 shape 404s with "Unsupported Version"; `version=2.1` works and
 *    returned Kelly W. Headley LCSW with her practice address on the first live query.
 *  • NAME-DISCOVERY — the search-engine lane from the KellyHeadley75 hunt, run with
 *    name-only queries (quoted name + one scoped query per walled platform), so a person
 *    search sees Facebook/Instagram/LinkedIn/TikTok/Reddit/X profiles the direct probes
 *    can never distinguish from fakes.
 *
 * DOCTRINE: public, keyless, legal sources only. A returned empty set is reported AS an
 * empty set from THAT source — the report always names the source so a zero from one
 * record system can never read as "this person does not exist".
 */

import { egressProbe, type OsintSiteCategory } from './osint.js';
import type { CustomTool } from '../types/index.js';
import { searchEngineDiscovery, buildNameQueries, type SearchDiscoveryResult } from './osint-searchdiscovery.js';

const TIMEOUT_MS = 25_000;

// ═══════════════════════════════════════════════════════════════════════════
// 1. BOP FEDERAL INMATE LOCATOR
// ═══════════════════════════════════════════════════════════════════════════

export interface BopInmate {
  nameLast: string;
  nameFirst: string;
  nameMiddle?: string;
  suffix?: string;
  sex?: string;
  race?: string;
  age?: string;
  /** BOP register number, e.g. 24965-111. */
  inmateNum: string;
  facilityCode?: string;
  facilityName?: string;
  facilityType?: string;
  facilityUrl?: string;
  projectedReleaseDate?: string;
  actualReleaseDate?: string;
  /** R = released, etc. Empty means in custody without a release code. */
  releaseCode?: string;
  profileUrl: string;
}

export interface BopSearchResult {
  source: 'bop.gov federal inmate locator';
  /** true = at least one record; false = honest zero from BOP; null = BOP did not answer. */
  found: boolean | null;
  count: number;
  inmates: BopInmate[];
  /** Which transport answered — the BOP box needs no proxy, but the report says. */
  via: string;
  note?: string;
}

export interface BopSearchParams {
  firstName?: string;
  middleName?: string;
  lastName?: string;
  /** Exact age filter (BOP matches it exactly, not a range). */
  age?: string;
  /** I | A | B | W (the locator's own select values). */
  race?: string;
  /** M | F (the locator's own select values). */
  sex?: string;
  /** Register (IRN) / DCDC / FBI / INS number, with inmateNumType. */
  inmateNum?: string;
  inmateNumType?: 'IRN' | 'DCDC' | 'FBI' | 'INS';
}

/** Injected transport for tests; default rides the osint egress ladder. */
export type PeopleFetcher = (url: string, init?: { method?: string; body?: string; headers?: Record<string, string> }) => Promise<{ status: number; body: string; via: string }>;

export const defaultPeopleFetcher: PeopleFetcher = async (url, init = {}) => {
  const r = await egressProbe(url, TIMEOUT_MS, init);
  return { status: r.status, body: r.body, via: r.via };
};

export function buildBopForm(p: BopSearchParams): string {
  const num = (p.inmateNum || '').trim();
  if (num) {
    // Measured: the number form posts todo/output/inmateNumType/inmateNum. Types are the
    // locator's own select values (IRN | DCDC | FBI | INS) — a wrong type returns an
    // authoritative-looking empty set, so the module pins them.
    return `todo=query&output=json&inmateNumType=${encodeURIComponent(p.inmateNumType || 'IRN')}&inmateNum=${encodeURIComponent(num)}`;
  }
  const last = (p.lastName || '').trim();
  if (!last && !(p.firstName || '').trim()) {
    throw new Error('BOP locator needs a last name (plus optional first/middle/age/race/sex) or an inmate number');
  }
  const parts: Array<[string, string]> = [
    ['todo', 'query'],
    ['output', 'json'],
    ['inmateNum', ''],
    ['nameFirst', (p.firstName || '').trim()],
    ['nameMiddle', (p.middleName || '').trim()],
    ['nameLast', last],
    ['race', (p.race || '').trim()],
    ['age', (p.age || '').trim()],
    ['sex', (p.sex || '').trim()],
  ];
  return parts.map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');
}

/** Parser over the captured response shapes: populated InmateLocator, honest empty,
 *  Exceptions (validation), Captcha. Pinned by fixtures captured 2026-10-26. */
export function parseBopResponse(body: string): { inmates: BopInmate[]; captcha: boolean; exception?: string } {
  let j: {
    Captcha?: boolean;
    InmateLocator?: Array<Record<string, string>>;
    Exceptions?: { FriendlyMessage?: string; ExceptionMessage?: string };
  };
  try {
    j = JSON.parse(body);
  } catch {
    throw new Error(`BOP answered non-JSON (${body.slice(0, 80)}…) — treat as unmeasured, never as "no record"`);
  }
  if (j.Captcha === true) return { inmates: [], captcha: true };
  const exception = j.Exceptions?.FriendlyMessage || j.Exceptions?.ExceptionMessage;
  if (exception) return { inmates: [], captcha: false, exception };
  const rows = Array.isArray(j.InmateLocator) ? j.InmateLocator : [];
  return {
    captcha: false,
    inmates: rows.map((r) => ({
      nameLast: r.nameLast || '',
      nameFirst: r.nameFirst || '',
      nameMiddle: r.nameMiddle || undefined,
      suffix: r.suffix || undefined,
      sex: r.sex || undefined,
      race: r.race || undefined,
      age: r.age || undefined,
      inmateNum: r.inmateNum || '',
      facilityCode: r.faclCode || undefined,
      facilityName: r.faclName || undefined,
      facilityType: r.faclType || undefined,
      facilityUrl: r.faclURL ? `https://www.bop.gov${r.faclURL}` : undefined,
      projectedReleaseDate: r.projRelDate || undefined,
      actualReleaseDate: r.actRelDate || undefined,
      releaseCode: r.releaseCode || undefined,
      profileUrl: r.inmateNum ? `https://www.bop.gov/inmateloc/#/inmate?regNumber=${encodeURIComponent(r.inmateNum)}` : 'https://www.bop.gov/inmateloc/',
    })),
  };
}

export async function bopInmateSearch(p: BopSearchParams, fetcher: PeopleFetcher = defaultPeopleFetcher): Promise<BopSearchResult> {
  const form = buildBopForm(p);
  const res = await fetcher('https://www.bop.gov/PublicInfo/execute/inmateloc', {
    method: 'POST',
    body: form,
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
      // The locator's own page as referer + XHR marker: measured required headers for the
      // JSON shape (without them the endpoint still answers, but they cost nothing).
      referer: 'https://www.bop.gov/inmateloc/',
      'x-requested-with': 'XMLHttpRequest',
    },
  });
  if (res.status === 403 || res.status === 429) {
    return { source: 'bop.gov federal inmate locator', found: null, count: 0, inmates: [], via: res.via, note: `BOP answered HTTP ${res.status} — rate-limit/WAF; treat as UNMEASURED, never as "no record"` };
  }
  if (res.status !== 200) {
    return { source: 'bop.gov federal inmate locator', found: null, count: 0, inmates: [], via: res.via, note: `BOP answered HTTP ${res.status}` };
  }
  const parsed = parseBopResponse(res.body);
  if (parsed.captcha) {
    return { source: 'bop.gov federal inmate locator', found: null, count: 0, inmates: [], via: res.via, note: 'BOP served a captcha challenge — solve it in a browser or retry later; UNMEASURED' };
  }
  if (parsed.exception) {
    return { source: 'bop.gov federal inmate locator', found: null, count: 0, inmates: [], via: res.via, note: `BOP refused the query: ${parsed.exception} (needs a last name or a number)` };
  }
  return {
    source: 'bop.gov federal inmate locator',
    found: parsed.inmates.length > 0,
    count: parsed.inmates.length,
    inmates: parsed.inmates,
    via: res.via,
    note: parsed.inmates.length === 0 ? 'BOP answered 200 with an empty InmateLocator — an honest zero from THIS source (current federal custody only; not state prisons, not released-except-where-marked)' : undefined,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. CMS NPI REGISTRY — official public clinician records
// ═══════════════════════════════════════════════════════════════════════════

export interface NpiRecord {
  npi: string;
  name: string;
  credential?: string;
  sex?: string;
  enumerationDate?: string;
  taxonomies: string[];
  addresses: Array<{ purpose: string; address: string; city: string; state: string; postalCode: string; phone?: string }>;
}

export interface NpiSearchResult {
  source: 'CMS NPI registry (npiregistry.cms.hhs.gov)';
  found: boolean | null;
  count: number;
  records: NpiRecord[];
  via: string;
  note?: string;
}

export function buildNpiUrl(p: { firstName?: string; lastName?: string; taxonomy?: string; state?: string; npi?: string }): string {
  const base = 'https://npiregistry.cms.hhs.gov/api/?version=2.1';
  if (p.npi) return `${base}&number=${encodeURIComponent(p.npi)}`;
  const params = new URLSearchParams();
  params.set('enumeration_type', 'NPI-1');
  params.set('first_name', (p.firstName || '').trim());
  params.set('last_name', (p.lastName || '').trim());
  params.set('use_first_name_alias', 'true');
  if (p.taxonomy) params.set('taxonomy_description', p.taxonomy);
  if (p.state) params.set('state', p.state);
  params.set('limit', '20');
  return `${base}&${params.toString()}`;
}

export function parseNpiResponse(body: string): NpiRecord[] {
  const j = JSON.parse(body) as {
    result_count?: number;
    results?: Array<{
      number: number;
      basic?: { first_name?: string; last_name?: string; middle_name?: string; credential?: string; sex?: string; enumeration_date?: string };
      taxonomies?: Array<{ desc?: string }>;
      addresses?: Array<{ address_purpose?: string; address_1?: string; address_2?: string; city?: string; state?: string; postal_code?: string; telephone_number?: string }>;
    }>;
  };
  return (j.results || []).map((r) => ({
    npi: String(r.number),
    name: [r.basic?.first_name, r.basic?.middle_name, r.basic?.last_name].filter(Boolean).join(' '),
    credential: r.basic?.credential || undefined,
    sex: r.basic?.sex || undefined,
    enumerationDate: r.basic?.enumeration_date || undefined,
    taxonomies: (r.taxonomies || []).map((t) => t.desc || '').filter(Boolean),
    addresses: (r.addresses || []).map((a) => ({
      purpose: a.address_purpose || '',
      address: [a.address_1, a.address_2].filter(Boolean).join(', '),
      city: a.city || '',
      state: a.state || '',
      postalCode: a.postal_code || '',
      phone: a.telephone_number || undefined,
    })),
  }));
}

export async function npiRegistryLookup(p: { firstName?: string; lastName?: string; taxonomy?: string; state?: string; npi?: string }, fetcher: PeopleFetcher = defaultPeopleFetcher): Promise<NpiSearchResult> {
  if (!p.npi && !(p.lastName || '').trim()) throw new Error('NPI lookup needs a last name or an NPI number');
  const url = buildNpiUrl(p);
  const res = await fetcher(url);
  if (res.status !== 200) {
    return { source: 'CMS NPI registry (npiregistry.cms.hhs.gov)', found: null, count: 0, records: [], via: res.via, note: `NPI registry answered HTTP ${res.status}` };
  }
  // v1 of this API 404s with {"Errors":[{"description":"Unsupported Version"...}]} — the
  // module pins version=2.1, and an error payload here is reported, not parsed as empty.
  if (res.body.includes('"Errors"')) {
    return { source: 'CMS NPI registry (npiregistry.cms.hhs.gov)', found: null, count: 0, records: [], via: res.via, note: `NPI registry returned an error payload: ${res.body.slice(0, 160)}` };
  }
  const records = parseNpiResponse(res.body);
  return {
    source: 'CMS NPI registry (npiregistry.cms.hhs.gov)',
    found: records.length > 0,
    count: records.length,
    records,
    via: res.via,
    note: records.length === 0 ? 'No US clinician registered under this name/taxonomy — honest zero from the CMS registry' : undefined,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. NAME-DISCOVERY — the search-engine lane, name-only
// ═══════════════════════════════════════════════════════════════════════════

export interface PeopleDiscoveryResult extends SearchDiscoveryResult {
  subject: string;
}

/** Run the walled-platform search lane for a PERSON (no handle needed). The subject name is
 *  both seed and corroboration: a hit corroborates only when the name appears in it. */
export async function peopleNameDiscovery(
  name: string,
  opts: { deadlineMs?: number; paceMs?: number; fetcher?: import('./osint-searchdiscovery.js').SearchFetcher; onStage?: (s: string, d: string) => void } = {}
): Promise<PeopleDiscoveryResult> {
  const subject = (name || '').trim();
  if (!subject || !subject.includes(' ')) throw new Error('people discovery needs a full name (first + last)');
  const r = await searchEngineDiscovery(subject, {
    name: subject,
    queries: buildNameQueries(subject),
    deadlineMs: opts.deadlineMs,
    paceMs: opts.paceMs,
    fetcher: opts.fetcher,
    onStage: opts.onStage,
  });
  return { subject, ...r };
}

/** Compact operator-facing text for the three lanes. */
export function formatPeopleReport(bop: BopSearchResult | null, npi: NpiSearchResult | null, disc: PeopleDiscoveryResult | null): string {
  const L: string[] = [];
  if (bop) {
    L.push('── BOP FEDERAL INMATE LOCATOR ──');
    if (bop.found === true) {
      L.push(`${bop.count} record(s) in CURRENT federal custody:`);
      for (const m of bop.inmates.slice(0, 15)) {
        L.push(`  · ${m.nameFirst} ${m.nameMiddle || ''} ${m.nameLast}${m.suffix ? ' ' + m.suffix : ''} — reg ${m.inmateNum}${m.age ? `, age ${m.age}` : ''}${m.sex ? `, ${m.sex}` : ''}${m.race ? `, ${m.race}` : ''}`);
        L.push(`      ${m.facilityName || '?'} (${m.facilityType || '?'})${m.facilityUrl ? ` — ${m.facilityUrl}` : ''} · projected release ${m.projectedReleaseDate || 'n/a'}${m.actualReleaseDate ? ` · actual ${m.actualReleaseDate}` : ''}`);
      }
    } else if (bop.found === false) {
      L.push(`No record in CURRENT federal custody (honest zero from BOP).${bop.note ? ' ' + bop.note : ''}`);
    } else {
      L.push(`BOP unmeasured — ${bop.note}`);
    }
  }
  if (npi) {
    L.push('');
    L.push('── CMS NPI REGISTRY (clinicians) ──');
    if (npi.found === true) {
      for (const r of npi.records.slice(0, 10)) {
        L.push(`  · ${r.name}${r.credential ? ` (${r.credential})` : ''} — NPI ${r.npi}${r.taxonomies.length ? ` · ${r.taxonomies.join('; ')}` : ''}`);
        for (const a of r.addresses.slice(0, 2)) L.push(`      ${a.purpose}: ${a.address}, ${a.city}, ${a.state} ${a.postalCode}${a.phone ? ` · ${a.phone}` : ''}`);
      }
    } else if (npi.found === false) L.push(`No registered clinician under this name (honest zero).${npi.note ? ' ' + npi.note : ''}`);
    else L.push(`NPI unmeasured — ${npi.note}`);
  }
  if (disc) {
    L.push('');
    L.push(`── SEARCH-ENGINE DISCOVERY (walled platforms) ── ${disc.queriesRun.length} queries · ${disc.pagesWithResults} result page(s)`);
    for (const h of disc.hits.slice(0, 20)) L.push(`  ${h.identity === 'name-match' ? '✓' : '?'} ${h.site}: ${h.url}`);
    for (const d of disc.directories.slice(0, 6)) L.push(`  [directory] ${d.platform}: ${d.url}`);
    for (const m of disc.mentions.slice(0, 10)) L.push(`  · ${m.title || '(untitled)'} — ${m.url}`);
    if (disc.engineStatus !== 'ok') L.push(`  engine: ${disc.engineStatus}`);
  }
  if (!L.length) L.push('Nothing to report — supply a name and at least one lane.');
  return L.join('\n');
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. AGENT TOOLS
// ═══════════════════════════════════════════════════════════════════════════

export const OSINT_PEOPLE_TOOLS: CustomTool[] = [
  {
    name: 'osint_bop_inmate_search',
    description:
      'Search the Federal Bureau of Prisons PUBLIC inmate locator (bop.gov/inmateloc) by name (last name required, optional first/middle/age/race/sex) or by register number (IRN/DCDC/FBI/INS). Covers CURRENT federal custody only — not state prisons, not jails. An empty result is an honest zero from BOP and is reported as such; a captcha or validation refusal is reported as UNMEASURED.',
    category: 'osint',
    parameters: [
      { name: 'lastName', type: 'string', description: 'Subject last name (required unless inmateNum is given)', required: false },
      { name: 'firstName', type: 'string', description: 'First name', required: false },
      { name: 'age', type: 'string', description: 'Exact age filter', required: false },
      { name: 'race', type: 'string', description: 'I | A | B | W', required: false },
      { name: 'sex', type: 'string', description: 'M | F', required: false },
      { name: 'inmateNum', type: 'string', description: 'Register number, e.g. 24965-111 (inmateNumType defaults to IRN)', required: false },
      { name: 'inmateNumType', type: 'string', description: 'IRN | DCDC | FBI | INS', required: false },
    ],
    handler: async (context) => {
      const p = context.parameters as Record<string, string>;
      try {
        const r = await bopInmateSearch({
          lastName: p.lastName, firstName: p.firstName, age: p.age, race: p.race, sex: p.sex,
          inmateNum: p.inmateNum, inmateNumType: p.inmateNumType as BopSearchParams['inmateNumType'],
        });
        return { success: true, output: formatPeopleReport(r, null, null) };
      } catch (e) {
        return { success: false, error: `BOP search failed: ${e instanceof Error ? e.message : String(e)}` };
      }
    },
  },
  {
    name: 'osint_npi_registry_lookup',
    description:
      'Look up a person in the CMS NPI registry — the official US clinician registry (npiregistry.cms.hhs.gov, keyless). Returns NPI numbers, credentials, taxonomy, practice addresses and phones. Use for identifying licensed providers by name.',
    category: 'osint',
    parameters: [
      { name: 'lastName', type: 'string', description: 'Clinician last name (required unless npi is given)', required: false },
      { name: 'firstName', type: 'string', description: 'First name', required: false },
      { name: 'taxonomy', type: 'string', description: 'Taxonomy description filter, e.g. "Clinical Social Worker"', required: false },
      { name: 'state', type: 'string', description: 'Two-letter state filter', required: false },
      { name: 'npi', type: 'string', description: 'Exact NPI number lookup', required: false },
    ],
    handler: async (context) => {
      const p = context.parameters as Record<string, string>;
      try {
        const r = await npiRegistryLookup({ lastName: p.lastName, firstName: p.firstName, taxonomy: p.taxonomy, state: p.state, npi: p.npi });
        return { success: true, output: formatPeopleReport(null, r, null) };
      } catch (e) {
        return { success: false, error: `NPI lookup failed: ${e instanceof Error ? e.message : String(e)}` };
      }
    },
  },
  {
    name: 'osint_people_name_discovery',
    description:
      'Run the search-engine discovery lane for a PERSON\'s full name: quoted-name query plus one scoped query per login-walled platform (LinkedIn, Instagram, Facebook, X, TikTok, Reddit) — the platforms whose direct probes cannot distinguish real profiles from fakes. Returns profile hits (name-corroborated where the name appears), name-directory pages, and web mentions.',
    category: 'osint',
    parameters: [
      { name: 'name', type: 'string', description: 'Subject full name (first + last)', required: true },
      { name: 'budgetMs', type: 'number', description: 'Wall-clock ceiling in ms (default 90000)', required: false },
    ],
    handler: async (context) => {
      const name = String(context.parameters.name || '');
      const budgetMs = Math.max(15_000, Math.min(300_000, Number(context.parameters.budgetMs) || 90_000));
      try {
        const r = await peopleNameDiscovery(name, { deadlineMs: Date.now() + budgetMs });
        return { success: true, output: formatPeopleReport(null, null, r) };
      } catch (e) {
        return { success: false, error: `people discovery failed: ${e instanceof Error ? e.message : String(e)}` };
      }
    },
  },
];

// Re-export for the operator toolkit registries.
export type { OsintSiteCategory };
