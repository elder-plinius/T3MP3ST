// =============================================================================
// AGGRESSIVE PEOPLE-SEARCH DIRECTOR — playbook-driven, LLM-steered, public-source
// only. The model does not "know" current OSINT method (its training is frozen);
// instead it is handed a VERSIONED METHOD PLAYBOOK + the live coverage state and
// picks what to run next. The engine executes the chosen methods, validates
// every result through the existing extractors, and feeds the new coverage back
// for another round until the budget ends or the model stops finding gaps.
//
// Doctrine (unchanged, deliberate): conventional + unconventional METHODS of
// investigation — every public platform, archives, breach/dump lanes the operator
// has keys for, leak-site victim posts, correlation sweeps. NOT dark-web
// credential marketplaces, NOT unauthorized doxing, NOT access-control bypass.
// Findings are evidence for a case, so provenance is kept on every row.
// =============================================================================

import { validateUsername, usernamePermutations } from './osint.js';

/** HARD GUARD: the director may COMBINE known identifiers, but any contact-shaped
 *  token (email / phone / URL) in a proposed query or URL that is NOT already in
 *  the known set is a FABRICATION — refuse the pick outright. Small local models
 *  invent plausible emails; executing those searches poisons the dossier with
 *  invented evidence. The LLM directs; it never supplies the facts. */
export function queryHasUnknownIdentifier(query: string, known: { emails: string[]; phones: string[]; urls: string[]; handles: string[] }): string | null {
  const lowerKnown = [...known.emails, ...known.phones, ...known.urls, ...known.handles].map((k) => String(k).toLowerCase());
  const inKnown = (tok: string) => lowerKnown.some((k) => k === tok || k.includes(tok) || tok.includes(k));
  const emailsInQ = query.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi) || [];
  for (const e of emailsInQ) if (!inKnown(e.toLowerCase())) return 'email ' + e;
  const phonesInQ = query.match(/(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}/g) || [];
  for (const p of phonesInQ) if (!inKnown(p.replace(/\D/g, ''))) return 'phone ' + p;
  const siteHosts = query.match(/(?:site|domain|inurl):([a-z0-9.-]+)/gi) || [];
  for (const s of siteHosts) { const h = s.split(':').slice(1).join(':').toLowerCase(); if (!inKnown(h)) return 'site ' + h; }
  const urlsInQ = query.match(/https?:\/\/[^\s"']+/gi) || [];
  for (const u of urlsInQ) if (!inKnown(u.toLowerCase().replace(/\/$/, ''))) return 'url ' + u;
  return null;
}

export type DirectorMethodId =
  | 'web_search' | 'username_sweep' | 'breach_dump' | 'people_records'
  | 'screening' | 'darkweb_monitor' | 'infostealer' | 'breach_catalog'
  | 'historical' | 'geolocation' | 'associates' | 'contact_page';

export interface PlaybookMethod {
  id: DirectorMethodId;
  name: string;
  needs: ('name' | 'email' | 'username' | 'phone' | 'domain' | 'any')[];
  /** Prompt fragment describing what this method does and when to use it. */
  hint: string;
}

/** Versioned method playbook — the "current methods" surface the planner reads.
 *  Updating OSINT practice = updating THIS array (+ the prompt), not the model. */
export const OSINT_PLAYBOOK: PlaybookMethod[] = [
  { id: 'web_search', name: 'Web search (LLM-planned queries + page fetch/mine)', needs: ['any'],
    hint: 'Search engines + fetch result pages and mine emails/phones/addresses. Use for name+employer, quotes around identifiers, site: operators.' },
  { id: 'contact_page', name: 'Direct contact/profile page fetch', needs: ['any'],
    hint: 'Fetch specific public contact/about/press/profile URLs the model or earlier rounds surfaced. High yield for companies and public figures.' },
  { id: 'username_sweep', name: 'Username enumeration (permuted handles → 490+ platforms)', needs: ['name'],
    hint: 'Generate handle variants from the real name and probe every platform in the catalog. Run when no confirmed handle exists yet.' },
  { id: 'breach_dump', name: 'Breach/dump lanes (LeakCheck/DeHashed/Snusbase + free)', needs: ['email', 'username', 'phone'],
    hint: 'Query breaches per identifier. Free lanes always run; keyed lanes add records. Run whenever a new email/handle/phone appears.' },
  { id: 'infostealer', name: 'Infostealer infections (Hudson Rock)', needs: ['email'],
    hint: 'Live malware infection records for an email — a compromise class dumps miss.' },
  { id: 'breach_catalog', name: 'Breach catalogue by domain (HIBP)', needs: ['domain'],
    hint: 'Was this employer/domain ever breached? Pwn counts + leaked data classes.' },
  { id: 'people_records', name: 'Public people-records (browser-rendered pages)', needs: ['name'],
    hint: 'Age, city, past addresses, relatives, aliases from public records sites. Strong for locating missing persons and skip traces.' },
  { id: 'screening', name: 'Sanctions/watchlist screening (Interpol/OFAC)', needs: ['name'],
    hint: 'Confirm or exclude identity against official watchlists.' },
  { id: 'darkweb_monitor', name: 'Dark-web victim posts (ransomware leak sites)', needs: ['domain'],
    hint: 'Check whether the target org/person appears on ransomware leak sites (public victim posts).' },
  { id: 'historical', name: 'Historical recovery (Wayback archives)', needs: ['any'],
    hint: 'Deleted bios/contact pages via Wayback; old pages leak emails/phones/addresses. Run on any URL already found.' },
  { id: 'geolocation', name: 'Geolocation (public geo signals)', needs: ['any'],
    hint: 'Geocode city/location strings, map social signals. Location narrows people and validates identity claims.' },
  { id: 'associates', name: 'Associates pivot (family/employer/colleagues → back-search)', needs: ['name'],
    hint: 'Mine relatives, employers, colleagues from records/socials, then back-search each as a new lead. The classic missing-persons method.' },
];

export interface DirectorPick {
  method: DirectorMethodId;
  query?: string;
  url?: string;
  username?: string;
  reason?: string;
}
export interface DirectorMethodRun {
  method: DirectorMethodId;
  round: number;
  status: 'ok' | 'skip' | 'error';
  found: number;
  note?: string;
}
export interface AggressiveSearchResult {
  model?: string;
  rounds: number;
  picks: DirectorPick[];
  runs: DirectorMethodRun[];
  /** Contacts discovered by the director (validated) — merge into the dossier. */
  found: { emails: string[]; phones: string[]; addresses: string[]; locations: string[]; handles: string[]; urls: string[] };
  /** Gaps the model still names on its last round (drives the next plan). */
  remainingGaps: string[];
}

export const DIRECTOR_SYSTEM = [
  'You are the DIRECTOR of an aggressive public-source people search (missing-person / skip-trace / fraud OSINT).',
  'You are given a METHOD PLAYBOOK and the current COVERAGE. Choose the next 1-3 methods to run, with concrete parameters, targeting the biggest remaining gaps.',
  'Return ONLY JSON: {"picks":[{"method":"<id>","query":"<optional search string>","url":"<optional public https url>","username":"<optional handle>","reason":"<max 12 words>"}],"gaps":["<what is still missing>"]}',
  'Rules: method MUST be a playbook id. Never re-pick a method that already ran clean with no leads unless you have a new parameter (new query/url/handle). URLs must be public https. Prioritise breadth first, then verification of the strongest leads. No prose.',
].join(' ');

// =============================================================================
// SOCIAL ENGINEERING PRETEXT LAB — scripted pretext/conversation material for
// AUTHORIZED engagements: phishing-simulation campaigns, awareness training, and
// red-team conversation playbooks. The method (cover story → rapport → discovery
// → objection handling → exit) is standard security-industry practice.
//
// Scope discipline, matching the rest of this platform: every request carries an
// explicit authorization reference, the scenario is the RESEARCHER's own words
// (never auto-populated from a located person's dossier), and the output is
// conversation material — no credential-harvesting pages, malware, or payloads.
// =============================================================================

export const SE_CHANNELS = ['email', 'phone', 'sms', 'in_person', 'chat'] as const;
export const SE_OBJECTIVES = ['credential_test', 'data_collection', 'access_badge', 'compliance_test', 'rapport_recon'] as const;
export type SeChannel = (typeof SE_CHANNELS)[number];
export type SeObjective = (typeof SE_OBJECTIVES)[number];

export interface SeScenario {
  channel: SeChannel;
  objective: SeObjective;
  /** Authorization reference (engagement/ticket/approval id + who authorized it). */
  scope: string;
  /** Researcher's own scenario description — free text. */
  scenario: string;
  /** Optional non-identifying context (org type, role archetype, industry). */
  context?: string;
}

export interface PretextScript {
  title: string;
  rationale: string;
  opening: string;
  keyQuestions: string[];
  valueExchange: string;
  objectionHandling: string[];
  callToAction: string;
  channel: SeChannel;
  objective: SeObjective;
}

const OBJECTIVE_BRIEF: Record<SeObjective, string> = {
  credential_test: 'a credential-awareness simulation (test whether the target reports it / hands over a test credential)',
  data_collection: 'collecting non-sensitive business information (org structure, process, tooling) to map the attack surface',
  access_badge: 'a physical-access / tailgating or badge-handling awareness exercise',
  compliance_test: 'a policy-compliance test (e.g. verifying someone honors a stated verification policy)',
  rapport_recon: 'pure rapport-building and open-ended reconnaissance with no ask',
};

export function buildPretextSystemPrompt(s: SeScenario): string {
  return [
    'You are a senior social-engineering specialist who designs AUTHORIZED engagement material for red-team engagements and security-awareness training.',
    `Channel: ${s.channel}. Objective: ${s.objective} — ${OBJECTIVE_BRIEF[s.objective] || s.objective}.`,
    'Produce THREE distinct pretext scripts. Each must follow professional pretext structure: a believable cover story, a natural opening, 2-3 discovery questions that feel like conversation (not interrogation), a value exchange (what the "attacker" offers), handling of 2 likely objections, and a low-pressure call to action or graceful exit.',
    'Rules: write naturally and concisely — a real operator could deliver these verbatim. Keep every claim generic enough to be testable but never target a specific real private individual (this is authorized-simulation material, not a targeting dossier). Do NOT produce credential-harvesting page content, malware, or any technical payload — conversation and messaging only.',
    'Return ONLY JSON: {"scripts":[{"title":"","rationale":"","opening":"","keyQuestions":["",""],"valueExchange":"","objectionHandling":["",""],"callToAction":""}]}',
    'No prose outside the JSON object.',
  ].join(' ');
}

export function buildPretextUserPrompt(s: SeScenario): string {
  return [
    `AUTHORIZATION: ${s.scope}`,
    `CHANNEL: ${s.channel}`,
    `OBJECTIVE: ${s.objective} (${OBJECTIVE_BRIEF[s.objective] || s.objective})`,
    s.context ? `CONTEXT: ${s.context}` : '',
    '',
    'SCENARIO (researcher-supplied):',
    s.scenario,
    '',
    'Produce the three scripts as specified.',
  ].filter(Boolean).join('\n');
}

/** Tolerant parse of the model reply (fenced JSON, leading prose, single object). */
export function parsePretextResponse(raw: string, s: Pick<SeScenario, 'channel' | 'objective'>): PretextScript[] {
  const fenced = raw.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const body = fenced ? fenced[1] : raw;
  const start = body.indexOf('{');
  const end = body.lastIndexOf('}');
  if (start === -1 || end <= start) return [];
  let j: Record<string, unknown>;
  try { j = JSON.parse(body.slice(start, end + 1)) as Record<string, unknown>; } catch { return []; }
  const arr = Array.isArray(j.scripts) ? j.scripts : [];
  const out: PretextScript[] = [];
  for (const item of arr.slice(0, 3)) {
    const o = item as Record<string, unknown>;
    const str = (v: unknown, n = 400) => String(v || '').trim().slice(0, n);
    const list = (v: unknown) => (Array.isArray(v) ? v.map((x) => str(x, 160)).filter(Boolean).slice(0, 4) : []);
    const title = str(o.title, 80);
    const opening = str(o.opening);
    if (!title && !opening) continue;
    out.push({
      title: title || 'Variant ' + (out.length + 1),
      rationale: str(o.rationale, 240),
      opening,
      keyQuestions: list(o.keyQuestions),
      valueExchange: str(o.valueExchange, 300),
      objectionHandling: list(o.objectionHandling),
      callToAction: str(o.callToAction, 240),
      channel: s.channel,
      objective: s.objective,
    });
  }
  return out;
}


export function buildDirectorBrief(input: {
  subject: string; name?: string; email?: string; username?: string; phone?: string; domain?: string;
  known: { emails: string[]; phones: string[]; addresses: string[]; handles: string[]; urls: string[]; accounts: string };
  ran: DirectorMethodRun[];
}): string {
  const playbook = OSINT_PLAYBOOK.map((m) => `- ${m.id} (${m.name}) [needs: ${m.needs.join('|')}]: ${m.hint}`).join('\n');
  const ran = input.ran.length
    ? input.ran.map((r) => `- ${r.method} round ${r.round}: ${r.status}, ${r.found} lead(s)${r.note ? ' — ' + r.note : ''}`).join('\n')
    : '- (nothing yet)';
  return [
    `SUBJECT: ${input.subject}`,
    input.name ? `NAME: ${input.name}` : '',
    input.email ? `EMAIL: ${input.email}` : '',
    input.username ? `USERNAME: ${input.username}` : '',
    input.phone ? `PHONE: ${input.phone}` : '',
    input.domain ? `DOMAIN: ${input.domain}` : '',
    '',
    'KNOWN SO FAR:',
    `emails: ${input.known.emails.join(', ') || 'none'}`,
    `phones: ${input.known.phones.join(', ') || 'none'}`,
    `addresses: ${input.known.addresses.join(', ') || 'none'}`,
    `handles: ${input.known.handles.join(', ') || 'none'}`,
    `urls: ${input.known.urls.slice(0, 10).join(', ') || 'none'}`,
    `accounts: ${input.known.accounts || 'none'}`,
    '',
    'ALREADY RAN:',
    ran,
    '',
    'METHOD PLAYBOOK:',
    playbook,
    '',
    'Pick the next 1-3 methods.',
  ].filter(Boolean).join('\n');
}

/** Tolerant parse of the director pick — method must exist in the playbook. */
export function parseDirectorPicks(raw: string): { picks: DirectorPick[]; gaps: string[] } {
  const fenced = raw.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const body = fenced ? fenced[1] : raw;
  const s = body.indexOf('{'); const e = body.lastIndexOf('}');
  if (s === -1 || e <= s) return { picks: [], gaps: [] };
  let j: Record<string, unknown>;
  try { j = JSON.parse(body.slice(s, e + 1)) as Record<string, unknown>; } catch { return { picks: [], gaps: [] }; }
  const byId = new Map(OSINT_PLAYBOOK.map((m) => [m.id, m]));
  const picks: DirectorPick[] = [];
  // Cap AFTER validation (scan a few extra so one bad pick cannot starve the round).
  for (const item of (Array.isArray(j.picks) ? j.picks : []).slice(0, 8)) {
    const o = item as Record<string, unknown>;
    const method = String(o.method || '') as DirectorMethodId;
    if (!byId.has(method)) continue; // refuse invented methods
    const q = String(o.query || '').replace(/\s+/g, ' ').trim().slice(0, 160);
    const urlRaw = String(o.url || '').trim();
    const safeUrl = /^https?:\/\//i.test(urlRaw) ? urlRaw : undefined; // file://, data:, junk → dropped
    const u = String(o.username || '').trim().slice(0, 40);
    // a pick must carry at least one actionable (validated) parameter
    if (!q && !u && !safeUrl && method !== 'screening' && method !== 'people_records' && method !== 'username_sweep' && method !== 'breach_dump' && method !== 'infostealer' && method !== 'breach_catalog' && method !== 'darkweb_monitor' && method !== 'associates') continue;
    picks.push({
      method,
      query: q || undefined,
      url: safeUrl,
      username: u ? (validateUsername(u) || undefined) : undefined,
      reason: String(o.reason || '').slice(0, 80),
    });
    if (picks.length >= 3) break;
  }
  const gaps = (Array.isArray(j.gaps) ? j.gaps : []).map((g) => String(g).slice(0, 100)).filter(Boolean).slice(0, 6);
  return { picks, gaps };
}

/** Permutation helpers the director can call for a name-only subject. */
export function directorHandleCandidates(name: string): string[] {
  const words = name.trim().split(/\s+/).filter(Boolean);
  if (words.length < 2) return [];
  try { return usernamePermutations(words[0], words[words.length - 1], { max: 8 }); } catch { return []; }
}
