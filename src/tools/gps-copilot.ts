// =============================================================================
// GPS COPILOT — a grounded analyst for the public GPS map
// =============================================================================
// The map screen already answers "what is where". What it cannot do is read the
// whole viewport the way an operator does: "is anything in this view worth my
// time, what is the nearest significant quake to my pin, how far is the ISS".
//
// This module makes that possible WITHOUT letting a language model invent map
// facts. The split is deliberate and is the whole point:
//
//   1. GEOMETRY + FEED AGGREGATION happen here, in TypeScript, from the same
//      cached public feeds the map renders (OpenSky / USGS / NOAA / wheretheiss).
//      Distances, bearings, counts, nearest/biggest — every number is computed
//      deterministically and handed to the model as a finished FACT.
//   2. The local LLM only decides two things: which whitelisted map ACTIONS to
//      run (fly to, toggle a layer, load a satellite group, measure a leg) and
//      how to SAY what the facts mean in prose.
//   3. Every action is validated and clamped here before the browser ever sees
//      it. An unknown action, a bad coordinate or a hostile layer name is
//      dropped, not forwarded.
//
// Consequence: the model can be wrong about tone and miss a nuance, but it
// cannot move the map somewhere impossible, invent a measurement, or smuggle a
// string into the DOM — and the page still works (minus the prose) if the
// local model is down.
//
// Doctrine: same line as public-gps.ts. This copilot reads public environment
// and vehicle broadcasts. It does not locate, track or profile people, and it
// has no telephony positioning to reason about. The prompt states that so the
// model doesn't drift into stalker framing on an unlucky phrasing.

import type { Bbox, GpsFeed, GpsPoint } from './public-gps.js';

// --- action vocabulary ----------------------------------------------------------

export type CopilotActionName =
  | 'answer'          // text only, no map effect
  | 'fly_to'          // { lat, lon, zoom? } — center the map
  | 'search_place'    // { q } — geocode a free-text place, then center
  | 'set_pin'         // { lat, lon } — move the operator pin
  | 'layer'           // { kind, on } — turn a map layer on/off
  | 'satellites'      // { group, limit? } — load a CelesTrak group
  | 'pois'            // { kind, radius? } — query OSM POIs around the pin
  | 'measure'         // { to: "iss" | {lat,lon}, from?: "pin" | {lat,lon} }
  | 'clear_measure'   // remove the measurement line
  | 'auto'            // { on } — 30s auto-refresh

export interface CopilotAction {
  action: CopilotActionName;
  args?: Record<string, unknown>;
  /** True for the leading prose action — rendered as the answer, not executed. */
  say?: string;
  /** Filled by resolveCopilotPlan() for `measure` — deterministic numbers only. */
  result?: CopilotMeasurement;
}

export interface CopilotMeasurement {
  fromLabel: string;
  toLabel: string;
  from: { lat: number; lon: number };
  to: { lat: number; lon: number };
  km: number;
  bearing: number;
  bearingCompass: string;
  /** Sampled great-circle path for drawing the leg on the map. */
  path: Array<[number, number]>;
}

export interface CopilotPlan {
  say: string;
  actions: CopilotAction[];
  /** Set when the model replied with prose the parser could not read as a plan.
   *  The prose is still shown — a local model that chats instead of planning is
   *  a degraded answer, not a failed one. */
  parseFailed: boolean;
}

/** Machine-readable action catalogue. Shipped to the browser for the quick
 *  chips and embedded in the system prompt so the model cannot invent verbs. */
export const COPILOT_ACTIONS: Array<{ action: CopilotActionName; args: string; help: string }> = [
  { action: 'answer', args: '{}', help: 'Explain the view in prose. No map effect.' },
  { action: 'fly_to', args: '{"lat":40.7,"lon":-74.0,"zoom":12}', help: 'Center the map on coordinates.' },
  { action: 'search_place', args: '{"q":"Brooklyn Navy Yard"}', help: 'Geocode a place name, then center there.' },
  { action: 'set_pin', args: '{"lat":40.7,"lon":-74.0}', help: 'Move the operator pin.' },
  { action: 'layer', args: '{"kind":"sat","on":true}', help: 'Toggle a layer: aircraft, sat, quake, alert, iss, poi, tower, app.' },
  { action: 'satellites', args: '{"group":"starlink","limit":200}', help: 'Load a CelesTrak group (visual, stations, starlink, weather, gnss, ...).' },
  { action: 'pois', args: '{"kind":"hospital","radius":1000}', help: 'Load OSM POIs around the pin (cafe, restaurant, fuel, hospital, pharmacy, police, bank, hotel, school, place_of_worship).' },
  { action: 'measure', args: '{"to":"iss"}', help: 'Measure the leg from the pin to the ISS (or to coordinates).' },
  { action: 'clear_measure', args: '{}', help: 'Remove the measurement line.' },
  { action: 'auto', args: '{"on":true}', help: 'Toggle the 30s auto-refresh.' },
];

const LAYER_KINDS = ['aircraft', 'sat', 'quake', 'alert', 'iss', 'poi', 'tower', 'app'] as const;
const SAT_GROUPS_ALLOWED = ['stations', 'visual', 'weather', 'gnss', 'starlink', 'science', 'geo', 'resource', 'education', 'military', 'communication', 'navigation', 'weather', 'last-30-days'];
const POI_KINDS_ALLOWED = ['cafe', 'restaurant', 'fuel', 'hospital', 'pharmacy', 'police', 'bank', 'hotel', 'school', 'place_of_worship'];
const ALERT_SEVERITY_RANK: Record<string, number> = { Extreme: 4, Severe: 3, Moderate: 2, Minor: 1, Unknown: 0 };

// --- geodesy --------------------------------------------------------------------

export interface LatLon { lat: number; lon: number }

const R_KM = 6371.0088;
const rad = (d: number) => (d * Math.PI) / 180;
const deg = (r: number) => (r * 180) / Math.PI;

export function haversineKm(a: LatLon, b: LatLon): number {
  const dLat = rad(b.lat - a.lat);
  const dLon = rad(b.lon - a.lon);
  const s = Math.sin(dLat / 2) ** 2 + Math.cos(rad(a.lat)) * Math.cos(rad(b.lat)) * Math.sin(dLon / 2) ** 2;
  return 2 * R_KM * Math.asin(Math.min(1, Math.sqrt(s)));
}

export function bearingDeg(a: LatLon, b: LatLon): number {
  const y = Math.sin(rad(b.lon - a.lon)) * Math.cos(rad(b.lat));
  const x = Math.cos(rad(a.lat)) * Math.sin(rad(b.lat)) - Math.sin(rad(a.lat)) * Math.cos(rad(b.lat)) * Math.cos(rad(b.lon - a.lon));
  return (deg(Math.atan2(y, x)) + 360) % 360;
}

export function compassPoint(deg0: number): string {
  const pts = ['N', 'NNE', 'NE', 'ENE', 'E', 'ESE', 'SE', 'SSE', 'S', 'SSW', 'SW', 'WSW', 'W', 'WNW', 'NW', 'NNW'];
  return pts[Math.round(((deg0 % 360) + 360) % 360 / 22.5) % 16];
}

/** Sampled great-circle path so the browser can draw the measured leg without
 *  shipping another geodesy implementation to the client. */
export function greatCirclePath(a: LatLon, b: LatLon, samples = 64): Array<[number, number]> {
  const φ1 = rad(a.lat), λ1 = rad(a.lon), φ2 = rad(b.lat), λ2 = rad(b.lon);
  const d = 2 * Math.asin(Math.min(1, Math.sqrt(Math.sin((φ2 - φ1) / 2) ** 2 + Math.cos(φ1) * Math.cos(φ2) * Math.sin((λ2 - λ1) / 2) ** 2)));
  if (!Number.isFinite(d) || d < 1e-9) return [[a.lat, a.lon], [b.lat, b.lon]];
  const out: Array<[number, number]> = [];
  for (let i = 0; i <= samples; i++) {
    const f = i / samples;
    const A = Math.sin((1 - f) * d) / Math.sin(d);
    const B = Math.sin(f * d) / Math.sin(d);
    const x = A * Math.cos(φ1) * Math.cos(λ1) + B * Math.cos(φ2) * Math.cos(λ2);
    const y = A * Math.cos(φ1) * Math.sin(λ1) + B * Math.cos(φ2) * Math.sin(λ2);
    const z = A * Math.sin(φ1) + B * Math.sin(φ2);
    out.push([deg(Math.atan2(z, Math.sqrt(x * x + y * y))), deg(Math.atan2(y, x))]);
  }
  return out;
}

// --- view context ---------------------------------------------------------------

/** What the browser knows about the screen right now (cheap, client-supplied). */
export interface CopilotView {
  bbox?: Bbox | null;
  center?: LatLon | null;
  zoom?: number | null;
  pin?: LatLon | null;
  pinLabel?: string | null;
  layers?: string[] | null;
  satellites?: { group?: string; count?: number } | null;
  pois?: { kind?: string; count?: number } | null;
  towers?: number | null;
}

export interface CopilotFeeds {
  aircraft?: GpsFeed | null;
  quakes?: GpsFeed | null;
  alerts?: GpsFeed | null;
  iss?: GpsFeed | null;
}

/** Everything the copilot is allowed to state as fact. Numbers are computed
 *  here; the model only phrases them. */
export interface CopilotContext {
  view: CopilotView;
  counts: { aircraft: number; quakes: number; alerts: number; iss: number; towers: number; pois: number; satellites: number };
  pins: LatLon | null;
  issFix: LatLon | null;
  quakesInView: GpsPoint[];
  alertsInView: GpsPoint[];
  aircraftSample: GpsPoint[];
  facts: string[];
  notes: string[];
}

function inBbox(b: Bbox | null | undefined, lat: number, lon: number): boolean {
  if (!b) return true;
  return lat >= b.lamin && lat <= b.lamax && lon >= b.lomin && lon <= b.lomax;
}

function km(v: number): string {
  return v >= 100 ? Math.round(v).toLocaleString('en-US') : v.toFixed(1);
}

export function buildCopilotContext(view: CopilotView, feeds: CopilotFeeds): CopilotContext {
  const bbox = view.bbox || null;
  const pin = view.pin && Number.isFinite(view.pin.lat) && Number.isFinite(view.pin.lon) ? { lat: view.pin.lat, lon: view.pin.lon } : null;
  const notes: string[] = [];

  const quakesAll = feeds.quakes?.points || [];
  const alertsAll = feeds.alerts?.points || [];
  const aircraftAll = feeds.aircraft?.points || [];
  const issAll = feeds.iss?.points || [];
  for (const f of [feeds.aircraft, feeds.quakes, feeds.alerts, feeds.iss]) {
    if (f?.note) notes.push(f.note);
  }

  const quakesInView = quakesAll.filter((p) => inBbox(bbox, p.lat, p.lon));
  const alertsInView = alertsAll.filter((p) => inBbox(bbox, p.lat, p.lon));
  const issFix = issAll[0] ? { lat: issAll[0].lat, lon: issAll[0].lon } : null;

  // Nearest quake matters more to an operator than the biggest one on the
  // planet, so rank by distance to the pin when there is one, magnitude otherwise.
  let nearest: { p: GpsPoint; km: number; bearing: number } | null = null;
  let biggest: GpsPoint | null = null;
  for (const p of quakesInView) {
    if (!biggest || (typeof p.mag === 'number' && typeof biggest.mag !== 'number') || ((p.mag ?? -99) > (biggest.mag ?? -99))) biggest = p;
    if (pin) {
      const d = haversineKm(pin, p);
      if (!nearest || d < nearest.km) nearest = { p, km: d, bearing: bearingDeg(pin, p) };
    }
  }
  let nearestNoPin: { p: GpsPoint; km: number; bearing: number } | null = null;
  if (!pin && view.center) {
    const c = { lat: view.center.lat, lon: view.center.lon };
    for (const p of quakesInView) {
      const d = haversineKm(c, p);
      if (!nearestNoPin || d < nearestNoPin.km) nearestNoPin = { p, km: d, bearing: bearingDeg(c, p) };
    }
  }
  const nearestAny = nearest || nearestNoPin;

  const topAlerts = [...alertsInView]
    .sort((a, b) => (severityOf(b) - severityOf(a)))
    .slice(0, 6);

  const counts = {
    aircraft: aircraftAll.length,
    quakes: quakesInView.length,
    alerts: alertsInView.length,
    iss: issFix ? 1 : 0,
    towers: Number(view.towers || 0),
    pois: Number(view.pois?.count || 0),
    satellites: Number(view.satellites?.count || 0),
  };

  const facts: string[] = [];
  facts.push(`Viewport: ${bbox ? `${bbox.lamin}..${bbox.lamin === bbox.lamax ? bbox.lamin : bbox.lamax} lat, ${bbox.lomin}..${bbox.lomax} lon` : 'unknown'}, zoom ${view.zoom ?? '?'}.`);
  if (pin) facts.push(`Operator pin: ${view.pinLabel || 'unnamed place'} at ${pin.lat.toFixed(4)}, ${pin.lon.toFixed(4)}.`);
  else facts.push('Operator pin: not set (the operator has not dropped a pin).');
  facts.push(`Aircraft in view: ${counts.aircraft} (public ADS-B broadcast).`);
  facts.push(`Earthquakes in view (past 24h): ${counts.quakes}.`);
  if (biggest) facts.push(`Strongest quake in view: M${(biggest.mag ?? 0).toFixed(1)} — ${stripLabel(biggest.label)} at ${biggest.lat.toFixed(2)}, ${biggest.lon.toFixed(2)}.`);
  if (nearestAny) {
    facts.push(`Closest quake to ${nearest ? 'the pin' : 'map center'}: M${(nearestAny.p.mag ?? 0).toFixed(1)} — ${stripLabel(nearestAny.p.label)}, ${km(nearestAny.km)} km ${compassPoint(nearestAny.bearing)} (bearing ${Math.round(nearestAny.bearing)}°).`);
  }
  facts.push(`Weather alerts in view: ${counts.alerts}.`);
  for (const a of topAlerts) {
    facts.push(`Alert: ${stripLabel(a.label)} — ${(a.detail || 'no detail').slice(0, 160)}`);
  }
  if (issFix) {
    facts.push(`ISS live fix: ${issFix.lat.toFixed(2)}, ${issFix.lon.toFixed(2)}${issAll[0]?.detail ? ` (${issAll[0].detail})` : ''}.`);
    if (pin) {
      const d = haversineKm(pin, issFix);
      facts.push(`Pin-to-ISS great-circle distance: ${km(d)} km on bearing ${Math.round(bearingDeg(pin, issFix))}° (${compassPoint(bearingDeg(pin, issFix))}).`);
    }
  } else {
    facts.push('ISS: no live fix available right now.');
  }
  if (counts.satellites) facts.push(`Satellites loaded: ${view.satellites?.group || '?'} group, ${counts.satellites} plotted.`);
  if (counts.pois) facts.push(`POIs loaded at pin: ${view.pois?.kind || '?'}, ${counts.pois} within the last query radius.`);
  if (counts.towers) facts.push(`Cell-tower SITES in view: ${counts.towers} (antenna registry positions only — no device association).`);
  if (notes.length) facts.push(`Feed caveats: ${[...new Set(notes)].join(' | ')}`);

  const aircraftSample = [...aircraftAll].sort((a, b) => (b.velocity || 0) - (a.velocity || 0)).slice(0, 5);

  return { view, counts, pins: pin, issFix, quakesInView, alertsInView, aircraftSample, facts, notes: [...new Set(notes)] };
}

function severityOf(p: GpsPoint): number {
  const m = String(p.detail || '').match(/\b(Extreme|Severe|Moderate|Minor|Unknown)\b/);
  return m ? ALERT_SEVERITY_RANK[m[1]] ?? 0 : 0;
}

function stripLabel(label: string): string {
  return String(label || '').replace(/^[^\w[(]+/, '').trim();
}

// --- prompt ---------------------------------------------------------------------

export type CopilotMode = 'auto' | 'brief' | 'command' | 'ask';

const DOCTRINE = [
  'This screen maps PUBLIC environment and vehicle broadcasts: aircraft ADS-B, earthquake epicenters,',
  'weather-alert polygons, the ISS, public satellites, OpenStreetMap places, and cell-tower SITE positions.',
  'It does not track, locate or profile people, and there is no device or phone positioning here.',
  'If an operator asks you to find or follow a person, say plainly that this screen cannot do that and point to the OSINT Locator for lawful public-digital-footprint work.',
].join(' ');

const MODE_BRIEF = [
  'TASK: write the operator\'s situation briefing for this viewport.',
  'Rules: 3-6 short lines, plain text, no markdown headers, no invented numbers.',
  'Lead with anything time-critical (severe alerts, strong or close quakes), then the rest, then one concrete next action the operator could take on this map.',
  'Do not repeat the raw fact list verbatim — interpret it.',
].join('\n');

const MODE_COMMAND = [
  'TASK: turn the operator\'s request into map actions.',
  'Rules: emit the actions needed, nothing decorative. If the request needs no map change, emit a single "answer" action carrying the reply.',
].join('\n');

const MODE_ASK = [
  'TASK: answer the operator\'s question from the FACTS block only.',
  'Rules: if the facts do not contain the answer, say exactly what is missing and what feed or action would produce it. Never estimate a number that is not in FACTS.',
].join('\n');

const MODE_AUTO = [
  'TASK: decide what the operator wants. They may be asking a question, asking for a briefing, or asking for the map to move.',
  'Rules: when the request implies movement or a layer change, emit the action. When it implies understanding, answer in prose. Often both: actions first, then "answer".',
].join('\n');

export function buildCopilotSystemPrompt(ctx: CopilotContext, mode: CopilotMode = 'auto'): string {
  const modeBlock = mode === 'brief' ? MODE_BRIEF : mode === 'command' ? MODE_COMMAND : mode === 'ask' ? MODE_ASK : MODE_AUTO;
  const enabled = (ctx.view.layers || []).join(', ') || 'none reported';
  return [
    'You are the map copilot inside T3MP3ST, a security operator console. You talk to an operator looking at a live public-data map.',
    'Answer ONLY as the map copilot. Do not mention or role-play any other identity or system you may have been told about.',
    '',
    'GROUNDING RULES (these are absolute):',
    '- Every number, name, coordinate and event you state must come from the FACTS block below. They are computed from the live feeds; you do not calculate distances, magnitudes or bearings yourself.',
    '- If something is not in FACTS, say it is not available and name the feed that would supply it. Do not guess, extrapolate, or use your own knowledge of a place as if it were live map data.',
    '- Keep answers short: an operator is reading a map, not an essay. No markdown headers. Bullets are fine.',
    '- You may only use the actions listed below. There is no other way to change the map.',
    '',
    DOCTRINE,
    '',
    `MODE: ${mode}`,
    modeBlock,
    '',
    'AVAILABLE ACTIONS (JSON only):',
    ...COPILOT_ACTIONS.map((a) => `- ${a.action} ${a.args} — ${a.help}`),
    '',
    'RESPONSE FORMAT — reply with ONE JSON object and nothing else:',
    '{"say":"<your answer to the operator, 1-4 sentences of plain text>","actions":[{"action":"fly_to","args":{"lat":40.7,"lon":-74.0,"zoom":12}}]}',
    'Include an action only when it changes something. Every action needs "action" and "args".',
    '',
    `CURRENT SCREEN — enabled layers: ${enabled}.`,
    'FACTS (computed from the live feeds, authoritative):',
    ...ctx.facts.map((f) => `- ${f}`),
  ].join('\n');
}

export function buildCopilotUserPrompt(prompt: string): string {
  return String(prompt || '').trim() || 'Give me the situation briefing for this view.';
}

// --- reply parsing ---------------------------------------------------------------

/** Find the first balanced JSON object/array in the text, ignoring braces inside
 *  strings. Local models wrap JSON in prose and fences more often than not. */
export function extractJsonBlob(raw: string): string | null {
  const s = String(raw || '');
  const start = s.search(/[[{]/);
  if (start < 0) return null;
  const open = s[start];
  const close = open === '{' ? '}' : ']';
  let depth = 0;
  let inStr = false;
  let esc = false;
  for (let i = start; i < s.length; i++) {
    const ch = s[i];
    if (inStr) {
      if (esc) esc = false;
      else if (ch === '\\') esc = true;
      else if (ch === '"') inStr = false;
      continue;
    }
    if (ch === '"') { inStr = true; continue; }
    if (ch === open) depth++;
    else if (ch === close) {
      depth--;
      if (depth === 0) return s.slice(start, i + 1);
    }
  }
  // Truncated generation (hit maxTokens mid-object): salvage the longest prefix
  // that still parses by closing what is open.
  return null;
}

function coerceNumber(v: unknown): number | null {
  const n = typeof v === 'number' ? v : parseFloat(String(v ?? ''));
  return Number.isFinite(n) ? n : null;
}

function coerceLatLon(v: unknown): LatLon | null {
  if (!v || typeof v !== 'object') return null;
  const o = v as Record<string, unknown>;
  const lat = coerceNumber(o.lat);
  const lon = coerceNumber(o.lon);
  if (lat === null || lon === null) return null;
  if (Math.abs(lat) > 90 || Math.abs(lon) > 180) return null;
  return { lat: +lat.toFixed(5), lon: +lon.toFixed(5) };
}

/** Validate + clamp ONE model-proposed action. Returns null for anything not in
 *  the vocabulary or with unusable args — an unexecutable instruction is dropped
 *  rather than half-run. */
export function validateCopilotAction(raw: unknown): CopilotAction | null {
  if (!raw || typeof raw !== 'object') return null;
  const o = raw as Record<string, unknown>;
  const name = String(o.action || o.verb || '').trim().toLowerCase();
  const a = (o.args && typeof o.args === 'object' ? o.args : o) as Record<string, unknown>;

  switch (name) {
    case 'answer': {
      const say = String(a.say || a.text || o.say || o.text || '').trim().slice(0, 4000);
      return say ? { action: 'answer', say, args: {} } : null;
    }
    case 'fly_to': {
      const ll = coerceLatLon(a) || coerceLatLon({ lat: a.latitude, lon: a.longitude });
      if (!ll) return null;
      const zoom = coerceNumber(a.zoom);
      return { action: 'fly_to', args: { ...ll, zoom: zoom === null ? 11 : Math.max(1, Math.min(18, Math.round(zoom))) } };
    }
    case 'search_place': {
      const q = String(a.q || a.place || a.name || '').trim().slice(0, 120);
      return q ? { action: 'search_place', args: { q } } : null;
    }
    case 'set_pin': {
      const ll = coerceLatLon(a);
      return ll ? { action: 'set_pin', args: { lat: ll.lat, lon: ll.lon } } : null;
    }
    case 'layer': {
      const kind = String(a.kind || a.layer || '').trim().toLowerCase();
      if (!(LAYER_KINDS as readonly string[]).includes(kind)) return null;
      const onRaw = a.on !== undefined ? a.on : a.enabled;
      const on = onRaw === undefined ? true : !(/^(false|0|off|no)$/i.test(String(onRaw)));
      return { action: 'layer', args: { kind, on } };
    }
    case 'satellites': {
      const group = String(a.group || '').trim().toLowerCase();
      if (!SAT_GROUPS_ALLOWED.includes(group)) return null;
      const limit = coerceNumber(a.limit);
      return { action: 'satellites', args: { group, limit: limit === null ? 200 : Math.max(10, Math.min(500, Math.round(limit))) } };
    }
    case 'pois': {
      const kind = String(a.kind || '').trim().toLowerCase();
      if (!POI_KINDS_ALLOWED.includes(kind)) return null;
      const radius = coerceNumber(a.radius);
      return { action: 'pois', args: { kind, radius: radius === null ? 500 : Math.max(50, Math.min(2000, Math.round(radius))) } };
    }
    case 'measure': {
      const toRaw = a.to === undefined ? 'iss' : a.to;
      if (toRaw === 'iss' || toRaw === undefined || toRaw === null || String(toRaw).toLowerCase() === 'iss') {
        return { action: 'measure', args: { to: 'iss' } };
      }
      const ll = coerceLatLon(toRaw);
      return ll ? { action: 'measure', args: { to: ll } } : null;
    }
    case 'clear_measure':
      return { action: 'clear_measure', args: {} };
    case 'auto': {
      const onRaw = a.on !== undefined ? a.on : a.enabled;
      return { action: 'auto', args: { on: onRaw === undefined ? true : !(/^(false|0|off|no)$/i.test(String(onRaw))) } };
    }
    default:
      return null;
  }
}

/** Parse a raw model reply into a plan. Tolerates fences, leading prose and a
 *  bare action array; degrades to prose-only when nothing parses. */
export function parseCopilotReply(raw: string): CopilotPlan {
  const text = String(raw || '').trim();
  if (!text) return { say: '', actions: [], parseFailed: true };

  const blob = extractJsonBlob(text);
  if (!blob) return { say: stripFences(text), actions: [], parseFailed: true };

  let parsed: unknown;
  try {
    parsed = JSON.parse(blob);
  } catch {
    return { say: stripFences(text), actions: [], parseFailed: true };
  }

  const obj = (Array.isArray(parsed) ? { actions: parsed } : parsed) as Record<string, unknown>;
  const say = String(obj.say ?? obj.answer ?? obj.reply ?? obj.text ?? '').trim().slice(0, 4000);
  const list = Array.isArray(obj.actions) ? obj.actions : Array.isArray(obj.plan) ? obj.plan : [];
  const actions = list.map(validateCopilotAction).filter((a): a is CopilotAction => a !== null);
  const inlineSay = actions.find((a) => a.action === 'answer')?.say;
  return { say: say || inlineSay || '', actions: actions.filter((a) => a.action !== 'answer'), parseFailed: false };
}

function stripFences(s: string): string {
  return s.replace(/^\s*```(?:json)?\s*/i, '').replace(/```\s*$/, '').trim();
}

/** Fill the deterministic half of a `measure` action now that the live ISS fix
 *  and the operator pin are known. Runs AFTER parsing, never inside the model. */
export function resolveCopilotPlan(plan: CopilotPlan, ctx: { pin: LatLon | null; iss: LatLon | null; center?: LatLon | null; pinLabel?: string | null }): CopilotPlan {
  const actions: CopilotAction[] = [];
  for (const act of plan.actions) {
    if (act.action !== 'measure') { actions.push(act); continue; }
    const from = ctx.pin || ctx.center || null;
    const to = act.args?.to === 'iss' ? ctx.iss : (act.args?.to as LatLon | undefined);
    if (!from || !to || typeof to !== 'object') continue; // nothing to measure against — drop it
    const kmd = haversineKm(from, to);
    const brg = bearingDeg(from, to);
    actions.push({
      ...act,
      result: {
        from,
        to,
        km: +kmd.toFixed(1),
        bearing: Math.round(brg),
        bearingCompass: compassPoint(brg),
        path: greatCirclePath(from, to),
        fromLabel: ctx.pin ? (ctx.pinLabel || 'operator pin') : 'map center',
        toLabel: act.args?.to === 'iss' ? 'ISS' : `${(act.args?.to as LatLon).lat.toFixed(3)}, ${(act.args?.to as LatLon).lon.toFixed(3)}`,
      },
    });
  }
  return { ...plan, actions };
}
