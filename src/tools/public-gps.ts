// =============================================================================
// PUBLIC GPS FEEDS — keyless open-geodata screen engine
// =============================================================================
// Aggregates PUBLIC environment/vehicle position broadcasts onto one map screen:
//   - Aircraft ADS-B positions (OpenSky Network anonymous API — public flight
//     broadcast data, the same feed aviation trackers render)
//   - USGS earthquakes (past 24h, global GeoJSON)
//   - NOAA active weather alerts (US, public NWS API)
//   - ISS live position (wheretheiss.at — the most public GPS point in orbit)
//   - Public satellites from CelesTrak GP TLE + SGP4 (stations/visual/weather/GNSS/Starlink/every group)
//   - OSM POIs around a pin (Overpass API — keyless OpenStreetMap data)
//   - Cell-tower site locations (OpenCelliD getInArea — key-gated free tier,
//     T3MP3ST_OPENCELLID_KEY; maps TOWER INFRASTRUCTURE, not devices)
//   - Reverse geocoding for the operator's map pin (Nominatim /reverse)
// Every source is keyless. This layer maps VEHICLES, PHENOMENA and PLACES — it
// does not and will not resolve, fuse or track individual people. Person work
// stays in the OSINT Locator (public digital footprint) and nowhere else.

export interface GpsPoint {
  id: string;
  kind: 'aircraft' | 'quake' | 'alert' | 'iss' | 'poi' | 'tower' | 'sat';
  label: string;
  lat: number;
  lon: number;
  detail?: string;
  /** Emoji the UI renders as the map marker (when set; aircraft/quakes use vector markers instead). */
  icon?: string;
  /** Aircraft true track in degrees (0 = north) — the UI rotates the plane glyph by it. */
  heading?: number;
  /** Ground velocity in m/s (from ADS-B) — the UI extrapolates the glyph between pings. */
  velocity?: number;
  /** Earthquake magnitude — the UI scales the marker radius and color by it. */
  mag?: number;
}

export interface GpsFeed {
  source: string;
  fetchedAt: number;
  points: GpsPoint[];
  note?: string;
}

import { directFetch } from '../net/proxy.js';
import * as satellite from 'satellite.js';

type FetchLike = (url: string, init?: Record<string, unknown>) => Promise<{ ok: boolean; status: number; json: () => Promise<unknown>; text: () => Promise<string> }>;
const defaultFetch: FetchLike = (url, init) => directFetch(url as any, init as any) as unknown as ReturnType<FetchLike>;

async function fetchJson<T>(url: string, opts: { fetcher?: FetchLike; timeoutMs?: number; headers?: Record<string, string>; method?: string; body?: string } = {}): Promise<T> {
  const f = opts.fetcher || defaultFetch;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), opts.timeoutMs ?? 12_000);
  try {
    const r = await f(url, {
      method: opts.method || 'GET',
      headers: { ...(opts.headers || {}) },
      signal: ctrl.signal,
      ...(opts.body ? { body: opts.body } : {}),
    } as never);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return (await r.json()) as T;
  } finally {
    clearTimeout(timer);
  }
}

async function fetchText(url: string, opts: { fetcher?: FetchLike; timeoutMs?: number; headers?: Record<string, string> } = {}): Promise<string> {
  const f = opts.fetcher || defaultFetch;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), opts.timeoutMs ?? 20_000);
  try {
    const r = await f(url, { headers: { ...(opts.headers || {}) }, signal: ctrl.signal } as never);
    if (!r.ok) {
      let body = '';
      try { body = await r.text(); } catch { /* body stays empty — the status alone is the signal */ }
      const snippet = body ? ` — ${body.slice(0, 140).replace(/\s+/g, ' ')}` : '';
      throw new Error(`HTTP ${r.status}${snippet}`);
    }
    return await r.text();
  } finally {
    clearTimeout(timer);
  }
}

// --- bbox helpers -------------------------------------------------------------

export interface Bbox { lamin: number; lomin: number; lamax: number; lomax: number }

/** Parse + clamp an operator/browser-supplied bbox. Anonymous OpenSky is a shared
 *  free tier — spans are capped at 10° per axis so the screen stays a polite client. */
export function buildBbox(lamin: unknown, lomin: unknown, lamax: unknown, lomax: unknown): Bbox | null {
  const n = [lamin, lomin, lamax, lomax].map((v) => typeof v === 'number' ? v : parseFloat(String(v ?? '')));
  if (n.some((v) => !Number.isFinite(v))) return null;
  let [s, w, nn, e] = n;
  if (s > nn) [s, nn] = [nn, s];
  if (w > e) [w, e] = [e, w];
  s = Math.max(-90, Math.min(90, s)); nn = Math.max(-90, Math.min(90, nn));
  w = Math.max(-180, Math.min(180, w)); e = Math.max(-180, Math.min(180, e));
  if (nn - s > 10) nn = s + 10;
  if (e - w > 10) e = w + 10;
  if (nn - s < 0.01 || e - w < 0.01) return null;
  return { lamin: +s.toFixed(4), lomin: +w.toFixed(4), lamax: +nn.toFixed(4), lomax: +e.toFixed(4) };
}

export function bboxOverlaps(b: Bbox, lat: number, lon: number): boolean {
  return lat >= b.lamin && lat <= b.lamax && lon >= b.lomin && lon <= b.lomax;
}

// --- OpenSky aircraft (ADS-B broadcast) ----------------------------------------

// OpenSky state vector: [icao24, callsign, origin_country, time_position,
// last_contact, longitude, latitude, baro_altitude, on_ground, velocity,
// true_track, vertical_rate, sensors, geo_altitude, squawk, spi, position_source]
type OpenSkyState = (string | number | boolean | null | number[])[];

export function parseOpenSkyStates(states: OpenSkyState[], bbox?: Bbox, cap = 300): GpsPoint[] {
  const out: GpsPoint[] = [];
  for (const s of Array.isArray(states) ? states : []) {
    const lon = typeof s[5] === 'number' ? (s[5] as number) : null;
    const lat = typeof s[6] === 'number' ? (s[6] as number) : null;
    if (lat === null || lon === null || Number.isNaN(lat) || Number.isNaN(lon)) continue;
    if (bbox && !bboxOverlaps(bbox, lat, lon)) continue;
    const icao = String(s[0] || '').trim();
    const callsign = String(s[1] || '').trim() || icao;
    const country = String(s[2] || '').trim();
    const alt = typeof s[13] === 'number' ? (s[13] as number) : (typeof s[7] === 'number' ? (s[7] as number) : null);
    const vel = typeof s[9] === 'number' ? (s[9] as number) : null;
    const trk = typeof s[10] === 'number' ? (s[10] as number) : null;
    const onGround = s[8] === true;
    out.push({
      id: `aircraft:${icao}`,
      kind: 'aircraft',
      label: `✈ ${callsign}`,
      lat, lon,
      heading: trk ?? undefined,
      velocity: vel ?? undefined,
      detail: [
        country ? `Origin: ${country}` : null,
        alt !== null ? `Alt: ${Math.round(alt)} m` : null,
        vel !== null ? `Speed: ${Math.round(vel * 3.6)} km/h` : null,
        trk !== null ? `Track: ${Math.round(trk)}°` : null,
        onGround ? 'ON GROUND' : 'airborne',
      ].filter(Boolean).join(' · '),
    });
    if (out.length >= cap) break;
  }
  return out;
}

interface OpenSkyResponse { time?: number; states?: OpenSkyState[] }

const aircraftCache = new Map<string, { at: number; feed: GpsFeed }>();

export async function fetchAircraft(bbox: Bbox, opts: { fetcher?: FetchLike; refresh?: boolean } = {}): Promise<GpsFeed> {
  const key = `${bbox.lamin},${bbox.lomin},${bbox.lamax},${bbox.lomax}`;
  const hit = aircraftCache.get(key);
  if (hit && !opts.refresh && Date.now() - hit.at < 45_000) return hit.feed;
  const url = `https://opensky-network.org/api/states/all?lamin=${bbox.lamin}&lomin=${bbox.lomin}&lamax=${bbox.lamax}&lomax=${bbox.lomax}`;
  try {
    const j = await fetchJson<OpenSkyResponse>(url, { fetcher: opts.fetcher, timeoutMs: 15_000 });
    const points = parseOpenSkyStates(j.states || [], bbox);
    const feed: GpsFeed = { source: 'OpenSky Network (ADS-B)', fetchedAt: Date.now(), points };
    aircraftCache.set(key, { at: Date.now(), feed });
    return feed;
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'network error';
    const note = /HTTP 429/.test(msg)
      ? 'rate-limited by OpenSky (shared anonymous tier) — retry in a minute'
      : /HTTP 50[23]/.test(msg) ? 'OpenSky temporarily unavailable' : `fetch failed: ${msg.slice(0, 80)}`;
    if (hit) return { ...hit.feed, note };
    return { source: 'OpenSky Network (ADS-B)', fetchedAt: Date.now(), points: [], note };
  }
}

// --- USGS earthquakes -----------------------------------------------------------

interface UsgsFeature { properties?: { mag?: number | null; place?: string | null; time?: number | null; url?: string | null }; geometry?: { coordinates?: [number, number, number] } }

export function parseUsgsQuakes(fc: { features?: UsgsFeature[] }, bbox?: Bbox, cap = 400): GpsPoint[] {
  const out: GpsPoint[] = [];
  for (const f of Array.isArray(fc.features) ? fc.features : []) {
    const c = f.geometry?.coordinates;
    if (!c || typeof c[0] !== 'number' || typeof c[1] !== 'number') continue;
    const [lon, lat, depth] = c;
    if (bbox && !bboxOverlaps(bbox, lat, lon)) continue;
    const mag = typeof f.properties?.mag === 'number' ? f.properties.mag : null;
    const when = typeof f.properties?.time === 'number' ? new Date(f.properties.time).toISOString().replace('T', ' ').slice(0, 16) + ' UTC' : null;
    out.push({
      id: `quake:${f.properties?.url || `${lat},${lon},${when}`}`,
      kind: 'quake',
      label: `🌍 M${mag !== null ? mag.toFixed(1) : '?'} ${f.properties?.place || 'unknown area'}`,
      lat, lon,
      mag: mag ?? undefined,
      detail: [when, depth !== undefined ? `Depth: ${Math.round(depth)} km` : null].filter(Boolean).join(' · '),
    });
    if (out.length >= cap) break;
  }
  return out;
}

const quakeCache = { at: 0, feed: null as GpsFeed | null };

export async function fetchEarthquakes(opts: { fetcher?: FetchLike; refresh?: boolean } = {}): Promise<GpsFeed> {
  if (quakeCache.feed && !opts.refresh && Date.now() - quakeCache.at < 120_000) return quakeCache.feed;
  try {
    const j = await fetchJson<{ features?: UsgsFeature[] }>(
      'https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/all_day.geojson',
      { fetcher: opts.fetcher, timeoutMs: 15_000 }
    );
    const feed: GpsFeed = { source: 'USGS (past 24h)', fetchedAt: Date.now(), points: parseUsgsQuakes(j) };
    quakeCache.at = Date.now(); quakeCache.feed = feed;
    return feed;
  } catch (e) {
    const note = `USGS feed unavailable: ${(e instanceof Error ? e.message : 'network error').slice(0, 80)}`;
    if (quakeCache.feed) return { ...quakeCache.feed, note };
    return { source: 'USGS (past 24h)', fetchedAt: Date.now(), points: [], note };
  }
}

// --- NOAA active weather alerts --------------------------------------------------

interface NoaaFeature { properties?: { event?: string; severity?: string; areaDesc?: string; headline?: string }; geometry?: unknown }

export function parseNoaaAlerts(fc: { features?: NoaaFeature[] }, bbox?: Bbox, cap = 200): GpsPoint[] {
  const out: GpsPoint[] = [];
  for (const f of Array.isArray(fc.features) ? fc.features : []) {
    const p = f.properties || {};
    const event = String(p.event || 'Weather alert');
    // NOAA alert geometry is a polygon (or zone refs without geometry). Polygon
    // centroids are cheap and good enough to place an alert pin on the map.
    const centroid = polygonCentroid(f.geometry);
    if (centroid) {
      if (bbox && !bboxOverlaps(bbox, centroid.lat, centroid.lon)) continue;
      out.push({
        id: `alert:${event}:${p.areaDesc || out.length}`,
        kind: 'alert',
        label: `⚠ ${event}`,
        lat: centroid.lat, lon: centroid.lon,
        icon: '⚠️',
        detail: [p.severity, p.areaDesc, p.headline].filter(Boolean).join(' · ').slice(0, 300),
      });
    }
    if (out.length >= cap) break;
  }
  return out;
}

export function polygonCentroid(geom: unknown): { lat: number; lon: number } | null {
  const g = geom as { type?: string; coordinates?: unknown } | null | undefined;
  if (!g || typeof g.type !== 'string') return null;
  let rings: number[][][] = [];
  if (g.type === 'Polygon') rings = (g.coordinates as number[][][]) || [];
  else if (g.type === 'MultiPolygon') {
    for (const poly of ((g.coordinates as number[][][][]) || [])) rings.push(poly[0]);
  } else return null;
  let sx = 0, sy = 0, n = 0;
  for (const ring of rings) {
    const pts = (ring || []).filter((pt) => Array.isArray(pt) && typeof pt[0] === 'number' && typeof pt[1] === 'number');
    // Skip the closing vertex — rings repeat their first point at the end, and
    // counting it twice skews the centroid toward the start corner.
    if (pts.length > 1) {
      const first = pts[0], last = pts[pts.length - 1];
      if (first[0] === last[0] && first[1] === last[1]) pts.pop();
    }
    for (const pt of pts) { sx += pt[0]; sy += pt[1]; n++; }
  }
  if (!n) return null;
  return { lon: +(sx / n).toFixed(4), lat: +(sy / n).toFixed(4) };
}

const alertsCache = { at: 0, feed: null as GpsFeed | null };

export async function fetchWeatherAlerts(opts: { fetcher?: FetchLike; refresh?: boolean } = {}): Promise<GpsFeed> {
  if (alertsCache.feed && !opts.refresh && Date.now() - alertsCache.at < 120_000) return alertsCache.feed;
  try {
    const j = await fetchJson<{ features?: NoaaFeature[] }>(
      // NOTE: no `limit` parameter. api.weather.gov rejects the whole request with
      // HTTP 400 ("Query parameter \"limit\" is not recognized") when it is present,
      // which is what silently killed the weather-alerts layer: the route reported
      // an honest note but the map had been showing ZERO alerts for every operator.
      // Volume is bounded by the parser cap instead (below), not by the API.
      'https://api.weather.gov/alerts/active?status=actual&message_type=alert',
      { fetcher: opts.fetcher, timeoutMs: 15_000, headers: { 'user-agent': 'T3MP3ST-PublicGPS/1.0 (security testing platform)' } }
    );
    const feed: GpsFeed = { source: 'NOAA/NWS active alerts (US)', fetchedAt: Date.now(), points: parseNoaaAlerts(j) };
    alertsCache.at = Date.now(); alertsCache.feed = feed;
    return feed;
  } catch (e) {
    const note = `NWS feed unavailable: ${(e instanceof Error ? e.message : 'network error').slice(0, 80)}`;
    if (alertsCache.feed) return { ...alertsCache.feed, note };
    return { source: 'NOAA/NWS active alerts (US)', fetchedAt: Date.now(), points: [], note };
  }
}

// --- ISS live position -----------------------------------------------------------

interface IssResponse { latitude?: number; longitude?: number; altitude?: number; velocity?: number }

const issCache = { at: 0, feed: null as GpsFeed | null };

export async function fetchIss(opts: { fetcher?: FetchLike; refresh?: boolean } = {}): Promise<GpsFeed> {
  if (issCache.feed && !opts.refresh && Date.now() - issCache.at < 15_000) return issCache.feed;
  try {
    const j = await fetchJson<IssResponse>('https://api.wheretheiss.at/v1/satellites/25544', { fetcher: opts.fetcher, timeoutMs: 10_000 });
    if (typeof j.latitude !== 'number' || typeof j.longitude !== 'number') throw new Error('no position in response');
    const feed: GpsFeed = {
      source: 'wheretheiss.at',
      fetchedAt: Date.now(),
      points: [{
        id: 'iss', kind: 'iss',
        label: '🛰 ISS (Zarya)',
        lat: j.latitude, lon: j.longitude,
        icon: '🛰️',
        detail: [
          j.altitude !== undefined ? `Alt: ${Math.round(j.altitude)} km` : null,
          j.velocity !== undefined ? `${Math.round(j.velocity)} km/h` : null,
        ].filter(Boolean).join(' · '),
      }],
    };
    issCache.at = Date.now(); issCache.feed = feed;
    return feed;
  } catch (e) {
    const note = `ISS feed unavailable: ${(e instanceof Error ? e.message : 'network error').slice(0, 80)}`;
    if (issCache.feed) return { ...issCache.feed, note };
    return { source: 'wheretheiss.at', fetchedAt: Date.now(), points: [], note };
  }
}

// --- Reverse geocoding (pin → place name, Nominatim) ------------------------------

interface NominatimReverse { display_name?: string; address?: Record<string, string>; type?: string }

const reverseCache = new Map<string, { label: string; address: Record<string, string> } | null>();
const reverseLastCall = { at: 0 };

/** Nominatim /reverse for the operator's own map pin. 1 req/s throttle + process-
 *  lifetime cache per the usage policy. Returns null (cached) when nothing resolves. */
export async function reverseGeocode(lat: number, lon: number, opts: { fetcher?: FetchLike } = {}): Promise<{ label: string; address: Record<string, string> } | null> {
  if (!Number.isFinite(lat) || !Number.isFinite(lon) || Math.abs(lat) > 90 || Math.abs(lon) > 180) return null;
  const key = `${lat.toFixed(4)},${lon.toFixed(4)}`;
  if (reverseCache.has(key)) return reverseCache.get(key) ?? null;
  const wait = 1100 - (Date.now() - reverseLastCall.at);
  if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  reverseLastCall.at = Date.now();
  try {
    const j = await fetchJson<NominatimReverse>(
      `https://nominatim.openstreetmap.org/reverse?lat=${lat}&lon=${lon}&format=jsonv2&zoom=14`,
      { fetcher: opts.fetcher, timeoutMs: 10_000, headers: { 'user-agent': 'T3MP3ST-PublicGPS/1.0 (security testing platform)' } }
    );
    const hit = j.display_name ? { label: j.display_name, address: j.address || {} } : null;
    reverseCache.set(key, hit);
    return hit;
  } catch {
    reverseCache.set(key, null);
    return null;
  }
}

// --- OSM POIs around the pin (Overpass) --------------------------------------------

export const POI_KINDS = ['cafe', 'restaurant', 'fuel', 'hospital', 'pharmacy', 'police', 'bank', 'hotel', 'school', 'place_of_worship'] as const;
export type PoiKind = (typeof POI_KINDS)[number];

export function isPoiKind(k: unknown): k is PoiKind {
  return typeof k === 'string' && (POI_KINDS as readonly string[]).includes(k);
}

export function overpassQuery(lat: number, lon: number, radiusM: number, kind: PoiKind): string {
  const r = Math.max(50, Math.min(2000, Math.round(radiusM || 500)));
  return `[out:json][timeout:20];node(around:${r},${lat},${lon})[amenity=${kind}];out 50;`;
}

/** Per-amenity marker glyphs — the map should read like a map, not a dot grid. */
export const POI_ICONS: Record<PoiKind, string> = {
  cafe: '☕',
  restaurant: '🍴',
  fuel: '⛽',
  hospital: '🏥',
  pharmacy: '💊',
  police: '🚓',
  bank: '🏦',
  hotel: '🏨',
  school: '🏫',
  place_of_worship: '🛐',
};

interface OverpassElement { type?: string; id?: number; lat?: number; lon?: number; tags?: { name?: string; [k: string]: string | undefined } }

const poiCache = new Map<string, { at: number; feed: GpsFeed }>();
const poiLastCall = { at: 0 };

export async function fetchPois(lat: number, lon: number, radiusM: number, kind: PoiKind, opts: { fetcher?: FetchLike; refresh?: boolean } = {}): Promise<GpsFeed> {
  if (!Number.isFinite(lat) || !Number.isFinite(lon)) return { source: 'OpenStreetMap (Overpass)', fetchedAt: Date.now(), points: [], note: 'invalid pin coordinates' };
  const key = `${lat.toFixed(4)},${lon.toFixed(4)},${Math.round(radiusM)},${kind}`;
  const hit = poiCache.get(key);
  if (hit && !opts.refresh && Date.now() - hit.at < 600_000) return hit.feed;
  // Overpass etiquette: space out calls a few seconds.
  const wait = 3000 - (Date.now() - poiLastCall.at);
  if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  poiLastCall.at = Date.now();
  try {
    const f = opts.fetcher || defaultFetch;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 25_000);
    let json: { elements?: OverpassElement[] };
    try {
      const r = await f('https://overpass-api.de/api/interpreter', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', 'user-agent': 'T3MP3ST-PublicGPS/1.0' },
        body: `data=${encodeURIComponent(overpassQuery(lat, lon, radiusM, kind))}`,
        signal: ctrl.signal,
      } as never);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      json = (await r.json()) as { elements?: OverpassElement[] };
    } finally {
      clearTimeout(timer);
    }
    const points: GpsPoint[] = [];
    for (const el of Array.isArray(json.elements) ? json.elements : []) {
      if (typeof el.lat !== 'number' || typeof el.lon !== 'number') continue;
      const name = el.tags?.name || `(unnamed ${kind})`;
      const extras = Object.entries(el.tags || {})
        .filter(([k, v]) => v && k !== 'name' && !k.startsWith('name:') && k !== 'amenity')
        .slice(0, 4).map(([k, v]) => `${k}: ${v}`);
      points.push({
        id: `poi:${el.type}:${el.id}`,
        kind: 'poi',
        label: `${POI_ICONS[kind]} ${name}`,
        lat: el.lat, lon: el.lon,
        icon: POI_ICONS[kind],
        detail: extras.join(' · ') || kind.replace(/_/g, ' '),
      });
      if (points.length >= 50) break;
    }
    const feed: GpsFeed = { source: 'OpenStreetMap (Overpass)', fetchedAt: Date.now(), points };
    poiCache.set(key, { at: Date.now(), feed });
    return feed;
  } catch (e) {
    const note = `Overpass unavailable: ${(e instanceof Error ? e.message : 'network error').slice(0, 80)}`;
    if (hit) return { ...hit.feed, note };
    return { source: 'OpenStreetMap (Overpass)', fetchedAt: Date.now(), points: [], note };
  }
}

// --- Cell-tower sites (OpenCelliD, key-gated free tier) -----------------------------
// Infrastructure geography only: where TOWER SITES are registered. This layer maps
// antenna positions — it carries no device association and cannot locate anyone.

interface OpenCellidCell { lat?: number; lon?: number; cellid?: number; radio?: string; mcc?: number; mnc?: number; range?: number; samples?: number }

export function parseOpenCellidCells(j: { cells?: OpenCellidCell[] }, bbox?: Bbox, cap = 150): GpsPoint[] {
  const out: GpsPoint[] = [];
  for (const c of Array.isArray(j.cells) ? j.cells : []) {
    if (typeof c.lat !== 'number' || typeof c.lon !== 'number') continue;
    if (bbox && !bboxOverlaps(bbox, c.lat, c.lon)) continue;
    const radio = String(c.radio || 'unknown').toUpperCase();
    out.push({
      id: `tower:${c.cellid ?? `${c.lat},${c.lon}`}`,
      kind: 'tower',
      label: `📱 ${radio} site ${c.cellid ?? ''}`.trim(),
      lat: c.lat, lon: c.lon,
      icon: '📱',
      detail: [
        c.mcc !== undefined ? `MCC ${c.mcc}` : null,
        c.mnc !== undefined ? `MNC ${c.mnc}` : null,
        c.range !== undefined ? `≈${Math.round(c.range)} m cell range` : null,
        c.samples !== undefined ? `${c.samples} samples` : null,
      ].filter(Boolean).join(' · '),
    });
    if (out.length >= cap) break;
  }
  return out;
}

const towerCache = new Map<string, { at: number; feed: GpsFeed }>();

// Runtime OpenCellID key (Settings-persisted; env fallback) — same pattern as the
// OSINT dump-lane keys: arms the towers layer instantly from the UI, no restart.
let runtimeOpencellidKey: string | undefined;

export function setOpencellidKey(key: string | undefined): void {
  runtimeOpencellidKey = key && key.trim() ? key.trim() : undefined;
}

export function getOpencellidKey(): string {
  return runtimeOpencellidKey || process.env.T3MP3ST_OPENCELLID_KEY || '';
}

export async function fetchCellTowers(bbox: Bbox, opts: { fetcher?: FetchLike; refresh?: boolean; apiKey?: string } = {}): Promise<GpsFeed> {
  const key = opts.apiKey !== undefined ? opts.apiKey : getOpencellidKey();
  const source = 'OpenCelliD (cell-tower registry)';
  if (!key) {
    return { source, fetchedAt: Date.now(), points: [], note: 'key required — set T3MP3ST_OPENCELLID_KEY (free non-commercial token from opencellid.org) and restart' };
  }
  // OpenCellID caps BBOX area at 4,000,000 m² (~2×2 km). The map viewport can be
  // 10° wide, so clamp to a single centered window per https://docs.opencellid.org/docs/api/cells-in-area
  let qbox = bbox;
  const dLat = bbox.lamax - bbox.lamin;
  const dLon = bbox.lomax - bbox.lomin;
  if (dLat > 0.02 || dLon > 0.02) {
    const cLat = (bbox.lamin + bbox.lamax) / 2;
    const cLon = (bbox.lomin + bbox.lomax) / 2;
    qbox = {
      lamin: +(cLat - 0.01).toFixed(4), lomin: +(cLon - 0.01).toFixed(4),
      lamax: +(cLat + 0.01).toFixed(4), lomax: +(cLon + 0.01).toFixed(4),
    };
  }
  const ck = `${qbox.lamin},${qbox.lomin},${qbox.lamax},${qbox.lomax}`;
  const hit = towerCache.get(ck);
  if (hit && !opts.refresh && Date.now() - hit.at < 300_000) return hit.feed;
  // Single search per docs — https://docs.opencellid.org/docs/api/cells-in-area
  // Example: getInArea?key=KEY&BBOX=latmin,lonmin,latmax,lonmax&format=json — 50 max per call
  const url = `https://opencellid.org/cell/getInArea?key=${encodeURIComponent(key)}&BBOX=${qbox.lamin},${qbox.lomin},${qbox.lamax},${qbox.lomax}&format=json`;
  try {
    const j = await fetchJson<{ cells?: OpenCellidCell[]; error?: string; code?: number }>(url, { fetcher: opts.fetcher, timeoutMs: 15_000 });
    if ((j as any)?.error) throw new Error(String((j as any).error));
    const points = parseOpenCellidCells(j, qbox);
    const feed: GpsFeed = { source, fetchedAt: Date.now(), points };
    if (qbox !== bbox) feed.note = `view clamped to ~2×2 km (API BBOX cap) — zoom in to re-center`;
    towerCache.set(ck, { at: Date.now(), feed });
    return feed;
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'network error';
    const note = /HTTP 40[13]/.test(msg)
      ? 'OpenCelliD rejected the token (check T3MP3ST_OPENCELLID_KEY)'
      : /HTTP 429/.test(msg) ? 'OpenCelliD rate-limited — retry in a minute' : `fetch failed: ${msg.slice(0, 80)}`;
    if (hit) return { ...hit.feed, note };
    return { source, fetchedAt: Date.now(), points: [], note };
  }
}

// --- Public satellites — CelesTrak GP TLE + SGP4 (satellite.js) --------------------
// Keyless. Every group is a slice of the public NORAD catalog pulled from
// https://celestrak.org/NORAD/elements/gp.php?GROUP=<name>&FORMAT=tle and
// propagated to the current instant with SGP4. No key, no auth, no tracking.

export const SAT_GROUPS = [
  'stations', 'visual', 'active', 'weather', 'noaa', 'goes', 'resource', 'sarsat', 'disaster',
  'gps-ops', 'glo-ops', 'galileo', 'beidou', 'sbas', 'nnss', 'musson',
  'science', 'geodetic', 'engineering', 'education', 'military', 'radar',
  'cubesat', 'other', 'gnss', 'starlink', 'oneweb', 'planet', 'spire',
  'iridium', 'iridium-NEXT', 'orbcomm', 'globalstar', 'swarm',
  'geo', 'tle-new', 'last-30-days',
] as const;
export type SatGroup = (typeof SAT_GROUPS)[number];
export function isSatGroup(v: unknown): v is SatGroup {
  return typeof v === 'string' && (SAT_GROUPS as readonly string[]).includes(v);
}
/** Human label for the group selector. */
export const SAT_GROUP_LABELS: Record<string, string> = {
  stations: 'Space stations (ISS etc.)', visual: 'Brightest / visual', active: 'All active (cap 500)',
  weather: 'Weather', noaa: 'NOAA', goes: 'GOES', resource: 'Earth resources', sarsat: 'Search & rescue', disaster: 'Disaster monitoring',
  'gps-ops': 'GPS operational', 'glo-ops': 'GLONASS operational', galileo: 'Galileo', beidou: 'BeiDou', sbas: 'SBAS (WAAS/EGNOS)', nnss: 'Transit (NNSS)', musson: 'Musson',
  science: 'Science', geodetic: 'Geodetic', engineering: 'Engineering', education: 'Education', military: 'Military', radar: 'Radar calibration',
  cubesat: 'CubeSats', other: 'Other', gnss: 'GNSS mixed', starlink: 'Starlink', oneweb: 'OneWeb', planet: 'Planet Labs', spire: 'Spire',
  iridium: 'Iridium', 'iridium-NEXT': 'Iridium NEXT', orbcomm: 'Orbcomm', globalstar: 'Globalstar', swarm: 'Swarm',
  geo: 'Geostationary', 'tle-new': 'New TLEs (last 30d)', 'last-30-days': 'Launches (last 30d)',
};

export function parseCelestrakTle(text: string): { name: string; line1: string; line2: string }[] {
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const out: { name: string; line1: string; line2: string }[] = [];
  for (let i = 0; i < lines.length; ) {
    // CelesTrak GP FORMAT=tle is 3 lines per sat: NAME, 1 ..., 2 ...
    if (i + 2 < lines.length && lines[i + 1].startsWith('1 ') && lines[i + 2].startsWith('2 ')) {
      out.push({ name: lines[i], line1: lines[i + 1], line2: lines[i + 2] });
      i += 3;
    } else if (i + 1 < lines.length && lines[i].startsWith('1 ') && lines[i + 1].startsWith('2 ')) {
      // No-name TLE pair (rare)
      out.push({ name: lines[i].slice(2, 8).trim() || 'SAT', line1: lines[i], line2: lines[i + 1] });
      i += 2;
    } else {
      i += 1;
    }
  }
  return out;
}

function satrecToGpsPoint(rec: { name: string; line1: string; line2: string }): GpsPoint | null {
  try {
    const satrec = satellite.twoline2satrec(rec.line1, rec.line2);
    const now = new Date();
    const pv = satellite.propagate(satrec, now);
    const pos = pv.position as satellite.EciVec3<number> | false;
    const vel = pv.velocity as satellite.EciVec3<number> | false;
    if (!pos || typeof pos.x !== 'number') return null;
    const gmst = satellite.gstime(now);
    const geo = satellite.eciToGeodetic(pos as satellite.EciVec3<number>, gmst);
    const lat = satellite.degreesLat(geo.latitude);
    const lon = satellite.degreesLong(geo.longitude);
    if (!Number.isFinite(lat) || !Number.isFinite(lon)) return null;
    const altKm = geo.height;
    const velMs = vel && typeof (vel as satellite.EciVec3<number>).x === 'number'
      ? Math.sqrt((vel as satellite.EciVec3<number>).x ** 2 + (vel as satellite.EciVec3<number>).y ** 2 + (vel as satellite.EciVec3<number>).z ** 2) * 1000
      : undefined;
    const norad = rec.line1.slice(2, 7).trim();
    const detailParts = [
      norad ? `NORAD ${norad}` : null,
      Number.isFinite(altKm) ? `Alt ${Math.round(altKm)} km` : null,
      typeof velMs === 'number' ? `${Math.round(velMs * 3.6).toLocaleString()} km/h` : null,
    ].filter(Boolean);
    return {
      id: `sat:${norad || rec.name}`,
      kind: 'sat',
      label: `🛰 ${rec.name}`,
      lat, lon,
      icon: '🛰️',
      velocity: velMs,
      detail: detailParts.join(' · '),
    };
  } catch { return null; }
}

const satCache = new Map<string, { at: number; feed: GpsFeed }>();

export async function fetchSatellites(opts: { group?: string; limit?: number; refresh?: boolean; fetcher?: FetchLike } = {}): Promise<GpsFeed> {
  const group = isSatGroup(opts.group) ? opts.group : 'visual';
  const limit = Math.max(1, Math.min(500, Math.round(opts.limit ?? 200) || 200));
  const key = `${group}:${limit}`;
  const hit = satCache.get(key);
  if (hit && !opts.refresh && Date.now() - hit.at < 120_000) return hit.feed;
  const url = `https://celestrak.org/NORAD/elements/gp.php?GROUP=${encodeURIComponent(group)}&FORMAT=tle`;
  const source = `CelesTrak ${group} (GP TLE + SGP4)`;
  try {
    const text = await fetchText(url, { fetcher: opts.fetcher, timeoutMs: 20_000 });
    if (!text || !text.includes('1 ') || !text.includes('2 ')) throw new Error('no TLE data in response');
    const tles = parseCelestrakTle(text);
    const points: GpsPoint[] = [];
    for (const rec of tles) {
      const p = satrecToGpsPoint(rec);
      if (p) points.push(p);
      if (points.length >= limit) break;
    }
    const feed: GpsFeed = { source, fetchedAt: Date.now(), points };
    if (tles.length === 0) (feed as GpsFeed).note = 'no TLE records returned for this group';
    else if (points.length === 0) (feed as GpsFeed).note = 'SGP4 propagation produced no positions (try again)';
    satCache.set(key, { at: Date.now(), feed });
    return feed;
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'network error';
    let note: string;
    if (/GP data has not updated/.test(msg)) note = 'CelesTrak throttles this group to once per ~2 h per egress IP — your exit IP fetched it recently; retry after the window or change egress. Cached data (if any) is shown.';
    else if (/HTTP 429/.test(msg)) note = 'CelesTrak rate-limited — retry in a minute';
    else note = `CelesTrak unavailable: ${msg.slice(0, 160)}`;
    if (hit) return { ...hit.feed, note };
    return { source, fetchedAt: Date.now(), points: [], note };
  }
}

// --- Operator pin → nearest public infrastructure context --------------------------
// Purely informational: names the OSM place at the pin and (for IPv4 pins) the
// reverse-resolved hostname. Gives the operator quick context for a map point.

export async function pinContext(lat: number, lon: number): Promise<{ label: string | null; note?: string }> {
  const rev = await reverseGeocode(lat, lon);
  if (rev) return { label: rev.label };
  return { label: null, note: 'no OSM place at this point' };
}
