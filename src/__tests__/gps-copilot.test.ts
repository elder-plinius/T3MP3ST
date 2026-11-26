import { describe, it, expect } from 'vitest';
import {
  buildCopilotContext,
  buildCopilotSystemPrompt,
  buildCopilotUserPrompt,
  parseCopilotReply,
  resolveCopilotPlan,
  validateCopilotAction,
  extractJsonBlob,
  haversineKm,
  bearingDeg,
  compassPoint,
  greatCirclePath,
  COPILOT_ACTIONS,
  type CopilotFeeds,
} from '../tools/gps-copilot.js';
import type { GpsFeed, GpsPoint } from '../tools/public-gps.js';

const feed = (points: GpsPoint[]): GpsFeed => ({ source: 'test', fetchedAt: 0, points });

const PIN = { lat: 40.7, lon: -73.97 };

const QUAKES: GpsPoint[] = [
  { id: 'q1', kind: 'quake', label: '🌍 M6.1 90 km SW of the pin', lat: 40.0, lon: -73.5, mag: 6.1, detail: '2026-09-25 10:00 UTC' },
  { id: 'q2', kind: 'quake', label: '🌍 M2.4 near the pin', lat: 40.75, lon: -74.0, mag: 2.4 },
  { id: 'q3', kind: 'quake', label: '🌍 M3.0 far side', lat: 10, lon: 10, mag: 3.0 }, // outside the bbox
];

const ALERTS: GpsPoint[] = [
  { id: 'a1', kind: 'alert', label: '⚠ Severe Thunderstorm Warning', lat: 41, lon: -74, detail: 'Severe · New York · Storms expected' },
  { id: 'a2', kind: 'alert', label: '⚠ Wind Advisory', lat: 40.6, lon: -73.5, detail: 'Minor · New York · Wind advisory' },
];

const AIRCRAFT: GpsPoint[] = [
  { id: 'a1', kind: 'aircraft', label: '✈ UAL123', lat: 40.8, lon: -74.2, velocity: 230, detail: 'Alt: 10000 m' },
  { id: 'a2', kind: 'aircraft', label: '✈ DL77', lat: 40.9, lon: -73.5, velocity: 180 },
];

const ISS: GpsPoint[] = [{ id: 'iss', kind: 'iss', label: '🛰 ISS', lat: 1.5, lon: 100.0, detail: 'alt 420 km' }];

const VIEW = {
  bbox: { lamin: 40, lomin: -75, lamax: 42, lomax: -73 },
  center: PIN,
  zoom: 11,
  pin: PIN,
  pinLabel: 'New York, NY',
  layers: ['aircraft', 'quake'],
  satellites: { group: 'visual', count: 0 },
  pois: { kind: 'cafe', count: 0 },
  towers: 0,
};

const FEEDS: CopilotFeeds = {
  aircraft: feed(AIRCRAFT),
  quakes: feed(QUAKES),
  alerts: feed(ALERTS),
  iss: feed(ISS),
};

// ── geodesy ──────────────────────────────────────────────────────────────────

describe('gps-copilot geodesy', () => {
  it('computes a known great-circle distance', () => {
    // NYC → LA is ~3,944 km; allow 0.5% for the spherical-earth assumption.
    const km = haversineKm({ lat: 40.7128, lon: -74.006 }, { lat: 34.0522, lon: -118.2437 });
    expect(km).toBeGreaterThan(3920);
    expect(km).toBeLessThan(3970);
  });

  it('is symmetric and zero for a zero leg', () => {
    expect(haversineKm(PIN, PIN)).toBe(0);
    expect(haversineKm(PIN, { lat: 0, lon: 0 })).toBeCloseTo(haversineKm({ lat: 0, lon: 0 }, PIN), 6);
  });

  it('computes the initial bearing and its compass point', () => {
    expect(Math.round(bearingDeg(PIN, ISS[0]))).toBeGreaterThanOrEqual(0);
    // Due north → due south → due west compass points
    expect(compassPoint(0)).toBe('N');
    expect(compassPoint(90)).toBe('E');
    expect(compassPoint(180)).toBe('S');
    expect(compassPoint(270)).toBe('W');
  });

  it('samples a great-circle path that starts and ends on the endpoints', () => {
    const path = greatCirclePath(PIN, ISS[0], 32);
    expect(path).toHaveLength(33);
    expect(path[0][0]).toBeCloseTo(PIN.lat, 3);
    expect(path[0][1]).toBeCloseTo(PIN.lon, 3);
    expect(path[32][0]).toBeCloseTo(ISS[0].lat, 3);
    expect(path[32][1]).toBeCloseTo(ISS[0].lon, 3);
  });
});

// ── context ──────────────────────────────────────────────────────────────────

describe('gps-copilot context', () => {
  const ctx = buildCopilotContext(VIEW, FEEDS);

  it('counts only what is inside the viewport', () => {
    expect(ctx.counts.quakes).toBe(2); // q3 is outside the bbox
    expect(ctx.counts.alerts).toBe(2);
    expect(ctx.counts.aircraft).toBe(2);
    expect(ctx.counts.iss).toBe(1);
  });

  it('derives the nearest quake to the pin with a real distance and bearing', () => {
    // q2 (M2.4) is ~6 km from the pin; q1 (M6.1) is ~90 km away. Nearest ≠ biggest.
    const line = ctx.facts.find((f) => f.startsWith('Closest quake to the pin'))!;
    expect(line).toContain('M2.4');
    const km = parseFloat(line.match(/([\d.]+) km/)?.[1] || '0');
    expect(km).toBeGreaterThan(4);
    expect(km).toBeLessThan(10);
    expect(line).toMatch(/bearing \d+°/);
  });

  it('keeps the strongest quake as a separate fact', () => {
    expect(ctx.facts.some((f) => f.startsWith('Strongest quake in view') && f.includes('M6.1'))).toBe(true);
  });

  it('computes the pin-to-ISS leg server-side, never leaving it to the model', () => {
    const line = ctx.facts.find((f) => f.startsWith('Pin-to-ISS'))!;
    expect(line).toMatch(/[\d,]+ km/);
    expect(line).toMatch(/bearing \d+°/);
  });

  it('handles an unset pin honestly instead of inventing an origin', () => {
    const noPin = buildCopilotContext({ ...VIEW, pin: null, pinLabel: null }, FEEDS);
    expect(noPin.facts.some((f) => f.includes('pin: not set'))).toBe(true);
    expect(noPin.facts.some((f) => f.startsWith('Pin-to-ISS'))).toBe(false);
  });

  it('carries feed caveats through as notes', () => {
    const degraded = buildCopilotContext(VIEW, { ...FEEDS, aircraft: { ...feed([]), note: 'rate-limited by OpenSky' } });
    expect(degraded.notes).toContain('rate-limited by OpenSky');
    expect(degraded.facts.some((f) => f.includes('Feed caveats'))).toBe(true);
  });
});

// ── prompt ───────────────────────────────────────────────────────────────────

describe('gps-copilot prompt', () => {
  const ctx = buildCopilotContext(VIEW, FEEDS);

  it('grounds the model in the facts and the action vocabulary', () => {
    const p = buildCopilotSystemPrompt(ctx, 'auto');
    expect(p).toContain('M2.4');
    expect(p).toContain('fly_to');
    expect(p).toContain('measure');
    expect(p).toMatch(/reply with ONE JSON object/i);
  });

  it('carries the doctrine line and the active layers', () => {
    const p = buildCopilotSystemPrompt(ctx, 'brief');
    expect(p).toContain('does not track, locate or profile people');
    expect(p).toContain('enabled layers: aircraft, quake');
    expect(p).toContain('situation briefing');
  });

  it('defaults a blank operator prompt to the briefing', () => {
    expect(buildCopilotUserPrompt('   ')).toMatch(/briefing/i);
  });
});

// ── reply parsing ────────────────────────────────────────────────────────────

describe('gps-copilot reply parsing', () => {
  it('finds the JSON blob past prose and code fences', () => {
    const blob = extractJsonBlob('Sure!\n```json\n{"say":"ok","actions":[]}\n```');
    expect(blob).toBe('{"say":"ok","actions":[]}');
  });

  it('ignores braces inside strings', () => {
    const plan = parseCopilotReply('{"say":"the {ISS} is far","actions":[]}');
    expect(plan.say).toBe('the {ISS} is far');
  });

  it('parses a well-formed plan', () => {
    const plan = parseCopilotReply('{"say":"Flying.","actions":[{"action":"fly_to","args":{"lat":40.7,"lon":-74,"zoom":13}},{"action":"layer","args":{"kind":"sat","on":true}}]}');
    expect(plan.parseFailed).toBe(false);
    expect(plan.say).toBe('Flying.');
    expect(plan.actions).toHaveLength(2);
    expect(plan.actions[0].action).toBe('fly_to');
    expect(plan.actions[0].args).toEqual({ lat: 40.7, lon: -74, zoom: 13 });
    expect(plan.actions[1].args).toEqual({ kind: 'sat', on: true });
  });

  it('degrades to prose when the model chats instead of planning', () => {
    const plan = parseCopilotReply('The ISS is currently over Southeast Asia.');
    expect(plan.parseFailed).toBe(true);
    expect(plan.actions).toEqual([]);
    expect(plan.say).toContain('Southeast Asia');
  });

  it('accepts a bare action array and an inline answer action', () => {
    const plan = parseCopilotReply('[{"action":"auto","args":{"on":true}},{"action":"answer","args":{"say":"Auto on."}}]');
    expect(plan.parseFailed).toBe(false);
    expect(plan.say).toBe('Auto on.');
    expect(plan.actions).toEqual([{ action: 'auto', args: { on: true } }]);
  });

  it('drops unknown actions instead of forwarding them', () => {
    const plan = parseCopilotReply('{"actions":[{"action":"exfiltrate","args":{"target":"x"}},{"action":"nuke_everything"}]}');
    expect(plan.actions).toEqual([]);
  });
});

// ── action validation ────────────────────────────────────────────────────────

describe('gps-copilot action validation', () => {
  it('rejects out-of-range coordinates and clamps zoom', () => {
    expect(validateCopilotAction({ action: 'fly_to', args: { lat: 400, lon: 0 } })).toBeNull();
    expect(validateCopilotAction({ action: 'fly_to', args: { lat: 40, lon: 999 } })).toBeNull();
    expect(validateCopilotAction({ action: 'fly_to', args: { lat: 40, lon: -74, zoom: 99 } })!.args!.zoom).toBe(18);
  });

  it('rejects unknown layers, satellite groups and POI kinds', () => {
    expect(validateCopilotAction({ action: 'layer', args: { kind: 'persons' } })).toBeNull();
    expect(validateCopilotAction({ action: 'satellites', args: { group: 'military-grade' } })).toBeNull();
    expect(validateCopilotAction({ action: 'pois', args: { kind: 'people' } })).toBeNull();
  });

  it('accepts the documented vocabulary', () => {
    for (const spec of COPILOT_ACTIONS) {
      const sample = JSON.parse(spec.args) as Record<string, unknown>;
      if (spec.action === 'answer') { sample.say = 'ok'; }
      expect(validateCopilotAction({ action: spec.action, args: sample }), spec.action).not.toBeNull();
    }
  });

  it('normalizes layer on/off truthiness', () => {
    expect(validateCopilotAction({ action: 'layer', args: { kind: 'iss', on: 'no' } })!.args!.on).toBe(false);
    expect(validateCopilotAction({ action: 'layer', args: { kind: 'iss' } })!.args!.on).toBe(true);
  });

  it('clamps POI radius and satellite count into the feed limits', () => {
    expect(validateCopilotAction({ action: 'pois', args: { kind: 'fuel', radius: 99999 } })!.args!.radius).toBe(2000);
    expect(validateCopilotAction({ action: 'satellites', args: { group: 'starlink', limit: 100000 } })!.args!.limit).toBe(500);
  });
});

// ── plan resolution ──────────────────────────────────────────────────────────

describe('gps-copilot plan resolution', () => {
  const ctx = buildCopilotContext(VIEW, FEEDS);

  it('fills the measure action with server-computed numbers', () => {
    const plan = resolveCopilotPlan(parseCopilotReply('{"actions":[{"action":"measure","args":{"to":"iss"}}]}'), {
      pin: ctx.pins, iss: ctx.issFix, center: ctx.view.center, pinLabel: ctx.view.pinLabel!,
    });
    const m = plan.actions[0];
    expect(m.action).toBe('measure');
    expect(m.result!.fromLabel).toBe('New York, NY');
    expect(m.result!.toLabel).toBe('ISS');
    expect(m.result!.km).toBeGreaterThan(1000);
    expect(m.result!.path.length).toBeGreaterThan(10);
    // The drawn leg must agree with the stated distance.
    const drawn = haversineKm(m.result!.from, m.result!.to);
    expect(Math.abs(drawn - m.result!.km)).toBeLessThan(1);
  });

  it('drops a measure with no live ISS fix rather than reporting a fake leg', () => {
    const plan = resolveCopilotPlan(parseCopilotReply('{"actions":[{"action":"measure","args":{"to":"iss"}}]}'), { pin: PIN, iss: null, center: PIN });
    expect(plan.actions).toEqual([]);
  });

  it('leaves non-measure actions untouched', () => {
    const plan = resolveCopilotPlan(parseCopilotReply('{"actions":[{"action":"auto","args":{"on":true}}]}'), { pin: PIN, iss: ctx.issFix });
    expect(plan.actions[0]).toEqual({ action: 'auto', args: { on: true } });
  });
});
