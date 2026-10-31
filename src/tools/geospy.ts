/**
 * GEOSPY — AI-powered image/video geolocation for the Social Engineering Lab
 *
 * Two complementary signals, same verdict shape:
 *   1) EXIF forensics — real GPS tags baked into JPEG/TIFF/HEIC (when present).
 *   2) Vision AI — landmark, terrain, vegetation, architecture, language,
 *      signage, license plates, skyline, sun angle → coordinate estimate.
 *
 * Video is handled by analysing the most informative frame (client extracts a
 * JPEG thumbnail; server accepts it as the image). Audio is not needed.
 *
 * No native deps. EXIF is parsed pure-JS off the JPEG APP1/TIFF structure.
 * Vision uses the configured LLM backbone when a vision-capable provider is
 * available, otherwise returns a structured heuristic result with the EXIF
 * verdict still intact — never a fake coordinate.
 */

import { config } from '../config/index.js';
import { reverseGeocode } from './public-gps.js';
import { directFetch } from '../net/proxy.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type GeospySource = 'exif' | 'vision' | 'hybrid';
export type GeospyConfidence = 'high' | 'medium' | 'low' | 'none';

export interface GeospyExifResult {
  hasGps: boolean;
  lat?: number;
  lon?: number;
  altitude?: number;
  raw?: Record<string, unknown>;
  make?: string;
  model?: string;
  datetime?: string;
  /** Stripped? e.g. social platforms wipe EXIF. */
  strippedHint?: string;
}

export interface GeospyVisionResult {
  lat?: number;
  lon?: number;
  /** Human place name the model believes it sees */
  place?: string;
  country?: string;
  region?: string;
  city?: string;
  state?: string;
  confidence: GeospyConfidence;
  reasoning: string;
  interpretation?: string;
  clues: string[];
  landmarks?: string[];
  /** Alternate candidates (GeoIntel style) */
  locations?: Array<{ city?: string; state?: string; country?: string; lat?: number; lon?: number; confidence: GeospyConfidence; explanation?: string }>;
  /** Model that produced the verdict, or 'heuristic' */
  model?: string;
  /** When the model refused or no vision provider is configured */
  note?: string;
}

export interface GeospyVerdict {
  source: GeospySource;
  /** Best coordinate — EXIF wins when present, else vision */
  lat?: number;
  lon?: number;
  confidence: GeospyConfidence;
  exif: GeospyExifResult;
  vision: GeospyVisionResult;
  reverse?: { label: string; address: Record<string, string> } | null;
  /** Social-engineering lab hooks derived from the verdict */
  hooks?: GeospyHooks;
  /** Google grounding (like Google Images) — web hits for vision clues/place */
  googleGrounding?: GoogleGrounding | null;
  /** Google Lens reverse-image result — hits + second vision pass on best hit */
  lens?: LensResult | null;
}

export interface GeospyHooks {
  /** Tracking-link template that would report the viewer back */
  trackingLinkHint: string;
  /** OSINT pivots from the located place */
  pivots: Array<{ label: string; url: string }>;
  /** Device/network fingerprint the image leaks (EXIF make/model etc) */
  deviceIntel: string[];
}

// ---------------------------------------------------------------------------
// EXIF — minimal JPEG APP1/TIFF parser (GPS IFD only + a few tags)
// ---------------------------------------------------------------------------

function readAscii(view: DataView, offset: number, len: number): string {
  let s = '';
  for (let i = 0; i < len; i++) {
    const c = view.getUint8(offset + i);
    if (c === 0) break;
    s += String.fromCharCode(c);
  }
  return s;
}

function readRational(view: DataView, offset: number, little: boolean): number {
  const num = view.getUint32(offset, little);
  const den = view.getUint32(offset + 4, little);
  if (den === 0) return 0;
  return num / den;
}

function dmsToDecimal(dms: number[], ref: string): number {
  if (dms.length < 3) return 0;
  let dec = dms[0] + dms[1] / 60 + dms[2] / 3600;
  if (ref === 'S' || ref === 'W') dec = -dec;
  return dec;
}

/**
 * Parse EXIF from a JPEG buffer. Returns null if no APP1/EXIF found.
 * Pure JS — no exiftool, no WASM.
 */
export function parseExifGps(buffer: Uint8Array): GeospyExifResult {
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  const out: GeospyExifResult = { hasGps: false, raw: {} };

  // JPEG must start SOI 0xFFD8
  if (buffer.length < 4 || view.getUint16(0, false) !== 0xffd8) {
    out.strippedHint = 'not a JPEG (or truncated)';
    return out;
  }

  let offset = 2;
  let app1: { off: number; len: number } | null = null;

  while (offset + 4 <= buffer.length) {
    if (view.getUint8(offset) !== 0xff) break;
    const marker = view.getUint8(offset + 1);
    const len = view.getUint16(offset + 2, false);
    if (marker === 0xe1) { // APP1
      app1 = { off: offset + 4, len: len - 2 };
      break;
    }
    if (marker === 0xd9) break; // EOI
    if (marker === 0xda) break; // SOS — image data follows, no more APPs
    offset += 2 + len;
  }

  if (!app1) {
    out.strippedHint = 'no EXIF APP1 — likely stripped by platform or screenshot';
    return out;
  }

  // APP1 must start with "Exif\0\0"
  if (app1.len < 14) return out;
  const exifHeader = readAscii(view, app1.off, 6);
  if (!exifHeader.startsWith('Exif')) return out;

  const tiffOff = app1.off + 6;
  if (tiffOff + 8 > buffer.length) return out;

  const little = (() => {
    const b0 = view.getUint8(tiffOff);
    const b1 = view.getUint8(tiffOff + 1);
    if (b0 === 0x49 && b1 === 0x49) return true;  // II
    if (b0 === 0x4d && b1 === 0x4d) return false; // MM
    return false;
  })();

  const get16 = (o: number) => view.getUint16(o, little);
  const get32 = (o: number) => view.getUint32(o, little);

  const magic = get16(tiffOff + 2);
  if (magic !== 42) return out;
  const ifd0Off = get32(tiffOff + 4);
  if (tiffOff + ifd0Off + 2 > buffer.length) return out;

  const readTagValue = (entryOff: number, type: number, count: number, valOff: number): unknown => {
    const typeSize: Record<number, number> = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8 };
    const sz = (typeSize[type] || 1) * count;
    const dataOff = sz <= 4 ? entryOff + 8 : tiffOff + valOff;
    if (dataOff + sz > buffer.length) return null;
    try {
      if (type === 2) return readAscii(view, dataOff, count); // ASCII
      if (type === 3 && count === 1) return get16(dataOff); // SHORT
      if (type === 4 && count === 1) return get32(dataOff); // LONG
      if (type === 5 && count >= 3) { // RATIONAL array → number[]
        const arr: number[] = [];
        for (let i = 0; i < count; i++) arr.push(readRational(view, dataOff + i * 8, little));
        return arr;
      }
      if (type === 5 && count === 1) return readRational(view, dataOff, little);
      if (type === 1 && count === 1) return view.getUint8(dataOff);
    } catch { /* ignore */ }
    return null;
  };

  const parseIfd = (ifdAbs: number): Map<number, unknown> => {
    const m = new Map<number, unknown>();
    if (ifdAbs + 2 > buffer.length) return m;
    const num = get16(ifdAbs);
    for (let i = 0; i < num; i++) {
      const e = ifdAbs + 2 + i * 12;
      if (e + 12 > buffer.length) break;
      const tag = get16(e);
      const type = get16(e + 2);
      const cnt = get32(e + 4);
      const val = get32(e + 8);
      m.set(tag, readTagValue(e, type, cnt, val));
    }
    return m;
  };

  // IFD0
  const ifd0Abs = tiffOff + ifd0Off;
  const ifd0 = parseIfd(ifd0Abs);

  // Tag shortcuts from IFD0
  const getStr = (tag: number): string | undefined => {
    const v = ifd0.get(tag);
    return typeof v === 'string' ? v.replace(/\0+$/, '').trim() || undefined : undefined;
  };
  out.make = getStr(0x010f);
  out.model = getStr(0x0110);
  out.datetime = getStr(0x0132) || getStr(0x9003);

  // GPS IFD pointer is tag 0x8825 in IFD0
  const gpsPtr = ifd0.get(0x8825) as number | undefined;
  if (typeof gpsPtr !== 'number') {
    (out.raw as Record<string, unknown>)['ifd0Tags'] = Array.from(ifd0.keys());
    return out;
  }

  const gpsIfdAbs = tiffOff + gpsPtr;
  const gpsIfd = parseIfd(gpsIfdAbs);
  (out.raw as Record<string, unknown>)['gpsTags'] = Array.from(gpsIfd.keys());

  const latRef = (gpsIfd.get(0x0001) as string | undefined)?.trim().replace(/\0/g, '') || 'N';
  const latVal = gpsIfd.get(0x0002) as number[] | undefined;
  const lonRef = (gpsIfd.get(0x0003) as string | undefined)?.trim().replace(/\0/g, '') || 'E';
  const lonVal = gpsIfd.get(0x0004) as number[] | undefined;
  const altVal = gpsIfd.get(0x0006) as number | undefined;
  const altRef = gpsIfd.get(0x0005) as number | undefined; // 0 = above sea, 1 = below

  if (Array.isArray(latVal) && latVal.length >= 3 && Array.isArray(lonVal) && lonVal.length >= 3) {
    const lat = dmsToDecimal(latVal as number[], latRef);
    const lon = dmsToDecimal(lonVal as number[], lonRef);
    if (Number.isFinite(lat) && Number.isFinite(lon) && (Math.abs(lat) > 0 || Math.abs(lon) > 0)) {
      out.hasGps = true;
      out.lat = lat;
      out.lon = lon;
      if (typeof altVal === 'number' && Number.isFinite(altVal)) {
        out.altitude = altRef === 1 ? -altVal : altVal;
      }
    }
  }

  return out;
}

// ---------------------------------------------------------------------------
// Vision — call the configured LLM with a vision prompt when available
// ---------------------------------------------------------------------------

function getGeointelBasePrompt(): string {
  return `You are an expert geolocation analyst. Determine the precise geographic location shown in an image using a systematic, hierarchical chain-of-thought methodology.

=== METHODOLOGY ===

PHASE 1 — SYSTEMATIC EVIDENCE GATHERING (8 categories):
1. TEXT & SIGNAGE — language/script, business/street signs, phone formats, domains, units
2. ROAD INFRASTRUCTURE — driving side, surface, markings, sign shape/color, bollards/guardrails, lights
3. ARCHITECTURE — style, roof/material, era, windows/balconies, fences
4. VEHICLES — makes, plates, transit type, bike infra
5. VEGETATION & ENVIRONMENT — biome, tree species, soil/terrain, water
6. CLIMATE & ATMOSPHERE — sun angle/shadows, haze, season, light quality
7. INFRASTRUCTURE & UTILITIES — power/streetlight/utility pole, sidewalk/curb
8. CULTURAL & SOCIOECONOMIC — clothing, development level, commerce, agriculture, religious structures

PHASE 2 — HIERARCHICAL DEDUCTION: Hemisphere/Climate → Continent → Country (cite 3 independent categories) → Region/State → City/Area → Coordinates (always provide best estimate)

PHASE 3 — CROSS-VALIDATION: check consistency, note contradictions, assess confidence (High=4+ categories converge, Medium=2-3, Low=1/speculative)

CRITICAL RULES: NEVER refuse to guess — always provide at least one location with coordinates; provide up to 3 ordered by confidence; keep interpretation 3-5 sentences and each explanation 2-3 sentences.`;
}

const VISION_SYSTEM = getGeointelBasePrompt() + `

Return ONLY valid JSON with this exact shape (no markdown, no preamble):
{
  "interpretation": "3-5 sentence summary: what you see, what it tells you, and your conclusion",
  "lat": number,
  "lon": number,
  "place": "specific human place name — never null, best guess required",
  "city": "city — best guess, never null if you have a country",
  "state": "state/region — best guess",
  "country": "country — mandatory, never null",
  "confidence": "high|medium|low",
  "landmarks": ["landmark1", ...],
  "clues": ["clue1: what you saw and why it matters", ...],
  "reasoning": "2-4 sentences explaining the deduction chain — vegetation, architecture, signage language, license plates, skyline, sun/shadows, terrain, infrastructure",
  "locations": [
    { "city": "city", "state": "state", "country": "country", "coordinates": { "latitude": 12.34, "longitude": 56.78 }, "confidence": "High|Medium|Low", "explanation": "2-3 sentences why this candidate" }
  ]
}

MANDATORY RULES:
- You MUST provide lat/lon as numbers on EVERY response — never null. If uncertain, give your best estimate at low confidence. A description without coordinates is a FAILURE.
- confidence "none" is FORBIDDEN — use low/medium/high. low = educated guess, medium = strong regional signal, high = landmark or 4+ converging signals.
- You have Google Search available — verify signage, architecture, vegetation against what you see. Use it to refine, but always return the JSON above as your final output.
- clues must be grounded in visible pixels, not generic. Each clue: "what you saw : why it narrows location".
- locations: 1-3 candidates ranked. First entry MUST match top-level lat/lon. Even a generic landscape gets a country-level guess.`;

function buildVisionPayload(imageBase64: string, mime: string, opts: { context?: string; guess?: string; model?: string } = {}): unknown {
  const extra: string[] = [];
  if (opts.context?.trim()) extra.push(`Additional context from operator: "${opts.context.trim().slice(0, 400)}"`);
  if (opts.guess?.trim()) extra.push(`Operator guess (validate or refute): "${opts.guess.trim().slice(0, 200)}"`);
  const suffix = extra.length ? '\n\n' + extra.join('\n') : '';
  // Never fall back to a text-only default — payload model is overridden by pickVisionProvider anyway, but keep a vision-safe default here too
  const VISION_FALLBACK = 'google/gemini-3.1-pro-preview';
  return {
    model: opts.model || VISION_FALLBACK,
    messages: [
      { role: 'system', content: VISION_SYSTEM },
      {
        role: 'user',
        content: [
          { type: 'text', text: 'Locate this image. Return the JSON only.' + suffix },
          { type: 'image_url', image_url: { url: `data:${mime};base64,${imageBase64}` } },
        ],
      },
    ],
    max_tokens: 1100,
    temperature: 0.2,
  };
}

function pickVisionProvider(modelOverride?: string, perRequestKey?: string): { provider: 'openrouter' | 'openai' | 'gemini' | 'local' | 'ollama' | 'none'; baseUrl: string; apiKey: string; model: string } {
  const pick = (modelOverride || '').trim();
  const overrideKey = (perRequestKey || '').trim();
  // Auto must pick a VISION model — the global openrouter default (z-ai/glm-5.3-flash) is text-only and ignores images
  const VISION_DEFAULT = 'google/gemini-3.1-pro-preview';
  const NON_VISION = new Set(['z-ai/glm-5.3-flash','z-ai/glm-5.3','z-ai/glm-5.2:free','deepseek/deepseek-v4-pro','deepseek/deepseek-v4-flash','qwen/qwen3.8-max','qwen/qwen3.8-flash','moonshotai/kimi-k3','minimax/minimax-m3','minimax/minimax-m3:free','tencent/hy4-preview','z-ai/glm-4.7','inclusionai/ling-3.0-flash-fin:free','google/gemma-4-31b-it:free','nvidia/nemotron-3-super-120b-a12b:free','qwen/qwen3.8-27b','mistralai/mistral-large']);
  const resolvedPick = (!pick || NON_VISION.has(pick)) ? VISION_DEFAULT : pick;
  // Dead-id aliases — measured against the live OpenRouter catalog 2026-10-29: grok-4/4.1/4-fast/4.1-fast all 404; current vision grok is 4.3+
  const deprecationAlias: Record<string, string> = {
    'x-ai/grok-4': 'x-ai/grok-4.3',
    'x-ai/grok-4.1': 'x-ai/grok-4.3',
    'x-ai/grok-4-fast': 'x-ai/grok-4.3',
    'x-ai/grok-4.1-fast': 'x-ai/grok-4.3',
    'mistralai/pixtral-12b': 'mistralai/mistral-medium-3.5',
    'mistralai/pixtral-large-2411': 'mistralai/mistral-medium-3.5',
    'qwen/qwen-2-vl-72b-instruct': 'qwen/qwen3-vl-235b-a22b-instruct',
    'meta-llama/llama-3.2-90b-vision-instruct': 'meta-llama/llama-4-maverick',
    'meta-llama/llama-3.2-11b-vision-instruct': 'meta-llama/llama-4-scout',
    'google/gemini-2.0-flash': 'google/gemini-3.1-pro-preview',
    'anthropic/claude-3.5-sonnet': 'anthropic/claude-haiku-5.5',
  };
  const effectivePick = deprecationAlias[resolvedPick] || resolvedPick;
  // Route hints
  const isHermesPick = /^nousresearch\/hermes/i.test(effectivePick) || /^hermes/i.test(effectivePick);
  if (isHermesPick) {
    // Hermes via OpenRouter (operator asked "plus hermes") — route like any OpenRouter model so vision payload rides along
    const orKey = (config.getApiKey('openrouter') || '').trim();
    if (orKey || overrideKey) return { provider: 'openrouter', baseUrl: config.get('openrouter').baseUrl || 'https://openrouter.ai/api/v1', apiKey: overrideKey || orKey, model: effectivePick };
  }
  // Local/Ollama explicit picks — hermes3, llava, gemma, qwen2-vl etc when operator types a local tag
  const wantLocal = /^(local|ollama)\//i.test(effectivePick) || /^(hermes3|llava|bakllava|gemma|qwen2?-vl|minicpm|moondream|pixtral)/i.test(effectivePick);
  if (wantLocal) {
    const base = (process.env.OLLAMA_BASE_URL?.trim() || process.env.TEMPEST_LOCAL_BASE_URL?.trim() || 'http://192.168.1.162:11434').replace(/\/$/, '').replace(/\/api\/?$/, '') || 'http://192.168.1.162:11434';
    const apiKey = (config.getApiKey('ollama') || config.getApiKey('local') || '').trim();
    const bare = effectivePick.replace(/^(local|ollama)\//i, '');
    // Provider flag still 'openrouter'-shaped for chat/completions, but mark as local so visionLocate's Ollama branch fires
    return { provider: 'ollama', baseUrl: base, apiKey, model: bare || 'gemma4:e4b' };
  }
  // Gemini models are namespaced via google/ or explicitly include gemini
  const wantGemini = effectivePick ? /^google\//i.test(effectivePick) || /gemini/i.test(effectivePick) : false;
  const wantOpenAI = effectivePick ? /^openai\//i.test(effectivePick) || /^(gpt-|o1|o3)/i.test(effectivePick) : false;

  if (!pick || NON_VISION.has(pick)) {
    // Auto or blind model → force a vision model; Gemini direct wins when a google/ model is requested and a Gemini key is configured (your GEMINI_API_KEY is valid, your OpenRouter one is revoked — so this matters)
    const wantGeminiAuto = /^google\//i.test(effectivePick) || /gemini/i.test(effectivePick);
    if (wantGeminiAuto) {
      const gemKey = overrideKey || (config.getApiKey('gemini') || '').trim();
      if (gemKey) {
        const bare = effectivePick.replace(/^google\//i, '');
        return { provider: 'gemini', baseUrl: config.get('gemini').baseUrl || 'https://generativelanguage.googleapis.com/v1beta', apiKey: gemKey, model: bare };
      }
    }
    const orKey = overrideKey && !wantGemini ? overrideKey : (config.getApiKey('openrouter') || '').trim();
    if (orKey && !wantGemini) return { provider: 'openrouter', baseUrl: config.get('openrouter').baseUrl || 'https://openrouter.ai/api/v1', apiKey: orKey, model: effectivePick };
    if (wantGeminiAuto) {
      const gemKey2 = overrideKey || (config.getApiKey('gemini') || '').trim();
      if (gemKey2) return { provider: 'gemini', baseUrl: config.get('gemini').baseUrl || 'https://generativelanguage.googleapis.com/v1beta', apiKey: gemKey2, model: effectivePick.replace(/^google\//i, '') };
    }
    const oaKey = (config.getApiKey('openai') || '').trim();
    if (oaKey) return { provider: 'openai', baseUrl: config.get('openai').baseUrl || 'https://api.openai.com/v1', apiKey: oaKey, model: 'gpt-4o' };
    const gemKey2 = overrideKey || (config.getApiKey('gemini') || '').trim();
    if (gemKey2) return { provider: 'gemini', baseUrl: config.get('gemini').baseUrl || 'https://generativelanguage.googleapis.com/v1beta', apiKey: gemKey2, model: effectivePick.replace(/^google\//i, '') };
    return { provider: 'none', baseUrl: '', apiKey: '', model: '' };
  }

  if (wantGemini) {
    const gemKey = overrideKey || (config.getApiKey('gemini') || '').trim();
    if (gemKey) {
      const bare = effectivePick.replace(/^google\//i, '');
      return { provider: 'gemini', baseUrl: config.get('gemini').baseUrl || 'https://generativelanguage.googleapis.com/v1beta', apiKey: gemKey, model: bare };
    }
    // Gemini model requested but no gemini key — fall through to openrouter (many gemini models are also on OR)
  }
  if (wantOpenAI) {
    const oaKey = (config.getApiKey('openai') || '').trim();
    if (oaKey) return { provider: 'openai', baseUrl: config.get('openai').baseUrl || 'https://api.openai.com/v1', apiKey: oaKey, model: effectivePick };
  }
  // Default: route through OpenRouter — it proxies every provider in AVAILABLE_MODELS
  const orKey = (config.getApiKey('openrouter') || '').trim();
  if (orKey) return { provider: 'openrouter', baseUrl: config.get('openrouter').baseUrl || 'https://openrouter.ai/api/v1', apiKey: orKey, model: effectivePick };
  const oaKey = (config.getApiKey('openai') || '').trim();
  if (oaKey) return { provider: 'openai', baseUrl: config.get('openai').baseUrl || 'https://api.openai.com/v1', apiKey: oaKey, model: effectivePick };
  const gemKey = overrideKey || (config.getApiKey('gemini') || '').trim();
  if (gemKey) return { provider: 'gemini', baseUrl: config.get('gemini').baseUrl || 'https://generativelanguage.googleapis.com/v1beta', apiKey: gemKey, model: effectivePick.replace(/^google\//i, '') };
  return { provider: 'none', baseUrl: '', apiKey: '', model: effectivePick };
}

function extractJson(text: string): unknown | null {
  if (!text) return null;
  // Try direct parse, then fence extraction, then first {...} block
  const attempts: string[] = [text];
  const fence = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) attempts.push(fence[1]);
  const brace = text.match(/\{[\s\S]*\}/);
  if (brace) attempts.push(brace[0]);
  for (const a of attempts) {
    try { return JSON.parse(a.trim()); } catch { /* next */ }
  }
  return null;
}

export async function visionLocate(
  imageBase64: string,
  mime: string,
  opts: { timeoutMs?: number; context?: string; guess?: string; model?: string; apiKey?: string } = {},
): Promise<GeospyVisionResult> {
  const pick = pickVisionProvider(opts.model, opts.apiKey);

  // Helper: local Ollama vision (lab box 192.168.1.162:11434) — zero-cost fallback when remote credits are dead
  // Prefers the operator-requested local tag (hermes3, llava, qwen2-vl etc), falls back to gemma4:e4b.
  async function tryLocalOllamaVision(remainingMs: number, preferredModel?: string): Promise<GeospyVisionResult | null> {
    const base = (process.env.OLLAMA_BASE_URL?.trim() || process.env.TEMPEST_LOCAL_BASE_URL?.trim() || 'http://192.168.1.162:11434').replace(/\/$/, '').replace(/\/api\/?$/, '');
    const b64 = imageBase64.replace(/^data:[^;]+;base64,/, '');
    const localPrompt = VISION_SYSTEM + '\n\nLocate this image. Return the JSON only.' + (opts.context ? `\nContext: ${opts.context}` : '') + (opts.guess ? `\nGuess: ${opts.guess}` : '');
    // Model priority: explicit local pick > OLLAMA_MODEL env > gemma4:e4b. Hermes vision tag = hermes3:8b or adrienbrault/nous-hermes2pro
    const localModel = (preferredModel || (pick.provider === 'ollama' ? pick.model : '') || process.env.OLLAMA_MODEL?.trim() || process.env.TEMPEST_LOCAL_MODEL?.trim() || 'gemma4:e4b').trim() || 'gemma4:e4b';
    const ctrl2 = new AbortController();
    const t2 = setTimeout(() => ctrl2.abort(), Math.max(5000, Math.min(remainingMs, 45000)));
    try {
      const r = await directFetch(`${base}/api/chat` as never, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          model: localModel,
          stream: false,
          format: 'json',
          messages: [{ role: 'user', content: localPrompt, images: [b64] }],
          options: { temperature: 0.2, num_predict: 1100 },
        }),
        signal: ctrl2.signal as never,
      } as never) as Response;
      const raw = await (r as unknown as { text: () => Promise<string> }).text();
      let j: unknown;
      try { j = JSON.parse(raw); } catch { j = null; }
      const msg = (j as { message?: { content?: string }; error?: string })?.message?.content || (typeof j === 'string' ? j as string : raw) || '';
      const parsed = extractJson(typeof msg === 'string' ? msg : JSON.stringify(msg)) as Record<string, unknown> | null;
      if (!parsed) return null;
      const lat = typeof parsed['lat'] === 'number' ? parsed['lat'] : (typeof (parsed['coordinates'] as Record<string, unknown>)?.['latitude'] === 'number' ? (parsed['coordinates'] as Record<string, unknown>)['latitude'] as number : undefined);
      const lon = typeof parsed['lon'] === 'number' ? parsed['lon'] : (typeof (parsed['coordinates'] as Record<string, unknown>)?.['longitude'] === 'number' ? (parsed['coordinates'] as Record<string, unknown>)['longitude'] as number : undefined);
      const conf = (['high', 'medium', 'low', 'none'] as const).includes(String(parsed['confidence']).toLowerCase() as GeospyConfidence) ? String(parsed['confidence']).toLowerCase() as GeospyConfidence : (lat != null && lon != null ? 'low' : 'none');
      const locs = Array.isArray(parsed['locations']) ? (parsed['locations'] as unknown[]).slice(0, 3).map((l) => {
        const o = l as Record<string, unknown>;
        const c = o['coordinates'] as Record<string, unknown> | undefined;
        return { city: typeof o['city'] === 'string' ? o['city'] : undefined, state: typeof o['state'] === 'string' ? o['state'] : undefined, country: typeof o['country'] === 'string' ? o['country'] : undefined, lat: typeof c?.['latitude'] === 'number' ? c['latitude'] as number : typeof o['lat'] === 'number' ? o['lat'] as number : undefined, lon: typeof c?.['longitude'] === 'number' ? c['longitude'] as number : typeof o['lon'] === 'number' ? o['lon'] as number : undefined, confidence: (['high', 'medium', 'low', 'none'] as const).includes(String(o['confidence']).toLowerCase() as GeospyConfidence) ? String(o['confidence']).toLowerCase() as GeospyConfidence : 'low' as GeospyConfidence, explanation: typeof o['explanation'] === 'string' ? o['explanation'] : undefined };
      }) : undefined;
      if (!Number.isFinite(lat as number) && !Number.isFinite(lon as number) && !parsed['place'] && !parsed['city'] && !(locs && locs.length)) return null;
      return {
        lat: Number.isFinite(lat as number) ? (lat as number) : undefined,
        lon: Number.isFinite(lon as number) ? (lon as number) : undefined,
        place: typeof parsed['place'] === 'string' ? parsed['place'] : undefined,
        city: typeof parsed['city'] === 'string' ? parsed['city'] : undefined,
        state: typeof parsed['state'] === 'string' ? parsed['state'] : undefined,
        country: typeof parsed['country'] === 'string' ? parsed['country'] : undefined,
        confidence: conf,
        reasoning: typeof parsed['reasoning'] === 'string' ? parsed['reasoning'] : typeof parsed['explanation'] === 'string' ? parsed['explanation'] : '',
        interpretation: typeof parsed['interpretation'] === 'string' ? parsed['interpretation'] : undefined,
        clues: Array.isArray(parsed['clues']) ? (parsed['clues'] as unknown[]).filter((x): x is string => typeof x === 'string').slice(0, 12) : [],
        landmarks: Array.isArray(parsed['landmarks']) ? (parsed['landmarks'] as unknown[]).filter((x): x is string => typeof x === 'string').slice(0, 8) : [],
        locations: locs,
        model: localModel + ' (local)',
      };
    } catch { return null; } finally { clearTimeout(t2); }
  }

  if (pick.provider === 'none') {
    return {
      confidence: 'none',
      reasoning: 'No vision LLM configured — set OPENROUTER_API_KEY, OPENAI_API_KEY or GEMINI_API_KEY to enable AI geolocation. EXIF result still available above.',
      clues: [],
      model: opts.model || 'none',
      note: 'Vision disabled — configure a provider in Settings → API Keys. The image was still checked for embedded GPS.',
    };
  }

  const payload = buildVisionPayload(imageBase64, mime, { context: opts.context, guess: opts.guess, model: pick.model });
  // Override model with the picked one
  (payload as Record<string, unknown>)['model'] = pick.model;

  const timeout = Math.max(5000, Math.min(60000, opts.timeoutMs ?? 25000));
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout);
  try {
    // Gemini uses a different wire (generateContent) — handle separately
    if (pick.provider === 'gemini') {
      const b64 = imageBase64.replace(/^data:[^;]+;base64,/, '');
      const isPro = /gemini-3\.1-pro|gemini-3-pro|gemini-2\.5-pro/i.test(pick.model);
      const isThinking = /gemini-(3|2\.5)/i.test(pick.model);
      // Full Gemini capabilities: Search Grounding lets it verify against Google's index,
      // thinking budget lets Pro reason through the 8-phase methodology.
      // We do NOT set responseMimeType when tools are present — it conflicts and caused the
      // b688c52 Unparseable bug (tool+JSON mime returns citations, not JSON). Prompt is strict instead.
      const gemBody: Record<string, unknown> = {
        contents: [{ role: 'user', parts: [{ text: VISION_SYSTEM + '\n\nLocate this image. Return ONLY the JSON object above — no preamble, no markdown.' + (opts.context ? `\nContext: ${opts.context}` : '') + (opts.guess ? `\nGuess: ${opts.guess}` : '') }, { inline_data: { mime_type: mime || 'image/jpeg', data: b64 } }] }],
        generationConfig: {
          temperature: 0.18,
          maxOutputTokens: isPro ? 8192 : isThinking ? 4096 : 2048,
          ...(isThinking ? { thinkingConfig: { thinkingBudget: isPro ? 12000 : 8000, includeThoughts: false } } : {}),
        } as unknown as Record<string, unknown>,
        tools: [{ google_search: {} }],
        toolConfig: { functionCallingConfig: { mode: 'AUTO' } } as unknown as Record<string, unknown>,
      };
      // Native generateContent lives at /v1beta/models/...  but config gemini baseUrl is the
      // OpenAI-compat path /v1beta/openai — strip the /openai segment for the native call.
      const nativeBase = pick.baseUrl.replace(/\/openai\/?$/i, '').replace(/\/$/, '') || 'https://generativelanguage.googleapis.com/v1beta';
      const gemUrl = `${nativeBase}/models/${encodeURIComponent(pick.model)}:generateContent?key=${encodeURIComponent(pick.apiKey)}`;
      const r = await directFetch(gemUrl as never, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(gemBody),
        signal: ctrl.signal as never,
      } as never) as Response;
      // Gemini may return empty body when egress is via Tor — parse as text first so we don't throw on r.json()
      const gemRaw = await (r as unknown as { text: () => Promise<string> }).text().catch(() => '');
      let j: { candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }>; error?: { message?: string } } = {} as never;
      try { j = gemRaw ? JSON.parse(gemRaw) as typeof j : {} as never; } catch { j = { error: { message: gemRaw.slice(0, 400) || `HTTP ${r.status}` } } as never; }
      if (!r.ok) {
        const msg = (j as { error?: { message?: string } })?.error?.message || gemRaw.slice(0, 400) || `HTTP ${r.status}`;
        // 404 = model not found at this endpoint (common when baseUrl still had /openai) — transparently retry via OpenRouter before falling local
        const isModelNotFound = r.status === 404 || /not[ _-]?found|unknown model|model .*not/i.test(msg);
        if (isModelNotFound) {
          const orKey = (config.getApiKey('openrouter') || '').trim();
          if (orKey) {
            try {
              const orModel = `google/${pick.model.replace(/^google\//i, '')}`;
              const orPayload = buildVisionPayload(imageBase64, mime, { context: opts.context, guess: opts.guess, model: orModel });
              (orPayload as Record<string, unknown>)['model'] = orModel;
              const orBase = config.get('openrouter').baseUrl || 'https://openrouter.ai/api/v1';
              const orCtrl = new AbortController();
              const orT = setTimeout(() => orCtrl.abort(), Math.max(5000, Math.min(timeout - 1000, 25000)));
              try {
                const orRes = await directFetch(`${orBase.replace(/\/$/, '')}/chat/completions` as never, {
                  method: 'POST',
                  headers: { 'content-type': 'application/json', authorization: `Bearer ${orKey}`, 'http-referer': 'https://t3mp3st.local/geospy', 'x-title': 'T3MP3ST Geospy' },
                  body: JSON.stringify(orPayload),
                  signal: orCtrl.signal as never,
                } as never) as Response;
                const oj = await (orRes as unknown as { json: () => Promise<unknown> }).json() as { choices?: Array<{ message?: { content?: string } }>; error?: { message?: string } };
                if (orRes.ok) {
                  const oc = oj.choices?.[0]?.message?.content || '';
                  const op = extractJson(typeof oc === 'string' ? oc : JSON.stringify(oc)) as Record<string, unknown> | null;
                  if (op) {
                    const lat = typeof op['lat'] === 'number' ? op['lat'] : (typeof (op['coordinates'] as Record<string, unknown>)?.['latitude'] === 'number' ? (op['coordinates'] as Record<string, unknown>)['latitude'] as number : undefined);
                    const lon = typeof op['lon'] === 'number' ? op['lon'] : (typeof (op['coordinates'] as Record<string, unknown>)?.['longitude'] === 'number' ? (op['coordinates'] as Record<string, unknown>)['longitude'] as number : undefined);
                    const conf = (['high', 'medium', 'low', 'none'] as const).includes(String(op['confidence']).toLowerCase() as GeospyConfidence) ? String(op['confidence']).toLowerCase() as GeospyConfidence : (lat != null && lon != null ? 'low' : 'none');
                    const locs = Array.isArray(op['locations']) ? (op['locations'] as unknown[]).slice(0, 3).map((l) => {
                      const o = l as Record<string, unknown>;
                      const c = o['coordinates'] as Record<string, unknown> | undefined;
                      return { city: typeof o['city'] === 'string' ? o['city'] : undefined, state: typeof o['state'] === 'string' ? o['state'] : undefined, country: typeof o['country'] === 'string' ? o['country'] : undefined, lat: typeof c?.['latitude'] === 'number' ? c['latitude'] as number : typeof o['lat'] === 'number' ? o['lat'] as number : undefined, lon: typeof c?.['longitude'] === 'number' ? c['longitude'] as number : typeof o['lon'] === 'number' ? o['lon'] as number : undefined, confidence: (['high', 'medium', 'low', 'none'] as const).includes(String(o['confidence']).toLowerCase() as GeospyConfidence) ? String(o['confidence']).toLowerCase() as GeospyConfidence : 'low' as GeospyConfidence, explanation: typeof o['explanation'] === 'string' ? o['explanation'] : undefined };
                    }) : undefined;
                    return { lat: Number.isFinite(lat as number) ? (lat as number) : undefined, lon: Number.isFinite(lon as number) ? (lon as number) : undefined, place: typeof op['place'] === 'string' ? op['place'] : undefined, city: typeof op['city'] === 'string' ? op['city'] : undefined, state: typeof op['state'] === 'string' ? op['state'] : undefined, country: typeof op['country'] === 'string' ? op['country'] : undefined, confidence: conf, reasoning: typeof op['reasoning'] === 'string' ? op['reasoning'] : typeof op['explanation'] === 'string' ? op['explanation'] : '', interpretation: typeof op['interpretation'] === 'string' ? op['interpretation'] : undefined, clues: Array.isArray(op['clues']) ? (op['clues'] as unknown[]).filter((x): x is string => typeof x === 'string').slice(0, 12) : [], landmarks: Array.isArray(op['landmarks']) ? (op['landmarks'] as unknown[]).filter((x): x is string => typeof x === 'string').slice(0, 8) : [], locations: locs, model: `${orModel} (openrouter-fallback)` };
                  }
                }
              } finally { clearTimeout(orT); }
            } catch { /* fall through to local */ }
          }
        }
        // Any remote failure now falls back to local lab box — billing, auth, or egress-blocked empty JSON all qualify
        {
          const remaining = Math.max(5000, timeout - 1500);
          const local = await tryLocalOllamaVision(remaining);
          if (local) { (local as unknown as Record<string, unknown>)['note'] = `Remote Gemini unavailable (${msg.slice(0,120)}) — fell back to local gemma4:e4b`; return local; }
        }
        let friendly = msg;
        if (r.status === 404 || isModelNotFound) friendly = `Gemini ${pick.model} not found at ${nativeBase} (HTTP 404). Your key may target a different Gemini API version — lab tried OpenRouter and local gemma4:e4b. Try Auto or set a funded key in Settings → API Keys. Original: ${msg.slice(0,160)}`;
        else if (/credit|quota|insufficient|billing|RESOURCE_EXHAUSTED|prepayment|depleted/i.test(msg)) friendly = msg + ' — Gemini prepayment depleted (your key is valid but out of credits). Local fallback attempted; to restore cloud, add billing at ai.google.dev or rotate key in Settings → API Keys.';
        else if (!msg || /Unexpected end|empty/i.test(msg)) friendly = `Gemini egress blocked or empty reply (HTTP ${r.status}) — lab tried local fallback. If Tor is active, set TEMPEST_PROXY_BYPASS or retry with DO_NOT_PROXY.`;
        return { confidence: 'none', reasoning: `Gemini error: ${friendly}`, clues: [], model: pick.model, note: friendly.slice(0, 280) };
      }
      const gemText = j.candidates?.[0]?.content?.parts?.map((p) => (p as Record<string, unknown>)['thought'] ? '' : (p as { text?: string }).text || '').join('').trim()
        || j.candidates?.[0]?.content?.parts?.map((p) => (p as { text?: string }).text || '').join('').trim() || '';
      // Grounding with google_search returns citations; JSON is still in the text part — extract the JSON block
      const gemParsed = extractJson(gemText) as Record<string, unknown> | null;
      if (!gemParsed){
        // Last resort: try to salvage a truncated JSON (thinking models sometimes emit very long reasoning before JSON)
        const brace = gemText.match(/\{[\s\S]*"lat"[\s\S]*\}/);
        if(brace){
          try{ const salvage = JSON.parse(brace[0]) as Record<string, unknown>; if(salvage && typeof salvage['lat']==='number') return { lat: salvage['lat'] as number, lon: salvage['lon'] as number, place: typeof salvage['place']==='string'?salvage['place']:undefined, city: typeof salvage['city']==='string'?salvage['city']:undefined, state: typeof salvage['state']==='string'?salvage['state']:undefined, country: typeof salvage['country']==='string'?salvage['country']:undefined, confidence: 'low' as GeospyConfidence, reasoning: typeof salvage['reasoning']==='string'?salvage['reasoning']:gemText.slice(0,400), interpretation: typeof salvage['interpretation']==='string'?salvage['interpretation']:undefined, clues: [], landmarks: [], model: pick.model }; }catch{}
        }
        return { confidence: 'none', reasoning: gemText.slice(0, 600) || 'Gemini returned no parseable JSON — grounding/thinking text filled the output. Retrying with conservative model may help.', clues: [], model: pick.model, note: 'Unparseable — raw: ' + gemText.slice(0, 200) };
      }
      const glat = typeof gemParsed['lat'] === 'number' ? gemParsed['lat'] : (typeof (gemParsed['coordinates'] as Record<string, unknown>)?.['latitude'] === 'number' ? (gemParsed['coordinates'] as Record<string, unknown>)['latitude'] as number : undefined);
      const glon = typeof gemParsed['lon'] === 'number' ? gemParsed['lon'] : (typeof (gemParsed['coordinates'] as Record<string, unknown>)?.['longitude'] === 'number' ? (gemParsed['coordinates'] as Record<string, unknown>)['longitude'] as number : undefined);
      const gconf = (['high', 'medium', 'low', 'none'] as const).includes(String(gemParsed['confidence']).toLowerCase() as GeospyConfidence) ? String(gemParsed['confidence']).toLowerCase() as GeospyConfidence : (glat != null && glon != null ? 'low' : 'none');
      const locs = Array.isArray(gemParsed['locations']) ? (gemParsed['locations'] as unknown[]).slice(0, 3).map((l) => {
        const o = l as Record<string, unknown>;
        const c = o['coordinates'] as Record<string, unknown> | undefined;
        return { city: typeof o['city'] === 'string' ? o['city'] : undefined, state: typeof o['state'] === 'string' ? o['state'] : undefined, country: typeof o['country'] === 'string' ? o['country'] : undefined, lat: typeof c?.['latitude'] === 'number' ? c['latitude'] as number : typeof o['lat'] === 'number' ? o['lat'] as number : undefined, lon: typeof c?.['longitude'] === 'number' ? c['longitude'] as number : typeof o['lon'] === 'number' ? o['lon'] as number : undefined, confidence: (['high', 'medium', 'low', 'none'] as const).includes(String(o['confidence']).toLowerCase() as GeospyConfidence) ? String(o['confidence']).toLowerCase() as GeospyConfidence : 'low' as GeospyConfidence, explanation: typeof o['explanation'] === 'string' ? o['explanation'] : undefined };
      }) : undefined;
      return {
        lat: Number.isFinite(glat as number) ? (glat as number) : undefined,
        lon: Number.isFinite(glon as number) ? (glon as number) : undefined,
        place: typeof gemParsed['place'] === 'string' ? gemParsed['place'] : undefined,
        city: typeof gemParsed['city'] === 'string' ? gemParsed['city'] : undefined,
        state: typeof gemParsed['state'] === 'string' ? gemParsed['state'] : undefined,
        country: typeof gemParsed['country'] === 'string' ? gemParsed['country'] : undefined,
        confidence: gconf,
        reasoning: typeof gemParsed['reasoning'] === 'string' ? gemParsed['reasoning'] : typeof gemParsed['explanation'] === 'string' ? gemParsed['explanation'] : '',
        interpretation: typeof gemParsed['interpretation'] === 'string' ? gemParsed['interpretation'] : undefined,
        clues: Array.isArray(gemParsed['clues']) ? (gemParsed['clues'] as unknown[]).filter((x): x is string => typeof x === 'string').slice(0, 12) : [],
        landmarks: Array.isArray(gemParsed['landmarks']) ? (gemParsed['landmarks'] as unknown[]).filter((x): x is string => typeof x === 'string').slice(0, 8) : [],
        locations: locs,
        model: pick.model,
      };
    }

    // --- Local / Ollama vision (operator picked a local tag like hermes3, llava, ollama/..., or Hermes via local) ---
    if (pick.provider === 'ollama' || pick.provider === 'local') {
      const remaining = Math.max(6000, timeout - 500);
      const local = await tryLocalOllamaVision(remaining, pick.model);
      if (local) return local;
      return { confidence: 'none', reasoning: `Local vision model ${pick.model} unavailable at ${pick.baseUrl} — is Ollama running? Try: ollama pull ${pick.model}  (fallback gemma4:e4b also tried). Set OLLAMA_BASE_URL if not 192.168.1.162:11434.`, clues: [], model: pick.model, note: 'Local Ollama unreachable' };
    }

    const r = await directFetch(`${pick.baseUrl.replace(/\/$/, '')}/chat/completions` as never, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${pick.apiKey}`,
        'http-referer': 'https://t3mp3st.local/geospy',
        'x-title': 'T3MP3ST Geospy',
      },
      body: JSON.stringify(payload),
      signal: ctrl.signal as never,
    } as never) as Response;
    const j = await (r as unknown as { json: () => Promise<unknown> }).json() as {
      choices?: Array<{ message?: { content?: string } }>;
      error?: { message?: string };
    };
    if (!r.ok) {
      const msg = (j as { error?: { message?: string } })?.error?.message || `HTTP ${r.status}`;
      const isAuthOrBill = /User not found/i.test(msg) || r.status === 401 || r.status === 402 || r.status === 404 || /credit|quota|insufficient|billing|RESOURCE_EXHAUSTED|prepayment|depleted|not[ _-]?found|invalid model/i.test(msg);
      if (isAuthOrBill) {
        const remaining = Math.max(5000, timeout - 1500);
        const local = await tryLocalOllamaVision(remaining);
        if (local) { (local as unknown as Record<string, unknown>)['note'] = `Remote ${pick.provider} failed (${msg.slice(0,120)}) — fell back to local gemma4:e4b`; return local; }
      }
      let friendly = msg;
      if (/hermes/i.test(pick.model) && (/image input/i.test(msg) || r.status === 404)) friendly = `${msg} — Hermes on OpenRouter is TEXT-ONLY (no image input; measured live 2026-10-29). Pick Qwen VL / Gemini / Grok 4.3 for cloud vision, or a local llava/qwen2-vl via the Ollama options.`;
      else if (/deprecated/i.test(msg) && /grok/i.test(msg)) friendly = msg + ' — Grok version deprecated. Auto-retrying as x-ai/grok-4.3; pick Grok 4.3 or Auto → google/gemini-3.1-pro-preview next time.';
      else if (r.status === 404 || /not[ _-]?found/i.test(msg)) friendly = `${msg} (HTTP 404 — model not found on ${pick.provider}). ${pick.provider === 'openrouter' ? 'Try Auto → google/gemini-3.1-pro-preview or set GEMINI_API_KEY; lab tried local gemma4:e4b.' : 'Try Auto or a vision-capable tag on this provider.'}`;
      else if (/User not found/i.test(msg) || r.status === 401) friendly = `OpenRouter key invalid or revoked — vision calls return 401. Add a valid key in Settings → API Keys (or keep using local gemma4:e4b fallback). Original: ${msg}`;
      else if (/credit/i.test(msg) || /quota/i.test(msg) || /insufficient/i.test(msg) || /RESOURCE_EXHAUSTED/i.test(msg)) friendly = msg + ' — remote credits depleted. Local gemma4:e4b attempted; add billing or rotate key to restore cloud. EXIF still works.';
      else if (/invalid model/i.test(msg)) friendly = msg + ' — model not available on this provider. Try Auto (google/gemini-3.1-pro-preview) or set GEMINI_API_KEY.';
      // auto-retry deprecated/renamed grok once as grok-4.3
      if (!/hermes/i.test(pick.model) && /deprecated|not a valid model/i.test(msg) && /grok/i.test(msg) && !pick.model.includes('4.3')) {
        try {
          const retryPayload = { ...payload as Record<string, unknown>, model: 'x-ai/grok-4.3' } as unknown as string;
          const r2 = await directFetch(`${pick.baseUrl.replace(/\/$/, '')}/chat/completions` as never, {
            method: 'POST',
            headers: { 'content-type': 'application/json', authorization: `Bearer ${pick.apiKey}`, 'http-referer': 'https://t3mp3st.local/geospy', 'x-title': 'T3MP3ST Geospy' },
            body: JSON.stringify(retryPayload),
            signal: ctrl.signal as never,
          } as never) as Response;
          if (r2.ok) {
            const j2 = await (r2 as unknown as { json: () => Promise<unknown> }).json() as { choices?: Array<{ message?: { content?: string } }> };
            const content2 = j2.choices?.[0]?.message?.content || '';
            const parsed2 = extractJson(typeof content2 === 'string' ? content2 : JSON.stringify(content2)) as Record<string, unknown> | null;
            if (parsed2) {
              const lat2 = typeof parsed2['lat'] === 'number' ? parsed2['lat'] : undefined;
              const lon2 = typeof parsed2['lon'] === 'number' ? parsed2['lon'] : undefined;
              return { lat: lat2, lon: lon2, place: typeof parsed2['place'] === 'string' ? parsed2['place'] : undefined, city: typeof parsed2['city'] === 'string' ? parsed2['city'] : undefined, state: typeof parsed2['state'] === 'string' ? parsed2['state'] : undefined, country: typeof parsed2['country'] === 'string' ? parsed2['country'] : undefined, confidence: 'low' as GeospyConfidence, reasoning: typeof parsed2['reasoning'] === 'string' ? parsed2['reasoning'] : '', interpretation: typeof parsed2['interpretation'] === 'string' ? parsed2['interpretation'] : undefined, clues: [], landmarks: [], model: 'x-ai/grok-4.3 (auto-retried from deprecated grok)', note: 'Deprecated Grok auto-retried as 4.3' };
            }
          }
        } catch {}
      }
      return { confidence: 'none', reasoning: `Vision provider error: ${friendly}`, clues: [], model: pick.model, note: friendly.slice(0, 280) };
    }
    const content = j.choices?.[0]?.message?.content || '';
    const parsed = extractJson(typeof content === 'string' ? content : JSON.stringify(content)) as Record<string, unknown> | null;
    if (!parsed) {
      return { confidence: 'none', reasoning: content.slice(0, 400) || 'Vision model returned no parseable JSON', clues: [], model: pick.model, note: 'Unparseable vision response' };
    }
    const lat = typeof parsed['lat'] === 'number' ? parsed['lat'] : (typeof (parsed['coordinates'] as Record<string, unknown>)?.['latitude'] === 'number' ? (parsed['coordinates'] as Record<string, unknown>)['latitude'] as number : undefined);
    const lon = typeof parsed['lon'] === 'number' ? parsed['lon'] : (typeof (parsed['coordinates'] as Record<string, unknown>)?.['longitude'] === 'number' ? (parsed['coordinates'] as Record<string, unknown>)['longitude'] as number : undefined);
    const conf = (['high', 'medium', 'low', 'none'] as const).includes(String(parsed['confidence']).toLowerCase() as GeospyConfidence) ? String(parsed['confidence']).toLowerCase() as GeospyConfidence : (lat != null && lon != null ? 'low' : 'none');
    const locs2 = Array.isArray(parsed['locations']) ? (parsed['locations'] as unknown[]).slice(0, 3).map((l) => {
      const o = l as Record<string, unknown>;
      const c = o['coordinates'] as Record<string, unknown> | undefined;
      return { city: typeof o['city'] === 'string' ? o['city'] : undefined, state: typeof o['state'] === 'string' ? o['state'] : undefined, country: typeof o['country'] === 'string' ? o['country'] : undefined, lat: typeof c?.['latitude'] === 'number' ? c['latitude'] as number : typeof o['lat'] === 'number' ? o['lat'] as number : undefined, lon: typeof c?.['longitude'] === 'number' ? c['longitude'] as number : typeof o['lon'] === 'number' ? o['lon'] as number : undefined, confidence: (['high', 'medium', 'low', 'none'] as const).includes(String(o['confidence']).toLowerCase() as GeospyConfidence) ? String(o['confidence']).toLowerCase() as GeospyConfidence : 'low' as GeospyConfidence, explanation: typeof o['explanation'] === 'string' ? o['explanation'] : undefined };
    }) : undefined;
    return {
      lat: Number.isFinite(lat as number) ? (lat as number) : undefined,
      lon: Number.isFinite(lon as number) ? (lon as number) : undefined,
      place: typeof parsed['place'] === 'string' ? parsed['place'] : undefined,
      city: typeof parsed['city'] === 'string' ? parsed['city'] : undefined,
      state: typeof parsed['state'] === 'string' ? parsed['state'] : undefined,
      country: typeof parsed['country'] === 'string' ? parsed['country'] : undefined,
      confidence: conf,
      reasoning: typeof parsed['reasoning'] === 'string' ? parsed['reasoning'] : typeof parsed['explanation'] === 'string' ? parsed['explanation'] : '',
      interpretation: typeof parsed['interpretation'] === 'string' ? parsed['interpretation'] : undefined,
      clues: Array.isArray(parsed['clues']) ? (parsed['clues'] as unknown[]).filter((x): x is string => typeof x === 'string').slice(0, 12) : [],
      landmarks: Array.isArray(parsed['landmarks']) ? (parsed['landmarks'] as unknown[]).filter((x): x is string => typeof x === 'string').slice(0, 8) : [],
      locations: locs2,
      model: pick.model,
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    // Every transport failure now attempts the local vision box before giving up — remote 402/401/egress-empty all land here when r.json() throws
    try {
      const remaining = Math.max(5000, timeout - 2000);
      const local = await tryLocalOllamaVision(remaining);
      if (local) return local;
    } catch {}
    const isAbort = msg.includes('abort') || msg.includes('Abort');
    return {
      confidence: 'none',
      reasoning: isAbort ? 'Vision request timed out — try a smaller image or increase timeout.' : `Vision failed: ${msg.slice(0, 280)} — local fallback also unavailable (is 192.168.1.162:11434 reachable?)`,
      clues: [],
      model: pick.model,
      note: msg.slice(0, 200),
    };
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// Orchestrator — merge EXIF + vision + reverse geocode + hooks
// ---------------------------------------------------------------------------

export function buildHooks(lat?: number, lon?: number, place?: string, exif?: GeospyExifResult): GeospyHooks {
  const pivots: Array<{ label: string; url: string }> = [];
  if (Number.isFinite(lat as number) && Number.isFinite(lon as number)) {
    const la = (lat as number).toFixed(5);
    const lo = (lon as number).toFixed(5);
    pivots.push({ label: 'OpenStreetMap', url: `https://www.openstreetmap.org/#map=16/${la}/${lo}` });
    pivots.push({ label: 'Google Maps', url: `https://www.google.com/maps/search/?api=1&query=${la},${lo}` });
    pivots.push({ label: 'Google Earth', url: `https://earth.google.com/web/search/${la},${lo}` });
    // Google reverse-image: Lens upload endpoint — multipart form posts the image directly
    pivots.push({ label: 'Google Lens (reverse image)', url: `https://lens.google.com/upload` });
    if (place) pivots.push({ label: `Search "${place}" nearby`, url: `https://www.google.com/search?q=${encodeURIComponent(place + ' location')}` });
  } else {
    // No coordinate yet — still offer Lens so operator can push the image to Google
    pivots.push({ label: 'Google Lens (reverse image)', url: `https://lens.google.com/upload` });
  }
  if (place) {
    pivots.push({ label: `OSINT dorks for "${place}"`, url: `https://www.google.com/search?q=${encodeURIComponent('"' + place + '" site:instagram.com OR site:tiktok.com OR site:facebook.com')}` });
  }
  const deviceIntel: string[] = [];
  if (exif?.make || exif?.model) deviceIntel.push(`Camera: ${(exif.make || '').trim()} ${(exif.model || '').trim()}`.trim());
  if (exif?.datetime) deviceIntel.push(`Captured: ${exif.datetime}`);
  if (exif?.altitude != null) deviceIntel.push(`Altitude: ${Math.round(exif.altitude)}m`);

  return {
    trackingLinkHint: 'Social-engineering hook: clone this scene as a tracking page (Geospy classic) — /api/geospy/hook?lat={lat}&lon={lon} (RESEARCH USE ONLY, receipted)',
    pivots,
    deviceIntel,
  };
}

// ---------------------------------------------------------------------------
// Google grounding — like Google Images: text search for vision clues to corroborate
// Uses DuckDuckGo HTML (keyless, no API key) via egress-aware directFetch.
// ---------------------------------------------------------------------------

export interface GoogleGrounding {
  query: string;
  hits: Array<{ title: string; url: string; snippet?: string }>;
  note?: string;
}

export interface LensHit {
  title: string;
  url: string;
  thumbUrl?: string;
  imageUrl?: string;
  source?: string;
  /** Server-fetched copy of the thumb as a data: URL — cannot be referrer-blocked (measured: hotlinked thumbs fail on some CDNs) */
  thumbDataUrl?: string;
}

export interface LensResult {
  queryHint: string;
  hits: LensHit[];
  refinedVision?: GeospyVisionResult | null;
  refinedFrom?: LensHit | null;
  note?: string;
  /** Google Lens vsrid URL — results are JS-only server-side (measured 2026-10-29), this is the open-in-your-browser hand-off */
  lensHandoff?: string;
}

function pickBestLensHitForRefine(hits: LensHit[]): LensHit | null {
  if (!hits.length) return null;
  // Prefer hits that actually carry a fetchable image URL
  return hits.find((h) => !!h.imageUrl) || hits[0] || null;
}

// ---------------------------------------------------------------------------
// Bing Visual Search (reverse image by URL) — the lane that actually works
// server-side. Measured 2026-10-29: Google Lens upload returns a pure JS shell
// (vsrid page, zero data) and headless renders hit the /sorry CAPTCHA wall, so
// machine-readable reverse-image results come from Bing's server-rendered HTML:
// anchors class="iusc" carry m="{...}" (HTML-escaped JSON) with murl (source
// image on the page), turl (Bing-hosted thumb, hotlinkable), purl (the page).
// ---------------------------------------------------------------------------

const BING_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

function titleFromPurl(purl: string): string {
  try {
    const u = new URL(purl);
    const seg = u.pathname.split('/').filter(Boolean).pop() || '';
    const base = decodeURIComponent(seg).replace(/\.(html?|php|aspx?|jpe?g|png|webp|gif)$/i, '').replace(/[-_+]+/g, ' ').trim();
    if (base.length >= 4) return base.slice(0, 100);
    return u.hostname.replace(/^www\./, '');
  } catch { return purl.slice(0, 60); }
}

/** True for URLs that are Google-internal shells a logged-out click can't use. */
function isDeadClickTarget(url: string): boolean {
  if (!/^https?:\/\//i.test(url)) return true;
  return /(^|\.)google\.[a-z.]+\/(search|url\?|imgres|advanced_search|preferences|support)|accounts\.google|policies\.google/i.test(url);
}

export async function bingVisualSearch(imageUrl: string, timeoutMs = 12000, cap = 10): Promise<{ hits: LensHit[]; blocked?: string }> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), Math.max(5000, timeoutMs));
  try {
    const u = `https://www.bing.com/images/search?view=detailv2&iss=sbi&form=SBIVSP&sbisrc=UrlPaste:${encodeURIComponent(imageUrl)}&q=imgurl:${encodeURIComponent(imageUrl)}`;
    const r = await directFetch(u as never, { headers: { 'user-agent': BING_UA, 'accept-language': 'en-US,en' }, signal: ctrl.signal as never } as never) as unknown as globalThis.Response;
    if (!r.ok) return { hits: [], blocked: `Bing visual search HTTP ${r.status} — blocked, not a real zero` };
    const html = await (r as unknown as { text(): Promise<string> }).text();
    const hits: LensHit[] = [];
    const seen = new Set<string>();
    const re = /class="iusc"[^>]*?\sm="([^"]+)"/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(html)) && hits.length < cap) {
      let json: string;
      try { json = m[1].replace(/&quot;/g, '"').replace(/&amp;/g, '&'); } catch { continue; }
      let meta: { murl?: string; turl?: string; purl?: string; t?: string } = {};
      try { meta = JSON.parse(json) as typeof meta; } catch { continue; }
      let purl = (meta.purl || '').trim();
      const murl = (meta.murl || '').trim();
      const turl = (meta.turl || '').trim();
      if (!purl && !murl) continue;
      // Google-internal shells can't be used logged-out — fall back to the image itself as the click target
      if (isDeadClickTarget(purl)) purl = '';
      const click = purl || (murl && /^https?:\/\//i.test(murl) ? murl : '');
      if (!click) continue;
      if (seen.has(click)) continue;
      seen.add(click);
      hits.push({
        title: (meta.t || '').trim().slice(0, 120) || titleFromPurl(purl || murl),
        url: click,
        thumbUrl: turl || undefined,
        imageUrl: murl || turl || undefined,
        source: 'bing-visual',
      });
    }
    if (!hits.length) {
      // A 200 with zero iusc anchors is usually a consent/JS wall — an honest UNMEASURED, not a zero
      const finalUrl = String((r as unknown as { url?: string }).url || '');
      if (!/bing\.com\/images/i.test(finalUrl)) return { hits: [], blocked: 'Bing served an interstitial (redirected off /images) — UNMEASURED' };
    }
    return { hits };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { hits: [], blocked: `Bing visual search failed: ${msg.slice(0, 120)}` };
  }
  finally { clearTimeout(t); }
}

/** Fetch small thumbs server-side and inline them as data: URLs so preview cannot be hotlink-blocked. */
async function inlineThumbs(hits: LensHit[], budgetMs = 9000): Promise<void> {
  const targets = hits.filter((h) => (h.thumbUrl || h.imageUrl) && !h.thumbDataUrl).slice(0, 8);
  await Promise.allSettled(targets.map(async (h) => {
    const fetched = await fetchImageAsBase64(h.thumbUrl || (h.imageUrl as string), budgetMs);
    if (fetched && fetched.b64.length < 700_000) h.thumbDataUrl = `data:${fetched.mime};base64,${fetched.b64}`;
  }));
}

/** Upload a base64 image to a public host so Bing Visual can fetch it (uploads otherwise have no public URL for reverse search). */
async function hostBase64ForBing(b64: string, mime: string, timeoutMs = 12000): Promise<string | null> {
  const clean = (b64 || '').replace(/^data:[^;]+;base64,/, '').trim();
  if (clean.length < 500) return null;
  const buf = Buffer.from(clean, 'base64');
  if (buf.length < 512 || buf.length > 18 * 1024 * 1024) return null;
  const ext = mime.includes('png') ? 'png' : mime.includes('webp') ? 'webp' : 'jpg';
  const hosts: Array<{ url: string; makeBody: () => { body: Buffer | Blob; headers: Record<string,string> } }> = [
    {
      url: 'https://catbox.moe/user/api.php',
      makeBody: () => {
        const boundary = '----T3mpHost' + Math.random().toString(16).slice(2);
        const header = `--${boundary}\r\nContent-Disposition: form-data; name="reqtype"\r\n\r\nfileupload\r\n--${boundary}\r\nContent-Disposition: form-data; name="fileToUpload"; filename="geospy.${ext}"\r\nContent-Type: ${mime}\r\n\r\n`;
        const footer = `\r\n--${boundary}--\r\n`;
        const body = Buffer.concat([Buffer.from(header), buf, Buffer.from(footer)]);
        return { body, headers: { 'content-type': `multipart/form-data; boundary=${boundary}` } };
      },
    },
  ];
  for (const host of hosts) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const { body, headers } = host.makeBody();
      const r = await directFetch(host.url as never, {
        method: 'POST',
        headers: { 'user-agent': BING_UA, accept: 'text/plain,*/*;q=0.8', ...headers } as never,
        body: body as unknown as never,
        signal: ctrl.signal as never,
      } as never) as unknown as globalThis.Response;
      const text = await (r as unknown as { text(): Promise<string> }).text().catch(() => '');
      const url = text.trim();
      if (r.ok && /^https?:\/\/[^\/]+\//.test(url) && /\.(png|jpe?g|webp|gif)$/i.test(url)) return url;
      if (r.ok && /^https?:\/\//.test(url)) return url;
    } catch { /* try next host */ }
    finally { clearTimeout(t); }
  }
  return null;
}

async function fetchImageAsBase64(url: string, timeoutMs = 8000): Promise<{ b64: string; mime: string } | null> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await directFetch(url as never, {
      headers: { 'user-agent': 'T3MP3ST-Geospy/1.0 (+https://t3mp3st.local)', accept: 'image/*,*/*;q=0.8' },
      signal: ctrl.signal as never,
    } as never) as unknown as Response;
    if (!r.ok) return null;
    const ct = String((r.headers as unknown as { get(n: string): string | null }).get?.('content-type') || 'image/jpeg').split(';')[0].trim() || 'image/jpeg';
    if (!ct.startsWith('image/')) return null;
    const ab = await (r as unknown as { arrayBuffer(): Promise<ArrayBuffer> }).arrayBuffer();
    if (!ab || (ab as ArrayBuffer).byteLength < 512) return null;
    const b64 = Buffer.from(ab as ArrayBuffer).toString('base64');
    if (b64.length < 800) return null;
    return { b64, mime: ct };
  } catch { return null; } finally { clearTimeout(t); }
}

/**
 * Real Lens reverse-image lookup (the "not working" fix).
 * We POST the raw bytes to https://lens.google.com/v3/upload, follow redirects,
 * then scrape the Lens result HTML for image result URLs. This is the user-
 * visible reverse-image index — the previous card just showed a <form>.
 */
export async function lensReverseSearch(
  imageBase64: string,
  mime = 'image/jpeg',
  opts: { timeoutMs?: number; refineWithVision?: boolean; visionModel?: string; visionTimeoutMs?: number; context?: string; guess?: string; apiKey?: string; publicImageUrl?: string } = {},
): Promise<LensResult> {
  // Machine-readable reverse-image results come from Bing Visual (by URL). Google Lens upload still
  // runs best-effort to capture the vsrid URL as an open-in-your-browser hand-off (its result page is
  // a pure JS shell to scripts and CAPTCHAs headless renders — measured 2026-10-29).
  const clean = (imageBase64 || '').replace(/^data:[^;]+;base64,/, '').trim();
  const timeoutMs = Math.max(8000, Math.min(45000, opts.timeoutMs ?? 18000));
  const publicUrl = (opts.publicImageUrl || '').trim();
  let hits: LensHit[] = [];
  let note: string | undefined;
  let lensHandoff: string | undefined;
  let autoHostedUrl: string | null = null;

  // 1) Bing visual by URL — the real hit source. For base64 uploads (no publicUrl) auto-host to catbox so Bing can fetch.
  let bingUrl = (publicUrl && /^https?:\/\//i.test(publicUrl)) ? publicUrl : '';
  if (!bingUrl && clean.length >= 500) {
    try { autoHostedUrl = await hostBase64ForBing(clean, mime, Math.min(14000, timeoutMs)); } catch { autoHostedUrl = null; }
    if (autoHostedUrl) bingUrl = autoHostedUrl;
  }
  if (bingUrl) {
    const bing = await bingVisualSearch(bingUrl, Math.min(14000, timeoutMs), 10);
    hits = bing.hits;
    if (bing.blocked) note = bing.blocked + (autoHostedUrl ? ' (via auto-hosted URL)' : '');
    else if (!hits.length) note = autoHostedUrl ? 'Bing visual search found no matches for this image (auto-hosted via catbox)' : 'Bing visual search returned no usable matches for this image URL';
    else if (autoHostedUrl) note = 'Reverse image via auto-hosted public URL (catbox) — temporary link';
  } else {
    note = 'Uploaded file has no public URL — machine reverse-search unavailable. Open the Lens link to see matches in your browser.';
  }

  // 2) Lens upload best-effort — capture the vsrid hand-off URL only (never parsed for hits: JS shell).
  // Skipped when Bing already produced hits: a 15s budget for a hand-off button is not worth the latency.
  if (!hits.length && clean.length >= 500) {
    const buf = Buffer.from(clean, 'base64');
    if (buf.length >= 512) {
      const boundary = '----T3mpF0rm' + Math.random().toString(16).slice(2);
      const ext = mime.includes('png') ? 'png' : mime.includes('webp') ? 'webp' : 'jpg';
      const header = `--${boundary}\r\nContent-Disposition: form-data; name="encoded_image"; filename="geospy.${ext}"\r\nContent-Type: ${mime}\r\n\r\n`;
      const footer = `\r\n--${boundary}--\r\n`;
      const body = Buffer.concat([Buffer.from(header), buf, Buffer.from(footer)]);
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), Math.min(15000, timeoutMs));
      try {
        const r = await directFetch('https://lens.google.com/v3/upload' as never, {
          method: 'POST',
          headers: { 'content-type': `multipart/form-data; boundary=${boundary}`, 'user-agent': BING_UA, accept: 'text/html,*/*;q=0.8' },
          body: body as unknown as never,
          redirect: 'follow',
          signal: ctrl.signal as never,
        } as never) as unknown as globalThis.Response;
        await (r as unknown as { text(): Promise<string> }).text().catch(() => '');
        const finalUrl = String((r as unknown as { url?: string }).url || '');
        if (r.ok && /vsrid=/.test(finalUrl)) {
          lensHandoff = finalUrl;
        }
      } catch { /* hand-off is best-effort */ }
      finally { clearTimeout(t); }
    }
  }

  // 3) Inline thumbs as data: URLs — preview cannot be referrer-blocked
  if (hits.length) await inlineThumbs(hits, Math.min(9000, timeoutMs));

  // 4) Second-opinion: re-run vision on the best hit's actual image
  if (opts.refineWithVision !== false && hits.length) {
    const pick = pickBestLensHitForRefine(hits);
    if (pick?.imageUrl) {
      const fetched = await fetchImageAsBase64(pick.imageUrl, Math.min(9000, timeoutMs));
      if (fetched) {
        try {
          const refined = await visionLocate(fetched.b64, fetched.mime, {
            timeoutMs: Math.max(6000, Math.min(30000, opts.visionTimeoutMs ?? 16000)),
            model: opts.visionModel,
            context: opts.context,
            guess: opts.guess,
            apiKey: opts.apiKey,
          });
          const hasLoc = Number.isFinite(refined.lat as number) && Number.isFinite(refined.lon as number);
          const hasPlace = !!(refined.place || refined.city || refined.country);
          if (hasLoc || hasPlace || refined.confidence !== 'none') {
            return { queryHint: publicUrl || autoHostedUrl || lensHandoff || '', hits, refinedVision: refined, refinedFrom: pick, note, lensHandoff };
          }
        } catch { /* keep hits, drop refine */ }
      }
    }
  }
  return { queryHint: publicUrl || autoHostedUrl || lensHandoff || '', hits, note, lensHandoff };
}
export async function googleGroundingSearch(query: string): Promise<GoogleGrounding> {
  const q = query.trim().slice(0, 200);
  if (!q) return { query: q, hits: [], note: 'empty query' };
  const UA = BING_UA;
  const fetchWithTimeout = async (url: string, headers: Record<string,string>, ms=8000): Promise<{ html:string; status:number; finalUrl:string } | null> => {
    const ctrl = new AbortController(); const t=setTimeout(()=>ctrl.abort(), ms);
    try{
      const r = await directFetch(url as never, { headers: headers as never, signal: ctrl.signal as never } as never) as unknown as globalThis.Response;
      const html = await (r as unknown as { text():Promise<string>}).text();
      return { html, status: r.status, finalUrl: String((r as unknown as {url?:string}).url||url) };
    }catch{ return null; }finally{ clearTimeout(t); }
  };
  const parseDuck = (html:string): Array<{title:string;url:string}> => {
    const hits: Array<{title:string;url:string}> = [];
    const re = /<a[^>]+class="result__url"[^>]*href="([^"]+)"[^>]*>([^<]+)<\/a>/gi;
    let m: RegExpExecArray|null;
    while((m=re.exec(html)) && hits.length<6){
      try{
        const href=m[1].replace(/&amp;/g,'&');
        const u=new URL(href,'https://duckduckgo.com');
        const real=u.searchParams.get('uddg')?decodeURIComponent(u.searchParams.get('uddg')!):href;
        hits.push({title:m[2].trim().slice(0,120), url: real.slice(0,300)});
      }catch{/*ignore*/}
    }
    if(!hits.length){
      const re2=/result__title[^>]*>[\s\S]*?<a[^>]+href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/gi;
      while((m=re2.exec(html)) && hits.length<6){
        const href=m[1].replace(/&amp;/g,'&'); const title=m[2].replace(/<[^>]+>/g,'').trim().slice(0,120);
        if(title && href.startsWith('http')) hits.push({title, url: href.slice(0,300)});
      }
    }
    return hits;
  };
  const parseBing = (html:string): Array<{title:string;url:string;snippet?:string}> => {
    const hits: Array<{title:string;url:string;snippet?:string}> = [];
    // Bing HTML: <li class="b_algo"><h2><a href="URL">title
    const re = /<li[^>]+class="[^"]*b_algo[^"]*"[\s\S]*?<h2[^>]*>\s*<a[^>]+href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/gi;
    let m: RegExpExecArray|null;
    while((m=re.exec(html)) && hits.length<6){
      const href=m[1].replace(/&amp;/g,'&');
      const title=m[2].replace(/<[^>]+>/g,'').trim().slice(0,120);
      if(title && href.startsWith('http') && !/bing\.com|microsoft\.com/i.test(href)) hits.push({title, url: href.slice(0,300)});
    }
    return hits;
  };
  // 1) DuckDuckGo primary (Chrome UA, timeout)
  const duck = await fetchWithTimeout(`https://html.duckduckgo.com/html/?q=${encodeURIComponent(q)}`, { 'user-agent': UA, 'accept-language':'en-US,en', accept:'text/html,*/*;q=0.8' }, 8000);
  if(duck && duck.status===200){
    const hits = parseDuck(duck.html);
    if(hits.length) return { query: q, hits };
    // Duck returns interstitial/captcha if hits 0 but html large — try Bing instead of reporting 0
    const isInterstitial = /captcha|attention required|blocked/i.test(duck.html.slice(0,2000)) || duck.html.length < 800;
    if(!isInterstitial && duck.html.includes('result')) return { query: q, hits: [], note: 'no hits parsed' };
  }
  // 2) Bing fallback (proven server-side pattern already used for visual search)
  const bing = await fetchWithTimeout(`https://www.bing.com/search?q=${encodeURIComponent(q)}&form=QBRE`, { 'user-agent': UA, 'accept-language':'en-US,en', accept:'text/html,*/*;q=0.8' }, 8000);
  if(bing && bing.status===200){
    const hits = parseBing(bing.html);
    if(hits.length) return { query: q, hits, note: 'via Bing (DuckDuckGo empty/blocked)' };
    if(/captcha|attention|blocked/i.test(bing.html.slice(0,2000))) return { query: q, hits: [], note: 'search blocked (interstitial) — UNMEASURED' };
    return { query: q, hits: [], note: 'no hits parsed' };
  }
  const errNote = (!duck && !bing) ? 'search failed: network/timeout' : (duck && duck.status!==200 ? `DuckDuckGo HTTP ${duck.status} — UNMEASURED` : (bing && bing.status!==200 ? `Bing HTTP ${bing.status} — UNMEASURED` : 'search blocked — UNMEASURED'));
  return { query: q, hits: [], note: errNote };
}

export async function fetchImageUrlAsBase64(imageUrl: string): Promise<{ b64: string; mime: string } | { error: string }> {
  const url = String(imageUrl || '').trim();
  if (!/^https?:\/\//i.test(url)) return { error: 'imageUrl must be http(s) URL' };
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 10000);
  try {
    const r = await directFetch(url as never, {
      headers: { 'user-agent': 'T3MP3ST-Geospy/1.0 (+https://t3mp3st.local)', accept: 'image/*,*/*;q=0.8' },
      signal: ctrl.signal as never,
    } as never) as unknown as Response;
    if (!r.ok) return { error: `HTTP ${r.status} fetching imageUrl` };
    const ctRaw = String((r.headers as unknown as { get(n: string): string | null }).get?.('content-type') || '').split(';')[0].trim();
    const ct = ctRaw || 'image/jpeg';
    if (ctRaw && !ctRaw.startsWith('image/')) return { error: `URL did not return an image (Content-Type: ${ctRaw})` };
    const ab = await (r as unknown as { arrayBuffer(): Promise<ArrayBuffer> }).arrayBuffer();
    if (!ab || (ab as ArrayBuffer).byteLength < 512) return { error: 'image too small or empty' };
    if ((ab as ArrayBuffer).byteLength > 20 * 1024 * 1024) return { error: 'image too large — max 20 MB' };
    const b64 = Buffer.from(ab as ArrayBuffer).toString('base64');
    const mime = ct.startsWith('image/') ? ct : 'image/jpeg';
    return { b64, mime };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { error: msg.includes('abort') ? 'imageUrl fetch timed out' : `fetch failed: ${msg.slice(0,120)}` };
  } finally { clearTimeout(t); }
}

export async function analyzeGeospyImage(
  imageBase64: string,
  mime: string,
  opts: { doVision?: boolean; visionTimeoutMs?: number; context?: string; guess?: string; model?: string; doGoogle?: boolean; doLens?: boolean; lensRefineTimeoutMs?: number; apiKey?: string; exifImageBase64?: string; publicImageUrl?: string } = {},
): Promise<GeospyVerdict> {
  const cleanB64 = (imageBase64 || '').replace(/^data:[^;]+;base64,/, '').trim();
  // EXIF comes from the ORIGINAL upload when the caller downscaled for the vision call (canvas re-encoding strips metadata)
  const exifB64 = (opts.exifImageBase64 || '').replace(/^data:[^;]+;base64,/, '').trim() || cleanB64;
  let exif: GeospyExifResult = { hasGps: false };
  try {
    if (exifB64) {
      const buf = Buffer.from(exifB64, 'base64');
      exif = parseExifGps(new Uint8Array(buf));
    }
  } catch {
    exif = { hasGps: false, strippedHint: 'EXIF parse failed — likely not a JPEG or truncated upload' };
  }

  let vision: GeospyVisionResult = {
    confidence: 'none',
    reasoning: 'Vision not run',
    clues: [],
    model: 'none',
  };
  if (opts.doVision !== false && cleanB64) {
    vision = await visionLocate(cleanB64, mime || 'image/jpeg', { timeoutMs: opts.visionTimeoutMs, context: opts.context, guess: opts.guess, model: opts.model, apiKey: opts.apiKey });
    // GeoIntel synthesis: if model gave top-level lat/lon but no locations array, fabricate one High/Medium candidate so frontend's ranked list + per-candidate Maps links always appear
    if ((!vision.locations || !vision.locations.length) && Number.isFinite(vision.lat as number) && Number.isFinite(vision.lon as number)) {
      vision.locations = [{ city: vision.city, state: vision.state, country: vision.country, lat: vision.lat as number, lon: vision.lon as number, confidence: vision.confidence === 'none' ? 'low' : vision.confidence, explanation: vision.reasoning?.slice(0, 220) || vision.interpretation?.slice(0, 220) || '' }];
    }
  } else if (opts.doVision === false) {
    vision = { confidence: 'none', reasoning: 'Vision skipped — EXIF-only mode', clues: [], model: 'none', note: 'vision disabled by caller' };
  }

  // Best coordinate: EXIF wins, else vision
  let lat: number | undefined;
  let lon: number | undefined;
  let source: GeospySource = 'vision';
  let confidence: GeospyConfidence = vision.confidence;

  if (exif.hasGps && Number.isFinite(exif.lat as number) && Number.isFinite(exif.lon as number)) {
    lat = exif.lat as number;
    lon = exif.lon as number;
    source = vision.lat != null && vision.lon != null ? 'hybrid' : 'exif';
    confidence = 'high'; // real GPS beats any guess
  } else if (Number.isFinite(vision.lat as number) && Number.isFinite(vision.lon as number)) {
    lat = vision.lat as number;
    lon = vision.lon as number;
    source = 'vision';
    confidence = vision.confidence;
  } else {
    confidence = exif.hasGps ? 'high' : vision.confidence;
  }

  let reverse: { label: string; address: Record<string, string> } | null = null;
  if (Number.isFinite(lat as number) && Number.isFinite(lon as number)) {
    try { reverse = await reverseGeocode(lat as number, lon as number); } catch { /* ignore */ }
  }

  // Google grounding (like Google Images) — web search for vision clues when requested or when vision has a place but no web confirmation
  let googleGrounding: GoogleGrounding | null = null;
  const wantGoogle = opts.doGoogle !== false; // default ON — second opinion via web, operator can disable with doGoogle:false
  function buildGroundingQuery(vision: GeospyVisionResult): string {
    const parts: string[] = [];
    const place = (vision.place||'').trim();
    if(place) parts.push(`"${place}"`);
    if(vision.city) parts.push(vision.city);
    if(vision.country) parts.push(vision.country);
    const lms = (vision.landmarks||[]).slice(0,2).filter(s=>s && s.length>=3 && s.length<50);
    lms.forEach(l=>parts.push(`"${l}"`));
    // pick first clue with signal, skip generic sky/shadow/vegetation lines
    const genericRe = /^(sky|shadow|sun|vegetation|terrain|atmosphere|lighting|haze|cloud)/i;
    const clue = (vision.clues||[]).find(c=>c && c.length>18 && !genericRe.test(c.trim()));
    if(clue){
      const kw = clue.replace(/^[^:]*:\s*/,'').split(/[,.;—]/)[0].trim().slice(0,60);
      if(kw.length>10 && !/^\d+$/.test(kw)) parts.push(kw);
    }
    const q = parts.join(' ').trim().slice(0,200);
    return q || (vision.clues?.[0]?.slice(0,120) || place || '');
  }
  if (wantGoogle) {
    const q2 = buildGroundingQuery(vision);
    if(q2 && q2.length>=4){
      try { googleGrounding = await googleGroundingSearch(q2); } catch { /* ignore */ }
    }
  }

  // Lens reverse-image + second vision pass — the image hits get fed back to the main model for assessment
  let lens: LensResult | null = null;
  if (opts.doLens !== false && (cleanB64.length >= 500 || (opts.publicImageUrl || '').length > 10)) {
    try {
      lens = await lensReverseSearch(cleanB64, mime || 'image/jpeg', {
        refineWithVision: true,
        visionModel: opts.model,
        visionTimeoutMs: opts.lensRefineTimeoutMs ?? Math.max(6000, Math.min(22000, opts.visionTimeoutMs ?? 16000)),
        context: opts.context,
        guess: opts.guess,
        apiKey: opts.apiKey,
        publicImageUrl: opts.publicImageUrl,
      });
    } catch { /* Lens is best-effort — never fails the primary verdict */ }
  }

  // If primary vision drew a blank but the Lens second-pass hit a place, promote it into a soft vision verdict
  // so the map actually drops a pin — EXIF/hybrid pins still outrank this.
  let effectiveVision = vision;
  let effectiveSource = source;
  let effectiveLat = lat;
  let effectiveLon = lon;
  let effectiveConfidence = confidence;
  const refined = lens?.refinedVision;
  const refinedHasLoc = !!(refined && Number.isFinite(refined.lat as number) && Number.isFinite(refined.lon as number));
  const primaryHasLoc = Number.isFinite(effectiveLat as number) && Number.isFinite(effectiveLon as number);
  if (refinedHasLoc && !primaryHasLoc) {
    const tag = `Lens re-analysis of "${(lens?.refinedFrom?.title || 'top Lens hit').slice(0, 60)}"`;
    effectiveVision = {
      ...refined!,
      reasoning: `${tag}: ${refined!.reasoning || ''}`.slice(0, 900),
      note: [refined!.note, tag].filter(Boolean).join(' | ').slice(0, 280) || tag,
    };
    effectiveSource = exif.hasGps ? 'hybrid' : 'vision';
    effectiveLat = refined!.lat as number;
    effectiveLon = refined!.lon as number;
    effectiveConfidence = refined!.confidence;
    if (Number.isFinite(effectiveLat as number) && Number.isFinite(effectiveLon as number)) {
      try { reverse = await reverseGeocode(effectiveLat as number, effectiveLon as number); } catch {}
    }
  }

  return { source: effectiveSource, lat: effectiveLat, lon: effectiveLon, confidence: effectiveConfidence, exif, vision: effectiveVision, reverse, hooks: buildHooks(effectiveLat, effectiveLon, effectiveVision.place || reverse?.label, exif), googleGrounding, lens };
}
