/**
 * Locks the Binary/RE loadout's decompiled-vuln detector + benchmark into CI: the ruleset must catch
 * every seeded memory-safety / injection sink in the corpus and stay clean on the bounded-function
 * controls (strncpy/snprintf/fgets, literal printf). Deterministic + self-contained.
 */
import { describe, it, expect } from 'vitest';
import { loadCorpus, detect, scoreCorpus, RULES } from '../../scripts/binary-vuln-bench.mjs';

describe('binary/RE decompiled-vuln benchmark', () => {
  const corpus = loadCorpus();
  const score = scoreCorpus(corpus);

  it('corpus has seeded sinks + safe controls with ground truth', () => {
    expect(corpus.fixtures.length).toBeGreaterThanOrEqual(6);
    expect(corpus.fixtures.some((f) => f.clean)).toBe(true);
    expect(corpus.fixtures.every((f) => f.clean || f.expect.length > 0)).toBe(true);
  });

  it('detects every seeded sink', () => {
    expect(score.detection.hits).toBe(score.detection.total);
    expect(score.detection.total).toBeGreaterThanOrEqual(6);
  });

  it('does not false-positive on bounded-function controls', () => {
    expect(score.discrimination.falsePositives).toBe(0);
    // the bounded equivalents must NOT trip the unbounded rules
    expect(detect('strncpy(buf, src, sizeof(buf) - 1);').size).toBe(0);
    expect(detect('snprintf(out, sizeof(out), "%s", x);').size).toBe(0);
    expect(detect('fgets(name, sizeof(name), stdin);').size).toBe(0);
    // ...but the unbounded ones must
    expect(detect('strcpy(buf, src);').has('B-STRCPY')).toBe(true);
    expect(detect('printf(user);').has('B-FORMAT-STRING')).toBe(true);
  });

  it('flags memcpy/memmove with a non-constant length, not a bounded one', () => {
    // fires on a variable / wire-controlled / computed length
    expect(detect('memcpy(buf, pkt + 4, len);').has('B-MEMCPY')).toBe(true);
    expect(detect('memcpy(dst, src, hdr->len);').has('B-MEMCPY')).toBe(true);
    expect(detect('memcpy(dst, src, ntohl(hdr->len));').has('B-MEMCPY')).toBe(true);
    expect(detect('memmove(d, s, n);').has('B-MEMCPY')).toBe(true);
    // stays silent when the length is sizeof-bounded or a numeric literal —
    // this is what forces a discriminating rule rather than a bare /memcpy/ match
    expect(detect('memcpy(dst, src, sizeof(dst));').has('B-MEMCPY')).toBe(false);
    expect(detect('memcpy(hdr, src, 4);').has('B-MEMCPY')).toBe(false);
    expect(detect('memcpy(dst, src, 0x40);').has('B-MEMCPY')).toBe(false);
  });

  it('ruleset spans memory-safety + injection + integer-overflow', () => {
    expect(RULES.length).toBeGreaterThanOrEqual(6);
    expect(RULES.some((r) => r.id === 'B-CMD-INJECTION')).toBe(true);
    expect(RULES.some((r) => r.id === 'B-INT-OVERFLOW')).toBe(true);
    expect(RULES.some((r) => r.id === 'B-MEMCPY')).toBe(true);
  });
});
