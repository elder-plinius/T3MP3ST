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
    const fires = (c: string) => expect(detect(c).has('B-MEMCPY'), c).toBe(true);
    const silent = (c: string) => expect(detect(c).has('B-MEMCPY'), c).toBe(false);

    // fires on a variable / field / deref / wire-decoded / cast length
    fires('memcpy(buf, pkt + 4, len);');
    fires('memcpy(dst, src, hdr->len);');
    fires('memcpy(dst, src, ntohl(hdr->len));');
    fires('memmove(d, s, n);');
    fires('memcpy(&d, s, (size_t)len);');
    fires('memcpy(&local_38, param_1, size);');
    // pointer casts on args 1-2 are the common decompiled shape — must still fire
    fires('memcpy((void *)dst, src, len);');
    fires('memmove((uint8_t *)dst, (uint8_t *)src, len);');
    fires('memcpy((char *)dst + 4, src, len);');
    // a comma-bearing call in an arg is consumed as one arg, so a non-constant
    // length after it is still caught
    fires('memcpy(get_dst(a,b), src, len);');

    // silent when the length is sizeof-bounded or a numeric literal — this is what
    // forces a discriminating rule rather than a bare /memcpy/ match
    silent('memcpy(dst, src, sizeof(dst));');
    silent('memcpy(hdr, src, 4);');
    silent('memcpy(dst, src, 0x40);');
    silent('memcpy(dst, src, sizeof(struct hdr));');
    // a comma inside a nested call must NOT mis-split the arg list and false-fire
    // on a bounded sizeof length; casts on args 1-2 must not either
    silent('memcpy(dst, get_src(a,b), sizeof(dst));');
    silent('memcpy((void *)dst, (void *)src, sizeof(dst));');

    // Disclosed directional limits (see the rule comment): these non-constant
    // lengths are NOT flagged — pinned here so the scope boundary is auditable and
    // any future tightening surfaces as a deliberate change, not a silent one.
    silent('memcpy(d, s, 8 * count);'); //          leading-digit computed length
    silent('memcpy(d, s, sizeof(x) + n);'); //      sizeof plus a variable term
    silent('memcpy(dst, wrap(get(a,b)), len);'); // doubly-nested paren in an arg
    silent('__memcpy_chk(dst, src, len, dn);'); //  _chk variant (usually bounded)
    silent('wmemcpy(dst, src, len);'); //           wide-char variant
  });

  it('ruleset spans memory-safety + injection + integer-overflow', () => {
    expect(RULES.length).toBeGreaterThanOrEqual(6);
    expect(RULES.some((r) => r.id === 'B-CMD-INJECTION')).toBe(true);
    expect(RULES.some((r) => r.id === 'B-INT-OVERFLOW')).toBe(true);
    expect(RULES.some((r) => r.id === 'B-MEMCPY')).toBe(true);
  });
});
