/**
 * Shared adjudicate + cite-check (Phase-0 #5) — the two safety primitives lifted from
 * scripts/refute-finding.mjs into a pure src/mission/adjudicate.ts so the disclosure CLI
 * and the live pack-audit path can't drift (the pack-hunt design, HT-2).
 *
 * Pins: strict-majority thresholds; a MINORITY refute does NOT flip; ties don't refute;
 * a REFUTED whose killing_guard fails guardExistsInSource is downgraded to SURVIVED;
 * null/abstain handling never counts as a refute.
 */
import { describe, it, expect } from 'vitest';
import {
  adjudicate,
  guardExistsInSource,
  downgradeUnverifiedRefutes,
  type RefuterVote,
} from '../mission/adjudicate.js';

const refuted = (guard?: { file: string; line: number; quote: string }): RefuterVote => ({
  verdict: 'REFUTED',
  killing_guard: guard ?? null,
});
const survived = (): RefuterVote => ({ verdict: 'SURVIVED', killing_guard: null });

describe('adjudicate — strict-majority tally', () => {
  it('2 of 3 REFUTED → REFUTED (strict majority)', () => {
    const a = adjudicate([refuted(), refuted(), survived()]);
    expect(a.verdict).toBe('REFUTED');
    expect(a.refutedCount).toBe(2);
    expect(a.total).toBe(3);
  });

  it('1 of 3 REFUTED → SURVIVED (a MINORITY refute does NOT flip)', () => {
    const a = adjudicate([refuted(), survived(), survived()]);
    expect(a.verdict).toBe('SURVIVED');
    expect(a.refutedCount).toBe(1);
  });

  it('a TIE does not refute — 1 of 2 REFUTED → SURVIVED (need STRICT majority)', () => {
    expect(adjudicate([refuted(), survived()]).verdict).toBe('SURVIVED');
  });

  it('a TIE does not refute — 2 of 4 REFUTED → SURVIVED', () => {
    expect(adjudicate([refuted(), refuted(), survived(), survived()]).verdict).toBe('SURVIVED');
  });

  it('3 of 4 REFUTED → REFUTED', () => {
    expect(adjudicate([refuted(), refuted(), refuted(), survived()]).verdict).toBe('REFUTED');
  });

  it('unanimous single REFUTED → REFUTED; single SURVIVED → SURVIVED', () => {
    expect(adjudicate([refuted()]).verdict).toBe('REFUTED');
    expect(adjudicate([survived()]).verdict).toBe('SURVIVED');
  });

  it('collects killing guards from the counted REFUTED votes (nulls dropped)', () => {
    const g = { file: 'x.c', line: 9, quote: 'if (n > cap) return' };
    const a = adjudicate([refuted(g), refuted(g), survived()]);
    expect(a.killing_guards).toHaveLength(2);
    // a REFUTED with a null guard contributes no entry
    const b = adjudicate([refuted(g), refuted(), refuted()]);
    expect(b.killing_guards).toHaveLength(1);
  });
});

describe('adjudicate — null / abstain handling', () => {
  it('null and junk verdicts are dropped: neither refute count nor panel size', () => {
    // 1 real REFUTED, plus a null and a junk vote → panel size 1, not a majority-of-3
    const a = adjudicate([refuted(), null, { verdict: 'MAYBE' } as RefuterVote]);
    expect(a.total).toBe(1);
    expect(a.refutedCount).toBe(1);
    expect(a.verdict).toBe('REFUTED'); // 1 of 1 valid
  });

  it('abstentions cannot manufacture a majority — 1 REFUTED + 2 abstain among 2 survived stays SURVIVED', () => {
    const a = adjudicate([refuted(), survived(), survived(), null, { verdict: 'junk' } as RefuterVote]);
    expect(a.total).toBe(3);
    expect(a.verdict).toBe('SURVIVED');
  });

  it('empty panel → INCONCLUSIVE', () => {
    expect(adjudicate([]).verdict).toBe('INCONCLUSIVE');
    expect(adjudicate([null, undefined, { verdict: 'junk' } as RefuterVote]).verdict).toBe('INCONCLUSIVE');
    expect(adjudicate([null]).total).toBe(0);
  });
});

describe('guardExistsInSource — deterministic cite-check', () => {
  const source = [
    'void copy(size_t n) {',
    '  if (n > cap) return;   // the real killing guard',
    '  memcpy(dst, src, n);',
    '}',
  ].join('\n');

  it('verifies an exact quote (normalized substring, whitespace-insensitive)', () => {
    expect(guardExistsInSource({ file: 'a.c', line: 2, quote: 'if (n > cap) return' }, source)).toBe(true);
    // reformatted (extra spaces / different indent) still verifies
    expect(guardExistsInSource({ file: 'a.c', line: 2, quote: 'if(n>cap)   return' }, source)).toBe(true);
  });

  it('verifies a reversed-order comparison via the structural fallback (operator mirrored)', () => {
    // not a substring (operands swapped), but source `n > cap` ≡ cited `cap < n` — same guard, mirrored.
    expect(guardExistsInSource({ file: 'a.c', line: 2, quote: 'cap < n' }, source)).toBe(true);
    // same operands + same operator, just reformatted, also verifies structurally.
    expect(guardExistsInSource({ file: 'a.c', line: 2, quote: 'n>cap' }, source)).toBe(true);
  });

  it('REJECTS a same-operand comparison with the WRONG operator (a different guard, not a paraphrase)', () => {
    // source guard is `n > cap`; a cited `n >= cap` is a DIFFERENT bound (it also blocks n==cap) and
    // must NOT verify just because it shares the operands — the operator carries the guard's meaning.
    expect(guardExistsInSource({ file: 'a.c', line: 2, quote: 'n >= cap' }, source)).toBe(false);
    expect(guardExistsInSource({ file: 'a.c', line: 2, quote: 'n == cap' }, source)).toBe(false);
    expect(guardExistsInSource({ file: 'a.c', line: 2, quote: 'cap <= n' }, source)).toBe(false); // wrong mirror
  });

  // --- regex-literal tokenizing (adversarial review sixth pass): a quote INSIDE a regex must not open
  //     a phantom string that swallows a real guard on a later line. ---
  it('a quote inside a regex literal does NOT blank a real guard on a later line', () => {
    const src = [
      `function handle(idx, buf) {`,
      `  const cleaned = name.replace(/['"]/g, '');`, // ubiquitous sanitizer — quotes live in the regex
      `  if (idx >= buf.length) return ERR;`, //           the real killing guard, on the NEXT line
      `  return buf[idx];`,
      `}`,
    ].join('\n');
    expect(guardExistsInSource({ file: 'a.js', line: 3, quote: 'idx >= buf.length' }, src)).toBe(true);
  });

  it('an apostrophe-bearing regex does NOT blank a downstream comparison guard', () => {
    const src = [
      `s = s.replace(/'/g, "x");`, //                    a stray apostrophe inside the regex
      `if (userId >= tenant.limit) throw new Error('scope');`, // the real guard must still verify
    ].join('\n');
    expect(guardExistsInSource({ file: 'a.js', line: 2, quote: 'userId >= tenant.limit' }, src)).toBe(true);
  });

  it('still REJECTS a comparison that lives ONLY inside a regex literal (no false-verify)', () => {
    // the regex body is blanked like a string, so a hallucinated guard cannot hide there.
    const src = `const re = /idx >= len/; return arr[idx];`;
    expect(guardExistsInSource({ file: 'a.js', line: 1, quote: 'idx >= len' }, src)).toBe(false);
  });

  // --- seventh-pass BLOCKER: a regex in VALUE position (return/typeof/close-paren) must NOT leak its
  //     body — else a comparison that only lives inside the regex false-verifies a hallucinated guard. ---
  it('a value-position regex body cannot false-verify a hallucinated guard (return / if(x) /re/)', () => {
    expect(guardExistsInSource({ file: 'a.ts', line: 3, quote: 'm_id >= ls.w' },
      'const cell = ls.cells[m_id];\nreturn /m_id >= ls.w/.test(String(m_id));')).toBe(false);
    expect(guardExistsInSource({ file: 'a.js', line: 1, quote: 'a >= b' }, 'return /a >= b/.test(x);')).toBe(false);
    expect(guardExistsInSource({ file: 'a.js', line: 1, quote: 'a >= b' }, 'if (x) /a >= b/.test(y);')).toBe(false);
  });

  it('over-blanks a JS guard sharing a line AFTER a regex (safe: SURVIVED), keeps it in a no-regex language', () => {
    // A regex-bearing language (JS): everything after a regex `/` on the line is conservatively blanked
    // to end-of-line, so this same-line-after-regex guard does NOT verify — a false-REJECT (→ the
    // finding SURVIVES), the module's safe direction. The realistic case (guard on its OWN line) still
    // verifies (covered by the tests above).
    expect(guardExistsInSource({ file: 'a.js', line: 1, quote: 'idx < len' },
      `function f(s, idx, len) { return /['"]/.test(s) && idx < len; }`)).toBe(false);
    // A no-regex language (C/C++/…) keeps every `/` as division, so a real comparison sharing a line
    // with a division verifies at full fidelity.
    expect(guardExistsInSource({ file: 'a.c', line: 1, quote: 'idx < len' },
      'int g(int idx, int len) { int r = a / b; if (idx < len) return r; }')).toBe(true);
  });

  it('a single division on the guard line is preserved (idx >= len / 2)', () => {
    expect(guardExistsInSource({ file: 'a.js', line: 1, quote: 'idx >= len / 2' }, 'if (idx >= len / 2) return;')).toBe(true);
  });

  // --- 8th-pass BLOCKER: a DIVISION `/` earlier on a line must not mis-pair with a later regex's
  //     opening `/` (which would leak the regex body) or with a comment's `/` (leaking the comment). ---
  it('a division before a regex does not leak the regex body (no mis-pairing false-verify)', () => {
    expect(guardExistsInSource({ file: 'a.js', line: 1, quote: 'idx >= len' }, 'y = a / b; const re = /idx >= len/.test(z);')).toBe(false);
    expect(guardExistsInSource({ file: 'a.js', line: 1, quote: 'idx >= len' }, 'y = foo() / b; const re = /idx >= len/.test(z);')).toBe(false);
  });

  it('a division before a comment does not leak the comment body', () => {
    expect(guardExistsInSource({ file: 'a.js', line: 1, quote: 'lo <= hi' }, 'y = w / 2; // lo <= hi')).toBe(false);
    expect(guardExistsInSource({ file: 'a.js', line: 1, quote: 'lo <= hi' }, 'y = w / 2; /* lo <= hi */ z = 0;')).toBe(false);
  });

  it('a division after a CALL is preserved, and a regex after a CONTROL-flow ) is blanked', () => {
    expect(guardExistsInSource({ file: 'a.js', line: 1, quote: 'idx < getLen() / 2' }, 'if (idx < getLen() / 2) return;')).toBe(true); // call-div kept
    expect(guardExistsInSource({ file: 'a.js', line: 1, quote: 'idx >= len' }, 'if (x) /idx >= len/.test(y);')).toBe(false); // control-) regex blanked
  });

  // --- 9th-pass BLOCKERS: a regex after a block-closing `}`, after a keyword-as-PROPERTY, or after a
  //     block comment must not leak its body (the position-heuristic lexers all missed these). ---
  it('a regex after a block-closing } does not leak its body', () => {
    expect(guardExistsInSource({ file: 'a.js', line: 1, quote: 'idx > len' }, '{ let a = 1; } /idx > len/.test(input);')).toBe(false);
    expect(guardExistsInSource({ file: 'a.js', line: 1, quote: 'idx > len' }, 'if (c) { work(); } /idx > len/.exec(s);')).toBe(false);
    expect(guardExistsInSource({ file: 'a.js', line: 1, quote: 'idx > len' }, 'function h(){ return 0; } /idx > len/.test(q);')).toBe(false);
  });

  it('a regex after a keyword used as a PROPERTY (o.in / c) does not leak (no division mis-pair)', () => {
    expect(guardExistsInSource({ file: 'a.js', line: 1, quote: 'idx > len' }, 'const n = o.in / c; return raw.replace(/idx > len/g,"");')).toBe(false);
  });

  it('a regex after a block comment does not leak its body', () => {
    expect(guardExistsInSource({ file: 'a.js', line: 1, quote: 'idx > len' }, '/* note */ const re = /idx > len/.test(s);')).toBe(false);
    expect(guardExistsInSource({ file: 'a.js', line: 1, quote: 'idx > len' }, 'if /*c*/ (x) /idx > len/.test(y);')).toBe(false);
  });

  it('a regex containing BOTH a comparison and a quote does not leak (/a > b\'/)', () => {
    expect(guardExistsInSource({ file: 'a.js', line: 1, quote: 'a > b' }, "z = /a > b'/.test(s);")).toBe(false);
  });

  // --- 10th-pass BLOCKERS (fixed by deciding regex-vs-division by LANGUAGE, not per-`/`): a regex-
  //     internal quote must not consume a later real string's quote, and a `\`-continued string must
  //     not leak its comparison. ---
  it('a regex-internal quote does not consume a later string, leaking its comparison', () => {
    expect(guardExistsInSource({ file: 'x.ts', line: 1, quote: 'b > c' }, "const r = /a'/.test(x) ? y : 'b > c';")).toBe(false);
    expect(guardExistsInSource({ file: 'x.js', line: 1, quote: 'm_id >= ls.w' }, "if (/x'/.test(name)) log('m_id >= ls.w');")).toBe(false);
  });

  it('a backslash-continued string does not leak its comparison (JS and C)', () => {
    expect(guardExistsInSource({ file: 'a.js', line: 1, quote: 'idx >= len' }, 'var s = "boundary idx >= len \\\nmore"; buf[idx]=v;')).toBe(false);
    expect(guardExistsInSource({ file: 'a.c', line: 1, quote: 'idx >= len' }, 'char* s = "boundary idx >= len \\\nmore"; buf[idx]=v;')).toBe(false);
  });

  it('a no-regex language (.c) keeps divisions at full fidelity (a division never blanks a real guard)', () => {
    // In C there are no `/…/` regex literals, so `/` is always division; a real bounds guard sharing a
    // line with a division still verifies — no over-blank, unlike the regex-bearing (JS) path.
    expect(guardExistsInSource({ file: 'los.c', line: 2, quote: 'm_id >= ls_w' }, 'int cell(int m_id, int ls_w) {\n  if (m_id >= ls_w) return -1; return buf[m_id] / scale;\n}')).toBe(true);
  });

  // --- 11th-pass BLOCKERS: multi-language comment / string handling (the tokenizer is per-language). ---
  it('a JS nested template literal does not leak its inner string as code', () => {
    expect(guardExistsInSource({ file: 'x.js', line: 1, quote: 'a > b' }, 't = `${`a > b`}`;')).toBe(false);
    expect(guardExistsInSource({ file: 'x.js', line: 1, quote: 'idx >= len' }, 'h = `${`if (idx >= len) continue`}`;')).toBe(false);
  });

  it('a \\-continued string does not leak across the newline (LF and CRLF)', () => {
    expect(guardExistsInSource({ file: 'a.c', line: 1, quote: 'idx >= len' }, 'char* s = "x idx >= len \\\nmore"; return buf[idx];')).toBe(false);
    expect(guardExistsInSource({ file: 'a.js', line: 1, quote: 'idx >= len' }, 'var s = "x idx >= len \\\r\nmore"; buf[idx]=v;')).toBe(false);
  });

  it('Python: # comments and triple-quoted strings are stripped, but // is floor-division (kept)', () => {
    expect(guardExistsInSource({ file: 'a.py', line: 1, quote: 'idx >= len' }, 'x = 1  # idx >= len is the intended check\nreturn buf[idx]')).toBe(false); // # comment
    expect(guardExistsInSource({ file: 'a.py', line: 2, quote: 'idx >= len' }, 'def f():\n    """note: idx >= len denotes overflow"""\n    return buf[idx]')).toBe(false); // triple-quote
    expect(guardExistsInSource({ file: 'a.py', line: 2, quote: 'idx >= n' }, 'h = a // b\nif idx >= n: return -1')).toBe(true); // // is floor-div, guard verifies
  });

  it('a C backslash-continued // comment does not leak onto the next line', () => {
    expect(guardExistsInSource({ file: 'a.c', line: 2, quote: 'idx >= len' }, 'int f() { // cont \\\nidx >= len leaks?\n return 0; }')).toBe(false);
  });

  it('# (shell) and -- (SQL/Lua) line comments are stripped for those languages', () => {
    expect(guardExistsInSource({ file: 'run.sh', line: 1, quote: 'idx >= len' }, 'echo hi  # idx >= len check needed')).toBe(false);
    expect(guardExistsInSource({ file: 'q.sql', line: 1, quote: 'a >= b' }, 'select 1; -- a >= b intended')).toBe(false);
  });

  // --- 12th-pass: raw-string forms (Go / C++ / Rust) must not leak their body ---
  it('raw-string literals (Go backtick, C++ R"(...)", Rust r#"..."#) do not leak a comparison', () => {
    expect(guardExistsInSource({ file: 'x.go', line: 1, quote: 'idx >= len' }, 'q := `SELECT * WHERE idx >= len`\nreturn buf[idx]')).toBe(false);
    expect(guardExistsInSource({ file: 'x.cpp', line: 1, quote: 'n > cap' }, 'auto s = R"(payload n > cap here)";\nint real = 0;')).toBe(false);
    expect(guardExistsInSource({ file: 'x.cpp', line: 1, quote: 'n > cap' }, 'auto s = R"xy(has a \\" then n > cap here)xy"; int r = 0;')).toBe(false); // inner-quote parity
    expect(guardExistsInSource({ file: 'x.rs', line: 1, quote: 'n > cap' }, 'let s = r#"note n > cap and a " quote"#; let r = 0;')).toBe(false);
    // and real guards in those languages still verify
    expect(guardExistsInSource({ file: 'x.go', line: 1, quote: 'idx >= len' }, 'if idx >= len { return }')).toBe(true);
    expect(guardExistsInSource({ file: 'x.rs', line: 1, quote: 'n > cap' }, 'if n > cap { return; }')).toBe(true);
  });

  it('heredoc bodies (shell <<EOF / <<- / <<~ / quoted, ruby <<~) do not leak; code after them survives', () => {
    expect(guardExistsInSource({ file: 'x.sh', line: 2, quote: 'x > y' }, 'cat <<EOF\nif (( x > y )); then :; fi\nEOF\necho done')).toBe(false);
    expect(guardExistsInSource({ file: 'x.sh', line: 2, quote: 'a >= b' }, 'cat <<-EOF\n\ta >= b here\n\tEOF\n:')).toBe(false);
    expect(guardExistsInSource({ file: 'x.rb', line: 2, quote: 'i >= len' }, 't = <<~SQL\n  if i >= len then end\nSQL\nputs t')).toBe(false);
    expect(guardExistsInSource({ file: 'x.sh', line: 4, quote: 'n > cap' }, 'cat <<EOF\nbody\nEOF\nif (( n > cap )); then :; fi')).toBe(true); // code after heredoc
    expect(guardExistsInSource({ file: 'x.rb', line: 2, quote: 'n > cap' }, 'arr << item\nif n > cap then end')).toBe(true); // `<<` left-shift, not a heredoc
  });

  it('ambiguous extensions (.m, .pl) use the safe superset — a % comment cannot leak', () => {
    expect(guardExistsInSource({ file: 'x.m', line: 1, quote: 'a >= b' }, 'y = 1  % a >= b intended check\nz = 2')).toBe(false); // MATLAB %
    expect(guardExistsInSource({ file: 'x.pl', line: 1, quote: 'a >= b' }, 'foo :- bar.  % a >= b\nbaz.')).toBe(false); // Prolog %
    expect(guardExistsInSource({ file: 'x.rb', line: 1, quote: 'idx >= len' }, 'x = %q(note idx >= len here)\ny = 1')).toBe(false); // Ruby %q over-blanked
  });

  it('the `\\`-line-comment splice fires ONLY for C/C++ (JS/Python `//`/`#` do not splice)', () => {
    expect(guardExistsInSource({ file: 'x.c', line: 2, quote: 'idx >= len' }, 'int f() { // cont \\\nidx >= len leaks?\n return 0; }')).toBe(false); // C splices
    expect(guardExistsInSource({ file: 'x.js', line: 2, quote: 'idx >= len' }, 'foo(); // note ends with \\\nif (idx >= len) return;')).toBe(true); // JS does NOT splice
    expect(guardExistsInSource({ file: 'x.py', line: 2, quote: 'idx >= len' }, 'x = 1  # note ends with \\\nif idx >= len: return')).toBe(true); // Python does NOT splice
  });

  it('shell `<<<` here-string is NOT a heredoc (does not swallow the following code)', () => {
    expect(guardExistsInSource({ file: 'x.sh', line: 2, quote: 'n > cap' }, 'grep foo <<<word\nif (( n > cap )); then :; fi')).toBe(true);
    expect(guardExistsInSource({ file: 'x.sh', line: 2, quote: 'x > y' }, 'cat <<EOF\nx > y\nEOF\n:')).toBe(false); // a real heredoc still blanks
  });

  // --- 13th-pass: Perl POD / __END__ / quote-like operators (q// qq{} s/// tr/// m// qr// qw[]) ---
  it('Perl quote-like operators do not leak their body', () => {
    expect(guardExistsInSource({ file: 'x.pl', line: 1, quote: 'i >= size' }, 'my $s = q(check i >= size before use);')).toBe(false);
    expect(guardExistsInSource({ file: 'x.pl', line: 1, quote: 'a > b' }, '$x =~ s/note a > b here/X/g;')).toBe(false);
    expect(guardExistsInSource({ file: 'x.pl', line: 1, quote: 'a >= b' }, 'if ($x =~ m{a >= b}) { }')).toBe(false);
    expect(guardExistsInSource({ file: 'x.pl', line: 1, quote: 'a > b' }, 'my @w = qw[a > b c];')).toBe(false);
  });

  it('Perl POD (=word..=cut) and __END__/__DATA__ blocks do not leak', () => {
    expect(guardExistsInSource({ file: 'Auth.pm', line: 3, quote: 'idx < len' }, 'package Auth;\n=head1 SAFETY\nrefused unless idx < len upstream.\n=cut\nsub access { return $arr[0]; }')).toBe(false);
    expect(guardExistsInSource({ file: 'Q.pm', line: 3, quote: 'count > limit' }, 'sub f { 1 }\n__END__\ncount > limit is enforced\n')).toBe(false);
  });

  it('Perl quote-op lexing does not misfire on ordinary Perl (my/sub/hash), and a real guard verifies', () => {
    expect(guardExistsInSource({ file: 'x.pl', line: 3, quote: '$i >= $size' }, 'sub f {\n  my $x = 1;\n  if ($i >= $size) { return; }\n}')).toBe(true);
    expect(guardExistsInSource({ file: 'x.pl', line: 2, quote: '$n > $cap' }, 'my $v = $h->{q};\nif ($n > $cap) { die }')).toBe(true);
  });

  // --- 14th-pass fixes ---
  it('a single-parameter generic Type<Param> is NOT minted as a comparison guard (C++/Java/Rust/TS)', () => {
    expect(guardExistsInSource({ file: 'a.cpp', line: 1, quote: 'vector < int' }, 'std::vector<int> cache;\nreturn cache[i];')).toBe(false);
    expect(guardExistsInSource({ file: 'a.java', line: 1, quote: 'List < String' }, 'List<String> names = new ArrayList<>();')).toBe(false);
    expect(guardExistsInSource({ file: 'a.rs', line: 1, quote: 'Vec < u8' }, 'let mut buf: Vec<u8> = vec![];')).toBe(false);
    // a genuine single-`<`/`>` guard still verifies (via the operand-checked structural path)
    expect(guardExistsInSource({ file: 'a.c', line: 1, quote: 'idx < len' }, 'if (idx < len) ok();')).toBe(true);
  });

  it('a sigil-dropped citation verifies against $-prefixed operands (shell/Perl/PHP)', () => {
    expect(guardExistsInSource({ file: 'x.sh', line: 1, quote: 'n > cap' }, 'if (( $n > $cap )); then :; fi')).toBe(true);
    expect(guardExistsInSource({ file: 'x.pl', line: 1, quote: 'i >= size' }, 'if ($i >= $size) { return; }')).toBe(true);
  });

  it('PostgreSQL dollar-quoted strings ($$…$$ / $tag$…$tag$) do not leak; $N params are not confused', () => {
    expect(guardExistsInSource({ file: 'x.sql', line: 1, quote: 'n > cap' }, 'SELECT $$ if n > cap then $$;')).toBe(false);
    expect(guardExistsInSource({ file: 'x.sql', line: 1, quote: 'idx >= len' }, 'SELECT $body$ where idx >= len $body$ AS note;')).toBe(false);
    expect(guardExistsInSource({ file: 'x.sql', line: 1, quote: 'a > b' }, 'SELECT $1 WHERE a > b;')).toBe(true); // $1 is a param, not a dollar-quote
  });

  it('a comparison inside a JS `${…}` template interpolation does NOT verify (display text, not a bounds guard) and nested templates never leak', () => {
    // A comparison in a `${…}` interpolation produces template display text, not a killing guard — treat
    // it conservatively (blank), so a hallucinated guard citing it cannot false-VERIFY. Over-rejecting a
    // (contrived) real guard hidden inside an interpolation is the SAFE direction.
    expect(guardExistsInSource({ file: 'a.js', line: 1, quote: 'idx >= len' }, 'const s = `v ${idx >= len ? 1 : 0} w`; return;')).toBe(false);
    expect(guardExistsInSource({ file: 'a.js', line: 1, quote: 'a > b' }, 't = `${`a > b`}`;')).toBe(false);
    // interpolation reached THROUGH a nested template (a string) must not leak either
    expect(guardExistsInSource({ file: 'a.js', line: 1, quote: 'a > b' }, 'x = `${ `${ a > b }` }`;')).toBe(false);
    // a real guard OUTSIDE any template still verifies
    expect(guardExistsInSource({ file: 'a.js', line: 1, quote: 'idx >= len' }, 'const s = `hi ${name}`; if (idx >= len) return;')).toBe(true);
  });

  it('multi-parameter generics never false-VERIFY a `<` guard, and real `<` guards still verify', () => {
    expect(guardExistsInSource({ file: 'm.ts', line: 1, quote: 'Map < K' }, 'const m: Map<K, V> = new Map();')).toBe(false);
    expect(guardExistsInSource({ file: 'm.rs', line: 1, quote: 'HashMap < K' }, 'let m: HashMap<K, V> = h();')).toBe(false);
    expect(guardExistsInSource({ file: 'm.rs', line: 1, quote: 'Nested < Vec' }, 'let x: Nested<Vec<int>> = y;')).toBe(false);
    expect(guardExistsInSource({ file: 'm.rs', line: 1, quote: 'Box < T' }, 'let b: Box<T> = z;')).toBe(false); // single-arg still rejected
    expect(guardExistsInSource({ file: 'm.ts', line: 1, quote: 'idx < len' }, 'if (idx < len) return;')).toBe(true);
  });

  it('PHP heredoc/nowdoc bodies are blanked; `<<` left-shift is not a heredoc', () => {
    expect(guardExistsInSource({ file: 'x.php', line: 2, quote: 'idx >= len' }, '$s = <<<EOT\nif (idx >= len) leak\nEOT;\n$r = 0;')).toBe(false);
    expect(guardExistsInSource({ file: 'x.php', line: 2, quote: 'n > cap' }, "$s = <<<'EOT'\nnote n > cap here\nEOT;\n$r = 0;")).toBe(false); // nowdoc
    expect(guardExistsInSource({ file: 'x.php', line: 2, quote: 'x > y' }, '$s = <<<EOT\n    x > y here\n    EOT;\n$r = 0;')).toBe(false); // 7.3+ indented closer
    expect(guardExistsInSource({ file: 'x.php', line: 2, quote: 'n > cap' }, '$y = $x << 2;\nif (n > cap) return;')).toBe(true); // `<<` = left-shift, guard survives
  });

  it('an INDENTED __END__/__DATA__ is ordinary code (only column-0 is a Perl trailer)', () => {
    expect(guardExistsInSource({ file: 'x.pl', line: 3, quote: 'n > cap' }, 'sub f {\n    __END__\n    if (n > cap) { return }\n}')).toBe(true);
    expect(guardExistsInSource({ file: 'x.pl', line: 3, quote: 'a > b' }, 'code();\n__END__\na > b in pod trailer')).toBe(false);
  });

  it('Perl __END__ with trailing text is blanked, and a stray leading `=` without `=cut` stays code', () => {
    expect(guardExistsInSource({ file: 'Q.pm', line: 3, quote: 'count > limit' }, 'sub f { 1 }\n__END__ data\ncount > limit\n')).toBe(false);
    expect(guardExistsInSource({ file: 'x.pl', line: 3, quote: '$n > $cap' }, 'my $r = 1\n=x\nif ($n > $cap) { die }')).toBe(true); // no =cut → not POD
  });

  it('a bare Ruby `<<WORD` heredoc blanks its body only when a terminator exists (not `arr << CONST`)', () => {
    expect(guardExistsInSource({ file: 'x.rb', line: 2, quote: 'i > n' }, 'q = <<SQL\n  where i > n\nSQL\nputs q')).toBe(false);
    expect(guardExistsInSource({ file: 'x.rb', line: 2, quote: 'n > cap' }, 'arr << CONST\nif n > cap then end')).toBe(true);
  });

  it('REJECTS a hallucinated guard not present in source', () => {
    expect(guardExistsInSource({ file: 'a.c', line: 2, quote: 'if (m_id >= ls.w) continue;' }, source)).toBe(false);
  });

  it('REJECTS a paraphrased comparison whose operands never co-occur on one line', () => {
    expect(guardExistsInSource({ file: 'a.c', line: 2, quote: 'foo >= bar' }, source)).toBe(false);
  });

  it('REJECTS on empty/short quote, empty source, or null guard', () => {
    expect(guardExistsInSource({ file: 'a.c', line: 2, quote: '' }, source)).toBe(false);
    expect(guardExistsInSource({ file: 'a.c', line: 2, quote: 'if (n > cap) return' }, '')).toBe(false);
    expect(guardExistsInSource(null, source)).toBe(false);
    // sub-6-char quote falls through the substring path; no comparison → false
    expect(guardExistsInSource({ file: 'a.c', line: 2, quote: 'x;' }, source)).toBe(false);
  });
});

describe('guardExistsInSource — hardened against hallucinated cites (HT-2 regression)', () => {
  const source = [
    'void copy(size_t n) {',
    '  if (n > cap) return;   // the real killing guard',
    '  memcpy(dst, src, n);',
    '}',
  ].join('\n');
  // an OOB sink with NO bounds check at all — the exact case a hallucinating refuter targets
  const unbounded = 'void f(int idx){ memcpy(dst, table[idx], width); }';

  it('REJECTS a structural cite whose operands co-occur on a line but are never actually compared', () => {
    // `n` and `src` both appear on the memcpy line, but `n > src` is not a comparison anywhere.
    expect(guardExistsInSource({ file: 'a.c', line: 3, quote: 'n > src' }, source)).toBe(false);
  });

  it('REJECTS a fabricated bounds check on an unbounded sink (operands present, comparison absent)', () => {
    expect(guardExistsInSource({ file: 'a.c', line: 1, quote: 'idx >= width' }, unbounded)).toBe(false);
    expect(guardExistsInSource({ file: 'a.c', line: 1, quote: 'idx < width' }, unbounded)).toBe(false);
  });

  it('REJECTS a comparison of two tokens that are never compared together in source', () => {
    // source only ever compares n vs cap; {cap, dst} is not a real comparison.
    expect(guardExistsInSource({ file: 'a.c', line: 2, quote: 'cap > dst' }, source)).toBe(false);
  });

  it('REJECTS a bare common token that IS a substring but has no guard shape', () => {
    expect(guardExistsInSource({ file: 'a.c', line: 1, quote: 'size_t' }, source)).toBe(false);
    // the sink line itself is not a guard, even though it is a literal substring
    expect(guardExistsInSource({ file: 'a.c', line: 3, quote: 'memcpy(dst, src, n)' }, source)).toBe(false);
  });

  it('still verifies a genuine clamp/min guard cited exactly (no false-negative regression)', () => {
    const clamp = 'n = std::min(n, cap);';
    expect(guardExistsInSource({ file: 'a.c', line: 1, quote: 'std::min(n, cap)' }, clamp)).toBe(true);
  });

  it('REJECTS a guard that exists only in a COMMENT, not real code (comment stripping)', () => {
    const withComment = 'x = alloc();\n// if (n > cap) return;  (just a note, not real code)\ny = use(x);';
    expect(guardExistsInSource({ file: 'a.c', line: 2, quote: 'if (n > cap) return' }, withComment)).toBe(false);
  });

  it('REJECTS a guard that only matches by STITCHING across two unrelated lines', () => {
    const twoLines = 'if (done) break;\nprocess(data);';
    // "break;process" is a substring of the whitespace-flattened file, but never appears on ONE line
    expect(guardExistsInSource({ file: 'a.c', line: 1, quote: 'break; process' }, twoLines)).toBe(false);
  });

  it('REJECTS a guard that exists only inside a STRING LITERAL, not real code', () => {
    const inString = 'const msg = "if (n > cap) return";\nprocess(msg);';
    expect(guardExistsInSource({ file: 'a.c', line: 1, quote: 'if (n > cap) return' }, inString)).toBe(false);
  });

  it('does NOT false-reject a real guard sharing a line with a // inside a STRING literal', () => {
    const withUrl = 'const u = "http://x/y"; if (n > cap) return;'; // the // is inside the string, not a comment
    expect(guardExistsInSource({ file: 'a.c', line: 1, quote: 'n > cap' }, withUrl)).toBe(true);
  });

  it('END-TO-END: two hallucinated structural refutes no longer kill a real finding', () => {
    const resolve = (f: string): string => (f === 'sink.c' ? unbounded : '');
    const raw = [
      refuted({ file: 'sink.c', line: 1, quote: 'idx >= width' }), // fabricated bound
      refuted({ file: 'sink.c', line: 1, quote: 'idx < width' }), // fabricated bound
      survived(),
    ];
    const checked = downgradeUnverifiedRefutes(raw, resolve);
    expect(adjudicate(checked).verdict).toBe('SURVIVED');
    expect(adjudicate(checked).refutedCount).toBe(0);
  });
});

describe('downgradeUnverifiedRefutes — mandatory cite-check flips hallucinated refutes', () => {
  const realSource = 'if (n > cap) return;\nmemcpy(dst, src, n);';
  const resolve = (file: string): string => (file === 'real.c' ? realSource : '');

  it('a REFUTED with a VERIFIED guard survives the check (stays REFUTED)', () => {
    const votes = [refuted({ file: 'real.c', line: 1, quote: 'if (n > cap) return' })];
    const out = downgradeUnverifiedRefutes(votes, resolve);
    expect(out[0]?.verdict).toBe('REFUTED');
    expect(out[0]?.guard_check).toBe('verified');
  });

  it('a REFUTED whose killing_guard FAILS guardExistsInSource is downgraded to SURVIVED', () => {
    const votes = [refuted({ file: 'real.c', line: 1, quote: 'if (bogus >= nope) skip' })];
    const out = downgradeUnverifiedRefutes(votes, resolve);
    expect(out[0]?.verdict).toBe('SURVIVED');
    expect(out[0]?.original_verdict).toBe('REFUTED');
    expect(out[0]?.guard_check).toBe('unverified');
  });

  it('a REFUTED citing a MISSING file is downgraded (resolve returns empty)', () => {
    const votes = [refuted({ file: 'ghost.c', line: 1, quote: 'if (n > cap) return' })];
    expect(downgradeUnverifiedRefutes(votes, resolve)[0]?.verdict).toBe('SURVIVED');
  });

  it('a REFUTED with NO killing_guard cannot stand on a cite → downgraded', () => {
    expect(downgradeUnverifiedRefutes([refuted()], resolve)[0]?.verdict).toBe('SURVIVED');
  });

  it('SURVIVED votes and nulls pass through unchanged; the check is pure (input not mutated)', () => {
    const votes: Array<RefuterVote | null> = [survived(), null];
    const out = downgradeUnverifiedRefutes(votes, resolve);
    expect(out[0]?.verdict).toBe('SURVIVED');
    expect(out[1]).toBeNull();
    // purity: the original REFUTED vote object is not mutated by the downgrade
    const original = refuted({ file: 'ghost.c', line: 1, quote: 'nope nope' });
    downgradeUnverifiedRefutes([original], resolve);
    expect(original.verdict).toBe('REFUTED');
    expect(original.original_verdict).toBeUndefined();
  });

  it('END-TO-END: a minority-verified + majority-hallucinated panel does NOT refute after the cite-check', () => {
    // 2 hallucinated REFUTED + 1 SURVIVED: raw tally would REFUTE (2 of 3).
    const raw = [
      refuted({ file: 'real.c', line: 1, quote: 'if (madeup > 999) die' }),
      refuted({ file: 'real.c', line: 1, quote: 'if (alsofake < 0) bail' }),
      survived(),
    ];
    expect(adjudicate(raw).verdict).toBe('REFUTED'); // before cite-check: wrongly refuted
    const checked = downgradeUnverifiedRefutes(raw, resolve);
    expect(adjudicate(checked).verdict).toBe('SURVIVED'); // after cite-check: real finding preserved
    expect(adjudicate(checked).refutedCount).toBe(0);
  });
});
