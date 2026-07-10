/**
 * Language-aware parameter-name extractor for the multi-language ingest.
 *
 * tree-sitter hands us a parameter-list as raw source text; different languages
 * order name and type differently (Python/Go/TS are name-first, Java/C/C++ are
 * type-first). This returns the bare identifier names so the security-ranking
 * layer's `RISKY_PARAM_RE` can match on them exactly as it did for Python.
 */

/** Split on top-level commas only — commas inside (), [], {}, <> are nested. */
function splitTopLevel(s: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let cur = '';
  for (const ch of s) {
    if (ch === '(' || ch === '[' || ch === '{' || ch === '<') depth++;
    else if (ch === ')' || ch === ']' || ch === '}' || ch === '>') depth = Math.max(0, depth - 1);
    if (ch === ',' && depth === 0) {
      parts.push(cur);
      cur = '';
    } else {
      cur += ch;
    }
  }
  if (cur.trim()) parts.push(cur);
  return parts;
}

/** First identifier-shaped token in a string, or null. */
function firstId(s: string): string | null {
  const m = s.match(/[A-Za-z_$][A-Za-z0-9_$]*/);
  return m ? m[0] : null;
}

function paramName(partRaw: string, lang: string): string | null {
  const part = partRaw.trim();
  if (!part) return null;

  if (lang === 'py') {
    if (part.startsWith('*')) return null; // *args / **kwargs / bare *
    const p = part.split('=')[0].split(':')[0].trim();
    if (!p || p === '/' || p === 'self' || p === 'cls') return null;
    return firstId(p);
  }

  if (lang === 'ts' || lang === 'js') {
    // name-first: name is the token before ':' or '=', minus a trailing '?'.
    let p = part.replace(/^\.\.\./, '').split(':')[0].split('=')[0].trim();
    p = p.replace(/\?$/, '').trim();
    const toks = p.split(/\s+/).filter(Boolean); // drop TS modifiers (public/readonly)
    return firstId(toks[toks.length - 1] ?? '');
  }

  if (lang === 'go') {
    // name-first: first token of the group ("a, b int" already split → "a", "b int").
    return firstId(part);
  }

  // java / c / c++ / unknown: type-first → name is the last token; strip * & [].
  const p = part.split('=')[0].trim();
  const toks = p.split(/\s+/).filter(Boolean);
  const last = (toks[toks.length - 1] ?? '').replace(/^[*&]+/, '').replace(/\[\]$/, '');
  return firstId(last);
}

/** Bare parameter identifiers from a raw parameter list, per language dialect. */
export function splitParamList(raw: string, lang: string): string[] {
  let s = raw.trim();
  if (s.startsWith('(') && s.endsWith(')')) s = s.slice(1, -1).trim();
  if (!s) return [];
  const out: string[] = [];
  for (const part of splitTopLevel(s)) {
    const name = paramName(part, lang);
    if (name) out.push(name);
  }
  return out;
}
