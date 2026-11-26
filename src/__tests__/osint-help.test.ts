import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';

const html = readFileSync(new URL('../../docs/osint.html', import.meta.url), 'utf8');

/**
 * The scan runs on the STATIC markup only: script blocks are stripped first, so
 * the JS templates that render the locator's result sub-titles cannot be mistaken
 * for authored sections. That matches what injectHelpButtons() actually attaches
 * to — tool sections in the markup, not the dossier's rendered report blocks.
 */
const staticHtml = html.replace(/<script\b[\s\S]*?<\/script>/gi, '');

/** Mirror of the page's helpKeyFor(): strip emoji, collapse whitespace, upper-case. */
function helpKeyFor(text: string): string {
  return text
    .replace(/[\u2190-\u2BFF\u{1F000}-\u{1FAFF}]|\u{FE0F}/gu, '')
    .replace(/\s+/g, ' ')
    .trim()
    .toUpperCase();
}

/** Every tool section header the page ships in its markup — this is what gets a "?". */
function sectionKeys(): string[] {
  const out: string[] = [];
  // The capture may not cross another div boundary, or the match runs from one
  // header all the way to the end of the file.
  const re = /class="(?:panel-title|dossier-section-title)([^"]*)"[^>]*>((?:(?!<\/?div[\s>]|$)[\s\S])*?)<\/div>/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(staticHtml))) {
    // Visible text only, with `.count` hint spans removed — the same rule
    // helpKeyForNode() applies in the browser, so test and page agree exactly.
    const text = m[2]
      .replace(/<span class="count"[^>]*>[\s\S]*?<\/span>/g, ' ')
      .replace(/<[^>]*>/g, ' ')
      .replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#39;/g, "'");
    const key = helpKeyFor(text);
    if (key) out.push(key);
  }
  return [...new Set(out)];
}

/** Keys declared in the page's OSINT_HELP registry. */
function registryKeys(): string[] {
  const block = html.match(/var OSINT_HELP = \{([\s\S]*?)\n {8}\};/);
  expect(block, 'OSINT_HELP registry not found in docs/osint.html').toBeTruthy();
  const keys: string[] = [];
  const re = /^\s{12}'([^']+)':\s*\{/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(block![1]))) keys.push(m[1]);
  return keys;
}

const sections = sectionKeys();
const registry = registryKeys();

describe('OSINT inline help', () => {
  it('finds the section headers it is meant to cover', () => {
    // Sanity: the scan is actually finding things, not silently matching zero.
    expect(sections.length).toBeGreaterThanOrEqual(20);
  });

  it('has a help entry for EVERY section', () => {
    const missing = sections.filter((s) => !registry.includes(s));
    expect(missing, `sections with no help entry: ${missing.join(' | ')}`).toEqual([]);
  });

  it('has no orphan help entries (a stale key hides a removed section)', () => {
    const orphans = registry.filter((k) => !sections.includes(k));
    expect(orphans, `help entries with no matching section: ${orphans.join(' | ')}`).toEqual([]);
  });

  it('every entry states what it does and how to use it', () => {
    for (const key of registry) {
      const start = html.indexOf(`'${key}': {`);
      expect(start, key).toBeGreaterThan(-1);
      const slice = html.slice(start, start + 2600);
      expect(slice, `${key} has no "what"`).toMatch(/what:/);
      expect(slice, `${key} has no "steps"`).toMatch(/steps:/);
    }
  });

  it('wires the "?" injector, the modal and the Esc handler', () => {
    expect(html).toContain('function injectHelpButtons()');
    expect(html).toContain('function toggleHelp(');
    expect(html).toContain('function closeHelp()');
    expect(html).toContain('injectHelpButtons();');
    expect(html).toMatch(/ev\.key === 'Escape'/);
    expect(html).toContain('id="helpModal"');
    expect(html).toContain('id="helpBody"');
  });

  it('escapes help copy before it reaches innerHTML', () => {
    // The renderer must escape its inputs — help text is static, but a future
    // entry that interpolates a value must not become an injection.
    const start = html.indexOf('function renderHelp(');
    const slice = html.slice(start, start + 1600);
    expect(slice).toContain("var esc = function (s)");
    expect(slice).toMatch(/esc\(e\.what\)/);
  });
});
