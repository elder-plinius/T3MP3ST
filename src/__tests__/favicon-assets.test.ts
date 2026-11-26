/**
 * Favicon / app-icon assets.
 *
 * These are the icons the browser tab, the iOS home screen and an installed
 * PWA shortcut actually load. They are the one part of the shell that is easy to
 * break without any test going red, because nothing in the app imports them —
 * they are only ever referenced from a <link> tag in static HTML.
 *
 * The PNG checks are not cosmetic. `<link rel="apple-touch-icon">` is IGNORED when
 * it points at an SVG — which is exactly what one page in this repo shipped
 * before this test existed — and iOS composites a transparent PNG onto black
 * before applying its own rounded mask, so shipping the rounded SVG tile as a
 * raster produces a black halo. Hence: it must be a real PNG, and it must carry
 * no alpha channel.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, existsSync, mkdtempSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const DOCS = join(process.cwd(), 'docs');
const PAGES = readdirSync(DOCS).filter((f) => f.endsWith('.html')).sort();

/** Minimal PNG header reader — enough to prove what a raster actually is. */
function pngInfo(file: string) {
  const b = readFileSync(join(DOCS, file));
  const signature = b.subarray(0, 8).toString('hex');
  return {
    bytes: b.length,
    isPng: signature === '89504e470d0a1a0a',
    width: b.readUInt32BE(16),
    height: b.readUInt32BE(20),
    bitDepth: b[24],
    /** 2 = truecolour RGB, 6 = truecolour + alpha. iOS wants 2. */
    colourType: b[25],
  };
}

describe('favicon assets', () => {
  it('every page exists and declares an icon', () => {
    expect(PAGES.length).toBeGreaterThan(0);
    for (const p of PAGES) {
      const html = readFileSync(join(DOCS, p), 'utf8');
      expect(html, `${p} has no favicon link`).toMatch(/<link rel="icon"[^>]*href="favicon\.svg"/);
    }
  });

  it('the SVG favicon is shipped and is actually an SVG', () => {
    expect(existsSync(join(DOCS, 'favicon.svg'))).toBe(true);
    const svg = readFileSync(join(DOCS, 'favicon.svg'), 'utf8');
    expect(svg.trimStart().startsWith('<svg')).toBe(true);
    expect(svg).toContain('</svg>');
  });

  it('every page declares an apple-touch-icon AND it points at a PNG', () => {
    // The regression this file exists for: a page carrying
    // <link rel="apple-touch-icon" href="favicon.svg">, which iOS silently drops.
    for (const p of PAGES) {
      const html = readFileSync(join(DOCS, p), 'utf8');
      expect(html, `${p} has no apple-touch-icon`).toMatch(/<link rel="apple-touch-icon"/);
      expect(html, `${p} points apple-touch-icon at something that is not a PNG`).not.toMatch(
        /<link rel="apple-touch-icon"[^>]*href="(?!apple-touch-icon\.png)[^"]*\.(svg|ico|jpg|jpeg|gif)"/i,
      );
      expect(html, `${p} apple-touch-icon does not resolve to the shipped PNG`).toMatch(
        /<link rel="apple-touch-icon" href="apple-touch-icon\.png">/,
      );
    }
  });

  it('every page links the manifest and the manifest itself is valid', () => {
    const manifestPath = join(DOCS, 'manifest.webmanifest');
    expect(existsSync(manifestPath)).toBe(true);
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    expect(manifest.name).toBeTruthy();
    expect(Array.isArray(manifest.icons) && manifest.icons.length).toBeTruthy();
    for (const p of PAGES) {
      const html = readFileSync(join(DOCS, p), 'utf8');
      expect(html, `${p} does not link the manifest`).toMatch(/<link rel="manifest" href="manifest\.webmanifest">/);
    }
  });

  it('every icon the manifest advertises actually exists on disk', () => {
    // A manifest naming a missing icon fails silently at install time — the
    // shortcut is created with a blank icon and nothing reports an error.
    const manifest = JSON.parse(readFileSync(join(DOCS, 'manifest.webmanifest'), 'utf8'));
    for (const icon of manifest.icons) {
      expect(existsSync(join(DOCS, icon.src)), `manifest names a missing icon: ${icon.src}`).toBe(true);
    }
  });

  it('the apple-touch-icon is a real, opaque PNG at the size iOS expects', () => {
    const info = pngInfo('apple-touch-icon.png');
    expect(info.isPng, 'apple-touch-icon.png is not a PNG').toBe(true);
    expect(info.width).toBe(180);
    expect(info.height).toBe(180);
    expect(info.bitDepth).toBe(8);
    // colourType 6 would mean an alpha channel, which iOS composites onto black
    // and turns the rounded tile into a black halo.
    expect(info.colourType, 'apple-touch-icon must carry NO alpha channel (colour type 2, not 6)').toBe(2);
  });

  it('the 512 icon is a real, opaque PNG', () => {
    const info = pngInfo('icon-512.png');
    expect(info.isPng).toBe(true);
    expect(info.width).toBe(512);
    expect(info.height).toBe(512);
    expect(info.colourType).toBe(2);
  });
});

describe('favicon assets are reproducible', () => {
  it('re-running the generator reproduces the committed PNGs byte-for-byte', () => {
    // The reason these assets are generated by scripts/make-favicon.mjs rather
    // than committed as opaque binaries: a binary with no source is a
    // maintenance trap, and nothing else would prove the shipped PNG still
    // matches the shipped SVG. ~2.5s, paid once.
    //
    // The generator is pointed at a SCRATCH directory, never at docs/. These
    // icons are referenced only from <link> tags, so a concurrent test reading
    // docs/apple-touch-icon.png while this run rewrites it could observe a
    // half-written file — and a suite that mutates the tree it runs in is a
    // defect regardless of whether anything noticed. Every other test in this
    // repo uses mkdtempSync for exactly this reason.
    const scratch = mkdtempSync(join(tmpdir(), 't3-favicon-'));
    try {
      execFileSync(process.execPath, [join(process.cwd(), 'scripts', 'make-favicon.mjs'), scratch], { stdio: 'ignore' });
      for (const f of ['apple-touch-icon.png', 'icon-512.png']) {
        const committed = readFileSync(join(DOCS, f));
        const rendered = readFileSync(join(scratch, f));
        expect(rendered.equals(committed), `${f} is not byte-identical to a fresh render — the committed PNG has drifted from the generator`).toBe(true);
      }
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  }, 30_000);
});
