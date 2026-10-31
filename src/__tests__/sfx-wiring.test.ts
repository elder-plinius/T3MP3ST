import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import vm from 'node:vm';

const DOCS = join(process.cwd(), 'docs');
const SFX_PAGES = [
  'about.html', 'arsenal.html', 'configs.html', 'ctf.html', 'cves.html', 'dfir.html',
  'evidence.html', 'general.html', 'index.html', 'live-scan.html', 'obsidivm.html',
  'operators.html', 'gps.html', 'receipts.html', 'self-improve.html', 'settings.html', 'terminal.html',
];

describe('sfx.js — operator sound effects wiring', () => {
  it('sfx.js parses as valid JavaScript', () => {
    const src = readFileSync(join(DOCS, 'sfx.js'), 'utf8');
    expect(() => new vm.Script(src, { filename: 'sfx.js' })).not.toThrow();
  });

  it('every leaf page loads sfx.js in <head> (before body scripts)', () => {
    for (const page of SFX_PAGES) {
      const html = readFileSync(join(DOCS, page), 'utf8');
      const tagAt = html.indexOf('<script src="sfx.js"></script>');
      const headCloseAt = html.indexOf('</head>');
      expect(tagAt, `${page} must include sfx.js`).toBeGreaterThan(-1);
      expect(tagAt, `${page} sfx.js must load before </head>`).toBeLessThan(headCloseAt);
    }
  });

  it('shell.html does NOT load sfx.js (frame would double every sound)', () => {
    const shell = readFileSync(join(DOCS, 'shell.html'), 'utf8');
    expect(shell.includes('sfx.js')).toBe(false);
  });

  it('engine rides the page EventSource for finding + credential without a second connection', () => {
    const src = readFileSync(join(DOCS, 'sfx.js'), 'utf8');
    expect(src).toContain('EventSource.prototype');
    expect(src.match(/new EventSource/g)).toBeNull();
    expect(src).toContain("'finding'");
    expect(src).toContain("'credential'");
  });

  it('engine pins the gamified behaviors: throttling, red-egress ominous, recovery all-clear, persisted mute', () => {
    const src = readFileSync(join(DOCS, 'sfx.js'), 'utf8');
    expect(src).toContain('GAPS'); // burst throttle — a 100-finding sweep must not become a siren
    expect(src).toContain('egress-leak');
    expect(src).toContain('egress-no-ip');
    expect(src).toContain('egress-error');
    expect(src).toContain('fxOminous');
    expect(src).toContain('fxAllClear');
    expect(src).toContain('t3mp3st_sfx_v1'); // localStorage persistence
    expect(src).toContain('t3sfxChip'); // mute chip
  });
});
