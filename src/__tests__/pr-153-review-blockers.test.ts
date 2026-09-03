import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, mkdirSync, symlinkSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { browserRequestInScope } from '../arsenal/browser.js';
import { approvedLocalPath } from '../arsenal/local-file-scope.js';

describe('PR #153 review blockers', () => {
  afterEach(() => { delete process.env.T3MP3ST_SOURCE_ROOT; });

  it('blocks cross-host browser redirects and subresources', () => {
    expect(browserRequestInScope('target.example', 'https://target.example/next')).toBe(true);
    expect(browserRequestInScope('target.example', 'https://cdn.target.example/app.js')).toBe(false);
    expect(browserRequestInScope('target.example', 'https://evil.example/redirect')).toBe(false);
    expect(browserRequestInScope('target.example', 'file:///etc/passwd')).toBe(false);
  });

  it('requires a canonical approved root and rejects traversal and symlink escape', () => {
    const base = mkdtempSync(join(tmpdir(), 't3mp3st-scope-'));
    const root = join(base, 'root');
    const outside = join(base, 'outside.bin');
    mkdirSync(root);
    writeFileSync(join(root, 'inside.bin'), 'safe');
    writeFileSync(outside, 'outside');
    symlinkSync(outside, join(root, 'escape.bin'));

    expect(approvedLocalPath('scan', join(root, 'inside.bin')).ok).toBe(false);
    process.env.T3MP3ST_SOURCE_ROOT = root;
    expect(approvedLocalPath('scan', 'inside.bin')).toMatchObject({ ok: true });
    expect(approvedLocalPath('scan', '../outside.bin')).toMatchObject({ ok: false });
    expect(approvedLocalPath('scan', 'escape.bin')).toMatchObject({ ok: false });
  });
});
