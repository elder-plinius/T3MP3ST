/**
 * whitebox path-containment tests (B-03)
 *
 * resolveContainedRepoPath is the security chokepoint for the white-box path: it
 * turns an operator-supplied repoPath into a canonical, contained absolute path
 * or throws RepoPathError. These tests pin the containment invariants so a future
 * refactor can't silently reopen the arbitrary-directory-read hole:
 *   - accepts real dirs inside the allowed root (root itself + nested)
 *   - rejects dirs outside the root, '..' escapes, and symlinks that escape
 *   - rejects non-existent paths, files (non-dirs), and empty/non-string input
 *
 * The root is pinned via T3MP3ST_REPO_ROOT to a realpath'd temp dir so the test
 * is independent of the operator's real home.
 */

import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, symlinkSync, realpathSync } from 'fs';
import { statSync } from 'node:fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { resolveContainedRepoPath, RepoPathError } from '../recon/whitebox.js';

// Mock node:fs (what whitebox.ts imports) so we can force statSync to throw AFTER realpath
// succeeds — the TOCTOU race path. Every other export keeps its real implementation, and
// statSync itself defaults to real (vi.fn wrapping the original), overridden per-test below.
vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>();
  return { ...actual, statSync: vi.fn(actual.statSync) };
});

describe('resolveContainedRepoPath (B-03 path containment)', () => {
  let base: string; // realpath'd temp base holding both root/ and outside/
  let root: string; // the allowed root (set as T3MP3ST_REPO_ROOT)
  let outside: string; // a sibling dir OUTSIDE the root
  let prevRoot: string | undefined;

  beforeAll(() => {
    prevRoot = process.env.T3MP3ST_REPO_ROOT;
    // realpath the temp base up-front: on macOS /tmp -> /private/tmp is a symlink,
    // which would otherwise make our own fixtures look like they escape the root.
    base = realpathSync(mkdtempSync(join(tmpdir(), 't3mp3st-contain-')));
    root = join(base, 'root');
    outside = join(base, 'outside');
    mkdirSync(join(root, 'repo', 'sub'), { recursive: true });
    mkdirSync(outside, { recursive: true });
    writeFileSync(join(root, 'afile.txt'), 'x');
    process.env.T3MP3ST_REPO_ROOT = root;
  });

  afterAll(() => {
    if (prevRoot === undefined) delete process.env.T3MP3ST_REPO_ROOT;
    else process.env.T3MP3ST_REPO_ROOT = prevRoot;
    try { rmSync(base, { recursive: true, force: true }); } catch { /* noop */ }
  });

  it('accepts a directory inside the allowed root (returns canonical path)', () => {
    expect(resolveContainedRepoPath(join(root, 'repo'))).toBe(realpathSync(join(root, 'repo')));
  });

  it('accepts the root itself', () => {
    expect(resolveContainedRepoPath(root)).toBe(realpathSync(root));
  });

  it('accepts a nested subdirectory', () => {
    expect(resolveContainedRepoPath(join(root, 'repo', 'sub'))).toBe(realpathSync(join(root, 'repo', 'sub')));
  });

  it('rejects a directory OUTSIDE the root', () => {
    expect(() => resolveContainedRepoPath(outside)).toThrow(RepoPathError);
  });

  it('rejects a traversal that escapes the root', () => {
    expect(() => resolveContainedRepoPath(join(root, '..', 'outside'))).toThrow(/outside the allowed root/);
  });

  it('rejects a non-existent path', () => {
    expect(() => resolveContainedRepoPath(join(root, 'nope'))).toThrow(/does not resolve/);
  });

  it('rejects a file (not a directory)', () => {
    expect(() => resolveContainedRepoPath(join(root, 'afile.txt'))).toThrow(/must be a directory/);
  });

  it('rejects empty / whitespace / non-string input', () => {
    expect(() => resolveContainedRepoPath('')).toThrow(RepoPathError);
    expect(() => resolveContainedRepoPath('   ')).toThrow(RepoPathError);
    expect(() => resolveContainedRepoPath(undefined as unknown as string)).toThrow(RepoPathError);
    expect(() => resolveContainedRepoPath(42 as unknown as string)).toThrow(RepoPathError);
  });

  it('rejects a symlink whose target escapes the root (realpath resolves it)', () => {
    const link = join(root, 'escape-link');
    try {
      symlinkSync(outside, link);
    } catch {
      return; // symlink creation not permitted in this env — skip rather than fail
    }
    expect(() => resolveContainedRepoPath(link)).toThrow(RepoPathError);
  });

  it('normalizes a statSync failure (TOCTOU delete after realpath) to RepoPathError', () => {
    // The dir realpath-resolves (exists) but statSync then throws — simulating a deletion in
    // the race window between realpath and stat. The wrap must convert it to a RepoPathError
    // ('not accessible'), which the API layer turns into a clean 400 (never an unhandled fs
    // error / unhandled rejection). Guards the statSync-wrap catch added this session.
    const target = join(root, 'repo'); // real, in-root dir — realpath succeeds
    vi.mocked(statSync).mockImplementationOnce(() => {
      throw Object.assign(new Error('ENOENT: no such file or directory'), { code: 'ENOENT' });
    });
    expect(() => resolveContainedRepoPath(target)).toThrow(/not accessible/);
  });
});
