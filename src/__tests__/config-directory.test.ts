import { afterEach, describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 't3mp3st-config-directory-'));
  roots.push(root);
  const home = join(root, 'operator');
  const config = join(root, 'isolated');
  const cwd = join(root, 'target');
  for (const dir of [home, config, cwd, join(home, '.t3mp3st')]) mkdirSync(dir, { recursive: true });
  writeFileSync(join(home, '.t3mp3st', '.env'), 'OPENROUTER_API_KEY=operator-owned-key\n');
  writeFileSync(join(home, '.env'), 'OPENROUTER_API_KEY=operator-home-key\n');
  writeFileSync(join(cwd, '.env'), 'OPENROUTER_API_KEY=hostile-target-key\n');
  return { root, home, config, cwd };
}

function run(f: ReturnType<typeof fixture>, directory?: string) {
  const env: NodeJS.ProcessEnv = { PATH: process.env.PATH, XDG_CONFIG_HOME: join(f.root, 'xdg') };
  if (directory !== undefined) env.T3MP3ST_CONFIG_DIR = directory;
  // Patch the built-in home resolver in the child only; never repurpose HOME or touch operator files.
  const source = `
    import os from 'node:os';
    import { syncBuiltinESMExports } from 'node:module';
    os.homedir = () => ${JSON.stringify(f.home)};
    syncBuiltinESMExports();
    const { config } = await import(${JSON.stringify(new URL('../config/index.ts', import.meta.url).href)});
    console.log(JSON.stringify({ key: config.getApiKey('openrouter') ?? null }));
  `;
  return spawnSync(process.execPath, ['--import', import.meta.resolve('tsx'), '--input-type=module', '-e', source], {
    cwd: f.cwd, env, encoding: 'utf8', timeout: 15000,
  });
}

describe('explicit configuration directory', () => {
  it('isolates saved settings and does not fall back to operator or target env files', () => {
    const f = fixture();
    const result = run(f, f.config);
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout).key).toBeNull();
    expect(JSON.parse(readFileSync(join(f.config, 'config.json'), 'utf8')).apiKeys).toEqual({});
  });

  it('loads only the explicitly selected env file', () => {
    const f = fixture();
    writeFileSync(join(f.config, '.env'), 'OPENROUTER_API_KEY=isolated-key\n');
    const result = run(f, f.config);
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout).key).toBe('isolated-key');
    expect(readFileSync(join(f.config, 'config.json'), 'utf8')).not.toContain('isolated-key');
  });

  it('preserves default home loading and ignores a target cwd env file', () => {
    const f = fixture();
    const result = run(f);
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout).key).toBe('operator-owned-key');
  });

  it('rejects relative paths before reading configuration', () => {
    const f = fixture();
    const result = run(f, 'relative-config');
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('T3MP3ST_CONFIG_DIR must be an absolute path');
  });
});
