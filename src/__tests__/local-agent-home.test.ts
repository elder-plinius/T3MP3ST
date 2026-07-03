/**
 * agentHome() — fix for "redirected HOME breaks local-agent detection".
 *
 * T3MP3ST may run with $HOME redirected (app-config storage), but the agent CLIs keep their
 * own auth artifacts (~/.claude.json, ~/.codex/auth.json, ~/.hermes/.env) in the REAL home.
 * If detection/spawn used the redirected HOME, an installed-and-authed agent would look
 * unavailable (dead Settings checkboxes). agentHome() resolves the real home independently.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { userInfo } from 'os';
import { agentHome } from '../agent/local-agents.js';

describe('agentHome — real CLI-auth home, independent of a redirected $HOME', () => {
  const saved = { override: process.env.T3MP3ST_AGENT_HOME, home: process.env.HOME };
  const restore = (k: 'T3MP3ST_AGENT_HOME' | 'HOME', v: string | undefined): void => {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  };
  afterEach(() => {
    restore('T3MP3ST_AGENT_HOME', saved.override);
    restore('HOME', saved.home);
  });

  it('prefers the explicit T3MP3ST_AGENT_HOME override over a redirected HOME', () => {
    process.env.T3MP3ST_AGENT_HOME = '/real/user/home';
    process.env.HOME = '/tmp/redirected';
    expect(agentHome()).toBe('/real/user/home');
  });

  it('auto-recovers the real home (OS user DB) when HOME is redirected and no override is set', () => {
    delete process.env.T3MP3ST_AGENT_HOME;
    process.env.HOME = '/tmp/redirected-should-be-ignored';
    // userInfo().homedir reads getpwuid, NOT $HOME → the true home
    expect(agentHome()).toBe(userInfo().homedir);
    expect(agentHome()).not.toBe('/tmp/redirected-should-be-ignored');
  });

  it('ignores a blank/whitespace override and falls through to the real home', () => {
    process.env.T3MP3ST_AGENT_HOME = '   ';
    expect(agentHome()).toBe(userInfo().homedir);
  });
});
