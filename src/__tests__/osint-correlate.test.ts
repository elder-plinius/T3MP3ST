// Deep username sweep — correlation, harvesting and expansion.
//
// The bug this suite exists to prevent: the sweep used to be a single pass that attached a
// handle to every site and discarded everything it learned. These tests pin the parts that make
// it an investigation instead — cross-link harvesting, evidence-based clustering, and the honest
// handling of a source that cannot answer.

import { describe, it, expect } from 'vitest';
import {
  handleSimilarity,
  levenshtein,
  isPlausibleHandle,
  handleFromProfileUrl,
  mineHandlesFromProfile,
  correlateAccounts,
  keybaseIdentities,
  linkHubLinks,
  emailHandleCandidates,
  nextUserAgent,
  OSINT_DEEP_TOOLS,
  KEYBASE_STATUS,
} from '../tools/osint-correlate.js';
import type { UsernameHit } from '../tools/osint.js';

const hit = (site: string, url: string, profile?: UsernameHit['profile']): UsernameHit => ({
  site,
  category: 'social',
  url,
  status: 'found',
  confidence: 'high',
  profile,
});

const jsonResponse = (body: unknown) =>
  new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
const htmlResponse = (body: string) => new Response(body, { status: 200, headers: { 'content-type': 'text/html' } });

describe('handle similarity', () => {
  it('ignores separators, so john_smith and john.smith are the same handle', () => {
    expect(handleSimilarity('john_smith', 'johnsmith')).toBe(1);
    expect(handleSimilarity('john.smith', 'johnsmith')).toBe(1);
    expect(handleSimilarity('JohnSmith', 'johnsmith')).toBe(1);
  });

  it('scores unrelated handles low and related ones high', () => {
    expect(handleSimilarity('abc', 'xyz')).toBe(0);
    expect(handleSimilarity('torvalds', 'tavares')).toBeLessThan(0.7);
    expect(levenshtein('kitten', 'sitting')).toBe(3);
  });

  it('treats containment as a strong signal, not a near-miss', () => {
    expect(handleSimilarity('smith', 'johnsmith')).toBe(0.9);
  });

  it('is safe with empty input', () => {
    expect(handleSimilarity('', 'abc')).toBe(0);
    expect(handleSimilarity('abc', '')).toBe(0);
  });
});

describe('plausible-handle filter', () => {
  it('rejects the things that are not handles', () => {
    for (const bad of ['', 'ab', '12345', 'photo.png', 'the', 'a'.repeat(60), '-leading', 'trailing-', 'has space']) {
      expect(isPlausibleHandle(bad), `${JSON.stringify(bad)} must be rejected`).toBe(false);
    }
  });

  it('accepts real handle shapes and strips a leading @', () => {
    for (const good of ['johnsmith', '@jsmith', 'a.b_c', 'user-1', 'torvalds_here']) {
      expect(isPlausibleHandle(good), `${JSON.stringify(good)} must be accepted`).toBe(true);
    }
  });

  it('rejects leading/trailing separators, which the major platforms disallow', () => {
    // GitHub forbids "_" in usernames outright; X forbids a leading/trailing "_". Being strict
    // here is what keeps asset blobs and truncated segments out of the probe queue.
    for (const bad of ['_leading', 'trailing_', '-dash', '.dot']) {
      expect(isPlausibleHandle(bad), `${JSON.stringify(bad)} must be rejected`).toBe(false);
    }
  });
});

describe('profile URL → handle', () => {
  it('reads the handle off the platforms that use it', () => {
    expect(handleFromProfileUrl('https://github.com/torvalds')).toBe('torvalds');
    expect(handleFromProfileUrl('https://x.com/jack')).toBe('jack');
    expect(handleFromProfileUrl('https://reddit.com/u/kuf')).toBe('kuf');
    expect(handleFromProfileUrl('https://medium.com/@author')).toBe('author');
  });

  it('rejects asset URLs — the first version harvested favicon.ico as a "handle"', () => {
    expect(handleFromProfileUrl('https://assets.production.linktr.ee/profiles/_next/static/logo.png')).toBeNull();
    expect(handleFromProfileUrl('https://ugc.production.linktr.ee/favicon.ico')).toBeNull();
    expect(handleFromProfileUrl('https://cdn.example.com/static/main.js')).toBeNull();
  });

  it('rejects bare domains and non-profile paths', () => {
    expect(handleFromProfileUrl('https://github.com')).toBeNull();
    expect(handleFromProfileUrl('https://example.com/p/about')).toBeNull();
    expect(handleFromProfileUrl('https://example.com/blog/post-title')).toBeNull();
    expect(handleFromProfileUrl('not a url')).toBeNull();
  });
});

describe('profile harvesting', () => {
  it('mines the cross-links a public profile already publishes', () => {
    const found = mineHandlesFromProfile(
      hit('GitHub', 'https://github.com/torvalds', {
        displayName: 'Linus Torvalds',
        twitter: 'torvalds_here',
        blog: 'https://lkml.kernel.org/',
        bio: 'Creator of Linux. ping @gregkh',
      })
    );
    const handles = found.map((h) => h.handle);
    expect(handles).toContain('torvalds_here');
    expect(handles).toContain('gregkh');
    expect(handles).toContain('linustorvalds');
    // Every result must carry its provenance — an unexplained handle is not evidence.
    for (const h of found) expect(h.detail.length).toBeGreaterThan(0);
  });

  it('lower-cases display-name guesses, since handles are case-insensitive', () => {
    const found = mineHandlesFromProfile(hit('GitHub', 'https://github.com/x', { displayName: 'Linus Torvalds' }));
    for (const h of found) expect(h.handle).toBe(h.handle.toLowerCase());
  });

  it('returns nothing for a bare account with no profile data', () => {
    expect(mineHandlesFromProfile(hit('Reddit', 'https://reddit.com/u/x'))).toEqual([]);
  });
});

describe('account correlation', () => {
  it('links accounts that share an avatar and rates it medium', () => {
    const groups = correlateAccounts([
      hit('GitHub', 'https://github.com/torvalds', { imageUrl: 'https://avatars.githubusercontent.com/u/1?v=4' }),
      hit('Reddit', 'https://reddit.com/u/torvalds', { imageUrl: 'https://avatars.githubusercontent.com/u/1?v=4' }),
    ]);
    expect(groups).toHaveLength(1);
    expect(groups[0].strength).toBe('medium');
    expect(groups[0].sites.sort()).toEqual(['GitHub', 'Reddit']);
  });

  it('treats an explicit self-published cross-link as the strongest evidence', () => {
    const groups = correlateAccounts(
      [hit('Keybase', 'https://keybase.io/l_torvalds'), hit('GitHub', 'https://github.com/torvalds')],
      { keybaseLinks: [{ from: 'l_torvalds', to: 'torvalds', service: 'github', proof: 'github_https' }] }
    );
    expect(groups).toHaveLength(1);
    expect(groups[0].strength).toBe('strong');
    expect(groups[0].evidence[0]).toMatch(/Keybase links/);
  });

  it('links accounts sharing a distinctive bio term', () => {
    const groups = correlateAccounts([
      hit('DevTo', 'https://dev.to/alpha', { bio: 'rust systems engineer kernel maintainer' }),
      hit('Mastodon', 'https://mastodon.social/@alpha', { bio: 'kernel maintainer and rust dev' }),
    ]);
    expect(groups).toHaveLength(1);
    expect(groups[0].evidence.join(' ')).toMatch(/Shares bio term/);
  });

  // The failure mode that makes naive sweeps look impressive while being worthless.
  it('never groups accounts that merely both exist', () => {
    const groups = correlateAccounts([
      hit('GitHub', 'https://github.com/zebra'),
      hit('Reddit', 'https://reddit.com/u/potato'),
      hit('Twitch', 'https://twitch.tv/quantumfox'),
    ]);
    expect(groups).toEqual([]);
  });

  it('returns nothing when there is nothing found', () => {
    expect(correlateAccounts([])).toEqual([]);
  });
});

describe('Keybase lane (defunct — must be honest, not silently empty)', () => {
  it('reports an outage instead of pretending it found no identities', () => {
    // The reason this lane exists at all: a dead source that returns [] quietly reads as
    // "this person has no linked identities". The status string says what actually happened.
    expect(KEYBASE_STATUS).toMatch(/offline|404/i);
    expect(KEYBASE_STATUS.length).toBeGreaterThan(40);
  });

  it('returns [] when the endpoint 404s', async () => {
    const notFound = async () => new Response('404 - sorry, not found.', { status: 404 });
    expect(await keybaseIdentities('chris', notFound as never)).toEqual([]);
  });

  it('still parses identities if the legacy shape ever returns', async () => {
    const legacy = async () =>
      jsonResponse({
        user: { username: 'chris' },
        identities: [
          { username: 'chris', service_name: 'twitter', proofs: [{ service: 'twitter' }] },
          { username: 'cmix', service_name: 'github', proofs: [{ service: 'github_https', pretty_proof_url: 'https://github.com/cmix' }] },
        ],
      });
    const ids = await keybaseIdentities('chris', legacy as never);
    // The identity naming the seed itself carries no new information.
    expect(ids.map((i) => i.username)).toEqual(['cmix']);
    expect(ids[0].proof).toBe('github_https');
  });
});

describe('link-hub harvesting', () => {
  it('keeps only known profile hosts — a hub page inlines its whole asset CDN', async () => {
    const page = htmlResponse(`
      <a href="https://github.com/torvalds">gh</a>
      <a href="https://x.com/torvalds">x</a>
      <a href="https://ugc.production.linktr.ee/RKwyKP4sTEq3VsGsF5yw_uvo5WsNmflRzmWjJ">blob</a>
      <a href="https://assets.production.linktr.ee/profiles/_next/static/logo.png">logo</a>
      <a href="https://about.link.me/privacypolicy">legal</a>
      <a href="https://linktr.ee/other">self</a>
    `);
    const links = await linkHubLinks('torvalds', (async () => page) as never);
    const handles = links.map((l) => l.handle);
    expect(handles).toContain('torvalds');
    expect(handles).not.toContain('privacypolicy');
    expect(handles).not.toContain('other');
    expect(links.every((l) => /^https?:\/\//.test(l.url))).toBe(true);
  });
});

describe('email → handle derivation (the Blackbird technique, reimplemented)', () => {
  it('uses the local-part first, then its mutations', () => {
    const h = emailHandleCandidates('linus.torvalds@gmail.com');
    expect(h[0]).toBe('linus.torvalds');
    expect(h).toContain('linustorvalds');   // Gmail dot-folding
    expect(h).toContain('linus_torvalds');
  });

  it('strips +tag sub-addressing, which is the mail provider not the person', () => {
    expect(emailHandleCandidates('linus.torvalds+kernel@linux-foundation.org')[0]).toBe('linus.torvalds');
  });

  it('adds initial+last and last+first for a dotted local-part', () => {
    const h = emailHandleCandidates('j.torvalds@kernel.org');
    expect(h).toContain('torvaldsj');
    expect(h).toContain('jtorvalds');
  });

  it('returns the plain local-part when there is nothing to mutate', () => {
    expect(emailHandleCandidates('raulg@msn.com')).toEqual(['raulg']);
  });

  it('refuses non-emails and local-parts that cannot be handles', () => {
    expect(emailHandleCandidates('not-an-email')).toEqual([]);
    expect(emailHandleCandidates('')).toEqual([]);
    expect(emailHandleCandidates('12345@x.com')).toEqual([]);   // digits only = an id, not a handle
  });

  it('never returns a duplicate and honours the cap', () => {
    const h = emailHandleCandidates('a.b.c.d@x.com', 3);
    expect(h.length).toBeLessThanOrEqual(3);
    expect(new Set(h.map((x) => x.toLowerCase())).size).toBe(h.length);
  });
});

describe('user-agent rotation', () => {
  it('cycles a pool of ordinary desktop strings instead of one static UA', () => {
    // A single static UA across hundreds of probes is the shape WAFs fingerprint; a 403 then
    // lands in the sweep as `unknown`, which is indistinguishable from "account does not exist".
    const seen = new Set<string>();
    for (let i = 0; i < 24; i++) seen.add(nextUserAgent());
    expect(seen.size).toBeGreaterThan(1);
    for (const ua of seen) expect(ua).toMatch(/Mozilla\/5\.0/);
  });
});

describe('agent tool registration', () => {
  it('registers the deep sweep as a real, required-parameter tool', () => {
    const t = OSINT_DEEP_TOOLS.find((x) => x.name === 'osint_username_deep');
    expect(t).toBeDefined();
    expect(t!.category).toBe('osint');
    expect((t!.parameters || []).some((p) => p.name === 'username' && p.required === true)).toBe(true);
  });

  it('keeps the deep tool separate from OSINT_TOOLS to avoid an import cycle', () => {
    // osint-correlate imports osint; osint must not import osint-correlate back.
    expect(OSINT_DEEP_TOOLS.map((t) => t.name)).not.toContain('osint_username_sweep');
  });
});
