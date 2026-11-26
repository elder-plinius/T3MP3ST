import { describe, it, expect } from 'vitest';
import { GOOGLE_OSINT_TOOLS } from '../tools/osint-google.js';
import {
  OSINT_SITES,
  OSINT_TOOLS,
  runUsernameSweep,
  usernamePermutations,
  phoneIntel,
  personDorks,
  validateUsername,
  isPrivateIp,
  ipGeo,
  geocodeText,
  parseHudsonRock,
  parseHibpCatalog,
} from '../tools/osint.js';
import { INFRA_TOOLS } from '../tools/osint-infra.js';

describe('osint site catalog', () => {
  it('every site is well-formed with unique names and valid probe configs', () => {
    const names = new Set<string>();
    expect(OSINT_SITES.length).toBeGreaterThanOrEqual(55);
    for (const s of OSINT_SITES) {
      expect(names.has(s.name), `duplicate site name ${s.name}`).toBe(false);
      names.add(s.name);
      expect(s.urlTemplate).toContain('{u}');
      expect(s.probeUrlTemplate).toContain('{u}');
      expect(['status', 'body_contains', 'json_array_nonempty', 'json_field']).toContain(s.probeType);
      expect(['high', 'medium', 'low']).toContain(s.reliability);
      // body/json probes need a discriminator value to be meaningful
      if (s.probeType === 'body_contains' || s.probeType === 'json_field') {
        expect(s.probeValue).toBeTruthy();
      }
    }
  });

  it('covers the flagship platforms', () => {
    const names = new Set(OSINT_SITES.map((s) => s.name));
    for (const expected of ['GitHub', 'Reddit', 'TikTok', 'Telegram', 'Keybase', 'chess.com', 'Steam', 'SoundCloud', 'Bluesky']) {
      expect(names.has(expected), `missing flagship site ${expected}`).toBe(true);
    }
  });
});

describe('osint agent tools', () => {
  it('registers 21 tools in the osint category with required parameters', () => {
    // The infrastructure registry is a separate array but the SAME category and the
    // SAME registered surface — src/index.ts registers both, so the gate covers both.
    // Counting only OSINT_TOOLS would let a new infrastructure tool ship unguarded.
    const ALL_OSINT = [...OSINT_TOOLS, ...INFRA_TOOLS, ...GOOGLE_OSINT_TOOLS];
    expect(OSINT_TOOLS.length).toBe(16);
    expect(INFRA_TOOLS.length).toBe(3);
    expect(GOOGLE_OSINT_TOOLS.length).toBe(2);
    expect(ALL_OSINT.length).toBe(21);
    // Catalog generators are legitimately invocable bare (they emit a query
    // library, they don't search one subject) — documented exception to the
    // "every tool has a required input" rule.
    const INPUT_OPTIONAL = new Set(['osint_google_dorks']);
    const names = new Set<string>();
    for (const t of ALL_OSINT) {
      expect(names.has(t.name), `duplicate tool ${t.name}`).toBe(false);
      names.add(t.name);
      expect(t.category).toBe('osint');
      expect(typeof t.handler).toBe('function');
      const required = (t.parameters || []).filter((p) => p.required);
      if (!INPUT_OPTIONAL.has(t.name)) expect(required.length).toBeGreaterThanOrEqual(1);
    }
    for (const expected of [
      'osint_username_sweep',
      'osint_email_lookup',
      'osint_phone_lookup',
      'osint_breach_lookup',
      'osint_person_locate',
      'osint_username_permutate',
      'osint_darkweb_leak_monitor',
      'osint_onion_search',
      'osint_onion_fetch',
      'osint_people_records',
      'osint_domain_infra',
      'osint_ip_infra',
      'osint_hash_lookup',
    ]) {
      expect(names.has(expected), `missing tool ${expected}`).toBe(true);
    }
  });

  it('sweep tool validates the username and rejects garbage', async () => {
    const sweep = OSINT_TOOLS.find((t) => t.name === 'osint_username_sweep')!;
    const bad = await sweep.handler({
      parameters: { username: 'not/valid##' },
      target: undefined,
    } as never);
    expect(bad.success).toBe(false);
    expect(bad.error).toMatch(/Invalid username/i);
  });

  it('permutate tool generates handle variants from a real name', async () => {
    const perm = OSINT_TOOLS.find((t) => t.name === 'osint_username_permutate')!;
    const res = await perm.handler({
      parameters: { first: 'John', last: 'Smith', birthYear: '1990' },
    } as never);
    expect(res.success).toBe(true);
    expect(res.output).toContain('johnsmith');
    expect(res.output).toContain('jsmith');
    expect(res.output).toContain('john.smith');
    expect(res.output).toContain('johnsmith1990');
  });
});

describe('username sweep classification', () => {
  it('classifies found/absent/unknown against a live local stub (all four probe types)', async () => {
    // Local stub standing in for four platform shapes: a status-probe hit (200),
    // a status-probe miss (404), a login-wall block (403 → unknown), a soft-404
    // body page (Telegram style), and a JSON array endpoint (GitLab style) —
    // proves the probe classifier without touching any real service.
    const { createServer } = await import('node:http');
    const srv = createServer((req, res) => {
      const path = req.url || '';
      if (path.startsWith('/status-ok')) { res.statusCode = 200; res.end('hello'); }
      else if (path.startsWith('/status-gone')) { res.statusCode = 404; res.end('nope'); }
      else if (path.startsWith('/blocked')) { res.statusCode = 403; res.end('forbidden'); }
      else if (path.startsWith('/soft-miss')) {
        res.statusCode = 200;
        res.end('<html>If you don\'t have Telegram... <b>no marker here</b></html>');
      } else if (path.startsWith('/soft-hit')) {
        res.statusCode = 200;
        res.end('<html><div class="tgme_page_title">Stub User</div></html>');
      } else if (path.startsWith('/arr-empty')) { res.statusCode = 200; res.end('[]'); }
      else if (path.startsWith('/arr-hit')) { res.statusCode = 200; res.end('[{"id":1}]'); }
      else { res.statusCode = 404; res.end(); }
    });
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
    const port = (srv.address() as { port: number }).port;
    const base = `http://127.0.0.1:${port}`;
    try {
      const sweep = await runUsernameSweep('stubuser', {
        customSites: [
          { name: 'StubStatusHit', category: 'social', urlTemplate: base + '/status-ok/{u}', probeUrlTemplate: base + '/status-ok/{u}', probeType: 'status', reliability: 'high' },
          { name: 'StubStatusMiss', category: 'social', urlTemplate: base + '/status-gone/{u}', probeUrlTemplate: base + '/status-gone/{u}', probeType: 'status', reliability: 'high' },
          { name: 'StubBlocked', category: 'social', urlTemplate: base + '/blocked/{u}', probeUrlTemplate: base + '/blocked/{u}', probeType: 'status', reliability: 'medium' },
          { name: 'StubSoft404Miss', category: 'messaging', urlTemplate: base + '/soft-miss/{u}', probeUrlTemplate: base + '/soft-miss/{u}', probeType: 'body_contains', probeValue: 'tgme_page_title', reliability: 'high' },
          { name: 'StubSoft404Hit', category: 'messaging', urlTemplate: base + '/soft-hit/{u}', probeUrlTemplate: base + '/soft-hit/{u}', probeType: 'body_contains', probeValue: 'tgme_page_title', reliability: 'high' },
          { name: 'StubArrMiss', category: 'dev', urlTemplate: base + '/arr-empty/{u}', probeUrlTemplate: base + '/arr-empty/{u}', probeType: 'json_array_nonempty', reliability: 'high' },
          { name: 'StubArrHit', category: 'dev', urlTemplate: base + '/arr-hit/{u}', probeUrlTemplate: base + '/arr-hit/{u}', probeType: 'json_array_nonempty', reliability: 'high' },
        ],
      });

      const bySite = new Map(sweep.found.map((h) => [h.site, h]));
      expect(bySite.get('StubStatusHit')!.status).toBe('found');
      expect(bySite.get('StubSoft404Hit')!.status).toBe('found');
      expect(bySite.get('StubArrHit')!.status).toBe('found');
      expect(sweep.absent).toBe(3);
      const unknown = sweep.unknown.map((u) => u.site);
      expect(unknown).toContain('StubBlocked');
      expect(sweep.checked).toBe(7);
    } finally {
      await new Promise<void>((r) => srv.close(() => r()));
    }
  });

  it('a site filter that matches nothing fails honestly', async () => {
    await expect(runUsernameSweep('someuser', { sites: ['__never_matches__'] })).rejects.toThrow(/no sites/i);
  });

  it('validateUsername strips @ and rejects path characters', () => {
    expect(validateUsername('@handle')).toBe('handle');
    expect(validateUsername('normal_user.1')).toBe('normal_user.1');
    expect(validateUsername('a/b')).toBeNull();
    expect(validateUsername('')).toBeNull();
    expect(validateUsername('x'.repeat(65))).toBeNull();
  });
});

describe('phone intel', () => {
  it('normalizes NANP numbers and validates the area code', () => {
    const p = phoneIntel('(718) 555-0199');
    expect(p.e164).toBe('+17185550199');
    expect(p.countryCode).toBe('1');
    expect(p.nanp).not.toBeNull();
    expect(p.nanp!.areaCode).toBe('718');
    expect(p.nanp!.validAreaCode).toBe(true);
    expect(p.searchLinks.some((l) => l.url.includes('truecaller'))).toBe(true);
  });

  it('routes international prefixes to the right country', () => {
    expect(phoneIntel('+44 20 7946 0958').country).toContain('United Kingdom');
    expect(phoneIntel('+49 30 901820').country).toContain('Germany');
    expect(phoneIntel('+8687654321').country).toContain('China');
  });

  it('flags invalid NANP area codes (N11 / leading 0/1)', () => {
    expect(phoneIntel('9115550199').nanp!.validAreaCode).toBe(false);
    expect(phoneIntel('0115550199').nanp!.validAreaCode).toBe(false);
  });

  it('rejects garbage', () => {
    expect(() => phoneIntel('123')).toThrow();
    expect(() => phoneIntel('not a phone at all')).toThrow();
  });
});

describe('username permutations', () => {
  it('generates the classic handle shapes with year suffixes', () => {
    const perms = usernamePermutations('John', 'Smith', { birthYear: '1990' });
    const set = new Set(perms);
    for (const expected of ['johnsmith', 'smithjohn', 'john.smith', 'john_smith', 'jsmith', 'johns', 'johnsmith1990', 'johnsmith90']) {
      expect(set.has(expected), `missing permutation ${expected}`).toBe(true);
    }
  });

  it('honors the max cap', () => {
    const perms = usernamePermutations('Al', 'Bee', { max: 10 });
    expect(perms.length).toBeLessThanOrEqual(10);
  });

  it('requires both names', () => {
    expect(() => usernamePermutations('', 'Smith')).toThrow();
    expect(() => usernamePermutations('John', '')).toThrow();
  });
});

describe('geo intel', () => {
  it('classifies private/loopback addresses without any network call', () => {
    expect(isPrivateIp('192.168.1.100')).toBe(true);
    expect(isPrivateIp('10.0.0.5')).toBe(true);
    expect(isPrivateIp('172.16.0.1')).toBe(true);
    expect(isPrivateIp('127.0.0.1')).toBe(true);
    expect(isPrivateIp('169.254.9.9')).toBe(true);
    expect(isPrivateIp('172.32.0.1')).toBe(false);
    expect(isPrivateIp('8.8.8.8')).toBe(false);
    expect(isPrivateIp('107.6.139.189')).toBe(false);
  });

  it('private IPs geolocate as LAN assets — honest no-public-geo result', async () => {
    const g = await ipGeo('192.168.1.100');
    expect(g.resolved).toBe(true);
    expect(g.privateLan).toBe(true);
    expect(g.note).toMatch(/private/i);
    expect(g.lat).toBeUndefined();
  });

  it('geocodeText caches per query (second call is instant, no network)', async () => {
    const first = await geocodeText('Brooklyn, New York');
    const t0 = Date.now();
    const second = await geocodeText('Brooklyn, New York');
    expect(second).toEqual(first);
    expect(Date.now() - t0).toBeLessThan(50);
  });
});

describe('dark web direct', () => {
  it('parses Ahmia result HTML into title/url/snippet records (fixture, no network)', async () => {
    const { parseAhmiaResults } = await import('../tools/osint.js');
    const fixture = `
      <li class="result first">
        <h4><a href="http://a2z5g7xrbqc3d5f7arbqc3d5f7arbqc3.onion/?id=1&amp;x=2">Searchable Onionservice One</a></h4>
        <p>First result snippet text.</p>
        <cite>http://a2z5g7xrbqc3d5f7arbqc3d5f7arbqc3.onion/?id=1&amp;x=2</cite>
      </li>
      <li class="result">
        <h4><a href="http://b2z5g7xrbqc3d5f7arbqc3d5f7arbqc3.onion/">Second Service</a></h4>
        <p>Second snippet.</p>
      </li>
      <li class="result">
        <h4><a href="http://a2z5g7xrbqc3d5f7arbqc3d5f7arbqc3.onion/?id=1&amp;x=2">Duplicate — should be skipped</a></h4>
      </li>
      <li class="result">
        <h4><a href="https://clearnet.example.com/not-onion">Not an onion — skipped</a></h4>
      </li>`;
    const results = parseAhmiaResults(fixture);
    expect(results.length).toBe(2);
    expect(results[0].title).toBe('Searchable Onionservice One');
    expect(results[0].url).toBe('http://a2z5g7xrbqc3d5f7arbqc3d5f7arbqc3.onion/?id=1&x=2');
    expect(results[0].snippet).toContain('First result snippet');
    expect(results[1].url).toContain('b2z5g7xrbqc3');
  });

  it('onionFetch rejects non-onion URLs before touching Tor', async () => {
    const { onionFetch } = await import('../tools/osint.js');
    await expect(onionFetch('https://example.com/clearnet')).rejects.toThrow(/not a \.onion/i);
  });
});

describe('identity corroboration', () => {
  it('matches subject names against profile display names', async () => {
    const { scoreIdentityMatch } = await import('../tools/osint.js');
    expect(scoreIdentityMatch({ name: 'Linus Torvalds' }, { displayName: 'Linus Torvalds' })).toBe('name-match');
    expect(scoreIdentityMatch({ name: 'Linus Torvalds' }, { displayName: 'Linus T.' })).toBe('name-mismatch'); // initial-only is ambiguous → never attributed to the subject
    expect(scoreIdentityMatch({ name: 'Linus Torvalds' }, { displayName: 'torvalds' })).toBe('name-match'); // last-name substring (handle-style)
    expect(scoreIdentityMatch({ name: 'Linus Torvalds' }, { displayName: 'bio: written by Linus Torvalds' })).toBe('name-match');
    expect(scoreIdentityMatch({ name: 'John Smith' }, { displayName: 'Alice Chains' })).toBe('name-mismatch');
    expect(scoreIdentityMatch({ name: 'John Smith' }, { displayName: 'JSmith Gaming' })).toBe('name-match'); // initials-style: carries the last name
    expect(scoreIdentityMatch({ name: 'Raul Glasgow' }, { displayName: 'Raul Gutierrez' })).toBe('name-mismatch'); // first-name-only overlap = DIFFERENT person
    expect(scoreIdentityMatch({ name: 'John Smith' }, null)).toBe('handle-only');
    expect(scoreIdentityMatch({}, { displayName: 'Linus Torvalds' })).toBe('handle-only'); // no hints, no claims
    expect(scoreIdentityMatch({ name: 'john smith' }, { displayName: '  John   Smith  ' })).toBe('name-match'); // normalization
  });
});

describe('search extraction', () => {
  it('extracts emails, phones and social URLs from search text', async () => {
    const { extractContacts } = await import('../tools/osint.js');
    const r = extractContacts(
      'Contact John Smith at john.smith83@gmail.com or call (718) 555-0142. ' +
      'See https://github.com/jsmith83 and https://t.me/jsmith83 — born 1985, year 2020 photo.png admin@example.com'
    );
    expect(r.emails).toContain('john.smith83@gmail.com');
    expect(r.emails.some((e) => e.includes('example.com'))).toBe(false); // decoy filtered
    expect(r.emails.some((e) => e.endsWith('.png'))).toBe(false);
    expect(r.phones).toContain('(718) 555-0142');
    expect(r.socialUrls.some((u) => u.includes('github.com/jsmith83'))).toBe(true);
    expect(r.socialUrls.some((u) => u.includes('t.me/jsmith83'))).toBe(true);
  });


  it('extracts street addresses with city/state/zip and filters junk', async () => {
    const { extractContacts } = await import('../tools/osint.js');
    const r = extractContacts(
      'Office: 742 Evergreen Terrace, Springfield, IL 62704 · PO Box 1234, Austin, TX 78701 · ' +
      'version 1.2.3.4 · lorem ipsum street example · 1600 Pennsylvania Ave NW, Washington, DC 20500'
    );
    expect(r.addresses.some((a) => a.includes('742 Evergreen Terrace') && a.includes('Springfield, IL 62704'))).toBe(true);
    expect(r.addresses.some((a) => /PO Box 1234/.test(a))).toBe(true);
    expect(r.addresses.some((a) => a.includes('1600 Pennsylvania Ave NW'))).toBe(true);
    expect(r.addresses.some((a) => a.includes('1.2.3.4') || a.includes('lorem'))).toBe(false);
  });

  it('htmlToText strips script/style/noise and keeps the visible text', async () => {
    const { htmlToText } = await import('../tools/osint.js');
    const txt = htmlToText('<html><script>var a=1;</script><style>.x{}</style><p>Call (212) 555-1234</p><div>123 Main St, Austin, TX 78701</div></html>');
    expect(txt).toContain('(212) 555-1234');
    expect(txt).toContain('123 Main St, Austin, TX 78701');
    expect(txt).not.toContain('var a=1');
    expect(txt).not.toContain('.x{}');
  });

  it('mineResultPage parses the FETCHED page (not the snippet) for contacts', async () => {
    const { mineResultPage } = await import('../tools/osint.js');
    const fakeFetchers = [
      async () => '<html><body><p>Reach the office at 350 Fifth Ave, New York, NY 10118 or billing@corp.example-site.test</p><p>Desk: (646) 555-7788</p></body></html>',
    ];
    const m = await mineResultPage('https://contactpage.test/about', 'About us', fakeFetchers);
    expect(m.fetched).toBe(true);
    expect(m.emails).toContain('billing@corp.example-site.test');
    expect(m.phones).toContain('(646) 555-7788');
    expect(m.addresses.some((a) => a.includes('350 Fifth Ave'))).toBe(true);
    const dead = await mineResultPage('https://x.test', 'x', [async () => null, async () => { throw new Error('down'); }]);
    expect(dead.fetched).toBe(false);
    expect(dead.emails).toHaveLength(0);
  });

  it('parses Bing SERP blocks into results (fixture)', async () => {
    const { parseBingResults } = await import('../tools/osint.js');
    const fixture = '<li class="b_algo"><h2><a href="https://example.org/profile">Profile Page</a></h2>' +
      '<p class="b_lineclamp">Snippet with (718) 555-0142 inside.</p></li>';
    const r = parseBingResults(fixture);
    expect(r.length).toBe(1);
    expect(r[0].title).toBe('Profile Page');
    expect(r[0].url).toBe('https://example.org/profile');
    expect(r[0].snippet).toContain('(718) 555-0142');
  });
});

describe('people records parsing', () => {
  it('parses FastPeopleSearch innerText into structured records (fixture)', async () => {
    const { parseFastPeopleSearch } = await import('../tools/osint.js');
    const fixture = [
      'FastPeopleSearch',
      '5 FREE public records found for Raul Glasgow.',
      'Raul Glasgow',
      'East Orange, NJ',
      'VIEW FREE DETAILS',
      'Raul Glasgow',
      'Age 54 \u2022 Brooklyn, NY',
      'Past Addresses: Brooklyn, NY \u2022 Newark, NJ \u2022 New York, NY',
      'Relatives: Cynthia Glasgow \u2022 Walter Lang',
      'AKA: Raul J Glasgow \u2022 Paul Glasgow',
      'VIEW FREE DETAILS',
    ].join('\n');
    const records = parseFastPeopleSearch(fixture, 'https://www.fastpeoplesearch.com/name/raul-glasgow');
    expect(records.length).toBe(2);
    expect(records[1].name).toBe('Raul Glasgow');
    expect(records[1].age).toBe(54);
    expect(records[1].city).toBe('Brooklyn, NY');
    expect(records[1].pastAddresses).toContain('Newark, NJ');
    expect(records[1].relatives).toContain('Cynthia Glasgow');
    expect(records[1].akas).toContain('Paul Glasgow');
    expect(records[1].sourceUrl).toContain('fastpeoplesearch.com');
  });
});

describe('person dorks', () => {
  it('builds engine + people-search links for every identifier kind', () => {
    const dorks = personDorks({ name: 'John Smith', email: 'john@example.com', username: 'jsmith', phone: '+17185550199', domain: 'example.com' });
    const labels = dorks.map((d) => d.label);
    expect(labels.some((l) => l.includes('Google: name'))).toBe(true);
    expect(labels.some((l) => l.includes('TruePeopleSearch'))).toBe(true);
    expect(labels.some((l) => l.includes('GitHub commits'))).toBe(true);
    expect(labels.some((l) => l.includes('Namechk'))).toBe(true);
    expect(labels.some((l) => l.includes('crt.sh'))).toBe(true);
    // Venmo lane is passive-only: search-engine index queries + the public profile URL.
    // No Venmo endpoint probing, no email→account enumeration.
    expect(labels.some((l) => l.includes('Venmo'))).toBe(true);
    const venmoIndexed = dorks.find((d) => d.label.includes('Venmo: indexed'));
    expect(venmoIndexed!.url).toContain('site%3Avenmo.com');
    const venmoProfile = dorks.find((d) => d.label.includes('Venmo: profile'));
    expect(venmoProfile!.url).toBe('https://venmo.com/u/jsmith');
    expect(dorks.every((d) => d.url.startsWith('https://'))).toBe(true);
  });
});

describe('new keyless breach lanes (Hudson Rock + HIBP catalogue)', () => {
  it('parseHudsonRock maps stealer infection records and handles the clean miss', () => {
    const hit = parseHudsonRock({
      total_corporate_services: 3, total_user_services: 7,
      stealers: [{ stealer_family: 'RedLine', date_compromised: '2026-08-14', computer_name: 'WS-42', ip_address: '203.0.113.9', operating_system: 'Windows 11', installed_software: ['Chrome', 'Slack'] }],
    });
    expect(hit.service).toBe('Hudson Rock');
    expect(hit.infected).toBe(true);
    expect(hit.infections[0].family).toBe('RedLine');
    expect(hit.infections[0].computerName).toBe('WS-42');
    expect(hit.infections[0].ip).toBe('203.0.113.9');
    expect(hit.infections[0].software).toEqual(['Chrome', 'Slack']);
    expect(hit.corporateServices).toBe(3);
    const miss = parseHudsonRock({ message: 'This email address is not associated with a computer infected by an info-stealer.', stealers: [] });
    expect(miss.infected).toBe(false);
    expect(miss.note).toContain('not associated');
  });

  it('parseHudsonRock tolerates camelCase and junk payloads', () => {
    const j = parseHudsonRock({ stealers: [{ malware: 'Raccoon', computerName: 'MBP', ip: '198.51.100.4', installedSoftware: 'not-an-array' }] });
    expect(j.infections[0].family).toBe('Raccoon');
    expect(j.infections[0].computerName).toBe('MBP');
    expect(j.infections[0].software).toBeUndefined();
    expect(parseHudsonRock(null).infected).toBe(false);
    expect(parseHudsonRock({ stealers: 'nope' }).infections).toHaveLength(0);
  });

  it('parseHibpCatalog maps catalogue entries and ignores non-arrays', () => {
    const entries = parseHibpCatalog([
      { Name: 'Adobe', Title: 'Adobe', Domain: 'adobe.com', BreachDate: '2013-10-04', PwnCount: 152445165, DataClasses: ['Email addresses', 'Password hints'], IsVerified: true, Description: '153M accounts' },
    ]);
    expect(entries).toHaveLength(1);
    expect(entries[0].name).toBe('Adobe');
    expect(entries[0].pwnCount).toBe(152445165);
    expect(entries[0].dataClasses).toContain('Password hints');
    expect(entries[0].isVerified).toBe(true);
    expect(parseHibpCatalog({ error: 'nope' })).toEqual([]);
  });
});

describe('ShadowDragon steps 3+5 (correlation + historical recovery)', () => {
  it('parseCdxSnapshots reads the CDX header row, keeps 200s, sorts, rejects junk', async () => {
    const { parseCdxSnapshots } = await import('../tools/osint.js');
    const snaps = parseCdxSnapshots([
      ['timestamp', 'original', 'statuscode', 'digest'],
      ['20200101', 'https://x.test/a', '404', 'd1'],
      ['20190101', 'https://x.test/a', '200', 'd2'],
      ['20210101', 'https://x.test/a', '200', 'd3'],
    ]);
    expect(snaps).toHaveLength(2);
    expect(snaps[0].timestamp).toBe('20190101');
    expect(snaps[1].digest).toBe('d3');
    expect(parseCdxSnapshots([['timestamp']])).toEqual([]);
    expect(parseCdxSnapshots({ error: 'rate limited' })).toEqual([]);
  });

  it('historicalProfileRecovery mines the newest archived snapshot for contacts', async () => {
    const { historicalProfileRecovery } = await import('../tools/osint.js');
    const cdx = JSON.stringify([['timestamp', 'original', 'statuscode'], ['20210101', 'https://site.test/u', '200']]);
    const page = '<html><body><p>Old bio: mail old@site.test, desk (212) 555-1234, 10 Downing St, Springfield, IL 62704</p></body></html>';
    const rec = await historicalProfileRecovery('https://site.test/u', {
      fetchRaw: async (u: string) => (u.includes('cdx') ? cdx : page),
    });
    expect(rec.snapshots).toHaveLength(1);
    expect(rec.recoveredAt).toBe('20210101');
    expect(rec.recoveredUrl).toContain('/web/20210101id_/');
    expect(rec.mined.emails).toContain('old@site.test');
    expect(rec.mined.phones).toContain('(212) 555-1234');
    expect(rec.mined.addresses.some((a) => a.includes('10 Downing St'))).toBe(true);
  });

  it('historicalProfileRecovery reports honestly when there are no snapshots', async () => {
    const { historicalProfileRecovery } = await import('../tools/osint.js');
    const rec = await historicalProfileRecovery('https://site.test/none', {
      fetchRaw: async () => JSON.stringify([['timestamp', 'original', 'statuscode']]),
    });
    expect(rec.snapshots).toHaveLength(0);
    expect(rec.note).toContain('no archived snapshots');
    expect(rec.mined.emails).toHaveLength(0);
  });

  it('correlateSocialSignals links same-avatar accounts across platforms and shared bio terms', async () => {
    const { correlateSocialSignals, bioTokens, avatarFingerprintBytes } = await import('../tools/osint.js');
    const fp = avatarFingerprintBytes(new Uint8Array([1, 2, 3, 4]));
    const sigs = correlateSocialSignals([
      { site: 'GitHub', url: 'https://github.com/x', avatarFingerprint: fp, bio: 'security researcher in Berlin' },
      { site: 'Mastodon', url: 'https://m.test/@x', avatarFingerprint: fp, bio: 'infosec Berlin' },
      { site: 'Reddit', url: 'https://reddit.com/u/x', avatarFingerprint: 'other', bio: 'gardening in Lisbon' },
    ]);
    const avatar = sigs.find((s) => s.kind === 'avatar');
    expect(avatar).toBeTruthy();
    expect(avatar!.accounts.map((a) => a.site).sort()).toEqual(['GitHub', 'Mastodon']);
    const bio = sigs.filter((s) => s.kind === 'bio').map((s) => s.value);
    expect(bio).toContain('berlin');
    expect(bio).not.toContain('lisbon');
    expect(bioTokens('the the and about').size).toBe(0);
  });
});
describe('local-LLM assist layer (unverified second opinion)', () => {
  it('parseLlmContactJson tolerates fences + prose and re-validates formats', async () => {
    const { parseLlmContactJson } = await import('../tools/osint.js');
    const fence = String.fromCharCode(96).repeat(3);
    const raw = 'Here you go:' + fence + 'json' + String.fromCharCode(10) + JSON.stringify({ emails: ['a@b.co', 'not an email'], phones: ['(212) 555-1234'], addresses: ['350 Fifth Ave, New York, NY 10118'] }) + String.fromCharCode(10) + fence;
    const ok = parseLlmContactJson(raw);
    expect(ok.emails).toContain('a@b.co');
    expect(ok.emails).toHaveLength(1); // the non-email died format validation
    expect(ok.phones).toContain('(212) 555-1234');
    expect(ok.addresses.some((a) => a.includes('350 Fifth Ave'))).toBe(true);
    expect(parseLlmContactJson('no json here').emails).toHaveLength(0);
  });

  it('llmAssistAcross returns empty without pages (never throws)', async () => {
    const { llmAssistAcross } = await import('../tools/osint.js');
    const out = await llmAssistAcross([{ url: 'x', title: 'x', fetched: false, emails: [], phones: [], addresses: [], socialUrls: [] }], async () => '{}');
    expect(out.pages).toBe(0);
    expect(out.emails).toHaveLength(0);
  });
});
describe('LLM search director (plan/rank parsing + guards)', () => {
  it('isPublicSearchUrl blocks private hosts, metadata and non-http schemes', async () => {
    const { isPublicSearchUrl } = await import('../tools/osint.js');
    expect(isPublicSearchUrl('https://www.cloudflare.com/contact')).toBe(true);
    expect(isPublicSearchUrl('http://example.com/x')).toBe(true);
    for (const bad of ['http://127.0.0.1:3333/api/health', 'http://localhost/x', 'http://192.168.1.5/admin', 'http://10.0.0.1', 'http://169.254.169.254/latest/meta-data', 'http://metadata.google.internal/x', 'file:///etc/passwd', 'javascript:alert(1)', 'not a url']) {
      expect(isPublicSearchUrl(bad), bad).toBe(false);
    }
  });

  it('parseLlmSearchPlan caps, sanitizes, sorts by priority and drops unsafe URLs', async () => {
    const { parseLlmSearchPlan } = await import('../tools/osint.js');
    const raw = JSON.stringify({
      plan: [
        { query: 'low priority thing', intent: 'x', priority: 10 },
        { query: 'high priority "Katherine May" Cloudflare', intent: 'direct email hunt', priority: 95 },
        { query: 'ab', intent: 'too short', priority: 99 },
      ],
      pages: [
        { url: 'https://www.cloudflare.com/contact', priority: 80, reason: 'contact page' },
        { url: 'http://127.0.0.1:3333/steal', priority: 99, reason: 'evil' },
      ],
    });
    const { plan, pages } = parseLlmSearchPlan(raw);
    expect(plan).toHaveLength(2);
    expect(plan[0].priority).toBe(95);
    expect(plan[0].query).toContain('Katherine May');
    expect(plan[1].priority).toBe(10);
    expect(pages).toHaveLength(1);
    expect(pages[0].url).toContain('cloudflare.com');
    expect(parseLlmSearchPlan('garbage').plan).toHaveLength(0);
  });

  it('parseLlmPageVerdicts only ranks URLs we actually fetched', async () => {
    const { parseLlmPageVerdicts } = await import('../tools/osint.js');
    const allowed = ['https://a.test/p1', 'https://a.test/p2'];
    const raw = JSON.stringify({ verdicts: [
      { url: 'https://a.test/p2', priority: 90, reason: 'strong' },
      { url: 'https://a.test/p1', priority: 40, reason: 'weak' },
      { url: 'https://never-fetched.test/x', priority: 100, reason: 'hallucinated' },
    ] });
    const v = parseLlmPageVerdicts(raw, allowed);
    expect(v).toHaveLength(2);
    expect(v[0].url).toContain('p2');
    expect(v.some((x) => x.url.includes('never-fetched'))).toBe(false);
  });
});
describe('aggressive director: playbook + fabrication guard', () => {
  it('queryHasUnknownIdentifier permits known identifiers and REFUSES fabricated ones', async () => {
    const { queryHasUnknownIdentifier } = await import('../tools/osint-aggressive.js');
    const known = { emails: ['jane@corp.example'], phones: ['4155550132'], urls: ['https://corp.example/team'], handles: ['jdoe'] };
    expect(queryHasUnknownIdentifier('"Jane Doe" ("jdoe" OR "janedoe") github', known)).toBeNull();
    expect(queryHasUnknownIdentifier('"Jane Doe" jane@corp.example', known)).toBeNull();
    expect(queryHasUnknownIdentifier('"Jane Doe" OR "zac.peters@onefiinix.com"', known)).toContain('email');
    expect(queryHasUnknownIdentifier('call (646) 555-7788', known)).toContain('phone');
    expect(queryHasUnknownIdentifier('site:invented-domain.test jane', known)).toContain('site');
  });

  it('parseDirectorPicks drops invented methods, unsafe urls and paramless picks', async () => {
    const { parseDirectorPicks } = await import('../tools/osint-aggressive.js');
    const raw = JSON.stringify({
      picks: [
        { method: 'web_search', query: '"Jane Doe" jdoe', reason: 'pivot' },
        { method: 'teleport_subject', query: 'hack the planet' },
        { method: 'contact_page', url: 'file:///etc/passwd' },
        { method: 'username_sweep' },
      ],
      gaps: ['no DOB', 'no linkage'],
    });
    const { picks, gaps } = parseDirectorPicks(raw);
    expect(picks).toHaveLength(2); // web_search + paramless username_sweep; teleport + file:// url refused
    expect(picks[0].method).toBe('web_search');
    expect(picks[1].method).toBe('username_sweep');
    expect(gaps).toEqual(['no DOB', 'no linkage']);
    expect(parseDirectorPicks('garbage').picks).toHaveLength(0);
  });

  it('directorHandleCandidates permutes a full name and rejects a single name', async () => {
    const { directorHandleCandidates, OSINT_PLAYBOOK } = await import('../tools/osint-aggressive.js');
    expect(OSINT_PLAYBOOK.length).toBeGreaterThanOrEqual(10);
    expect(OSINT_PLAYBOOK.map((m) => m.id)).toContain('people_records');
    expect(OSINT_PLAYBOOK.map((m) => m.id)).toContain('associates');
    const c = directorHandleCandidates('Jane Doe');
    expect(c.length).toBeGreaterThan(2);
    expect(c.some((h) => /jane|doe/i.test(h))).toBe(true);
    expect(directorHandleCandidates('Cher')).toEqual([]);
  });
});
describe('social-engineering pretext lab', () => {
  it('buildPretextSystemPrompt binds channel/objective and forbids payloads', async () => {
    const { buildPretextSystemPrompt } = await import('../tools/osint-aggressive.js');
    const p = buildPretextSystemPrompt({ channel: 'phone', objective: 'compliance_test', scope: 'ENG-1', scenario: 'x' });
    expect(p).toContain('Channel: phone');
    expect(p).toContain('AUTHORIZED');
    expect(p).toMatch(/compliance|policy/i);
    expect(p).toMatch(/malware|payload/i);
  });

  it('parsePretextResponse maps scripts, tolerates fences and caps at 3', async () => {
    const { parsePretextResponse } = await import('../tools/osint-aggressive.js');
    const fence = String.fromCharCode(96).repeat(3);
    const mk = (i: number) => ({ title: 'S' + i, rationale: 'r' + i, opening: 'opening ' + i, keyQuestions: ['q1 ' + i, ''], valueExchange: 'v' + i, objectionHandling: ['o1'], callToAction: 'c' + i });
    const raw = 'Here you go: ' + fence + 'json' + JSON.stringify({ scripts: [mk(1), mk(2), mk(3), mk(4)] }) + fence;
    const out = parsePretextResponse(raw, { channel: 'email', objective: 'credential_test' });
    expect(out).toHaveLength(3);
    expect(out[0].title).toBe('S1');
    expect(out[0].keyQuestions).toEqual(['q1 1']); // empty entries dropped
    expect(out[0].channel).toBe('email');
    expect(parsePretextResponse('garbage', { channel: 'phone', objective: 'credential_test' }).length).toBe(0);
  });
});
