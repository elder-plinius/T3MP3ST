import { describe, it, expect } from 'vitest';
import {
  classifyTarget,
  isIpv4,
  parseRdap,
  parseCrt,
  parseInternetDb,
  parseUrlscan,
  parseOtx,
  parseDnsAnswers,
  parseBlocklistDe,
  parseHashlookup,
  parseRipe,
  INFRA_TOOLS,
} from '../tools/osint-infra.js';

// =============================================================================
// OSINT INFRASTRUCTURE lane.
//
// Every parser below is pinned against the response shape that was measured
// LIVE, because four of them had a first draft that read the wrong field and
// silently returned an empty result while still reporting success:
//   * crt.sh   — name_value holds newline-separated SANs, not comma-separated
//   * Shodan   — "no data" is 200 + {detail}, which is NOT a result object
//   * dns.google — TXT data arrives wrapped in presentation quotes
//   * CIRCL    — keys are SHA-1 / SHA-256 (hyphenated), FileSize is a STRING,
//                and there is no FileType key at all
// =============================================================================

describe('classifyTarget', () => {
  it('reduces a full URL to its host', () => {
    expect(classifyTarget('https://www.Cloudflare.com/path?x=1#frag')).toEqual({ kind: 'domain', value: 'www.cloudflare.com' });
  });

  it('drops credentials and a port', () => {
    expect(classifyTarget('user@evil.co:443').kind).toBe('domain');
    expect(classifyTarget('user@evil.co:443').value).toBe('evil.co');
    expect(classifyTarget('1.1.1.1:8080').value).toBe('1.1.1.1');
  });

  it('strips a trailing dot and lowercases', () => {
    expect(classifyTarget('EXAMPLE.COM.').value).toBe('example.com');
  });

  it('REFUSES a schemeless email instead of unwrapping it into its domain', () => {
    // The regression: `v.replace(/^[^@]*@/, '')` unwraps URL credentials, and on a
    // plain `someone@example.com` it silently produced the DOMAIN example.com — so
    // this module answered with a confident, formatted report about a website the
    // operator never asked about. A negative that reads as real is worse than a crash.
    for (const addr of ['test@example.com', 'first.last+tag@mail.co.uk', '  spaced@example.com ']) {
      const t = classifyTarget(addr);
      expect(t.kind, `${addr} should be refused`).toBe('invalid');
      expect(t.note).toMatch(/email address/i);
    }
  });

  it('still unwraps REAL url credentials and the schemeless userinfo:port form', () => {
    // The port suffix is the whole distinction, so the pre-existing
    // `user@host:port` behaviour is untouched — the gate below already pinned it.
    expect(classifyTarget('https://user:pass@example.com/').value).toBe('example.com');
    expect(classifyTarget('user@evil.co:443').value).toBe('evil.co');
  });

  it('sends user@1.2.3.4 down the IP path, not the email path', () => {
    // DOMAIN_RE also matches an all-numeric dotted quad. Refusing this as "looks
    // like an email" would be technically true and practically useless next to
    // the real answer: it is a private address and the platform must not aim there.
    const t = classifyTarget('user@192.168.1.1');
    expect(t.value).toBe('192.168.1.1');
    expect(t.note).toMatch(/private|reserved/i);
  });

  it('REFUSES private / reserved addresses so the platform cannot be aimed at the operator LAN', () => {
    for (const ip of ['192.168.1.5', '10.0.0.1', '127.0.0.1', '169.254.1.1', '8.8.8.8'.replace('8.8.8.8', '0.0.0.0')]) {
      const t = classifyTarget(ip);
      expect(t.kind, `${ip} must be refused`).toBe('invalid');
      expect(t.note).toMatch(/private|reserved/);
    }
  });

  it('accepts public IPv4 and rejects out-of-range octets', () => {
    expect(classifyTarget('8.8.8.8').kind).toBe('ipv4');
    expect(isIpv4('8.8.8.8')).toBe(true);
    expect(isIpv4('999.1.1.1')).toBe(false);
    expect(classifyTarget('999.1.1.1').kind).toBe('invalid');
  });

  it('rejects IPv6 and garbage with an explanation rather than a silent empty', () => {
    expect(classifyTarget('2606:4700::1').note).toMatch(/IPv6/);
    expect(classifyTarget('nope').kind).toBe('invalid');
    expect(classifyTarget('').note).toBe('empty target');
  });
});

describe('parseRdap', () => {
  // Shape captured live from rdap.org -> rdap.verisign.com for cloudflare.com.
  const LIVE = {
    objectClassName: 'domain',
    handle: '2336799_DOMAIN_COM-VRSN',
    ldhName: 'CLOUDFLARE.COM',
    status: ['client delete prohibited', 'client transfer prohibited'],
    events: [
      { eventAction: 'registration', eventDate: '2009-02-17T22:07:54Z' },
      { eventAction: 'expiration', eventDate: '2033-02-17T22:07:54Z' },
      { eventAction: 'last changed', eventDate: '2024-01-09T16:45:28Z' },
    ],
    entities: [
      {
        roles: ['registrar'],
        vcardArray: ['vcard', [
          ['version', {}, 'text', '4.0'],
          ['fn', {}, 'text', 'Cloudflare, Inc.'],
        ]],
      },
    ],
    nameservers: [{ ldhName: 'NS3.CLOUDFLARE.COM' }, { ldhName: 'NS4.CLOUDFLARE.COM' }],
    secureDNS: { delegationSigned: false },
  };

  it('reads registrar, dates and nameservers from the real vCard shape', () => {
    const r = parseRdap(LIVE)!;
    expect(r.registrar).toBe('Cloudflare, Inc.');
    expect(r.events.find((e) => e.action === 'registration')?.date).toBe('2009-02-17T22:07:54Z');
    expect(r.nameservers).toEqual(['NS3.CLOUDFLARE.COM', 'NS4.CLOUDFLARE.COM']);
    expect(r.status).toContain('client delete prohibited');
  });

  it('refuses a non-RDAP payload instead of returning a hollow object', () => {
    expect(parseRdap({ hello: 'world' })).toBeNull();
    expect(parseRdap(null)).toBeNull();
    expect(parseRdap('<html>403 Forbidden</html>')).toBeNull();
  });

  it('tolerates a server that omits entities or events', () => {
    const r = parseRdap({ objectClassName: 'domain', ldhName: 'X.COM' })!;
    expect(r.registrar).toBeUndefined();
    expect(r.events).toEqual([]);
    expect(r.nameservers).toEqual([]);
  });
});

describe('parseCrt', () => {
  it('splits SANs on WHITESPACE — one crt.sh name_value holds newline-separated names', () => {
    // This is the load-bearing case: splitting on "," produced one garbage hostname.
    const rows = [{ name_value: 'a.example.com\nb.example.com', not_before: '2024-01-01T00:00:00', issuer_name: 'Test CA' }];
    const r = parseCrt(rows, 'example.com');
    expect(r.subdomains).toEqual(['a.example.com', 'b.example.com']);
  });

  it('strips the wildcard prefix and keeps the apex', () => {
    const r = parseCrt([{ name_value: '*.example.com\nexample.com' }], 'example.com');
    expect(r.subdomains).toEqual(['example.com']);
  });

  it('rejects SANs belonging to a shared multi-tenant certificate', () => {
    const r = parseCrt([{ name_value: 'unrelated.com\nshop.other.co.uk\nreal.example.com' }], 'example.com');
    expect(r.subdomains).toEqual(['real.example.com']);
  });

  it('dedupes and sorts, and reports zero honestly for an empty result', () => {
    const r = parseCrt([{ name_value: 'z.example.com\nz.example.com\na.example.com' }], 'example.com');
    expect(r.subdomains).toEqual(['a.example.com', 'z.example.com']);
    expect(r.total).toBe(2);
    expect(parseCrt([], 'example.com').total).toBe(0);
    expect(parseCrt(null, 'example.com').total).toBe(0);
  });

  it('tracks the certificate validity window', () => {
    const r = parseCrt(
      [{ name_value: 'a.example.com', not_before: '2020-01-01T00:00:00', not_after: '2021-01-01T00:00:00' },
       { name_value: 'b.example.com', not_before: '2023-01-01T00:00:00', not_after: '2024-01-01T00:00:00' }],
      'example.com',
    );
    expect(r.firstSeen).toBe('2020-01-01T00:00:00');
    expect(r.lastSeen).toBe('2024-01-01T00:00:00');
  });
});

describe('parseInternetDb', () => {
  it('reads the real Shodan shape', () => {
    const r = parseInternetDb({
      cpes: ['cpe:/a:ntp:ntp:3'],
      hostnames: ['scanme.nmap.org'],
      ip: '45.33.32.156',
      ports: [22, 80, 123, 31337],
      tags: ['cloud'],
      vulns: ['CVE-2021-32785'],
    })!;
    expect(r.ports).toEqual([22, 80, 123, 31337]);
    expect(r.vulns).toEqual(['CVE-2021-32785']);
    expect(r.hostnames).toEqual(['scanme.nmap.org']);
  });

  it('treats {"detail":"No information available"} as NO DATA, not as a scanned-but-empty host', () => {
    // A 200 here means "we have never seen this IP". Rendering it as a result
    // object printed an empty host as though it had been observed.
    expect(parseInternetDb({ detail: 'No information available' })).toBeNull();
  });

  it('tolerates missing optional arrays', () => {
    const r = parseInternetDb({ ip: '1.2.3.4', ports: [80] })!;
    expect(r.vulns).toEqual([]);
    expect(r.cpes).toEqual([]);
  });

  it('refuses a non-object', () => {
    expect(parseInternetDb(null)).toBeNull();
    expect(parseInternetDb('nope')).toBeNull();
  });
});

describe('parseDnsAnswers', () => {
  it('strips the presentation quotes DoH wraps TXT values in', () => {
    const r = parseDnsAnswers({ Status: 0, Answer: [{ type: 16, data: '"v=spf1 include:_spf.google.com ~all"', TTL: 300 }] });
    expect(r.records.TXT).toEqual(['v=spf1 include:_spf.google.com ~all']);
  });

  it('maps record types to names', () => {
    const r = parseDnsAnswers({
      Status: 0,
      Answer: [
        { type: 1, data: '104.16.0.1' },
        { type: 15, data: '10 mx.google.com' },
        { type: 2, data: 'ns1.example.com' },
        { type: 28, data: '2606:4700::1' },
      ],
    });
    expect(r.records.A).toEqual(['104.16.0.1']);
    expect(r.records.MX).toEqual(['10 mx.google.com']);
    expect(r.records.NS).toEqual(['ns1.example.com']);
    expect(r.records.AAAA).toEqual(['2606:4700::1']);
  });

  it('reports NXDOMAIN as a real answer, distinct from an empty record set', () => {
    expect(parseDnsAnswers({ Status: 3 }).nxdomain).toBe(true);
    expect(parseDnsAnswers({ Status: 0, Answer: [] }).nxdomain).toBe(false);
  });
});

describe('parseUrlscan', () => {
  it('reads the real result shape', () => {
    const j = {
      total: 10000,
      results: [{
        _id: '01a0e6dc',
        task: { url: 'http://example.com/' },
        page: { url: 'https://example.com/', title: 'Example', ip: '93.184.216.34', asn: 'AS15133', asnname: 'EDGECAST', country: 'US', status: '200', domain: 'example.com' },
        stats: { requests: 12, uniqIPs: 3 },
        sort: 1700000000000,
      }],
    };
    const r = parseUrlscan(j);
    expect(r.total).toBe(10000);
    expect(r.hits[0]).toMatchObject({ url: 'https://example.com/', ip: '93.184.216.34', asn: 'AS15133', requests: 12, uniqIPs: 3 });
  });

  it('honours the limit and skips entries with no URL', () => {
    const many = Array.from({ length: 50 }, (_, i) => ({ page: { url: `https://x${i}.com/` } }));
    expect(parseUrlscan({ results: many }, 5).hits).toHaveLength(5);
    expect(parseUrlscan({ results: [{ page: {} }, { task: { url: 'https://ok.com/' } }] }).hits).toHaveLength(1);
  });

  it('returns an empty result for garbage rather than throwing', () => {
    expect(parseUrlscan(null).hits).toEqual([]);
  });
});

describe('parseOtx', () => {
  it('preserves a reputation of 0 rather than treating it as missing', () => {
    // OTX returns reputation 0 for a clean indicator. `reputation || null` would
    // have turned that into "unknown", which reads as a different answer.
    const r = parseOtx({ indicator: '8.8.8.8', type: 'IPv4', reputation: 0, pulse_info: { count: 0, pulses: [] }, asn: 'AS15169 google llc' }, '8.8.8.8')!;
    expect(r.reputation).toBe(0);
    expect(r.pulseCount).toBe(0);
    expect(r.asn).toBe('AS15169 google llc');
  });

  it('surfaces pulse names and tags', () => {
    const r = parseOtx({ indicator: '1.2.3.4', type: 'IPv4', pulse_info: { count: 1, pulses: [{ name: 'APT-X', created: '2024-01-01T00:00:00', tags: ['c2'] }] } }, '1.2.3.4')!;
    expect(r.pulseCount).toBe(1);
    expect(r.pulses[0].name).toBe('APT-X');
    expect(r.pulses[0].tags).toEqual(['c2']);
  });

  it('refuses a non-OTX payload', () => {
    expect(parseOtx({ hello: 1 }, 'x')).toBeNull();
  });
});

describe('parseBlocklistDe', () => {
  it('parses the HTML fragment the service actually returns', () => {
    const r = parseBlocklistDe('attacks: 3<br />reports: 7<br />', '1.2.3.4')!;
    expect(r).toEqual({ ip: '1.2.3.4', attacks: 3, reports: 7, listed: true });
  });

  it('reads a clean IP as not-listed rather than absent', () => {
    const r = parseBlocklistDe('attacks: 0<br />reports: 0<br />', '8.8.8.8')!;
    expect(r.listed).toBe(false);
  });

  it('refuses an unrecognised body', () => {
    expect(parseBlocklistDe('<html>maintenance</html>', '1.2.3.4')).toBeNull();
    expect(parseBlocklistDe('', '1.2.3.4')).toBeNull();
  });
});

describe('parseHashlookup', () => {
  // Field names verified live against hashlookup.circl.lu.
  const LIVE = {
    CRC32: '8C736521',
    FileName: './usr/share/doc/node-express/examples/static-files/public/js/app.js',
    FileSize: '3',                       // a STRING, not a number
    MD5: 'ACBD18DB4CC2F85CEDEF654FCCC4A4D8',
    'SHA-1': '0BEEC7B5EA3F0FDBC95D0DD47F3C5BC275DA8A33',
    'SHA-256': '2C26B46B...',
    SSDEEP: '3:AXG:AX',
    OpSystemCode: { OpSystemName: 'TBD', OpSystemVersion: 'none' },
    mimetype: 'text/plain',
    'hashlookup:trust': 100,
    'nsrl-sha256': 'rds241-sha256.zip',  // known-GOOD software, not a threat
  };

  it('reads the hyphenated hash keys and coerces the string FileSize', () => {
    const r = parseHashlookup(LIVE, 'abc')!;
    expect(r.sha1).toBe('0BEEC7B5EA3F0FDBC95D0DD47F3C5BC275DA8A33');
    expect(r.sha256).toBe('2C26B46B...');
    expect(r.ssdeep).toBe('3:AXG:AX');
    expect(r.fileSize).toBe(3);
    expect(r.mimeType).toBe('text/plain');
    expect(r.os).toBe('TBD');
  });

  it('flags a NIST NSRL listing as KNOWN GOOD, never as a threat', () => {
    const r = parseHashlookup(LIVE, 'abc')!;
    expect(r.knownGood).toBe(true);
    // The key must not exist at all: this database cannot and does not judge
    // maliciousness, and the UI must not be able to imply that it does.
    expect((r as unknown as Record<string, unknown>).knownVulnerable).toBeUndefined();
  });

  it('refuses an empty body — "not in the database" is not a match', () => {
    expect(parseHashlookup({}, 'abc')).toBeNull();
    expect(parseHashlookup(null, 'abc')).toBeNull();
  });
});

describe('parseRipe', () => {
  // Shape captured live from stat.ripe.net for 45.33.32.156.
  const PREFIX = {
    is_less_specific: false,
    announced: true,
    asns: [{ asn: 63949, holder: 'AKAMAI-LINODE-AP - Akamai Connected Cloud' }],
    related_prefixes: { less_specific: [], more_specific: [] },
    resource: '45.33.32.0/19',
    type: 'assignment',
  };

  it('reads the prefix from `resource` — this endpoint has NO `prefix` key', () => {
    const r = parseRipe('45.33.32.156', PREFIX, [])!;
    expect(r.prefix).toBe('45.33.32.0/19');
    expect(r.asn).toBe('AS63949');
    expect(r.holder).toBe('AKAMAI-LINODE-AP - Akamai Connected Cloud');
    expect(r.announced).toBe(true);
  });

  it('accepts abuse_contacts as plain STRINGS (RIPE returns strings)', () => {
    expect(parseRipe('45.33.32.156', PREFIX, ['abuse@linode.com'])!.abuseEmail).toBe('abuse@linode.com');
  });

  it('also accepts abuse_contacts as {email} objects (other RIRs return those)', () => {
    expect(parseRipe('45.33.32.156', PREFIX, [{ email: 'abuse@example.net' }])!.abuseEmail).toBe('abuse@example.net');
  });

  it('reports no abuse contact honestly rather than inventing one', () => {
    expect(parseRipe('45.33.32.156', PREFIX, [])!.abuseEmail).toBeUndefined();
    expect(parseRipe('45.33.32.156', PREFIX, undefined)!.abuseEmail).toBeUndefined();
  });

  it('refuses a lookup with no prefix data at all', () => {
    expect(parseRipe('1.2.3.4', undefined, [])).toBeNull();
  });
});

describe('infrastructure agent tools', () => {
  it('registers the three lanes with a required input each', () => {
    expect(INFRA_TOOLS.map((t) => t.name)).toEqual(['osint_domain_infra', 'osint_ip_infra', 'osint_hash_lookup']);
    for (const t of INFRA_TOOLS) {
      expect(t.category).toBe('osint');
      expect(typeof t.handler).toBe('function');
      expect((t.parameters || []).filter((p) => p.required).length).toBeGreaterThanOrEqual(1);
    }
  });

  it('refuses a non-domain and a non-public IP WITHOUT calling anything', async () => {
    const domain = INFRA_TOOLS[0].handler({ parameters: { domain: '192.168.1.1' } } as never);
    const ip = INFRA_TOOLS[1].handler({ parameters: { ip: 'not-an-ip' } } as never);
    await expect(domain).resolves.toMatchObject({ success: false });
    await expect(ip).resolves.toMatchObject({ success: false });
  });

  it('states plainly that the hash lane identifies files and does not judge malware', () => {
    const hash = INFRA_TOOLS.find((t) => t.name === 'osint_hash_lookup')!;
    expect(hash.description).toMatch(/not a malware database/i);
  });
});
