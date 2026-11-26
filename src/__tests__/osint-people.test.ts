/**
 * PEOPLE-RECORDS LANES — BOP federal inmate locator, CMS NPI registry, name discovery.
 *
 * Every fixture is CAPTURED OUTPUT from the live endpoints (2026-10-26): the BOP locator
 * answer for Elizabeth Holmes (a full record), the honest empty set for Kelly Headley, the
 * validation-exception shape for a bare last name, the John Smith multi-record volume, and
 * the CMS NPI v2.1 shape (v1 answers "Unsupported Version" — pinned so the version pin can
 * never silently rot). The doctrine under test: a zero from ONE source is a zero from THAT
 * source; captcha/validation/transport failures are UNMEASURED, never "no record".
 */

import { describe, it, expect } from 'vitest';
import {
  buildBopForm,
  parseBopResponse,
  bopInmateSearch,
  buildNpiUrl,
  parseNpiResponse,
  npiRegistryLookup,
  peopleNameDiscovery,
  formatPeopleReport,
} from '../tools/osint-people.js';
import { buildNameQueries } from '../tools/osint-searchdiscovery.js';

// ── Captured 2026-10-26 ─────────────────────────────────────────────────────

const BOP_HOLMES = `{"Captcha":false,"Messages":{},"FormToken":"pub46922info","InmateLocator":[{"nameLast":"HOLMES","nameFirst":"ELIZABETH","nameMiddle":"","sex":"Female","race":"White","age":"42","inmateNum":"24965-111","inmateNumType":"","releaseCode":"","faclCode":"BRY","faclName":"Bryan","faclType":"FPC","faclURL":"/locations/institutions/bry/","projRelDate":"02/22/2030","actRelDate":"","suffix":""}]}`;
const BOP_EMPTY = `{"Captcha":false,"Messages":{},"FormToken":"pub35446info","InmateLocator":[]}`;
const BOP_VALIDATION = `{
  "FormToken": "pub118681info",
  "Exceptions": {
    "FriendlyMessage": "Validation failed, no valid field values",
    "ExceptionMessage": "Validation failed, no valid field values"
  },
  "ForwardLocation": "/inmateloc/index.jsp",
  "ForwardRequested": "true"
}`;
const NPI_HEADLEY = `{"result_count":1,"results":[{"addresses":[{"address_1":"20110 ASHBROOK PL STE 275","address_purpose":"LOCATION","address_type":"DOM","city":"ASHBURN","country_code":"US","country_name":"United States","postal_code":"201475065","state":"VA","telephone_number":"571-306-3038"}],"basic":{"certification_date":"2025-07-29","credential":"LCSW","enumeration_date":"2017-01-26","first_name":"KELLY","last_name":"HEADLEY","last_updated":"2025-07-29","middle_name":"W.","sex":"F"},"number":1104363282,"taxonomies":[{"code":"1041C0700X","desc":"Clinical","state":"VA"}]}]}`;
const NPI_V1_ERROR = `{"Errors":[{"description":"Unsupported Version","field":"version","number":"17"}]}`;

const ok = (body: string, via = 'egress') => async () => ({ status: 200, body, via });
const status = (s: number) => async () => ({ status: s, body: '', via: 'egress' });

describe('BOP form building', () => {
  it('posts the locator\'s own field set for a name search', () => {
    const form = buildBopForm({ firstName: 'Kelly', lastName: 'Headley' });
    expect(form).toContain('todo=query');
    expect(form).toContain('output=json');
    expect(form).toContain('nameFirst=Kelly');
    expect(form).toContain('nameLast=Headley');
    expect(form).toContain('race=');
    expect(form).toContain('sex=');
  });

  it('switches to the number form with a pinned type', () => {
    const form = buildBopForm({ inmateNum: '24965-111' });
    expect(form).toBe('todo=query&output=json&inmateNumType=IRN&inmateNum=24965-111');
    expect(buildBopForm({ inmateNum: '12345', inmateNumType: 'DCDC' })).toContain('inmateNumType=DCDC');
  });

  it('refuses to build a query with no searchable field', () => {
    expect(() => buildBopForm({})).toThrow(/last name/i);
  });
});

describe('BOP response parsing (captured shapes)', () => {
  it('parses a full record: identity, register number, facility, projected release', () => {
    const p = parseBopResponse(BOP_HOLMES);
    expect(p.captcha).toBe(false);
    expect(p.inmates).toHaveLength(1);
    const m = p.inmates[0];
    expect(m.nameFirst).toBe('ELIZABETH');
    expect(m.nameLast).toBe('HOLMES');
    expect(m.inmateNum).toBe('24965-111');
    expect(m.facilityName).toBe('Bryan');
    expect(m.facilityUrl).toBe('https://www.bop.gov/locations/institutions/bry/');
    expect(m.projectedReleaseDate).toBe('02/22/2030');
  });

  it('reads an empty InmateLocator as an HONEST ZERO, not an error', () => {
    const p = parseBopResponse(BOP_EMPTY);
    expect(p.inmates).toHaveLength(0);
    expect(p.captcha).toBe(false);
    expect(p.exception).toBeUndefined();
  });

  it('surfaces the validation exception instead of reading it as a zero', () => {
    const p = parseBopResponse(BOP_VALIDATION);
    expect(p.exception).toContain('Validation failed');
  });

  it('flags a captcha challenge as unmeasured', () => {
    const p = parseBopResponse('{"Captcha":true,"InmateLocator":[]}');
    expect(p.captcha).toBe(true);
  });

  it('a non-JSON body THROWS — unmeasured, never "no record"', () => {
    expect(() => parseBopResponse('<html>Error 404</html>')).toThrow(/non-JSON/);
  });
});

describe('BOP search verdicts through the transport', () => {
  it('found=true carries the records', async () => {
    const r = await bopInmateSearch({ lastName: 'Holmes', firstName: 'Elizabeth' }, ok(BOP_HOLMES));
    expect(r.found).toBe(true);
    expect(r.count).toBe(1);
    expect(r.source).toContain('bop.gov');
  });

  it('found=false says WHICH source answered zero', async () => {
    const r = await bopInmateSearch({ firstName: 'Kelly', lastName: 'Headley' }, ok(BOP_EMPTY));
    expect(r.found).toBe(false);
    expect(r.note).toContain('honest zero');
  });

  it('a 403 from the transport is UNMEASURED, never absence', async () => {
    const r = await bopInmateSearch({ lastName: 'Holmes' }, status(403));
    expect(r.found).toBeNull();
    expect(r.note).toContain('403');
    expect(r.note).toContain('UNMEASURED');
  });

  it('a validation exception from BOP is unmeasured with the reason', async () => {
    const r = await bopInmateSearch({ lastName: 'Maxwell' }, ok(BOP_VALIDATION));
    expect(r.found).toBeNull();
    expect(r.note).toContain('Validation failed');
  });
});

describe('CMS NPI registry', () => {
  it('builds the version=2.1 URL (v1 answers "Unsupported Version")', () => {
    const url = buildNpiUrl({ firstName: 'Kelly', lastName: 'Headley', state: 'VA' });
    expect(url).toContain('version=2.1');
    expect(url).toContain('last_name=Headley');
    expect(url).toContain('enumeration_type=NPI-1');
    expect(buildNpiUrl({ npi: '1104363282' })).toContain('number=1104363282');
  });

  it('parses the captured Kelly W. Headley record', () => {
    const rs = parseNpiResponse(NPI_HEADLEY);
    expect(rs).toHaveLength(1);
    expect(rs[0].npi).toBe('1104363282');
    expect(rs[0].name).toBe('KELLY W. HEADLEY');
    expect(rs[0].credential).toBe('LCSW');
    expect(rs[0].addresses[0].city).toBe('ASHBURN');
    expect(rs[0].addresses[0].phone).toBe('571-306-3038');
  });

  it('an NPI error payload is unmeasured, not an empty set', async () => {
    const r = await npiRegistryLookup({ lastName: 'Headley' }, ok(NPI_V1_ERROR));
    expect(r.found).toBeNull();
    expect(r.note).toContain('Unsupported Version');
  });

  it('a clean empty registry answer is an honest zero', async () => {
    const r = await npiRegistryLookup({ lastName: 'Nobody' }, ok('{"result_count":0,"results":[]}'));
    expect(r.found).toBe(false);
  });

  it('requires a last name or an NPI', async () => {
    await expect(npiRegistryLookup({}, ok('{}'))).rejects.toThrow(/last name/i);
  });
});

describe('name-only discovery (people mode)', () => {
  it('builds quoted-name + per-walled-platform queries', () => {
    const q = buildNameQueries('Kelly Headley');
    expect(q[0]).toBe('"Kelly Headley"');
    expect(q.some((x) => x.includes('site:linkedin.com'))).toBe(true);
    expect(q.some((x) => x.includes('site:facebook.com'))).toBe(true);
    expect(q.some((x) => x.includes('site:x.com'))).toBe(true);
  });

  it('refuses a bare first name', async () => {
    await expect(peopleNameDiscovery('Kelly', { paceMs: 0 })).rejects.toThrow(/full name/i);
  });

  it('corroborates a walled-platform hit only when the name appears in it', async () => {
    const ddgPage = `<html><body>
      <div class="result"><a class="result__a" href="https://www.linkedin.com/in/kelly-headley-978866342">Kelly Headley - -- | LinkedIn</a><a class="result__snippet">Experience: DHL · Location: Brooklyn</a></div>
      <div class="result"><a class="result__a" href="https://www.linkedin.com/in/someone-else-111">Someone Else - VP | LinkedIn</a><a class="result__snippet">totally unrelated</a></div>
      </body></html>`;
    let calls = 0;
    const r = await peopleNameDiscovery('Kelly Headley', {
      paceMs: 0,
      fetcher: async () => { calls++; return { status: 200, body: ddgPage, via: 'stub' }; },
    });
    // Both queries answered with the same page; dedupe keeps one LinkedIn hit.
    const hits = r.hits.filter((h) => h.site === 'LinkedIn');
    expect(hits.length).toBeGreaterThanOrEqual(1);
    const corroborated = hits.find((h) => h.url.includes('978866342'));
    expect(corroborated?.identity).toBe('name-match');
    expect(r.hits.some((h) => h.url.includes('someone-else'))).toBe(false);
  });
});

describe('the report names the source of every verdict', () => {
  it('a BOP zero never reads as "this person does not exist"', () => {
    const text = formatPeopleReport({
      source: 'bop.gov federal inmate locator', found: false, count: 0, inmates: [], via: 'egress',
      note: 'honest zero from THIS source',
    }, null, null);
    expect(text).toContain('BOP FEDERAL INMATE LOCATOR');
    expect(text).toContain('honest zero');
  });

  it('an unmeasured lane says UNMEASURED', () => {
    const text = formatPeopleReport({
      source: 'bop.gov federal inmate locator', found: null, count: 0, inmates: [], via: 'none', note: 'captcha',
    }, null, null);
    expect(text).toContain('unmeasured');
  });
});
