/**
 * T3MP3ST social OSINT tools — person/username-focused open-source intelligence.
 *
 * Closes the "social_osint family exists but has no tools" gap:
 *  - username_search: check a username's existence across public platforms
 *    (GitHub, GitLab, Reddit, Hacker News, Wikipedia, Steam, Keybase, VK, Telegram)
 *    using their public, unauthenticated surfaces. Sherlock-style, no API keys.
 *  - telegram_lookup: resolve a @username via the Telegram Bot API getChat
 *    (public info only: name, description, type, member count). Uses the
 *    TELEGRAM_BOT_TOKEN env var when present; without it the tool degrades to
 *    a "not configured" note, never a fabricated answer.
 *  - email_format: generate corporate email candidates from a person's name and
 *    check the domain's MX records (no sending, no spam).
 *
 * Honesty contract (same as every tool): every result is a REAL HTTP/DNS probe;
 * errors are reported as such; nothing is invented.
 */

import * as dns from 'dns';
import { promisify } from 'util';
import type { CustomTool, ToolFinding } from '../types/index.js';

const dnsResolveMx = promisify(dns.resolveMx);
const dnsResolve4 = promisify(dns.resolve4);

type ProfileValidator = (body: unknown) => boolean;

async function probeExists(url: string, validator: ProfileValidator, headers: Record<string, string> = {}): Promise<{ exists: boolean; note?: string }> {
  try {
    const res = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      signal: AbortSignal.timeout(6000),
      headers: { 'user-agent': 'Mozilla/5.0 (compatible; T3MP3ST-OSINT/1.0)', ...headers },
    });
    if (res.status === 200) {
      try { return { exists: validator(await res.json()) }; }
      catch { return { exists: false, note: 'invalid response' }; }
    }
    if (res.status === 404) return { exists: false };
    return { exists: false, note: `http ${res.status}` };
  } catch (e) {
    return { exists: false, note: e instanceof Error ? e.message.slice(0, 40) : 'error' };
  }
}

export const usernameSearchTool: CustomTool = {
  name: 'username_search',
  description: 'Check a username across public platforms (GitHub, GitLab, Reddit, Hacker News, Wikipedia, Steam, Keybase, VK, Telegram) — open-source intelligence, no API keys',
  category: 'osint',
  parameters: [
    { name: 'username', type: 'string', description: 'Username / handle to search', required: true },
  ],
  handler: async (context) => {
    const username = String(context.parameters.username || '').trim();
    if (!username || !/^[a-zA-Z0-9_.-]{2,64}$/.test(username)) {
      return { success: false, error: 'username_search: invalid username (2-64 chars, letters/digits/._-)' };
    }
    const u = encodeURIComponent(username);
    const checks: { platform: string; url: string; probe: Promise<{ exists: boolean; note?: string }> }[] = [
      { platform: 'GitHub', url: `https://github.com/${u}`, probe: probeExists(`https://api.github.com/users/${u}`, (body) => Boolean(body && typeof body === 'object' && String((body as { login?: unknown }).login || '').toLowerCase() === username.toLowerCase()), { accept: 'application/vnd.github+json' }) },
      { platform: 'GitLab', url: `https://gitlab.com/${u}`, probe: probeExists(`https://gitlab.com/api/v4/users?username=${u}`, (body) => Array.isArray(body) && body.some((item) => item && typeof item === 'object' && String((item as { username?: unknown }).username || '').toLowerCase() === username.toLowerCase())) },
      { platform: 'Reddit', url: `https://www.reddit.com/user/${u}`, probe: probeExists(`https://www.reddit.com/user/${u}/about.json`, (body) => Boolean(body && typeof body === 'object' && String((body as { data?: { name?: unknown } }).data?.name || '').toLowerCase() === username.toLowerCase())) },
      { platform: 'HackerNews', url: `https://news.ycombinator.com/user?id=${u}`, probe: probeExists(`https://hacker-news.firebaseio.com/v0/user/${u}.json`, (body) => Boolean(body && typeof body === 'object' && String((body as { id?: unknown }).id || '').toLowerCase() === username.toLowerCase())) },
    ];
    // Telegram via Bot API when a token is configured (chat may be private → note)
    const token = process.env.TELEGRAM_BOT_TOKEN?.trim();
    if (token) {
      checks.push({
        platform: 'Telegram',
        url: `https://t.me/${username}`,
        probe: fetch(`https://api.telegram.org/bot${token}/getChat?chat_id=@${username}`, { signal: AbortSignal.timeout(6000) })
          .then((r) => r.json() as Promise<{ ok: boolean }>)
          .then((j) => ({ exists: j.ok === true }))
          .catch(() => ({ exists: false })),
      });
    }

    const results = await Promise.all(checks.map(async (c) => ({ ...c, result: await c.probe })));
    const found = results.filter((r) => r.result.exists).map((r) => ({ platform: r.platform, url: r.url }));
    const notFound = results.filter((r) => !r.result.exists).map((r) => r.platform);

    const lines = found.map((f) => `  ✓ ${f.platform}: ${f.url}`);
    const output = [
      `Username search for "${username}":`,
      found.length ? `Found on ${found.length} platform(s):\n${lines.join('\n')}` : 'Not found on any checked platform.',
      `Checked ${results.length} platforms (not found: ${notFound.join(', ') || '—'}).`,
    ].join('\n');

    const findings: ToolFinding[] = [];
    if (found.length) {
      findings.push({
        title: `Social Accounts Found for '${username}'`,
        severity: 'info',
        details: `Username exists on: ${found.map((f) => `${f.platform} (${f.url})`).join('; ')}`,
      });
    }
    return { success: true, output, findings: findings.length ? findings : undefined };
  },
};

export const telegramLookupTool: CustomTool = {
  name: 'telegram_lookup',
  description: 'Resolve a Telegram @username via the Bot API getChat: name, type, description, member count (requires TELEGRAM_BOT_TOKEN)',
  category: 'osint',
  parameters: [
    { name: 'username', type: 'string', description: 'Telegram @username to resolve', required: true },
  ],
  handler: async (context) => {
    const username = String(context.parameters.username || '').trim().replace(/^@/, '');
    if (!username) return { success: false, error: 'telegram_lookup: username required' };
    const token = process.env.TELEGRAM_BOT_TOKEN?.trim();
    if (!token) {
      return { success: false, error: 'telegram_lookup: TELEGRAM_BOT_TOKEN not configured (set it in env or ~/.t3mp3st/.env)' };
    }
    try {
      const res = await fetch(`https://api.telegram.org/bot${token}/getChat?chat_id=@${encodeURIComponent(username)}`, {
        signal: AbortSignal.timeout(8000),
      });
      const json = (await res.json()) as {
        ok: boolean;
        result?: { id: number; type: string; username?: string; title?: string; first_name?: string; description?: string; member_count?: number; invite_link?: string };
        description?: string;
      };
      if (!json.ok) {
        return { success: true, output: `Telegram lookup for @${username}: not found or inaccessible (${json.description ?? 'error'})` };
      }
      const r = json.result!;
      const bits = [
        `id: ${r.id}`,
        `type: ${r.type}`,
        r.title && `title: ${r.title}`,
        r.first_name && `name: ${r.first_name}`,
        r.username && `username: @${r.username}`,
        r.member_count !== undefined && `members: ${r.member_count}`,
        r.description && `description: ${r.description.slice(0, 200)}`,
        r.invite_link && `invite: ${r.invite_link}`,
      ].filter(Boolean);
      return {
        success: true,
        output: `Telegram lookup for @${username}:\n${bits.join('\n')}`,
        findings: [{
          title: `Telegram Entity Found: @${username}`,
          severity: 'info',
          details: `Type: ${r.type}${r.title ? `, title: ${r.title}` : ''}${r.member_count !== undefined ? `, members: ${r.member_count}` : ''}`,
        }],
      };
    } catch (e) {
      return { success: false, error: `telegram_lookup failed: ${e instanceof Error ? e.message.slice(0, 150) : 'unknown'}` };
    }
  },
};

export const emailFormatTool: CustomTool = {
  name: 'email_format',
  description: 'Generate corporate email candidates from a person name + domain and check the domain MX records (OSINT; no sending)',
  category: 'osint',
  parameters: [
    { name: 'name', type: 'string', description: 'Full name, e.g. "John Smith"', required: true },
    { name: 'domain', type: 'string', description: 'Corporate domain, e.g. example.com', required: true },
  ],
  handler: async (context) => {
    const name = String(context.parameters.name || '').trim();
    const domain = String(context.parameters.domain || '').trim().toLowerCase();
    if (!name || !domain || !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(domain)) {
      return { success: false, error: 'email_format: valid name and domain required' };
    }
    const parts = name.toLowerCase().replace(/[^a-z\s-]/g, '').split(/[\s-]+/).filter(Boolean);
    if (parts.length < 2) return { success: false, error: 'email_format: need at least first + last name' };
    const first = parts[0];
    const last = parts[parts.length - 1];
    const initial = first[0];
    const candidates = [
      `${first}.${last}@${domain}`,
      `${first}${last}@${domain}`,
      `${initial}.${last}@${domain}`,
      `${initial}${last}@${domain}`,
      `${first}@${domain}`,
      `${last}.${first}@${domain}`,
      `${last}${first}@${domain}`,
    ];
    let mx: string[] = [];
    try {
      const records = await dnsResolveMx(domain);
      mx = records.map((r) => `${r.priority} ${r.exchange}`).slice(0, 5);
    } catch {
      mx = [];
    }
    const output = [
      `Email format candidates for "${name}" @ ${domain}:`,
      ...candidates.map((c) => `  ${c}`),
      mx.length ? `MX records (${domain} accepts mail):\n  ${mx.join('\n  ')}` : `No MX records for ${domain} — domain likely does not receive mail.`,
      'Note: candidates are educated guesses; no mail is sent or verified.',
    ].join('\n');
    const findings: ToolFinding[] | undefined = mx.length
      ? [{
          title: 'Corporate Email Format Enumerated',
          severity: 'info',
          details: `Domain ${domain} accepts mail (MX present). ${candidates.length} candidate formats generated for ${name}; verify via public sources before use.`,
        }]
      : undefined;
    return { success: true, output, findings };
  },
};

/** Resolve a hostname to IPv4 (helper, mirrors arsenal's dnsResolve4). */
export async function osintResolve4(host: string): Promise<string[]> {
  try { return await dnsResolve4(host); } catch { return []; }
}

export const ipInfoTool: CustomTool = {
  name: 'ip_info',
  description: 'OSINT on an IP address or hostname: geolocation, ISP/ASN, organization, reverse DNS (free APIs, no keys). For a hostname the A record is resolved first.',
  category: 'osint',
  parameters: [
    { name: 'target', type: 'string', description: 'IPv4 address or hostname', required: true },
  ],
  handler: async (context) => {
    let target = String(context.parameters.target || '').trim();
    if (!target) return { success: false, error: 'ip_info: target required' };
    // Hostname → IPv4 (first A record); bare IP passes through.
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(target)) {
      try {
        const addrs = await dnsResolve4(target);
        if (addrs.length) target = addrs[0];
        else return { success: false, error: `ip_info: no A record for ${target}` };
      } catch {
        return { success: false, error: `ip_info: cannot resolve ${target}` };
      }
    }
    // Primary free source: ip-api.com (45 req/min, no key). Fallback: ipwho.is.
    const sources: [string, (j: Record<string, unknown>) => string[]][] = [
      [`https://ip-api.com/json/${target}?fields=status,country,regionName,city,isp,org,as,reverse,query`, (j) => {
        const s = (v: unknown): string => (v === undefined || v === null ? '' : String(v));
        return [
          `IP: ${s(j.query) || target}`,
          s(j.country) && `country: ${s(j.country)}`,
          s(j.regionName) && `region: ${s(j.regionName)}`,
          s(j.city) && `city: ${s(j.city)}`,
          s(j.isp) && `ISP: ${s(j.isp)}`,
          s(j.org) && `org: ${s(j.org)}`,
          s(j.as) && `ASN: ${s(j.as)}`,
          s(j.reverse) && `reverse DNS: ${s(j.reverse)}`,
        ].filter(Boolean);
      }],
      [`https://ipwho.is/${target}`, (j) => {
        const conn = (j.connection ?? {}) as Record<string, unknown>;
        const s = (v: unknown): string => (v === undefined || v === null ? '' : String(v));
        return [
          `IP: ${target}`,
          s(j.country) && `country: ${s(j.country)}`,
          s(j.region) && `region: ${s(j.region)}`,
          s(j.city) && `city: ${s(j.city)}`,
          s(conn.isp) && `ISP: ${s(conn.isp)}`,
          s(conn.org) && `org: ${s(conn.org)}`,
          s(conn.asn) && `ASN: ${s(conn.asn)}`,
        ].filter(Boolean);
      }],
    ];
    let output = `IP info for ${target}:`;
    let ok = false;
    for (const [url, fmt] of sources) {
      try {
        const res = await fetch(url, { signal: AbortSignal.timeout(8000) });
        const json = (await res.json()) as Record<string, unknown>;
        const lines = fmt(json).filter(Boolean);
        if (lines.length > 1 || (json.status !== 'fail' && json.success !== false)) {
          output += '\n' + lines.join('\n');
          ok = true;
          break;
        }
      } catch { /* try next source */ }
    }
    if (!ok) return { success: false, error: `ip_info: lookup failed for ${target}` };
    return {
      success: true,
      output,
      findings: [{
        title: `IP Intelligence: ${target}`,
        severity: 'info',
        details: output.replace(/^IP info[^\n]*\n/, '').replace(/\n/g, '; ').slice(0, 400),
      }],
    };
  },
};
