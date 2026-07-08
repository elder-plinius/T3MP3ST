#!/usr/bin/env node
/**
 * disclosure-gen — turn a VERIFIED t3mp3st finding into a coordinated-disclosure
 * package: a vendor-ready report, an email-ready plaintext, and a human send
 * checklist. This is the piece that closes the loop — research only counts when
 * the vendor can fix it.
 *
 * DESIGN INVARIANTS (read before editing):
 *   1. DRAFTS ONLY. This tool NEVER sends anything. It opens no network sockets,
 *      no SMTP, no API. It writes files to disk and prints a checklist. The human
 *      reviews and sends. Coordinated disclosure has a person in the loop, always.
 *   2. HONEST SEVERITY. CVSS is computed from the vector, not asserted. If the
 *      author's self-rating is inflated vs. the computed score, or a DoS is dressed
 *      up with confidentiality/integrity impact, the tool flags it. Overselling
 *      burns vendor trust faster than anything.
 *   3. ONE FINDING, ONE VENDOR, ONE TIMELINE. The unit of work is a single
 *      verified bug routed to the people who own the code — not a batch, not a pile.
 *
 * Usage:
 *   node scripts/disclosure-gen.mjs --finding bench/wild-hunt/findings/<slug>.json
 *   node scripts/disclosure-gen.mjs --finding <file> --out /tmp/disclosure --format both
 *   node scripts/disclosure-gen.mjs --finding <file> --reporter "Name <email>" --days 90
 *
 * Finding JSON schema (all strings unless noted):
 *   slug, project, ecosystem, repo_url, versions_affected, commit, component,
 *   cwe, vuln_class, summary, root_cause, poc, impact, remediation,
 *   cvss_vector (CVSS:3.1/...), severity_self, reporter, novelty, discovery
 *
 * Exit 0 = package written. Exit 2 = bad input. Exit 3 = honesty gate wants review
 * (package still written; the warnings are printed so you fix the rating first).
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkSeverityEvidence } from './verify-finding.mjs';
import { lintDisclosure } from './lint-disclosure.mjs';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const R = (...p) => path.join(REPO, ...p);

// ── tiny arg parser ─────────────────────────────────────────────────────────
function parseArgs(argv) {
  const a = {};
  for (let i = 0; i < argv.length; i++) {
    const t = argv[i];
    if (t.startsWith('--')) {
      const k = t.slice(2);
      const v = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : 'true';
      a[k] = v;
    }
  }
  return a;
}

// ── CVSS v3.1 base score (official formula + roundup) ───────────────────────
const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  PR_U: { N: 0.85, L: 0.62, H: 0.27 },
  PR_C: { N: 0.85, L: 0.68, H: 0.5 },
  CIA: { N: 0, L: 0.22, H: 0.56 },
};
function roundup(input) {
  const i = Math.round(input * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}
function band(s) {
  if (s <= 0) return 'None';
  if (s < 4) return 'Low';
  if (s < 7) return 'Medium';
  if (s < 9) return 'High';
  return 'Critical';
}
function cvss31(vector) {
  if (!vector) return null;
  const m = Object.fromEntries(
    vector.replace(/^CVSS:3\.[01]\//, '').split('/').map((s) => s.split(':'))
  );
  for (const k of ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']) {
    if (!m[k]) return { error: `vector missing ${k}` };
  }
  const changed = m.S === 'C';
  const iss = 1 - (1 - W.CIA[m.C]) * (1 - W.CIA[m.I]) * (1 - W.CIA[m.A]);
  const impact = changed
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  const pr = (changed ? W.PR_C : W.PR_U)[m.PR];
  const expl = 8.22 * W.AV[m.AV] * W.AC[m.AC] * pr * W.UI[m.UI];
  let score;
  if (impact <= 0) score = 0;
  else score = roundup(Math.min((changed ? 1.08 : 1) * (impact + expl), 10));
  return { score, severity: band(score), changed, metrics: m, expl, impact };
}

// ── honesty gate — catch overselling before the vendor does ─────────────────
function honestyCheck(f, cvss) {
  const warns = [];
  const cls = `${f.vuln_class || ''} ${f.summary || ''} ${f.impact || ''}`.toLowerCase();
  const selfBand = (f.severity_self || '').trim();
  if (cvss && !cvss.error && selfBand) {
    const order = ['None', 'Low', 'Medium', 'High', 'Critical'];
    const di = order.indexOf(selfBand) - order.indexOf(cvss.severity);
    if (di >= 2) warns.push(`self-rating "${selfBand}" is ${di} bands above computed CVSS ${cvss.score} (${cvss.severity}). Justify or downgrade.`);
    else if (di === 1) warns.push(`self-rating "${selfBand}" is one band above computed CVSS ${cvss.score} (${cvss.severity}). Make sure the report argues why.`);
  }
  if (cvss && !cvss.error) {
    const m = cvss.metrics;
    const dosOnly = /\b(dos|denial of service|availability|crash|panic|hang|infinite loop|stack overflow|oom)\b/.test(cls)
      && !/\b(rce|code execution|write-what-where|overwrite|arbitrary write|disclosure|leak|bypass)\b/.test(cls);
    if (dosOnly && (m.C === 'H' || m.I === 'H')) warns.push(`impact reads as availability/DoS-only but CVSS sets C:${m.C}/I:${m.I}. If it's really just a crash, set C:N/I:N — that's the honest vector.`);
    if (/\bpotential\b|\bmay\b|\bcould\b/.test(cls) && m.C === 'H' && m.I === 'H' && m.A === 'H' && m.AC === 'L')
      warns.push(`impact is hedged ("potential/could") but CVSS asserts confirmed C:H/I:H/A:H at low complexity. If RCE is unproven, say "potential" in the vector too (raise AC or lower an impact metric) and label it clearly.`);
  }
  // catchable / marginal DoS → recommend the lighter-weight channel
  if (/\b(catchable|recoverable|try.?catch|rangeerror|caught)\b/.test(cls) || /\bavailability only\b/.test(cls)) {
    warns.push(`looks like a catchable / availability-only issue. Consider filing as a public hardening issue + PR rather than a high-severity private advisory — and say so in the report so you don't oversell.`);
  }
  // severity-evidence: AV/AC must be backed by the reachability text (the crit-vs-high lever)
  for (const fl of checkSeverityEvidence(f).flags) warns.push(fl);
  return warns;
}

// ── vendor-contact discovery (constructs the actionable checklist) ──────────
function ghParts(repoUrl) {
  const m = String(repoUrl || '').match(/github\.com[/:]([^/]+)\/([^/.]+)/i);
  return m ? { owner: m[1], repo: m[2] } : null;
}
function contactChecklist(f) {
  const gh = ghParts(f.repo_url);
  const lines = [];
  lines.push('## Where to send it — vendor security contact (check in this order)\n');
  lines.push('1. **Repo security policy** — look for a published policy first; it tells you exactly how they want it:');
  if (gh) {
    lines.push(`   - \`${f.repo_url}/security/policy\``);
    lines.push(`   - \`${f.repo_url}/blob/HEAD/SECURITY.md\`  ·  \`.github/SECURITY.md\`  ·  \`docs/SECURITY.md\``);
  } else {
    lines.push('   - SECURITY.md / .github/SECURITY.md / docs/SECURITY.md in the repo');
  }
  if (gh) {
    lines.push('2. **GitHub private advisory (preferred if enabled)** — opens a private channel + draft CVE:');
    lines.push(`   - \`https://github.com/${gh.owner}/${gh.repo}/security/advisories/new\``);
    lines.push(`   - (only works if the project enabled it; if 404, fall back to email)`);
  }
  lines.push('3. **Private email** — common patterns (confirm before trusting):');
  lines.push('   - `security@<vendor-domain>` · `security@<project>.org` · maintainer email from `git log`/`package.json`/`Cargo.toml`/commit author');
  lines.push('4. **Registry / ecosystem channels:**');
  lines.push('   - npm: `npm audit` advisory / GitHub Advisory DB submission · Go: golang/vulndb · crates: RustSec/advisory-db · PyPI: report to maintainer + OSV');
  lines.push('5. **Coordinator (if vendor is unresponsive after the ack window or has no contact):**');
  lines.push('   - CERT/CC: `https://www.kb.cert.org/vuls/report/` · or your regional CSIRT. They broker disclosure.');
  lines.push('\n> Do NOT post details in a public issue, PR, gist, or chat until the embargo is over (or the vendor declines to engage and the coordinator clears publication).');
  return lines.join('\n');
}

// ── timeline ────────────────────────────────────────────────────────────────
function fmtDate(d) { return d.toISOString().slice(0, 10); }
function timeline(days) {
  const today = new Date();
  const ack = new Date(today); ack.setDate(ack.getDate() + 14);
  const pub = new Date(today); pub.setDate(pub.getDate() + days);
  return { report: fmtDate(today), ack: fmtDate(ack), pub: fmtDate(pub), days };
}

// ── renderers ───────────────────────────────────────────────────────────────
function renderReport(f, cvss, tl, reporter, warnings) {
  const sevLine = cvss && !cvss.error
    ? `**${cvss.severity} (CVSS:3.1 ${cvss.score})** · \`${f.cvss_vector}\``
    : `${f.severity_self || 'Unrated'}${cvss?.error ? ` (CVSS vector error: ${cvss.error})` : ''}`;
  const out = [];
  out.push(`# Coordinated vulnerability disclosure — ${f.project}\n`);
  out.push('> **CONFIDENTIAL — sent privately to the maintainer under coordinated disclosure.**');
  out.push('> Please do not make this public until a fix is available or the disclosure window below elapses.');
  out.push('> Happy to adjust the timeline if you need more time — just reply.\n');
  out.push('| | |');
  out.push('|---|---|');
  out.push(`| **Project** | ${f.project} |`);
  if (f.ecosystem) out.push(`| **Ecosystem** | ${f.ecosystem} |`);
  out.push(`| **Affected** | ${f.versions_affected || 'see below'} |`);
  if (f.commit) out.push(`| **Audited at commit** | \`${f.commit}\` |`);
  out.push(`| **Component** | \`${f.component}\` |`);
  out.push(`| **Class** | ${f.cwe ? f.cwe + ' — ' : ''}${f.vuln_class} |`);
  out.push(`| **Severity** | ${sevLine} |`);
  out.push(`| **Reporter** | ${reporter} |`);
  out.push(`| **Reported** | ${tl.report} |`);
  out.push('');
  out.push('## Summary\n');
  out.push(`${f.summary}\n`);
  if (f.root_cause) { out.push('## Root cause\n'); out.push(`${f.root_cause}\n`); }
  if (f.poc) { out.push('## Proof of concept\n'); out.push(`${f.poc}\n`); }
  if (f.impact) { out.push('## Impact\n'); out.push(`${f.impact}\n`); }
  if (f.remediation) { out.push('## Suggested remediation\n'); out.push(`${f.remediation}\n`); }
  out.push('## Proposed disclosure timeline\n');
  out.push(`- **${tl.report}** — reported privately to the maintainer (today).`);
  out.push(`- **by ${tl.ack}** — requesting an acknowledgement (~14 days).`);
  out.push(`- **${tl.pub}** — proposed public disclosure / advisory (${tl.days} days), or sooner if a fix ships. Flexible on request.\n`);
  if (f.novelty) { out.push('## Prior-art / novelty diligence\n'); out.push(`${f.novelty}\n`); }
  if (f.discovery) { out.push('## How this was found\n'); out.push(`${f.discovery}\n`); }
  out.push('---');
  out.push('*Reported in good faith under coordinated disclosure. No production systems, live hardware, or third-party data were targeted; analysis was performed against published source at the pinned commit. We are not requesting a bounty — we just want it fixed.*');
  // NOTE: honesty-gate notes deliberately do NOT go in the outgoing report (clean-by-
  // construction); they are printed to stdout and listed in SEND-CHECKLIST.md.
  return out.join('\n') + '\n';
}

function renderEmail(f, cvss, tl, reporter) {
  const gh = ghParts(f.repo_url);
  const sev = cvss && !cvss.error ? `${cvss.severity} (CVSS:3.1 ${cvss.score}, ${f.cvss_vector})` : (f.severity_self || 'see report');
  return [
    `Subject: [Security] ${f.cwe ? f.cwe + ' ' : ''}${f.vuln_class} in ${f.project}`,
    '',
    `Hi ${gh ? gh.owner : 'maintainers'},`,
    '',
    `I'm reporting a security issue in ${f.project} privately under coordinated`,
    `disclosure. Summary below; a full report with root-cause, PoC, and a suggested`,
    `fix is attached (disclosure-report.md).`,
    '',
    `  Component : ${f.component}`,
    `  Class     : ${f.cwe ? f.cwe + ' — ' : ''}${f.vuln_class}`,
    `  Affected  : ${f.versions_affected || 'see report'}`,
    `  Severity  : ${sev}`,
    '',
    wrap(f.summary, 72),
    '',
    `I'd like to coordinate on a fix. Proposed timeline: acknowledgement by`,
    `${tl.ack}, public disclosure around ${tl.pub} (${tl.days} days) or whenever a`,
    `fix ships — happy to adjust if you need more time. I'm not seeking a bounty.`,
    '',
    `Please let me know the best channel for the details if email isn't it.`,
    '',
    `Thanks,`,
    reporter,
    '',
    '--',
    'Sent manually under coordinated disclosure; a human reviewed and sent this.',
  ].join('\n') + '\n';
}
function wrap(s, n) {
  const words = String(s || '').replace(/\s+/g, ' ').trim().split(' ');
  const lines = []; let cur = '';
  for (const w of words) {
    if ((cur + ' ' + w).trim().length > n) { lines.push(cur.trim()); cur = w; }
    else cur += ' ' + w;
  }
  if (cur.trim()) lines.push(cur.trim());
  return lines.join('\n');
}

function renderChecklist(f, cvss, tl, warnings) {
  const out = [];
  out.push(`# Send checklist — ${f.project}\n`);
  out.push('> This tool drafted the package. **You** review and send it. Work top to bottom.\n');
  if (warnings.length) {
    out.push('## ⚠ Honesty gate — resolve these first\n');
    for (const w of warnings) out.push(`- [ ] ${w}`);
    out.push('');
  }
  out.push('## Before you send\n');
  out.push('- [ ] Re-read `disclosure-report.md` end to end — every claim true, every line/offset correct against the pinned commit.');
  out.push('- [ ] CVSS vector reflects the *honest* threat model (attack vector, privileges, complexity). Adjust if you talked yourself into a higher number.');
  out.push('- [ ] PoC is enough for the maintainer to reproduce, but you\'re comfortable it\'s in their hands (private channel only).');
  out.push('- [ ] No secrets, internal paths, API keys, or unrelated findings leaked into the text.');
  out.push('- [ ] Confirm it isn\'t already public/fixed (re-check advisories + recent commits — don\'t report a closed bug).');
  out.push('');
  out.push(contactChecklist(f));
  out.push('\n## Send it (manually)\n');
  out.push('- [ ] Open the vendor channel you identified above (advisory form / email).');
  out.push('- [ ] Paste `disclosure-email.txt`, attach `disclosure-report.md` (or paste inline if they prefer).');
  out.push('- [ ] **You** hit send. (This tool does not and will not send for you.)');
  out.push('');
  out.push('## After you send — track it\n');
  out.push(`- [ ] Log the send date (${tl.report}) and set a reminder for the ack window (${tl.ack}).`);
  out.push(`- [ ] If no ack by ${tl.ack}, send one polite follow-up, then consider CERT/CC coordination.`);
  out.push(`- [ ] Hold all public detail until ${tl.pub} or a shipped fix — whichever comes first, per what you agree with the vendor.`);
  out.push('- [ ] When fixed: request a CVE (if not already), then publish the advisory. Credit the vendor for the fix.');
  out.push('');
  return out.join('\n');
}

// ── main ────────────────────────────────────────────────────────────────────
function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.finding || args.finding === 'true') {
    console.error('usage: node scripts/disclosure-gen.mjs --finding <finding.json> [--out <dir>] [--format md|email|both] [--reporter "Name <email>"] [--days 90]');
    process.exit(2);
  }
  const findingPath = path.isAbsolute(args.finding) ? args.finding : R(args.finding);
  if (!fs.existsSync(findingPath)) { console.error(`finding not found: ${findingPath}`); process.exit(2); }

  let f;
  try { f = JSON.parse(fs.readFileSync(findingPath, 'utf8')); }
  catch (e) { console.error(`bad finding JSON: ${e.message}`); process.exit(2); }

  const missing = ['slug', 'project', 'component', 'vuln_class', 'summary'].filter((k) => !f[k]);
  if (missing.length) { console.error(`finding missing required fields: ${missing.join(', ')}`); process.exit(2); }

  const reporter = args.reporter && args.reporter !== 'true' ? args.reporter : (f.reporter || 'Security researcher');
  const days = Number(args.days) > 0 ? Number(args.days) : 90;
  const format = ['md', 'email', 'both'].includes(args.format) ? args.format : 'both';

  const cvss = cvss31(f.cvss_vector);
  const tl = timeline(days);
  const warnings = honestyCheck(f, cvss);

  const outDir = args.out && args.out !== 'true'
    ? (path.isAbsolute(args.out) ? args.out : R(args.out))
    : R('bench/wild-hunt/disclosures', f.slug);
  fs.mkdirSync(outDir, { recursive: true });

  const written = [];
  if (format === 'md' || format === 'both') {
    const p = path.join(outDir, 'disclosure-report.md');
    fs.writeFileSync(p, renderReport(f, cvss, tl, reporter, warnings)); written.push(p);
  }
  if (format === 'email' || format === 'both') {
    const p = path.join(outDir, 'disclosure-email.txt');
    fs.writeFileSync(p, renderEmail(f, cvss, tl, reporter)); written.push(p);
  }
  const cp = path.join(outDir, 'SEND-CHECKLIST.md');
  fs.writeFileSync(cp, renderChecklist(f, cvss, tl, warnings)); written.push(cp);

  // ── summary to stdout ──
  console.log(`\n════════ disclosure package — ${f.project} ════════\n`);
  if (cvss && !cvss.error) {
    console.log(`  severity   : ${cvss.severity} (CVSS:3.1 ${cvss.score})`);
    if (f.severity_self && f.severity_self !== cvss.severity)
      console.log(`  self-rated : ${f.severity_self}  ${f.severity_self !== cvss.severity ? '(differs from computed — see honesty notes)' : ''}`);
  } else if (cvss?.error) {
    console.log(`  severity   : CVSS vector error — ${cvss.error}`);
  } else {
    console.log(`  severity   : ${f.severity_self || 'unrated'} (no CVSS vector provided)`);
  }
  console.log(`  timeline   : reported ${tl.report} · ack by ${tl.ack} · public ${tl.pub} (${tl.days}d)`);
  console.log(`  written    :`);
  for (const w of written) console.log(`               ${path.relative(REPO, w)}`);
  if (warnings.length) {
    console.log(`\n  ⚠ honesty gate (${warnings.length}) — resolve before sending:`);
    for (const w of warnings) console.log(`     • ${w}`);
  }
  // vendor-cleanliness lint of the outgoing artifacts (safe-by-construction)
  const outgoing = written.filter((w) => /disclosure-(report|email)\.(md|txt)$/.test(w)).map((w) => fs.readFileSync(w, 'utf8')).join('\n');
  const leaks = lintDisclosure(outgoing, { target: f.project });
  const blocks = leaks.filter((l) => l.sev === 'block');
  if (leaks.length) {
    console.log(`\n  vendor-cleanliness lint: ${blocks.length} blocking · ${leaks.length - blocks.length} warning(s)`);
    for (const l of leaks) console.log(`     ${l.sev === 'block' ? '❌' : '⚠'} ${l.label}: "${l.snippet}"`);
  } else console.log(`\n  vendor-cleanliness lint: ✅ clean`);

  console.log(`\n  NEXT: open ${path.relative(REPO, cp)} and work the checklist. This tool does NOT send — you do.\n`);
  process.exit((warnings.length || blocks.length) ? 3 : 0);
}

// reusable pieces (imported by tests); main() runs only when invoked directly
export { cvss31, roundup, band, honestyCheck, contactChecklist, renderReport, renderEmail, timeline };

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) main();
