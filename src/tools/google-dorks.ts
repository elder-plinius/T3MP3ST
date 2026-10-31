// =============================================================================
// GOOGLE DORKS ENGINE — advanced search operators as an OSINT technique
// =============================================================================
// Turns the Recorded Future "Google Dorks: Top Tips and Tricks" operator catalog
// into live, operator-ready search commands. Every dork is a *search-engine query*
// the operator fires in THEIR OWN BROWSER (no automated scraping, no bulk Google
// bot). The server merely BUILDS the query string + the ready-to-click engine URL.
//
// Top-20 operator cheat sheet (Recorded Future):
//   site: inurl: intitle: filetype: link: intext: allintitle: cache: related:
//   info: ext: define: phonebook: map: allinurl: before: after: numrange:
//   AROUND(X)  inanchor:  (+ wildcards *, logical OR/AND, exclusion -)
//
// Categories mirror GHDB + threat-intel use: People OSINT | Document Exposure |
// Credentials & Configs | Admin & Portal Enumeration | Directory Listing |
// Infrastructure & Sensitive Endpoints | Social & Reputation | Temporal / Cache |
// Operator combinators (for the query builder).
// =============================================================================

export type DorkCategory =
  | 'people'
  | 'documents'
  | 'credentials'
  | 'admin'
  | 'directory'
  | 'infrastructure'
  | 'social'
  | 'temporal';

export type DorkSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface DorkOperatorRef {
  op: string;
  desc: string;
}

export const DORK_OPERATORS: DorkOperatorRef[] = [
  { op: 'site:', desc: 'Restrict to a host or domain (site:example.com)' },
  { op: 'filetype: / ext:', desc: 'Filter by file extension (filetype:pdf)' },
  { op: 'intitle:', desc: 'Term appears in the page title' },
  { op: 'allintitle:', desc: 'All terms appear in the title' },
  { op: 'inurl:', desc: 'Term appears in the URL' },
  { op: 'allinurl:', desc: 'All terms appear in the URL' },
  { op: 'intext:', desc: 'Term appears in the body text' },
  { op: 'allintext:', desc: 'All terms appear in the body' },
  { op: 'inanchor:', desc: 'Term appears in anchor text of inbound links' },
  { op: 'cache:', desc: 'Google’s cached copy of a page' },
  { op: 'link:', desc: 'Pages that link to a given URL' },
  { op: 'related:', desc: 'Pages related to a URL' },
  { op: 'info:', desc: 'Info about a URL (cache, similar, links)' },
  { op: 'define:', desc: 'Definition of a term' },
  { op: 'AROUND(X)', desc: 'Two terms within X words of each other' },
  { op: 'before: / after:', desc: 'Results indexed before/after a date (YYYY-MM-DD)' },
  { op: 'numrange:', desc: 'Numeric range (numrange:100..500)' },
  { op: 'phonebook:', desc: 'Phonebook / contact listings (legacy, best-effort)' },
  { op: 'map:', desc: 'Map result for a location / address' },
  { op: '*', desc: 'Wildcard — matches one or more words' },
  { op: '-', desc: 'Exclusion — prefix a term to exclude it (-term)' },
  { op: 'OR / |', desc: 'Logical OR across terms' },
  { op: 'AND', desc: 'Logical AND (default between terms)' },
  { op: '" "', desc: 'Exact phrase (quoted)' },
];

export interface DorkTemplate {
  id: string;
  label: string;
  category: DorkCategory;
  severity: DorkSeverity;
  query: string;
  description: string;
  operators: string[];
  example?: string;
  /** GHDB / OSINT reference tag */
  tag?: string;
}

export interface DorkCommand {
  id: string;
  label: string;
  category: DorkCategory;
  severity: DorkSeverity;
  description: string;
  operators: string[];
  query: string;
  tag?: string;
  raw: string;
  engines: { label: string; url: string }[];
}

const ENGINES: [string, string][] = [
  ['Google', 'https://www.google.com/search?q='],
  ['Bing', 'https://www.bing.com/search?q='],
  ['DuckDuckGo', 'https://duckduckgo.com/?q='],
];

// ---------- helpers ----------
const q = (s: string) => encodeURIComponent(s);
function enginesFor(query: string): { label: string; url: string }[] {
  return ENGINES.map(([label, base]) => ({ label: `Search on ${label}`, url: `${base}${q(query)}` }));
}
function needsQuote(s: string): boolean { return /\s/.test(s) || /[^a-zA-Z0-9._@-]/.test(s); }
function quoteIfNeeded(s: string): string { return needsQuote(s) ? `"${s}"` : s; }
function domainFrom(raw: string): string { return raw.trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '').replace(/^www\./i, ''); }

// ---------- FULL CATALOG (parameterised templates) ----------
type Ctx = { name?: string; email?: string; username?: string; phone?: string; domain?: string; keyword?: string };

function instantiate(t: DorkTemplate, ctx: Ctx): DorkCommand | null {
  let query = t.query;
  const missing: string[] = [];

  const sub = (token: string, value?: string) => {
    if (query.includes(token)) {
      if (!value) missing.push(token);
      else query = query.split(token).join(value);
    }
  };

  const nameQ = ctx.name ? `"${ctx.name}"` : undefined;
  const emailQ = ctx.email ? `"${ctx.email}"` : undefined;
  const userQ = ctx.username ? quoteIfNeeded(ctx.username) : undefined;
  const phoneQ = ctx.phone ? ctx.phone.replace(/\D/g, '') : undefined;
  const phoneQuoted = phoneQ ? `"${phoneQ}"` : undefined;
  const domainQ = ctx.domain ? domainFrom(ctx.domain) : undefined;
  const domainSite = domainQ ? `site:${domainQ}` : undefined;
  const kwQ = ctx.keyword ? quoteIfNeeded(ctx.keyword) : undefined;
  const kwRaw = ctx.keyword || undefined;

  sub('{name}', nameQ);
  sub('{email}', emailQ);
  sub('{username}', userQ);
  sub('{username_raw}', ctx.username);
  sub('{phone}', phoneQuoted);
  sub('{phone_raw}', phoneQ);
  sub('{domain}', domainQ);
  sub('{domain_site}', domainSite || '');
  sub('{keyword}', kwQ);
  sub('{keyword_raw}', kwRaw);

  if (missing.length) return null;

  // Clean stray empty tokens (e.g. leftover "site: " when no domain, or dangling "AND")
  query = query.replace(/\s+/g, ' ').trim();

  return {
    id: t.id,
    label: t.label,
    category: t.category,
    severity: t.severity,
    description: t.description,
    operators: [...t.operators],
    query,
    tag: t.tag,
    raw: query,
    engines: enginesFor(query),
  };
}

// Every row below maps to one or more of the top-20 operators.
// Tags use GHDB-style shorthand for analyst familiarity.
const TEMPLATES: DorkTemplate[] = [
  // ---- PEOPLE (expands the existing personDorks with operator-rich variants) ----
  {
    id: 'people-exact-name',
    label: 'Exact name match',
    category: 'people',
    severity: 'info',
    query: '{name}',
    description: 'Quoted full-name search across the open web — foundation for every person locate.',
    operators: ['" "'],
    tag: 'people',
  },
  {
    id: 'people-cv-resume',
    label: 'CV / resume disclosure',
    category: 'people',
    severity: 'medium',
    query: '{name} (CV OR resume OR "curriculum vitae" OR bio)',
    description: 'CVs and bios leak employers, education, and contact details.',
    operators: ['OR', '" "', 'intext:'],
    tag: 'people',
  },
  {
    id: 'people-filetype-docs',
    label: 'Name in documents',
    category: 'people',
    severity: 'medium',
    query: '{name} (filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx OR filetype:pptx)',
    description: 'Bios, rosters, filings, and reports that mention the subject.',
    operators: ['filetype:'],
    tag: 'GHDB: files containing juicy info',
  },
  {
    id: 'people-email-exposure',
    label: 'Email address footprint',
    category: 'people',
    severity: 'info',
    query: '{email}',
    description: 'Every indexed page containing the email address.',
    operators: ['" "', 'intext:'],
    tag: 'people',
  },
  {
    id: 'people-email-filetype',
    label: 'Email in documents',
    category: 'people',
    severity: 'medium',
    query: '{email} (filetype:pdf OR filetype:doc OR filetype:docx OR filetype:csv OR filetype:xls)',
    description: 'Leaked mailing lists, exports, and document metadata.',
    operators: ['filetype:', '" "'],
    tag: 'GHDB: files containing juicy info',
  },
  {
    id: 'people-username-footprint',
    label: 'Username footprint',
    category: 'people',
    severity: 'info',
    query: '{username}',
    description: 'Bare handle across engines — catches forum/profile mirrors.',
    operators: ['intext:', 'inurl:'],
    tag: 'people',
  },
  {
    id: 'people-username-site-venmo',
    label: 'Username on Venmo (indexed)',
    category: 'people',
    severity: 'info',
    query: 'site:venmo.com {username}',
    description: 'Public Venmo pages as indexed (no platform enumeration — search-engine index only).',
    operators: ['site:'],
    tag: 'people',
  },
  {
    id: 'people-phone-exact',
    label: 'Phone number footprint',
    category: 'people',
    severity: 'medium',
    query: '{phone}',
    description: 'Phone number as indexed, quoted for precision.',
    operators: ['" "'],
    tag: 'people',
  },
  {
    id: 'people-phonebook',
    label: 'Phonebook record',
    category: 'people',
    severity: 'info',
    query: 'phonebook:{phone_raw}',
    description: 'Legacy phonebook operator (best-effort; engine support varies).',
    operators: ['phonebook:'],
  },
  {
    id: 'people-name-intitle',
    label: 'Name in page title',
    category: 'people',
    severity: 'info',
    query: 'intitle:{name}',
    description: 'Pages that headline the subject (profiles, articles, rosters).',
    operators: ['intitle:'],
    tag: 'people',
  },
  {
    id: 'people-name-inurl',
    label: 'Name in URL',
    category: 'people',
    severity: 'info',
    query: 'inurl:{name}',
    description: 'URL-borne person pages.',
    operators: ['inurl:'],
  },
  {
    id: 'people-name-around-company',
    label: 'Name NEAR keyword (AROUND)',
    category: 'people',
    severity: 'info',
    query: '{name} AROUND(5) {keyword}',
    description: 'Name within 5 words of a keyword — correlate subject with employer, event, or topic.',
    operators: ['AROUND(X)', '" "'],
    tag: 'people',
  },
  {
    id: 'people-social-linkedin-site',
    label: 'LinkedIn person (site:)',
    category: 'people',
    severity: 'info',
    query: 'site:linkedin.com/in {name}',
    description: 'LinkedIn profiles indexed by Google.',
    operators: ['site:'],
    tag: 'social',
  },
  // ---- DOCUMENT EXPOSURE ----
  {
    id: 'doc-pdf-site',
    label: 'PDFs on target domain',
    category: 'documents',
    severity: 'low',
    query: '{domain_site} filetype:pdf',
    description: 'Every indexed PDF on the target — research reports, filings, invoices.',
    operators: ['site:', 'filetype:'],
    tag: 'GHDB: files containing juicy info',
  },
  {
    id: 'doc-spreadsheet-site',
    label: 'Spreadsheets on target',
    category: 'documents',
    severity: 'medium',
    query: '{domain_site} (filetype:xls OR filetype:xlsx OR filetype:csv)',
    description: 'Data exports and rosters — often over-shared.',
    operators: ['site:', 'filetype:', 'OR'],
    tag: 'GHDB: files containing juicy info',
  },
  {
    id: 'doc-presentation-site',
    label: 'Presentations on target',
    category: 'documents',
    severity: 'low',
    query: '{domain_site} (filetype:ppt OR filetype:pptx)',
    description: 'Internal decks sometimes indexed.',
    operators: ['site:', 'filetype:'],
    tag: 'GHDB: files containing juicy info',
  },
  {
    id: 'doc-doc-site',
    label: 'Word docs on target',
    category: 'documents',
    severity: 'low',
    query: '{domain_site} (filetype:doc OR filetype:docx OR filetype:odt)',
    description: 'Memos, letters, and form templates.',
    operators: ['site:', 'filetype:'],
    tag: 'GHDB: files containing juicy info',
  },
  {
    id: 'doc-all-office-site',
    label: 'All office docs on target',
    category: 'documents',
    severity: 'medium',
    query: '{domain_site} (filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx OR filetype:csv OR filetype:ppt OR filetype:pptx)',
    description: 'Broad office-file sweep in one query.',
    operators: ['site:', 'filetype:', 'OR'],
    tag: 'GHDB',
  },
  // ---- CREDENTIALS & CONFIGS (use responsibly — authorized targets only) ----
  {
    id: 'creds-env-file',
    label: 'Exposed .env files',
    category: 'credentials',
    severity: 'critical',
    query: '{domain_site} filetype:env',
    description: 'Environment files that often contain secrets (keys, DB URLs).',
    operators: ['site:', 'filetype:'],
    tag: 'GHDB: files containing passwords',
  },
  {
    id: 'creds-env-dotenv-site',
    label: '.env with DB_PASSWORD / SECRET',
    category: 'credentials',
    severity: 'critical',
    query: '{domain_site} filetype:env "DB_PASSWORD"',
    description: 'Narrow .env to those leaking credential keywords.',
    operators: ['site:', 'filetype:', 'intext:'],
    tag: 'GHDB: files containing passwords',
  },
  {
    id: 'creds-log-file',
    label: 'Log files exposing tokens',
    category: 'credentials',
    severity: 'high',
    query: '{domain_site} (filetype:log OR filetype:txt) ("password" OR "passwd" OR "secret" OR "api_key")',
    description: 'Logs that accidentally captured credentials.',
    operators: ['site:', 'filetype:', 'OR', 'intext:'],
    tag: 'GHDB: files containing passwords',
  },
  {
    id: 'creds-sql-dump',
    label: 'SQL dumps',
    category: 'credentials',
    severity: 'critical',
    query: '{domain_site} (filetype:sql OR filetype:dump OR filetype:bak) ("INSERT INTO" OR "CREATE TABLE")',
    description: 'Database dumps indexed — full-table exposure.',
    operators: ['site:', 'filetype:', 'OR'],
    tag: 'GHDB: files containing juicy info',
  },
  {
    id: 'creds-private-key',
    label: 'Private keys',
    category: 'credentials',
    severity: 'critical',
    query: '{domain_site} ("BEGIN RSA PRIVATE KEY" OR "BEGIN OPENSSH PRIVATE KEY" OR "BEGIN DSA PRIVATE KEY")',
    description: 'PEM/SSH private keys pasted into indexed pages.',
    operators: ['site:', 'intext:', '" "'],
    tag: 'GHDB: files containing passwords',
  },
  {
    id: 'creds-htpasswd',
    label: '.htpasswd / .htaccess',
    category: 'credentials',
    severity: 'high',
    query: '{domain_site} (filetype:htpasswd OR filetype:htaccess OR intitle:"Index of" ".htpasswd")',
    description: 'Auth files exposed via misconfiguration.',
    operators: ['site:', 'filetype:', 'intitle:', 'OR'],
    tag: 'GHDB: files containing passwords',
  },
  {
    id: 'creds-config-js',
    label: 'Config / secrets in JS & JSON',
    category: 'credentials',
    severity: 'high',
    query: '{domain_site} (filetype:js OR filetype:json) ("api_key" OR "apikey" OR "secret" OR "aws_secret")',
    description: 'Client bundles that embed keys.',
    operators: ['site:', 'filetype:', 'OR'],
    tag: 'GHDB: files containing passwords',
  },
  {
    id: 'creds-git-folder',
    label: '.git folder exposed',
    category: 'credentials',
    severity: 'critical',
    query: '{domain_site} intitle:"Index of" ".git"',
    description: 'Git history browsable — full source + secrets.',
    operators: ['site:', 'intitle:', 'intext:'],
    tag: 'GHDB: sensitive directories',
  },
  {
    id: 'creds-aws-keys',
    label: 'AWS keys in text',
    category: 'credentials',
    severity: 'critical',
    query: '{domain_site} ("AKIA" AND "aws_secret_access_key")',
    description: 'AWS access keys in indexed config/docs.',
    operators: ['site:', 'AND', '" "'],
    tag: 'GHDB: files containing passwords',
  },
  // ---- ADMIN & PORTAL ENUMERATION ----
  {
    id: 'admin-login-page',
    label: 'Login pages',
    category: 'admin',
    severity: 'low',
    query: '{domain_site} inurl:login',
    description: 'Enumerate login endpoints for authorized scope.',
    operators: ['site:', 'inurl:'],
    tag: 'GHDB: pages containing login portals',
  },
  {
    id: 'admin-admin-panel',
    label: 'Admin panels',
    category: 'admin',
    severity: 'medium',
    query: '{domain_site} (inurl:admin OR inurl:administrator OR intitle:"admin panel")',
    description: 'Admin / dashboard URLs.',
    operators: ['site:', 'inurl:', 'intitle:', 'OR'],
    tag: 'GHDB: pages containing login portals',
  },
  {
    id: 'admin-wp-login',
    label: 'WordPress / CMS logins',
    category: 'admin',
    severity: 'low',
    query: '{domain_site} (inurl:wp-login OR inurl:wp-admin OR inurl:administrator/index.php)',
    description: 'CMS entry points.',
    operators: ['site:', 'inurl:', 'OR'],
    tag: 'GHDB: pages containing login portals',
  },
  {
    id: 'admin-intitle-login',
    label: 'Pages titled "Login"',
    category: 'admin',
    severity: 'low',
    query: '{domain_site} intitle:"login"',
    description: 'Title-based login discovery.',
    operators: ['site:', 'intitle:'],
    tag: 'GHDB: pages containing login portals',
  },
  // ---- DIRECTORY LISTING ----
  {
    id: 'dir-index-of',
    label: 'Open directory listings',
    category: 'directory',
    severity: 'medium',
    query: '{domain_site} intitle:"Index of"',
    description: 'Auto-indexed directories left open.',
    operators: ['site:', 'intitle:'],
    tag: 'GHDB: sensitive directories',
  },
  {
    id: 'dir-index-of-parent',
    label: 'Parent directory',
    category: 'directory',
    severity: 'medium',
    query: '{domain_site} intitle:"Index of /" "Parent Directory"',
    description: 'Classic directory listing marker.',
    operators: ['site:', 'intitle:', 'intext:'],
    tag: 'GHDB: sensitive directories',
  },
  {
    id: 'dir-backup-zip',
    label: 'Backup / archive files',
    category: 'directory',
    severity: 'high',
    query: '{domain_site} (filetype:zip OR filetype:bak OR filetype:backup OR filetype:tar OR filetype:gz) intitle:"Index of"',
    description: 'Backup artifacts in open directories.',
    operators: ['site:', 'filetype:', 'intitle:', 'OR'],
    tag: 'GHDB: files containing juicy info',
  },
  {
    id: 'dir-logs-listing',
    label: 'Log directories',
    category: 'directory',
    severity: 'medium',
    query: '{domain_site} intitle:"Index of" (filetype:log OR inurl:logs)',
    description: 'Log directories with listing enabled.',
    operators: ['site:', 'intitle:', 'filetype:', 'inurl:'],
    tag: 'GHDB: sensitive directories',
  },
  // ---- INFRASTRUCTURE & SENSITIVE ENDPOINTS ----
  {
    id: 'infra-api-docs',
    label: 'API docs (Swagger / OpenAPI)',
    category: 'infrastructure',
    severity: 'low',
    query: '{domain_site} (inurl:swagger OR inurl:openapi OR intitle:"Swagger UI" OR intitle:"OpenAPI")',
    description: 'Exposed API documentation.',
    operators: ['site:', 'inurl:', 'intitle:', 'OR'],
    tag: 'sensitive endpoints',
  },
  {
    id: 'infra-env-endpoint',
    label: 'Spring / env actuator',
    category: 'infrastructure',
    severity: 'high',
    query: '{domain_site} (inurl:"/actuator/env" OR inurl:"/env" OR inurl:"/_env")',
    description: 'Spring Boot / actuator env leaks.',
    operators: ['site:', 'inurl:', 'OR'],
    tag: 'sensitive endpoints',
  },
  {
    id: 'infra-graphql-endpoint',
    label: 'GraphQL endpoints',
    category: 'infrastructure',
    severity: 'low',
    query: '{domain_site} inurl:graphql',
    description: 'GraphQL explorers / playgrounds.',
    operators: ['site:', 'inurl:'],
    tag: 'sensitive endpoints',
  },
  {
    id: 'infra-jenkins',
    label: 'Jenkins / CI panels',
    category: 'infrastructure',
    severity: 'medium',
    query: '{domain_site} intitle:"Dashboard [Jenkins]"',
    description: 'CI dashboards exposed to the web.',
    operators: ['site:', 'intitle:'],
    tag: 'GHDB: footholds',
  },
  {
    id: 'infra-kibana-grafana',
    label: 'Kibana / Grafana',
    category: 'infrastructure',
    severity: 'medium',
    query: '{domain_site} (intitle:"Kibana" OR intitle:"Grafana")',
    description: 'Observability UIs that should not be public.',
    operators: ['site:', 'intitle:', 'OR'],
    tag: 'GHDB: footholds',
  },
  {
    id: 'infra-error-sql',
    label: 'SQL error messages',
    category: 'infrastructure',
    severity: 'medium',
    query: '{domain_site} ("Warning: mysql_connect" OR "Warning: pg_connect" OR "SQL syntax" OR "ORA-")',
    description: 'Verbose DB errors leaking stack traces.',
    operators: ['site:', 'OR', '" "'],
    tag: 'GHDB: error messages',
  },
  {
    id: 'infra-error-stacktrace',
    label: 'Stack traces',
    category: 'infrastructure',
    severity: 'high',
    query: '{domain_site} ("Exception in thread" OR "Stack Trace" OR "Traceback (most recent call last)")',
    description: 'Framework stack traces in indexed pages.',
    operators: ['site:', 'OR'],
    tag: 'error messages',
  },
  {
    id: 'infra-shodan-cache',
    label: 'Shodan-adjacent exposure',
    category: 'infrastructure',
    severity: 'info',
    query: '{domain_site} ("port 22" OR "port 3389" OR "port 8080")',
    description: 'Port hints that suggest exposed services — validate via authorized port scan.',
    operators: ['site:', 'OR'],
  },
  // ---- SOCIAL & REPUTATION ----
  {
    id: 'social-pastebin-leak',
    label: 'Pastes mentioning keyword',
    category: 'social',
    severity: 'medium',
    query: 'site:pastebin.com {keyword}',
    description: 'Pastebin leaks / shares for a keyword.',
    operators: ['site:'],
    tag: 'social',
  },
  {
    id: 'social-github-code',
    label: 'GitHub code search',
    category: 'social',
    severity: 'info',
    query: 'site:github.com {keyword}',
    description: 'Code, commits, and gists containing the keyword.',
    operators: ['site:'],
    tag: 'social',
  },
  {
    id: 'social-twitter-site',
    label: 'X (Twitter) mentions',
    category: 'social',
    severity: 'info',
    query: 'site:twitter.com OR site:x.com {keyword}',
    description: 'Public posts mentioning the keyword.',
    operators: ['site:', 'OR'],
    tag: 'social',
  },
  {
    id: 'social-reddit-site',
    label: 'Reddit discussion',
    category: 'social',
    severity: 'info',
    query: 'site:reddit.com {keyword}',
    description: 'Reddit threads mentioning the keyword.',
    operators: ['site:'],
    tag: 'social',
  },
  // ---- TEMPORAL / CACHE ----
  {
    id: 'temporal-after-date',
    label: 'Results after date',
    category: 'temporal',
    severity: 'info',
    query: '{domain_site} after:2024-01-01',
    description: 'Only pages indexed after a date — fresh exposure window.',
    operators: ['after:'],
    tag: 'temporal',
  },
  {
    id: 'temporal-before-date',
    label: 'Results before date',
    category: 'temporal',
    severity: 'info',
    query: '{domain_site} before:2024-01-01',
    description: 'Historical snapshot — what was once public.',
    operators: ['before:'],
    tag: 'temporal',
  },
  {
    id: 'temporal-cache-target',
    label: 'Cached copy of target',
    category: 'temporal',
    severity: 'info',
    query: 'cache:{domain}',
    description: 'Google-cached copy (survives takedowns for a window).',
    operators: ['cache:'],
    tag: 'temporal',
  },
  {
    id: 'temporal-related-domain',
    label: 'Sites related to target',
    category: 'temporal',
    severity: 'info',
    query: 'related:{domain}',
    description: 'Google-assessed related hosts.',
    operators: ['related:'],
    tag: 'temporal',
  },
  {
    id: 'temporal-info-domain',
    label: 'Info about domain',
    category: 'temporal',
    severity: 'info',
    query: 'info:{domain}',
    description: 'Google info: cache, related, similar.',
    operators: ['info:'],
    tag: 'temporal',
  },
  {
    id: 'temporal-inanchor-keyword',
    label: 'Pages linking with keyword anchor',
    category: 'temporal',
    severity: 'info',
    query: 'inanchor:{keyword}',
    description: 'Pages that link using the keyword as anchor text.',
    operators: ['inanchor:'],
    tag: 'temporal',
  },
];

export const GOOGLE_DORK_CATALOG: DorkTemplate[] = [...TEMPLATES];

// ---------- Public API ----------
export function googleDorkOperators(): DorkOperatorRef[] { return [...DORK_OPERATORS]; }
export function googleDorkCatalog(): DorkTemplate[] { return [...GOOGLE_DORK_CATALOG]; }

export interface GoogleDorkInput {
  name?: string;
  email?: string;
  username?: string;
  phone?: string;
  domain?: string;
  keyword?: string;
  category?: DorkCategory;
  severity?: DorkSeverity;
  operator?: string;
  limit?: number;
}

/** Build live dork commands from the catalog, filtered and parameterised by ctx. */
export function buildGoogleDorks(input: GoogleDorkInput = {}): DorkCommand[] {
  const domainNorm = input.domain ? domainFrom(input.domain) : undefined;
  const ctx: Ctx = {
    name: input.name?.trim() || undefined,
    email: input.email?.trim() || undefined,
    username: input.username?.trim().replace(/^@/, '') || undefined,
    phone: input.phone?.trim() || undefined,
    domain: domainNorm,
    keyword: input.keyword?.trim() || undefined,
  };

  let pool = GOOGLE_DORK_CATALOG;
  if (input.category) pool = pool.filter((t) => t.category === input.category);
  if (input.severity) pool = pool.filter((t) => t.severity === input.severity);
  if (input.operator) {
    const needle = input.operator.toLowerCase().replace(/:.*$/, '').trim();
    pool = pool.filter((t) => t.operators.some((op) => op.toLowerCase().includes(needle)));
  }

  const out: DorkCommand[] = [];
  for (const t of pool) {
    const cmd = instantiate(t, ctx);
    if (cmd) out.push(cmd);
  }

  const lim = typeof input.limit === 'number' && input.limit > 0 ? Math.min(input.limit, 200) : 120;
  return out.slice(0, lim);
}

/** One-liner cheat sheet: every operator + meaning, ready for the UI header. */
export function googleDorkCheatSheet(): string {
  return DORK_OPERATORS.map((r) => `${r.op.padEnd(16)} — ${r.desc}`).join('\n');
}
