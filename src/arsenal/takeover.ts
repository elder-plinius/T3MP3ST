/**
 * Subdomain-takeover detection — pure classification logic, separated from the Arsenal tool
 * handler so it is fully unit-testable without DNS or network I/O.
 *
 * A subdomain takeover happens when a DNS record (almost always a CNAME) points at a third-party
 * service resource that has been de-provisioned or never claimed. An attacker who registers that
 * dangling resource then serves content from the victim's subdomain. Detection has two independent
 * signals, either of which is decisive:
 *   1. the CNAME target no longer resolves (dangling) — the backing resource is gone; and/or
 *   2. the live response body carries a known "unclaimed resource" fingerprint for that service.
 *
 * Fingerprints are short, factual service error strings (the same public signals the community
 * `can-i-take-over-xyz` catalog documents). `nxdomainVuln` marks services where a dangling CNAME
 * alone is a strong takeover signal (the platform will happily serve a freshly-claimed name).
 */

export interface TakeoverFingerprint {
  service: string;
  /** Matches the CNAME target host that indicates this third-party service. */
  cname: RegExp;
  /** Matches the live-response "unclaimed resource" body signature (null = body is not distinctive). */
  fingerprint: RegExp | null;
  /** A dangling (non-resolving) CNAME to this service is itself a strong takeover signal. */
  nxdomainVuln: boolean;
}

export const TAKEOVER_FINGERPRINTS: TakeoverFingerprint[] = [
  { service: 'AWS/S3', cname: /(\.s3[.-]|\.s3\.amazonaws\.com|\.amazonaws\.com)/i, fingerprint: /NoSuchBucket|The specified bucket does not exist/i, nxdomainVuln: true },
  { service: 'GitHub Pages', cname: /\.github\.io$/i, fingerprint: /There isn't a GitHub Pages site here|For root URLs \(like http:\/\/example\.com\/\) you must provide an index/i, nxdomainVuln: false },
  { service: 'Heroku', cname: /(\.herokudns\.com|\.herokuapp\.com|\.herokussl\.com)$/i, fingerprint: /No such app|herokucdn\.com\/error-pages\/no-such-app\.html/i, nxdomainVuln: false },
  { service: 'Fastly', cname: /\.fastly(\.net|lb\.net)$/i, fingerprint: /Fastly error: unknown domain/i, nxdomainVuln: false },
  { service: 'Azure', cname: /(\.azurewebsites\.net|\.cloudapp\.net|\.cloudapp\.azure\.com|\.trafficmanager\.net|\.blob\.core\.windows\.net|\.azureedge\.net|\.azure-api\.net)$/i, fingerprint: null, nxdomainVuln: true },
  { service: 'Shopify', cname: /\.myshopify\.com$/i, fingerprint: /Sorry, this shop is currently unavailable/i, nxdomainVuln: false },
  { service: 'Surge.sh', cname: /\.surge\.sh$/i, fingerprint: /project not found/i, nxdomainVuln: false },
  { service: 'Bitbucket', cname: /\.bitbucket\.io$/i, fingerprint: /Repository not found/i, nxdomainVuln: false },
  { service: 'Ghost', cname: /\.ghost\.io$/i, fingerprint: /The thing you were looking for is no longer here|Domain error/i, nxdomainVuln: false },
  { service: 'Pantheon', cname: /\.pantheonsite\.io$/i, fingerprint: /The gods are wise|404 error unknown site/i, nxdomainVuln: false },
  { service: 'Tumblr', cname: /\.domains\.tumblr\.com$/i, fingerprint: /Whatever you were looking for doesn't currently exist at this address/i, nxdomainVuln: false },
  { service: 'WordPress.com', cname: /\.wordpress\.com$/i, fingerprint: /Do you want to register .*\.wordpress\.com/i, nxdomainVuln: false },
  { service: 'Read the Docs', cname: /\.readthedocs\.io$/i, fingerprint: /unknown to Read the Docs/i, nxdomainVuln: false },
  { service: 'Zendesk', cname: /\.zendesk\.com$/i, fingerprint: /Help Center Closed/i, nxdomainVuln: false },
  { service: 'Netlify', cname: /\.netlify\.(app|com)$/i, fingerprint: /Not Found - Request ID/i, nxdomainVuln: true },
];

export interface TakeoverSignal {
  /** The resolved CNAME target host (last hop in the chain), or null when the name has no CNAME. */
  cname: string | null;
  /** Whether the CNAME target itself resolves to an address (false = dangling). */
  cnameResolves: boolean;
  /** Live-response body, if one was fetched (used to confirm a service fingerprint). */
  body?: string;
}

export interface TakeoverVerdict {
  /** True only for a CONFIRMED takeover (fingerprint match, or dangling CNAME to an nxdomain-prone service). */
  vulnerable: boolean;
  confidence: 'confirmed' | 'potential' | 'none';
  service: string | null;
  severity: 'high' | 'medium' | 'info';
  reasons: string[];
}

/**
 * Classify a subdomain-takeover signal into a verdict. Pure — no I/O. Conservative by design:
 * a bare "CNAME points at service X" without a dangling target or a body fingerprint is only ever
 * `potential`, never a confirmed finding.
 */
export function classifySubdomainTakeover(sig: TakeoverSignal): TakeoverVerdict {
  if (!sig.cname) {
    return {
      vulnerable: false,
      confidence: 'none',
      service: null,
      severity: 'info',
      reasons: ['No CNAME record — subdomain takeover is CNAME-based, so this host is not a candidate.'],
    };
  }

  const match = TAKEOVER_FINGERPRINTS.find((f) => f.cname.test(sig.cname as string));
  const dangling = !sig.cnameResolves;
  const bodyMatch = !!(match && match.fingerprint && sig.body && match.fingerprint.test(sig.body));

  if (match) {
    if (bodyMatch) {
      return {
        vulnerable: true,
        confidence: 'confirmed',
        service: match.service,
        severity: 'high',
        reasons: [
          `CNAME points to ${match.service} (${sig.cname}) and the live response carries that service's "unclaimed resource" fingerprint.`,
          'The backing resource appears unclaimed — a takeover of this subdomain is likely possible.',
        ],
      };
    }
    if (dangling && match.nxdomainVuln) {
      return {
        vulnerable: true,
        confidence: 'confirmed',
        service: match.service,
        severity: 'high',
        reasons: [
          `CNAME points to ${match.service} (${sig.cname}) but that target no longer resolves (dangling).`,
          `${match.service} serves any freshly-claimed name at this target, so this subdomain is takeover-prone.`,
        ],
      };
    }
    return {
      vulnerable: false,
      confidence: 'potential',
      service: match.service,
      severity: 'medium',
      reasons: [
        `CNAME points to ${match.service} (${sig.cname}). No unclaimed-resource fingerprint was confirmed`,
        dangling ? 'but the CNAME target does not resolve — verify whether the resource can be claimed.'
                 : 'and the target still resolves — verify the resource is genuinely owned by the target.',
      ],
    };
  }

  if (dangling) {
    return {
      vulnerable: false,
      confidence: 'potential',
      service: null,
      severity: 'medium',
      reasons: [
        `CNAME points to ${sig.cname}, which no longer resolves (dangling) — a possible takeover of an unrecognized service.`,
        'Confirm whether the pointed-to resource can be registered by a third party.',
      ],
    };
  }

  return {
    vulnerable: false,
    confidence: 'none',
    service: null,
    severity: 'info',
    reasons: [`CNAME points to ${sig.cname}, which resolves normally and matches no known takeover fingerprint.`],
  };
}

/** Render a verdict as the human-readable tool output block. */
export function renderTakeoverReport(host: string, chain: string[], verdict: TakeoverVerdict): string {
  const badge = verdict.confidence === 'confirmed' ? '🚨 VULNERABLE (confirmed)'
    : verdict.confidence === 'potential' ? '⚠️  POTENTIAL — needs manual verification'
    : '✅ Not a takeover candidate';
  const lines = [
    `Subdomain takeover check — ${host}`,
    `Verdict: ${badge}`,
    verdict.service ? `Service: ${verdict.service}` : null,
    verdict.confidence !== 'none' ? `Severity: ${verdict.severity}` : null,
    chain.length ? `CNAME chain: ${[host, ...chain].join(' → ')}` : `CNAME chain: (none — ${host} has no CNAME)`,
    '',
    ...verdict.reasons.map((r) => `• ${r}`),
  ].filter((l): l is string => l !== null);
  return lines.join('\n');
}
