import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';

describe('Credentials Ledger and Evidence Vault Persistence', () => {
  const root = path.resolve(__dirname, '../..');
  const serverTs = fs.readFileSync(path.join(root, 'src/server.ts'), 'utf8');
  const evidenceHtml = fs.readFileSync(path.join(root, 'docs/evidence.html'), 'utf8');

  it('server.ts defines credentialsLedger and credential extractor', () => {
    expect(serverTs).toContain('const credentialsLedger = new Map<string, CredentialRecord>();');
    expect(serverTs).toContain('function extractCredentialsFromText');
    expect(serverTs).toContain('function recordCredentialToLedger');
    expect(serverTs).toContain('function reindexCredentialsFromLedgers');
  });

  it('server.ts persists credentialsLedger in state snapshots and restores on boot', () => {
    expect(serverTs).toContain('credentialsLedger: [...credentialsLedger.values()],');
    expect(serverTs).toContain('replaceMapContents(credentialsLedger, (state as Record<string, unknown>).credentialsLedger);');
    expect(serverTs).toContain('reindexCredentialsFromLedgers();');
  });

  it('server.ts listens to credential:harvested and indexes scan outputs', () => {
    expect(serverTs).toContain("tempestCommand.on('credential:harvested'");
    expect(serverTs).toContain("extractCredentialsFromText(params.detail || params.summary || '', target, params.source, title)");
    expect(serverTs).toContain("extractCredentialsFromText((finding.description || '') + ' ' + (finding.remediation || ''), target, 'finding', title)");
  });

  it('server.ts exposes GET /api/credentials and supplies credentials in /api/mission/findings', () => {
    expect(serverTs).toContain("app.get('/api/credentials'");
    expect(serverTs).toContain("app.get('/api/mission/findings'");
    expect(serverTs).toContain('credentials: dedupedCreds');
  });

  it('docs/evidence.html renders rich credential rows and files under both (credentials) and target domains', () => {
    expect(evidenceHtml).toContain('const credRow = (c) => {');
    expect(evidenceHtml).toContain('groupOf(d).creds.push(c);');
    expect(evidenceHtml).toContain("groupOf('(credentials)').creds = creds;");
    expect(evidenceHtml).toContain('Copy Secret');
    expect(evidenceHtml).toContain('if (_credCountEl) _credCountEl.textContent = creds.length;');
  });
});
