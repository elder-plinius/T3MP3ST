import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';

describe('Evidence Vault Navigation and Verbose Scan Details', () => {
  const root = path.resolve(__dirname, '../..');
  const indexHtml = fs.readFileSync(path.join(root, 'docs/index.html'), 'utf8');
  const evidenceHtml = fs.readFileSync(path.join(root, 'docs/evidence.html'), 'utf8');
  const shellJs = fs.readFileSync(path.join(root, 'docs/shell.js'), 'utf8');
  const serverTs = fs.readFileSync(path.join(root, 'src/server.ts'), 'utf8');

  it('docs/index.html wires Findings & Loot clicks to open in Evidence Vault', () => {
    expect(indexHtml).toContain('function openFindingInEvidenceVault');
    expect(indexHtml).toContain('t3mp3st_target_vault_finding');
    expect(indexHtml).toContain("parent.postMessage({ type: 't3mp3st:nav', href: 'evidence.html#'");
    expect(indexHtml).toContain('🔐 Vault');
    expect(indexHtml).toContain('openFindingInEvidenceVault(f)');
  });

  it('docs/evidence.html implements focusVaultFinding, auto-expansion, and highlighting', () => {
    expect(evidenceHtml).toContain('function focusVaultFinding');
    expect(evidenceHtml).toContain('vaultHighlightPulse');
    expect(evidenceHtml).toContain('.vault-highlight-pulse');
    expect(evidenceHtml).toContain("m.type === 't3mp3st:focus_finding'");
    expect(evidenceHtml).toContain("window.vaultOpenGroups[domain] = true");
    expect(evidenceHtml).toContain("window.vaultOpenFindingsMap[matchIndex] = true");
  });

  it('docs/evidence.html renders verbose scan details and raw tool outputs', () => {
    expect(evidenceHtml).toContain('Scan Command Executed');
    expect(evidenceHtml).toContain('Finding Analysis & Technical Claim');
    expect(evidenceHtml).toContain('Raw Scan Evidence & Tool Outputs');
    expect(evidenceHtml).toContain('Actionable Remediation');
    expect(evidenceHtml).toContain('window.copyFindingToClipboard');
    expect(evidenceHtml).toContain('window.copyAllEvidenceToClipboard');
  });

  it('docs/shell.js handles cross-frame navigation with target finding focus', () => {
    expect(shellJs).toContain("m.type === 't3mp3st:nav'");
    expect(shellJs).toContain("type: 't3mp3st:focus_finding'");
    expect(shellJs).toContain('targetFinding: m.targetFinding');
  });

  it('src/server.ts retains verbose scan detail and exposes command metadata', () => {
    expect(serverTs).toContain('redactLedgerText(content, 32000)');
    expect(serverTs).toContain('redactLedgerText(String(params.detail || \'\').trim(), 32000)');
    expect(serverTs).toContain('command: e.command');
  });
});
