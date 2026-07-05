/**
 * MCP recon authorization guards. The MCP plane is a standalone stdio process with no mission scope,
 * so it must enforce parity with the HTTP recon endpoint: local/lab targets free, public targets behind
 * an operator allowlist, and option-looking ("-…") targets rejected before reaching nmap's argv.
 */
import { describe, it, expect } from 'vitest';
import { validMcpTarget, isLocalLabTarget, mcpTargetDecision } from '../mcp-guards.js';

describe('validMcpTarget', () => {
  it('accepts hostnames and IPv4/IPv6 literals', () => {
    expect(validMcpTarget('scanme.nmap.org')).toBe(true);
    expect(validMcpTarget('10.0.0.5')).toBe(true);
    expect(validMcpTarget('::1')).toBe(true);
    expect(validMcpTarget('::ffff:1.2.3.4')).toBe(true);
  });
  it('rejects option-looking leading-dash targets (nmap flag smuggling)', () => {
    expect(validMcpTarget('-oNx')).toBe(false);
    expect(validMcpTarget('-iLwordlist')).toBe(false);
  });
  it('rejects shell metacharacters and non-strings', () => {
    expect(validMcpTarget('evil.com; id')).toBe(false);
    expect(validMcpTarget(42)).toBe(false);
  });
});

describe('mcpTargetDecision', () => {
  it('allows local/lab targets with no allowlist', () => {
    expect(mcpTargetDecision('127.0.0.1', []).allowed).toBe(true);
    expect(mcpTargetDecision('localhost', []).allowed).toBe(true);
    expect(mcpTargetDecision('10.0.0.5', []).allowed).toBe(true);
    expect(mcpTargetDecision('::1', []).allowed).toBe(true);
  });
  it('denies an unlisted public target', () => {
    expect(mcpTargetDecision('8.8.8.8', []).allowed).toBe(false);
    expect(mcpTargetDecision('scanme.nmap.org', []).allowed).toBe(false);
  });
  it('allows a public target listed exactly or as a subdomain', () => {
    expect(mcpTargetDecision('scanme.nmap.org', ['nmap.org']).allowed).toBe(true);
    expect(mcpTargetDecision('8.8.8.8', ['8.8.8.8']).allowed).toBe(true);
  });
  it('denies a leading-dash target regardless of allowlist', () => {
    expect(mcpTargetDecision('-oNx', ['nmap.org']).allowed).toBe(false);
  });
});

describe('isLocalLabTarget', () => {
  it('classifies loopback/RFC1918/link-local as lab', () => {
    expect(isLocalLabTarget('127.0.0.1')).toBe(true);
    expect(isLocalLabTarget('192.168.1.10')).toBe(true);
    expect(isLocalLabTarget('169.254.169.254')).toBe(true);
    expect(isLocalLabTarget('8.8.8.8')).toBe(false);
  });
});
