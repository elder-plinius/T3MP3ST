import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  CAPABILITY_OUTCOME_CODES,
  diagnoseOperatorCapabilities,
} from '../operators/capability-diagnostics.js';
import {
  ARCHETYPE_PROFILES,
  listOperatorPrompts,
  resetOperatorOverride,
  setOperatorOverride,
} from '../operators/index.js';

describe('operator capability diagnostics', () => {
  it('publishes the stable capability outcome vocabulary', () => {
    expect(CAPABILITY_OUTCOME_CODES).toEqual([
      'configuration_deferred',
      'tool_unavailable',
      'approval_required',
      'manual_step_required',
      'authorization_failed',
    ]);
  });

  it.each([
    'Sign up for a free trial.',
    'Create a new account when registration is available.',
    'Verify the email using the mailbox.',
    'Complete the CAPTCHA.',
  ])('classifies unsupported interactive signup without echoing text: %s', instructionText => {
    const diagnostics = diagnoseOperatorCapabilities(instructionText, ARCHETYPE_PROFILES.recon.defaultTools);
    expect(diagnostics).toEqual([expect.objectContaining({
      code: 'tool_unavailable',
      capability: 'interactive_signup',
      level: 'warning',
    })]);
    expect(JSON.stringify(diagnostics)).not.toContain(instructionText);
  });

  it('does not warn for ordinary recon instructions', () => {
    expect(diagnoseOperatorCapabilities(
      'Enumerate DNS records and inspect response headers.',
      ARCHETYPE_PROFILES.recon.defaultTools,
    )).toEqual([]);
  });

  it('returns diagnostics on the operator record without changing its callable tools', () => {
    setOperatorOverride('recon', { systemPrompt: 'Create a new account if registration is available.' });
    try {
      const recon = listOperatorPrompts().find(operator => operator.archetype === 'recon');
      expect(recon?.capabilityDiagnostics).toEqual([expect.objectContaining({ code: 'tool_unavailable' })]);
      expect(recon?.defaultTools).toEqual(ARCHETYPE_PROFILES.recon.defaultTools);
    } finally {
      resetOperatorOverride('recon');
    }
  });

  it('publishes diagnostics without copying edited text into the update event', () => {
    const serverSource = readFileSync(new URL('../server.ts', import.meta.url), 'utf8');
    const route = serverSource.slice(
      serverSource.indexOf("app.post('/api/operators/prompt'"),
      serverSource.indexOf("app.post('/api/operators/prompt/reset'"),
    );
    const event = route.slice(route.indexOf("broadcastEvent('operator:prompt_updated'"));

    expect(event).toContain('capabilityDiagnostics: updated?.capabilityDiagnostics || []');
    expect(event).not.toContain('systemPrompt,');
  });

  it('renders the effective tool list, boundary notice, and returned diagnostics in the editor', () => {
    const uiSource = readFileSync(new URL('../../docs/index.html', import.meta.url), 'utf8');
    expect(uiSource).toContain("Tools ('+(o.defaultTools||[]).length+')");
    expect(uiSource).toContain('(o.capabilityDiagnostics||[]).map');
    expect(uiSource).toContain('Instructions influence planning but do not add tools, expand target scope, or satisfy approval gates.');
  });
});
