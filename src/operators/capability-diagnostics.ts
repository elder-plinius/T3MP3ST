export const CAPABILITY_OUTCOME_CODES = [
  'configuration_deferred',
  'tool_unavailable',
  'approval_required',
  'manual_step_required',
  'authorization_failed',
] as const;

export type CapabilityOutcomeCode = typeof CAPABILITY_OUTCOME_CODES[number];

export interface OperatorCapabilityDiagnostic {
  code: CapabilityOutcomeCode;
  capability: 'interactive_signup';
  level: 'warning';
  message: string;
}

const INTERACTIVE_SIGNUP_SIGNALS = [
  /\b(?:sign[ -]?up|register|registration)\b/i,
  /\bcreate\s+(?:a\s+|an\s+)?(?:new\s+)?(?:user\s+)?account\b/i,
  /\b(?:verify|verification)\s+(?:an?\s+)?(?:e-?mail|mailbox)\b/i,
  /\b(?:captcha|mailbox)\b/i,
] as const;

// Reserved for a future, reviewed adapter. Keeping this explicit prevents a
// text edit from being mistaken for a grant of executable authority.
const INTERACTIVE_SIGNUP_TOOLS = new Set<string>();

export function diagnoseOperatorCapabilities(
  instructionText: string,
  effectiveTools: readonly string[],
): OperatorCapabilityDiagnostic[] {
  const requestsInteractiveSignup = INTERACTIVE_SIGNUP_SIGNALS.some(pattern => pattern.test(instructionText));
  const canPerformInteractiveSignup = effectiveTools.some(tool => INTERACTIVE_SIGNUP_TOOLS.has(tool));
  if (!requestsInteractiveSignup || canPerformInteractiveSignup) return [];

  return [{
    code: 'tool_unavailable',
    capability: 'interactive_signup',
    level: 'warning',
    message: 'Interactive signup is not callable by this operative. Use an authorized existing session or complete the step manually.',
  }];
}
