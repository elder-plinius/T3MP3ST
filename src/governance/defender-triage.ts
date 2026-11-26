/**
 * Defender checklist. Scope and reproducibility are computed.
 * Impact acceptance stays a human assertion. This module does not run tools.
 */

import type { Evidence } from '../types/index.js';
import { isTargetInAuthorizedScope } from './scope-match.js';
import { quoteMatches } from '../evidence/quote-gate.js';

const TOOL_EVIDENCE = new Set(['output', 'command', 'response', 'request', 'log', 'file']);
const PII_MARKERS = ['cookie:', 'authorization:', 'bearer ', '-----begin'];

export interface TriageQuestion {
  id: 'scope' | 'impact' | 'reproducible' | 'evidence' | 'pii';
  passed: boolean;
}

export interface TriageResult {
  passed: boolean;
  questions: TriageQuestion[];
}

export interface TriageInput {
  evidence: readonly Evidence[];
  quote: string;
  scope: readonly string[];
  targetName: string;
  impactAccepted: boolean;
}

function toolItems(evidence: readonly Evidence[]): Evidence[] {
  return evidence.filter((item) => TOOL_EVIDENCE.has(item?.type) && String(item.content ?? '').trim().length > 0);
}

export function defenderTriage(input: TriageInput): TriageResult {
  const tools = toolItems(input.evidence);
  const quote = quoteMatches(input.evidence, input.quote);
  const piiHit = tools.some((item) => {
    const haystack = String(item.content).toLowerCase();
    return PII_MARKERS.some((marker) => haystack.includes(marker));
  });
  const questions: TriageQuestion[] = [
    { id: 'scope', passed: isTargetInAuthorizedScope(input.targetName, input.scope) },
    { id: 'impact', passed: input.impactAccepted },
    { id: 'reproducible', passed: quote.passed },
    { id: 'evidence', passed: tools.length > 0 },
    { id: 'pii', passed: !piiHit },
  ];
  return { passed: questions.every((question) => question.passed), questions };
}
