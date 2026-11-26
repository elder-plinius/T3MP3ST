/**
 * Verbatim quote check for tool evidence attached to one finding.
 * Provenance stays in gateLiveFinding. This only answers whether the quote
 * occurs inside that finding's tool-typed evidence.
 */

import type { Evidence } from '../types/index.js';

const TOOL_EVIDENCE = new Set(['output', 'command', 'response', 'request', 'log', 'file']);
const MIN_QUOTE_LENGTH = 8;

export interface QuoteGateResult {
  passed: boolean;
  reasons: string[];
}

export function quoteMatches(evidence: readonly Evidence[] | undefined, quote: string | undefined): QuoteGateResult {
  const text = String(quote ?? '');
  if (text.length === 0) {
    return { passed: false, reasons: ['missing verbatim quote'] };
  }
  if (text.length < MIN_QUOTE_LENGTH) {
    return { passed: false, reasons: [`quote shorter than ${MIN_QUOTE_LENGTH} characters`] };
  }
  const items = Array.isArray(evidence) ? evidence : [];
  const hit = items.some((item) => TOOL_EVIDENCE.has(item?.type) && String(item.content ?? '').includes(text));
  if (!hit) {
    return { passed: false, reasons: ['quote is not a verbatim substring of this finding\'s tool evidence'] };
  }
  return { passed: true, reasons: [] };
}
