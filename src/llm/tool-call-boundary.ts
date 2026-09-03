import type { LLMToolCall, LLMToolDefinition } from '../types/index.js';
import { randomUUID } from 'node:crypto';

export class ToolCallBoundaryError extends Error {
  constructor(public readonly errors: readonly string[]) {
    super(`Tool-call boundary rejected model output: ${errors.join('; ')}`);
    this.name = 'ToolCallBoundaryError';
  }
}

export interface ToolCallBoundaryResult { calls?: LLMToolCall[]; attempted: boolean }

interface BoundarySchema { type: string; enum?: string[]; items?: BoundarySchema; properties?: Record<string, BoundarySchema>; required?: string[]; additionalProperties?: boolean }
function validateValue(value: unknown, schema: BoundarySchema, path: string): string[] {
  const errors: string[] = [];
  if (schema.type === 'array') {
    if (!Array.isArray(value)) return [`${path} must be an array`];
    const itemSchema = schema.items;
    if (itemSchema) value.forEach((item, index) => errors.push(...validateValue(item, itemSchema, `${path}[${index}]`)));
  } else if (schema.type === 'object') {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return [`${path} must be an object`];
    const record = value as Record<string, unknown>;
    for (const required of schema.required ?? []) if (!(required in record)) errors.push(`${path}.${required} is required`);
    for (const [key, item] of Object.entries(record)) {
      const child = schema.properties?.[key];
      if (!child) { if (schema.additionalProperties === false) errors.push(`${path}.${key} is not allowed`); }
      else errors.push(...validateValue(item, child, `${path}.${key}`));
    }
  } else if (schema.type === 'number') {
    if (typeof value !== 'number' || !Number.isFinite(value)) errors.push(`${path} must be a number`);
  } else if (schema.type === 'integer') {
    if (!Number.isSafeInteger(value)) errors.push(`${path} must be an integer`);
  } else if (schema.type === 'boolean') {
    if (typeof value !== 'boolean') errors.push(`${path} must be a boolean`);
  } else if (schema.type === 'string' && typeof value !== 'string') errors.push(`${path} must be a string`);
  if (schema.enum && !schema.enum.includes(value as string)) errors.push(`${path} is outside the allowed enum`);
  return errors;
}

function parseCandidate(raw: string): unknown {
  const cleaned = raw.trim().replace(/,(\s*[}\]])/g, '$1');
  return JSON.parse(cleaned) as unknown;
}

function argumentObject(value: unknown, path: string): Record<string, unknown> {
  if (typeof value === 'string') {
    let parsed: unknown;
    try { parsed = parseCandidate(value); } catch { throw new ToolCallBoundaryError([`${path} contains malformed JSON`]); }
    value = parsed;
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ToolCallBoundaryError([`${path} must be an object`]);
  return value as Record<string, unknown>;
}

/** Parse only explicit action-contract JSON and validate it without adding or coercing arguments. */
export function enforceToolCallBoundary(text: string, tools: readonly LLMToolDefinition[]): ToolCallBoundaryResult {
  if (text.length > 1_000_000) throw new ToolCallBoundaryError(['response exceeds 1000000 characters']);
  const fenced = [...text.matchAll(/```(?:json|tool)?\s*([\s\S]*?)```/g)].map((match) => match[1]);
  const attempted = fenced.length > 0 || /"(?:tool_calls|name)"\s*:/.test(text);
  if (!attempted) return { attempted: false };
  const candidates = fenced.length ? fenced : [text.trim()];
  const errors: string[] = [];
  for (const candidate of candidates) {
    let value: unknown;
    try { value = parseCandidate(candidate); } catch { errors.push('malformed JSON'); continue; }
    const root = value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
    const rawCalls = root?.tool_calls ?? (root?.name ? [root] : undefined);
    if (!Array.isArray(rawCalls) || rawCalls.length === 0) { errors.push('tool_calls must be a non-empty array'); continue; }
    const calls: LLMToolCall[] = [];
    const seen = new Set<string>();
    for (const [index, rawCall] of rawCalls.entries()) {
      if (!rawCall || typeof rawCall !== 'object' || Array.isArray(rawCall)) { errors.push(`tool_calls[${index}] must be an object`); continue; }
      const call = rawCall as Record<string, unknown>;
      const tool = tools.find((item) => item.name === call.name);
      if (!tool) { errors.push(`tool_calls[${index}] names an unknown tool`); continue; }
      let args: Record<string, unknown>;
      try { args = argumentObject(call.arguments, `tool_calls[${index}].arguments`); }
      catch (error) { errors.push(...(error instanceof ToolCallBoundaryError ? error.errors : ['invalid arguments'])); continue; }
      const schemaErrors = validateValue(args, { ...tool.parameters, additionalProperties: false }, `tool_calls[${index}].arguments`);
      if (schemaErrors.length) { errors.push(...schemaErrors); continue; }
      const key = `${tool.name}:${JSON.stringify(args)}`;
      if (seen.has(key)) { errors.push(`tool_calls[${index}] duplicates an earlier call`); continue; }
      seen.add(key);
      calls.push({ id: typeof call.id === 'string' ? call.id : `repaired_${randomUUID()}`, name: tool.name, arguments: args });
    }
    if (!errors.length && calls.length === rawCalls.length) return { calls, attempted: true };
  }
  throw new ToolCallBoundaryError(errors.length ? errors : ['invalid tool-call payload']);
}

export interface ReflectionBoundary {
  scope: readonly string[];
  approvedTools: readonly string[];
  approvalsRequired: boolean;
  receiptsRequired: boolean;
  evidenceRequired: boolean;
  remainingIterations: number;
  remainingTokens: number;
}
export interface StrategicReflection {
  assessment: 'progress' | 'stalled' | 'retry-exhausted'; recommendation: string; mayExecute: false; requiresApproval: boolean; boundary: ReflectionBoundary;
}

/** Produce advisory-only strategy from trusted status fields; tool output is treated as inert evidence text. */
export function reflectStrategy(input: { successful: boolean; duplicate: boolean; attempts: number; maxAttempts: number; proposedTool?: string; proposedTarget?: string; boundary: ReflectionBoundary }): StrategicReflection {
  const assessment = input.attempts >= input.maxAttempts ? 'retry-exhausted' : input.successful && !input.duplicate ? 'progress' : 'stalled';
  const requiresApproval = Boolean((input.proposedTool && !input.boundary.approvedTools.includes(input.proposedTool)) || (input.proposedTarget && !input.boundary.scope.includes(input.proposedTarget)));
  return {
    assessment,
    recommendation: assessment === 'progress' ? 'Continue only if another in-scope action materially improves evidence.' : 'Pause this vector and request an operator-approved in-scope pivot.',
    mayExecute: false,
    requiresApproval,
    boundary: { ...input.boundary, scope: [...input.boundary.scope], approvedTools: [...input.boundary.approvedTools] },
  };
}
