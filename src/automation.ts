// =============================================================================
// AUTOMATION RULES ENGINE — event-driven trigger → action execution
// =============================================================================
// Rules bind an event pattern + optional condition to an action.
// evaluateEvent() is called from broadcastEvent() on every internal event.
//
// Supported action types:
//   log            — emit a message to the server log
//   fire-webhook   — re-fire the event to a specific registered webhook
//   dispatch-agent — send a prompt to a connected local agent
//   spawn-operator — spawn a new mission operator
// =============================================================================

import { randomUUID } from 'crypto';
import { fireWebhooks } from './webhooks.js';

export type AutomationActionType =
  | 'log'
  | 'fire-webhook'
  | 'dispatch-agent'
  | 'spawn-operator';

export interface AutomationAction {
  type: AutomationActionType;
  // log
  message?: string;
  // fire-webhook — re-routes the event payload to a specific webhook id
  webhookId?: string;
  // dispatch-agent
  agentId?: string;
  /** Prompt template: {{payload.fieldName}} interpolation supported. */
  promptTemplate?: string;
  // spawn-operator
  archetype?: string;
  model?: string;
}

export interface AutomationTrigger {
  /** Event name pattern — '*' matches all; 'finding.*' matches any finding event. */
  event: string;
  /**
   * Optional simple condition. Evaluated against the event payload.
   * Supported forms:
   *   payload.<key> === '<value>'
   *   payload.<key> !== '<value>'
   */
  condition?: string;
}

export interface AutomationRule {
  id: string;
  name: string;
  enabled: boolean;
  trigger: AutomationTrigger;
  action: AutomationAction;
  createdAt: number;
  lastTriggeredAt?: number;
  triggerCount: number;
}

export interface AutomationContext {
  broadcast: (event: string, data: Record<string, unknown>) => void;
  dispatchAgent?: (agentId: string, prompt: string) => Promise<unknown>;
  spawnOperator?: (archetype: string, model?: string) => Promise<unknown>;
}

const _rules = new Map<string, AutomationRule>();

// =============================================================================
// RULE MANAGEMENT
// =============================================================================

export function addRule(
  rule: Omit<AutomationRule, 'id' | 'createdAt' | 'triggerCount'>,
): AutomationRule {
  const full: AutomationRule = {
    ...rule,
    id: randomUUID(),
    createdAt: Date.now(),
    triggerCount: 0,
  };
  _rules.set(full.id, full);
  return full;
}

export function updateRule(
  id: string,
  patch: Partial<Pick<AutomationRule, 'name' | 'enabled' | 'trigger' | 'action'>>,
): AutomationRule | null {
  const rule = _rules.get(id);
  if (!rule) return null;
  Object.assign(rule, patch);
  return rule;
}

export function removeRule(id: string): boolean {
  return _rules.delete(id);
}

export function listRules(): AutomationRule[] {
  return Array.from(_rules.values()).sort((a, b) => a.createdAt - b.createdAt);
}

// =============================================================================
// EVENT EVALUATION
// =============================================================================

function _eventMatches(pattern: string, event: string): boolean {
  if (pattern === '*') return true;
  if (pattern.endsWith('*')) return event.startsWith(pattern.slice(0, -1));
  return pattern === event;
}

function _evaluateCondition(
  condition: string,
  payload: Record<string, unknown>,
): boolean {
  const eqMatch = condition.match(/^payload\.(\w+)\s*===\s*['"](.*)['"]$/);
  if (eqMatch) return String(payload[eqMatch[1]]) === eqMatch[2];
  const neqMatch = condition.match(/^payload\.(\w+)\s*!==\s*['"](.*)['"]$/);
  if (neqMatch) return String(payload[neqMatch[1]]) !== neqMatch[2];
  // Unknown condition syntax → treated as false (fail-safe)
  return false;
}

function _interpolate(template: string, payload: Record<string, unknown>): string {
  return template.replace(
    /\{\{payload\.(\w+)\}\}/g,
    (_: string, key: string) => String(payload[key] ?? ''),
  );
}

/**
 * Evaluate all enabled rules against an event. Called on every broadcastEvent().
 * Errors per-rule are swallowed so one broken rule doesn't halt others.
 */
export async function evaluateEvent(
  event: string,
  payload: Record<string, unknown>,
  ctx: AutomationContext,
): Promise<void> {
  for (const rule of _rules.values()) {
    if (!rule.enabled) continue;
    if (!_eventMatches(rule.trigger.event, event)) continue;
    if (
      rule.trigger.condition &&
      !_evaluateCondition(rule.trigger.condition, payload)
    )
      continue;

    rule.triggerCount++;
    rule.lastTriggeredAt = Date.now();

    try {
      await _executeAction(rule, event, payload, ctx);
    } catch (err) {
      console.warn(
        `[automation] rule "${rule.name}" (${rule.id}) action failed: ${(err as Error).message}`,
      );
      ctx.broadcast('automation.error', {
        ruleId: rule.id,
        ruleName: rule.name,
        error: (err as Error).message,
      });
    }
  }
}

async function _executeAction(
  rule: AutomationRule,
  event: string,
  payload: Record<string, unknown>,
  ctx: AutomationContext,
): Promise<void> {
  const { action } = rule;

  switch (action.type) {
    case 'log':
      console.log(`[automation] "${rule.name}": ${action.message ?? '(triggered)'}`);
      ctx.broadcast('automation.triggered', {
        ruleId: rule.id,
        ruleName: rule.name,
        event,
        actionType: action.type,
      });
      break;

    case 'fire-webhook':
      await fireWebhooks(event, payload);
      ctx.broadcast('automation.triggered', {
        ruleId: rule.id,
        ruleName: rule.name,
        event,
        actionType: action.type,
        webhookId: action.webhookId,
      });
      break;

    case 'dispatch-agent':
      if (!action.agentId || !action.promptTemplate) {
        throw new Error('dispatch-agent requires agentId and promptTemplate');
      }
      if (!ctx.dispatchAgent) {
        throw new Error('no dispatchAgent handler registered');
      }
      await ctx.dispatchAgent(
        action.agentId,
        _interpolate(action.promptTemplate, payload),
      );
      ctx.broadcast('automation.triggered', {
        ruleId: rule.id,
        ruleName: rule.name,
        event,
        actionType: action.type,
        agentId: action.agentId,
      });
      break;

    case 'spawn-operator':
      if (!action.archetype) {
        throw new Error('spawn-operator requires archetype');
      }
      if (!ctx.spawnOperator) {
        throw new Error('no spawnOperator handler registered');
      }
      await ctx.spawnOperator(action.archetype, action.model);
      ctx.broadcast('automation.triggered', {
        ruleId: rule.id,
        ruleName: rule.name,
        event,
        actionType: action.type,
        archetype: action.archetype,
      });
      break;
  }
}
