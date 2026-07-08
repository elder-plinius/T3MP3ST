// =============================================================================
// AGENT SESSION STORE — persistent multi-turn conversation history
// =============================================================================
// Keeps message history per sessionId so local agents can hold multi-turn
// conversations across multiple /api/agents/local/dispatch calls.
// =============================================================================

import { randomUUID } from 'crypto';

export interface SessionMessage {
  role: 'user' | 'assistant';
  content: string;
  timestamp: number;
}

export interface AgentSession {
  id: string;
  agentId: string;
  messages: SessionMessage[];
  createdAt: number;
  updatedAt: number;
}

const _sessions = new Map<string, AgentSession>();

export function newSessionId(): string {
  return randomUUID();
}

export function getOrCreateSession(sessionId: string, agentId: string): AgentSession {
  let session = _sessions.get(sessionId);
  if (!session) {
    session = {
      id: sessionId,
      agentId,
      messages: [],
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };
    _sessions.set(sessionId, session);
  }
  return session;
}

export function appendToSession(
  sessionId: string,
  role: 'user' | 'assistant',
  content: string,
): void {
  const session = _sessions.get(sessionId);
  if (!session) return;
  session.messages.push({ role, content, timestamp: Date.now() });
  session.updatedAt = Date.now();
}

export function getSession(sessionId: string): AgentSession | undefined {
  return _sessions.get(sessionId);
}

export function listSessions(): AgentSession[] {
  return Array.from(_sessions.values()).sort((a, b) => b.updatedAt - a.updatedAt);
}

export function deleteSession(sessionId: string): boolean {
  return _sessions.delete(sessionId);
}

/**
 * Formats prior turns as a context prefix injected before the current prompt.
 * Returns '' for empty sessions so single-turn usage is unaffected.
 */
export function buildContextPrefix(session: AgentSession): string {
  if (session.messages.length === 0) return '';
  const lines = session.messages.map(
    (m) => `[${m.role.toUpperCase()}]: ${m.content}`,
  );
  return `Prior conversation history:\n${lines.join('\n')}\n\n---\nCurrent turn:\n`;
}
