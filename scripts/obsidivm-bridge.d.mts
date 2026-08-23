// Types for the OBSIDIVM bridge client (consumed by the vitest test).
// Runnable logic lives in the sibling .mjs (scripts run under bare `node`, no build step).

/** A network-level failure (connection refused / DNS / timeout) carries this flag,
 * distinguishing an unreachable service from an HTTP-status error (which sets `status`). */
export interface ObsidivmError extends Error {
  unreachable?: boolean;
  status?: number;
  body?: unknown;
}

export interface ObsidivmClient {
  readonly baseUrl: string;
  health(): Promise<unknown>;
  getSpec(): Promise<{ version?: string; targets?: Array<{ id: string; name?: string; port?: number }> } & Record<string, unknown>>;
  status(): Promise<unknown>;
  deploy(): Promise<unknown>;
  destroy(): Promise<unknown>;
  startTarget(id: string): Promise<unknown>;
  stopTarget(id: string): Promise<unknown>;
  scoreText(targetId: string, text: string): Promise<Record<string, unknown>>;
  createRun(payload?: Record<string, unknown>): Promise<Record<string, unknown>>;
  attachSession(runId: string, payload?: Record<string, unknown>): Promise<unknown>;
  proposeGoalposts(payload?: Record<string, unknown>): Promise<unknown>;
  evolveStart(payload?: Record<string, unknown>): Promise<unknown>;
  evolveStop(): Promise<unknown>;
  cloudgoatInstall(): Promise<unknown>;
  cloudgoatCreate(scenario: string): Promise<unknown>;
  cloudgoatDestroy(scenario: string): Promise<unknown>;
  cloudgoatDestroyAll(): Promise<unknown>;
}

export function obsidivm(opts?: { baseUrl?: string; timeoutMs?: number }): ObsidivmClient;
