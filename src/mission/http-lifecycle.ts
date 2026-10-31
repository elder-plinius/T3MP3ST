import type { MissionControl } from './index.js';

interface MissionBackendSelection {
  provider?: string;
  model?: string;
  apiKey?: string;
  baseUrl?: string;
}

/** Fixed diagnostic for a failed LLM backend resolution. Exported so the HTTP
 *  route and resolveMissionLaunchConfig cannot drift into two different strings.
 *  A provider error can carry credentials or internal configuration, so the raw
 *  message must never reach the client. */
export const LLM_BACKEND_UNCONFIGURED =
  'LLM backend not configured — configure a provider or connect a supported local agent';

/** Resolve before creating a command; configuration failures must produce an HTTP response. */
export function resolveMissionLaunchConfig<T>(
  selection: MissionBackendSelection,
  resolve: (provider?: string, model?: string, apiKey?: string, baseUrl?: string) => T,
): { ok: true; config: T } | { ok: false; error: string } {
  try {
    const { provider, model, apiKey, baseUrl } = selection;
    const config = baseUrl === undefined
      ? resolve(provider, model, apiKey)
      : resolve(provider, model, apiKey, baseUrl);
    return { ok: true, config };
  } catch {
    // Provider errors can contain credentials or internal configuration; expose a fixed diagnostic.
    return { ok: false, error: LLM_BACKEND_UNCONFIGURED };
  }
}

/** Completed missions lose active identity. Never substitute unrelated history for a requested run. */
export function resolveMissionStatus(
  missions: Pick<MissionControl, 'getMission' | 'getActiveMission'>,
  requestedId: unknown,
) {
  return typeof requestedId === 'string'
    ? missions.getMission(requestedId)
    : missions.getActiveMission();
}
