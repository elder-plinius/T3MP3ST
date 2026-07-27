# Fix: OpenAI-Compatible LLM Base URLs Set via Web UI Are Not Enforced

## Problem

OpenAI-compatible LLM providers configured through the web interface's **Universal API Config (UAC)** panel were completely ignored at runtime. Only terminal-set environment variables or the server's disk-based `Conf` store (`~/.config/t3mp3st/`) were used for LLM calls.

### Root Cause

Two independent configuration stores with no synchronization:

| Store | Location | Populated By | Consumed By |
|---|---|---|---|
| Browser `localStorage` | `localStorage` key `t3mp3st` | Web UI Settings panel | **Nothing** (was ignored) |
| Server `Conf` disk store | `~/.config/t3mp3st/` | `tempest setup` CLI, env vars | Server-side LLM calls |

Six specific disconnects were identified:

1. **`getApiKey()`** only checked `openrouterKey` — keys for openai, anthropic, and other providers entered via the UAC were never read.
2. **`resolveLLMBackend()`** only checked OpenRouter and Venice backends — the active provider (openai, anthropic, custom) was never detected for in-browser LLM calls (benchmarks, analysis).
3. **`_safeLLMCallOnce()`** used hardcoded endpoints — custom `baseUrl` values from the UAC were completely ignored.
4. **`startMissionFromDashboard()`** never passed `baseUrl` for cloud providers when dispatching missions to the server — only the `local` provider got a base URL override.
5. **`BackendDispatch.startMission()`** only included `baseUrl` in the API payload for the `local` provider.
6. **Server-side `resolveGeneralLLMConfig()`** explicitly blocked per-request `baseUrl` for all cloud providers with the comment: *"For any cloud provider it is ignored — never let a request redirect a cloud call."*

## Changes

### Browser-Side (`docs/index.html`)

| # | Function | Line | Change |
|---|---|---|---|
| 1 | `getApiKey()` | 11254 | Now checks `state.settings.activeProvider` and returns that provider's key before falling back to `openrouterKey` |
| 2 | `resolveLLMBackend()` | 11262 | Added detection for active provider (openai, anthropic, custom) with its key and custom `baseUrl` |
| 3 | `_safeLLMCallOnce()` | 11579 | Now resolves endpoints from `backend.baseUrl` when provided, with a map of known provider defaults as fallback |
| 4 | `startMissionFromDashboard()` | 19662 | Added `state.settings.activeProvider` check for provider detection; computes custom `cloudBaseUrl` from UAC settings |
| 5 | `BackendDispatch.startMission()` | 6561 | Added `cloudBaseUrl` parameter; passes `baseUrl` for all providers (not just local) |
| 6 | `getGeneralConfig()` | 17116 | Now includes custom `baseUrl` from UAC settings for cloud providers in the General/Admiral config |

### Server-Side (`src/server.ts`)

| # | Function | Line | Change |
|---|---|---|---|
| 7 | `resolveGeneralLLMConfig()` | 6835 | Extended per-request `baseUrl` sanitization to all OpenAI-compatible providers (openai, deepseek, xai, gemini, litellm, openrouter, venice, local); only per-request API key reaches a per-request URL |
| 8 | `createTempestCommandInstance()` | 348 | Per-request `baseUrl` now honored for all providers, not just `local` |

## Security Considerations

The previous code blocked per-request `baseUrl` for cloud providers to prevent request redirection attacks. Mitigations in the new code:

- **`sanitizeLocalBaseUrl()`** validates all base URLs — only `http://` and `https://` schemes are permitted; other protocols and malformed URLs throw.
- **Per-request API key requirement**: When a per-request `baseUrl` is provided, only the per-request `apiKey` is used — the server's configured secret is **never** forwarded to a client-chosen destination.
- **Loopback bind + origin guard**: The server binds to `127.0.0.1` only, so request bodies are only reachable from the local operator.

## Verification

```bash
# TypeScript compiles cleanly
npm run typecheck

# Build the project
npm run build

# Start the server
npm run server
```

Then in the web UI:
1. Open **Settings** → **Universal API Config**
2. Select a provider (e.g., `openai`), enter your API key and a custom base URL
3. Click **Save**
4. Your custom endpoint and key will now be used for all mission dispatch, General/Admiral planning, and in-browser LLM calls

## Affected Code Paths

- **Mission dispatch**: `startMissionFromDashboard()` → `BackendDispatch.startMission()` → `POST /api/mission/start` → `resolveGeneralLLMConfig()` → `createTempestCommandInstance()`
- **General/Admiral**: `getGeneralConfig()` → `POST /api/general/plan` / `POST /api/general/execute` → `resolveGeneralLLMConfig()`
- **In-browser benchmarks/analysis**: `resolveLLMBackend()` → `safeLLMCall()` → `_safeLLMCallOnce()`
