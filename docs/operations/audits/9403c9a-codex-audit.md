# Codex audit — 9403c9a

- **Commit**: `9403c9a` fix(agent): close credential-channel and detection gaps from audit
- **Auditor**: codex-cli 0.144.6, `gpt-5.6-sol`, reasoning effort high, `-s read-only`
- **Date**: 2026-07-24 (re-audit; first audit 2026-07-23 lives as raw transcript on branch `audit-records`, verdict SHIP)

## Verbatim verdict

> [OK] Behavioral tests invoke real exported implementations, and the positive timeout override/default semantics are correct; typecheck passes.
> [P2] `childEnv` strips only four names, not the full `KIMI_MODEL_*` family; Kimi 0.29.0 consumes many additional overrides, and the test mirrors this incomplete whitelist.
> [P2] `authState` uses `existsSync`, so a directory named `credentials/kimi-code.json` falsely counts as the exact credential file; the test misses this case.
> [P2] `authState` trims `KIMI_CODE_HOME` while `childEnv` forwards it unchanged, allowing detection and the spawned CLI to resolve different roots.

## P2 disposition (deferred, local_status mode)

GitHub Issues disabled on fork → tracked in `status.md` known-issues with TODO
(per close-session P2 rule). Candidates for one hardening PR:

- F-1: extend `PROVIDER_ENV_TO_STRIP` to the full `KIMI_MODEL_*` override family consumed by kimi-code 0.29.0 (audit: current whitelist = 4 names).
- F-2: `authState` must require a regular file, not `existsSync` (directory named `kimi-code.json` false-positive) + test case.
- F-3: normalize `KIMI_CODE_HOME` identically in `authState` (trims) and `childEnv` (forwards raw) so detection and spawned CLI resolve the same root.
