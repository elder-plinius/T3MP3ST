# T3MP3ST — status

<!-- Source of truth for tasks: this file (local_status mode — GitHub Issues disabled on fork). -->

**Branch:** `kimi-local-agent` @ `7182a53` (tracks `fork/kimi-local-agent`, pushed)
**Backbone:** Kimi K3 Max — `local-agent` provider, model `kimi` (`kimi-code/k3`, effort `max`)

## Done (2026-07-24)

- [x] Install validated vs GitHub; doctor green; kimi static test 8/8
- [x] Kimi K3 Max e2e: CLI login, config `k3`+`max`, server connect, mission on kimi proven by process ancestry
- [x] Server lifecycle + restart→reconnect procedure verified
- [x] Mission-start contract: explicit provider/model in body; approval receipt gate
- [x] Bounded authorized mission on CTF lab (sqli-basic, 196 ticks) — stopped by design
- [x] `7182a53` CTF sqli-basic build + healthcheck fix → pushed to fork (Codex-audited OK)
- [x] docker-compose 5.3.1 installed (brew) + cli-plugins symlink

## Backlog

- [x] **P1** GitHub Actions enabled on fork (user, 2026-07-24); PR [#1](https://github.com/LexorCrypto/T3MP3ST/pull/1) `kimi-local-agent` → `main` opened — **CI success** (run 30062926657, 59s)
- [ ] **P2** Restore/hollow CTF challenges: sqli-blind, xss-stored, ssrf-metadata, format-string, rsa-weak, memory-dump (no build context in repo)
- [ ] **P2** Optional arsenal: nuclei, semgrep, promptfoo (doctor warnings)
- [x] **P2** Upstream fix proposed: PR [elder-plinius#116](https://github.com/elder-plinius/T3MP3ST/pull/116) (`ctf-sqli-basic-fix`, contribution receipt included)

## Known issues

- `local-agent-path-resolution.test.ts` fails on this Mac (CLI in `~/.local/bin`); passes in CI — environment-specific, pre-existing on upstream `main`
- **P2 deferred (Codex audit 2026-07-24, kimi adapter hardening, candidate single PR):**
  - TODO F-1: extend `PROVIDER_ENV_TO_STRIP` to full `KIMI_MODEL_*` override family (current whitelist = 4 names)
  - TODO F-2: `authState` must require regular file, not `existsSync` (directory named `kimi-code.json` false-positive) + test
  - TODO F-3: normalize `KIMI_CODE_HOME` identically in `authState` (trims) and `childEnv` (forwards raw)
- `.serena/` untracked (agent tooling state)

**Обновлено:** 2026-07-24
