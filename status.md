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

- [ ] **P1** Enable GitHub Actions on fork (UI-only button on Actions tab — user action), then decide PR `kimi-local-agent` → `main` to fire CI
- [ ] **P2** Restore/hollow CTF challenges: sqli-blind, xss-stored, ssrf-metadata, format-string, rsa-weak, memory-dump (no build context in repo)
- [ ] **P2** Optional arsenal: nuclei, semgrep, promptfoo (doctor warnings)
- [ ] **P2** Decide whether to upstream the sqli-basic Dockerfile + healthcheck fix to elder-plinius

## Known issues

- GitHub Actions: 0 registered workflows on fork until enabled in UI
- `.serena/` untracked (agent tooling state)

**Обновлено:** 2026-07-24
