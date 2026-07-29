# Getting Started With T3MP3ST

T3MP3ST is a local offensive-security command center for authorized testing. It gives an AI coding agent or LLM-backed operator a UI, API, evidence store, mission model, and tool arsenal. Use it only on systems you own or have explicit written permission to test.

## Requirements

- Node.js 22.19 or newer
- npm
- git, if you want to update from upstream or contribute
- Optional local model runtime: Ollama, LM Studio, vLLM, or another OpenAI-compatible local server
- Optional security tools for deeper arsenal coverage; see [Arsenal Activation Plan](ARSENAL_ACTIVATION_PLAN.md)

## Install

From a clone:

```bash
git clone https://github.com/elder-plinius/T3MP3ST.git
cd T3MP3ST
npm install
```

From an existing checkout:

```bash
npm install
```

## Configure A Model

You can run with a hosted provider key or a local model.

Interactive setup:

```bash
npm run setup
```

Hosted provider environment variables are supported:

```bash
export OPENROUTER_API_KEY=...
export VENICE_API_KEY=...
export ANTHROPIC_API_KEY=...
export OPENAI_API_KEY=...
export DEEPSEEK_API_KEY=...
export LITELLM_BASE_URL=http://localhost:4000/v1
export LITELLM_API_KEY=...        # only if your LiteLLM proxy requires one
```

Local/offline example with Ollama:

```bash
ollama serve
ollama pull llama3
export TEMPEST_LOCAL_BASE_URL=http://localhost:11434/api
export TEMPEST_LOCAL_MODEL=llama3
export TEMPEST_LOCAL_API_KEY=...  # only if your local server requires one
```

Check current configuration:

```bash
npx t3mp3st status
npx t3mp3st models
npx t3mp3st test
```

## Start The War Room

```bash
npm run server
```

Open:

```text
http://127.0.0.1:3333/ui/
```

The server binds to `127.0.0.1` by default. Do not expose it to a network unless you understand the command-execution and browser-origin risk. If you intentionally bind elsewhere with `T3MP3ST_HOST`, put it behind your own access control.

If you need outbound test traffic to use a SOCKS5 proxy, configure it with `TEMPEST_PROXY_URL` or through the War Room settings. The expected form is:

```bash
export TEMPEST_PROXY_URL=socks5://127.0.0.1:9050
```

## First Safe Run

Use a target you control, a local lab, or a CTF service.

1. Open the War Room.
2. Run the preflight view and confirm the API is healthy.
3. Sync or inspect arsenal status so missing tools are visible.
4. Define the target and rules of engagement before any active probing.
5. Start with a passive or local-safe plan.
6. Approve only the active or networked operations that are inside scope.
7. Save evidence before promoting a finding.
8. Retest before reporting.

If you are only evaluating the app, use the built-in safe checks:

```bash
npm run doctor
npm run field:drill
npm run arsenal:smoke
npm run prompt:audit
```

## CLI Basics

```bash
npx t3mp3st              # interactive mode
npx t3mp3st setup        # setup wizard
npx t3mp3st status       # config status
npx t3mp3st models       # available models for the selected provider
npx t3mp3st test         # test the selected LLM connection
```

The interactive CLI can start an operation, spawn operators, add targets, create missions, chat with the configured model, and generate a report from collected findings.

## Updating

Preview an update:

```bash
npm run update:dry
```

Interactive update from upstream:

```bash
npm run update
```

Hard reset to upstream is opt-in:

```bash
npm run update:hard
```

The updater protects local secrets and run artifacts listed in `scripts/update-protected.txt`.

## Common Problems

| Symptom | Check |
|---|---|
| UI does not load | Confirm `npm run server` is still running and open `http://127.0.0.1:3333/ui/` |
| LLM calls fail | Run `npx t3mp3st status` and `npx t3mp3st test`; check provider key or local model URL |
| Arsenal tools show missing | Install the relevant tools from [Arsenal Activation Plan](ARSENAL_ACTIVATION_PLAN.md) |
| Active tool call is refused | Confirm the target is authorized and inside the active scope receipt |
| Update wants to change local files | Run `npm run update:dry` first and inspect the plan |
