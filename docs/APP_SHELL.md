# Incremental Application Shell

The dashboard remains a rendered HTML application while its shell is migrated module by module. `docs/index.html` is the canonical rendered source served by `/ui/`; `docs/app-shell.js` is the single source for shared route activation, hash deep links, keyboard activation, route lifecycle callbacks, and server-readiness presentation. Do not copy either asset into a per-module page.

## Accepted first module

CVE Vault is the representative first migration. Its navigation entry carries `data-shell-module="true"`, its rendered page remains in `docs/index.html`, and its behavior remains in self-hosted external scripts. This preserves useful content and the API fallback when JavaScript is unavailable. `#/cve-vault` is the stable deep link.

The readiness label is updated only from the same-origin `/api/health` response. The external shell performs a bounded probe so the representative module remains truthful under a self-only script policy; the existing API client can publish subsequent health results. Browser-stored keys or guessed provider state do not make API or LLM readiness claims. Offline and standalone states are explicit.

## Reproducible migration recipe

1. Start from current `main`; migrate one module in one focused PR.
2. Keep one rendered `.page` in `docs/index.html` with a unique `page-<route>` id and a no-JavaScript/error fallback.
3. Add one `.nav-item[data-page="<route>"]`; mark the migrated entry with `data-shell-module="true"`.
4. Register the title and any idempotent lifecycle callback once in `docs/app-shell.js`.
5. Put module behavior and styles in self-hosted external assets. Do not add inline event handlers, `eval`, remote executable content, origin overrides, or browser secret/config endpoints.
6. Extend `src/__tests__/app-shell.test.ts` with route, deep-link, readiness, keyboard, CSP, and stable layout assertions.
7. Run `node --check docs/app-shell.js`, `npm run test:pr`, the changed-line coverage gate, and `npm run docs:check`.

The documentation build synchronizes Markdown into the Pagenary docsite. It does not generate or duplicate dashboard source. Remaining dashboard modules should migrate only after this pattern is accepted.
