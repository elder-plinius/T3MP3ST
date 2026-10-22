import { defineConfig } from 'vitest/config';

// Coverage-only configuration. Test discovery, environment, and everything else
// stay on Vitest defaults — this file exists solely to enforce the multi-language
// ingest quality gate: 100% coverage (statements/branches/functions/lines) on the
// three fully-new source files this feature adds.
//
// Edited files (code-ingest.ts, whitebox.ts, server.ts) are NOT in `include`: a
// whole-file 100% threshold is unachievable on large pre-existing files, and the
// gate for them is "new branches covered", verified by the multilang/regression
// suites rather than a file-level threshold. The single server.ts bootstrap line
// (`await initGrammars()`) is the documented carve-out — smoke-covered, and
// initGrammars itself is unit-tested to 100% in ts-grammars.test.ts.
export default defineConfig({
  test: {
    // Keep generated JavaScript under dist/ out of discovery after `npm run build`.
    include: ['src/**/*.test.ts'],
    // Vitest's 5s default was STRICTER than the product budgets these tests
    // exist to police, so the harness could kill a test the product would have
    // passed. ts-parse-adversarial asserts the real 20k-function parse finishes
    // in under 10s, but the 5s default cut it off first — that assertion was
    // unreachable on a loaded box. The same clock cut ts-grammars (which loads
    // every tree-sitter grammar) and any test importing the platform or
    // spawning a child process. 30s sits above every internal budget so the
    // internal budget is what governs; nothing here relaxes an assertion.
    // Tests needing more than that carry their own per-test timeout, which
    // overrides this.
    testTimeout: 30_000,
    hookTimeout: 30_000,
    coverage: {
      provider: 'v8',
      include: [
        'src/recon/ts-grammars.ts',
        'src/recon/param-split.ts',
        'src/recon/ts-parse.ts',
      ],
      thresholds: {
        perFile: true,
        statements: 100,
        branches: 100,
        functions: 100,
        lines: 100,
      },
    },
  },
});
