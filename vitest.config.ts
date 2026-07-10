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
