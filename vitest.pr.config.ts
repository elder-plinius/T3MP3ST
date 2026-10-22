import { defineConfig } from 'vitest/config';

// Pull requests use changed-line coverage as a review signal. Release tags use
// vitest.config.ts, whose narrow 100% per-file contract remains unchanged.
export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    // Same rationale as vitest.config.ts: the 5s default was stricter than the
    // product budgets these tests police. Kept in step so a PR run and a release
    // run cannot disagree about which tests are allowed to finish.
    testTimeout: 30_000,
    hookTimeout: 30_000,
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.test.ts', 'src/**/__tests__/**', 'src/types/**'],
      reporter: ['json'],
      reportsDirectory: 'coverage-pr',
    },
  },
});
