import { defineConfig } from 'vitest/config';

// Pull requests use changed-line coverage as a review signal. Release tags use
// vitest.config.ts, whose narrow 100% per-file contract remains unchanged.
export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.test.ts', 'src/**/__tests__/**', 'src/types/**'],
      reporter: ['json'],
      reportsDirectory: 'coverage-pr',
    },
  },
});
