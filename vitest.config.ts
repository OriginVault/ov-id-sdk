import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: [
      'src/__tests__/**/*.test.ts',
      'src/__tests__/**/*.test.js',
    ],
    exclude: ['dist/**'],
    setupFiles: ['src/__tests__/setup/vitest.setup.ts'],
    coverage: {
      reporter: ['text', 'lcov', 'html', 'json'],
      reportsDirectory: 'coverage',
    },
    testTimeout: 30000,
    hookTimeout: 30000,
  },
  esbuild: {
    target: 'node22',
  },
});













