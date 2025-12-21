import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'edge-runtime',
    testTimeout: 60_000,
    hookTimeout: 120_000,
    globals: true,
    exclude: ['**/node_modules/**', '**/dist/**'],
  },
});
