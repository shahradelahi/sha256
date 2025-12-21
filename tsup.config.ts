import { defineConfig } from 'tsup';

export default defineConfig([
  {
    clean: true,
    splitting: true,
    entry: ['src/index.ts', 'src/node.ts'],
    format: ['cjs', 'esm'],
    target: 'esnext',
    outDir: 'dist',
  },
]);
