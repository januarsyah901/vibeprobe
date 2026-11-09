import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/bin.ts'],
  format: ['esm'],
  target: 'node22',
  platform: 'node',
  clean: true,
  // core and checks are private: bundle it into the published CLI.
  noExternal: ['@vibeprobe/core', '@vibeprobe/checks'],
  banner: { js: '#!/usr/bin/env node' },
});
