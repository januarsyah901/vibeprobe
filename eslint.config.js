import tseslint from 'typescript-eslint';

// PRD F2: GuardedHttpClient is the only code allowed to touch the network.
const NETWORK_MODULES = ['undici', 'node:http', 'node:https', 'node:net', 'node:dgram', 'node:tls', 'http', 'https', 'net', 'tls', 'axios', 'got', 'node-fetch'];

export default tseslint.config(
  { ignores: ['**/dist/**', '**/node_modules/**', 'fixtures/**'] },
  ...tseslint.configs.recommended,
  {
    files: ['**/*.ts'],
    rules: {
      'no-restricted-globals': ['error', { name: 'fetch', message: 'Use GuardedHttpClient from @vibeprobe/core.' }, { name: 'XMLHttpRequest', message: 'Use GuardedHttpClient from @vibeprobe/core.' }, { name: 'WebSocket', message: 'Use GuardedHttpClient from @vibeprobe/core.' }],
      'no-restricted-imports': ['error', { paths: NETWORK_MODULES.map((name) => ({ name, message: 'Network access goes through GuardedHttpClient in @vibeprobe/core.' })) }],
    },
  },
  {
    // The guard itself, and its tests (which run a local server), may use network modules.
    files: ['packages/core/src/guarded-client.ts', 'packages/core/src/scope.ts', 'packages/core/test/**/*.ts'],
    rules: { 'no-restricted-globals': 'off', 'no-restricted-imports': 'off' },
  },
);
