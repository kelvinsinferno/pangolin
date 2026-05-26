// SPDX-License-Identifier: AGPL-3.0-or-later
import tsParser from '@typescript-eslint/parser';
import tsPlugin from '@typescript-eslint/eslint-plugin';

export default [
  {
    files: ['specs/**/*.ts', 'setup/**/*.ts', 'wdio.conf.ts'],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: 2022,
        sourceType: 'module',
      },
      globals: {
        // WebDriverIO injects these globals at spec runtime.
        $: 'readonly',
        $$: 'readonly',
        browser: 'readonly',
        // Mocha BDD globals.
        describe: 'readonly',
        it: 'readonly',
        before: 'readonly',
        after: 'readonly',
        beforeEach: 'readonly',
        afterEach: 'readonly',
        // DOM types referenced via type-only casts in the WDIO
        // executeAsync callbacks.
        window: 'readonly',
        Window: 'readonly',
        // Node globals.
        console: 'readonly',
        process: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
        require: 'readonly',
      },
    },
    plugins: {
      '@typescript-eslint': tsPlugin,
    },
    rules: {
      'no-unused-vars': 'off',
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      'no-console': 'off',
    },
  },
  {
    ignores: ['node_modules/**', 'wdio-logs/**'],
  },
];
