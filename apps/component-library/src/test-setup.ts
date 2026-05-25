// SPDX-License-Identifier: AGPL-3.0-or-later
// Vitest setup file: extends `expect` with @testing-library/jest-dom's
// DOM matchers (toBeInTheDocument, toHaveAttribute, etc.) and wires up
// global cleanup so each test starts with a fresh DOM.
import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach } from 'vitest';

afterEach(() => {
  cleanup();
});
