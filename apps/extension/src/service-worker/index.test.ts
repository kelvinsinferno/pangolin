// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi, beforeAll } from 'vitest';

interface RuntimeListenerHook {
  addListener: ReturnType<typeof vi.fn>;
}
interface ChromeStub {
  runtime: {
    onInstalled: RuntimeListenerHook;
    onStartup: RuntimeListenerHook;
    connectNative: ReturnType<typeof vi.fn>;
  };
}

const chromeStub: ChromeStub = {
  runtime: {
    onInstalled: { addListener: vi.fn() },
    onStartup: { addListener: vi.fn() },
    connectNative: vi.fn(),
  },
};

beforeAll(() => {
  // Install the chrome global before the SW module imports + executes its
  // top-level registration calls.
  (globalThis as unknown as { chrome: ChromeStub }).chrome = chromeStub;
});

describe('service-worker', () => {
  it('registers chrome.runtime.onInstalled + onStartup listeners on import', async () => {
    // Dynamic import so the chrome stub is in place before module
    // top-level code runs.
    await import('./index');
    expect(chromeStub.runtime.onInstalled.addListener).toHaveBeenCalledTimes(1);
    expect(chromeStub.runtime.onStartup.addListener).toHaveBeenCalledTimes(1);
  });
});
