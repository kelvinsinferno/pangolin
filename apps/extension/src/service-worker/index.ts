// SPDX-License-Identifier: AGPL-3.0-or-later
//
// MV3 service worker — scaffold only. Registers lifecycle handlers and
// puts a placeholder structure in place for the future native-messaging
// bridge (MVP-4-E). No real connection happens here.
//
// MV3 service workers are NOT persistent — they idle out and restart.
// Any state added later MUST be re-derivable on cold start.

const NATIVE_HOST_NAME = 'com.pangolin.desktop';

chrome.runtime.onInstalled.addListener((details) => {
  console.log('Pangolin extension installed', details.reason);
});

chrome.runtime.onStartup.addListener(() => {
  console.log('Pangolin extension startup');
});

/**
 * Placeholder for the native-messaging bridge (MVP-4-E).
 *
 * In the real implementation this will:
 *   1. `chrome.runtime.connectNative(NATIVE_HOST_NAME)`
 *   2. Send framed JSON-RPC requests to the Rust native-messaging host.
 *   3. Re-derive any session state from the host on cold start.
 *
 * For MVP-4-C the function is unused on purpose — the manifest grants the
 * `nativeMessaging` permission so this slice can be smoke-tested end-to-end
 * once MVP-4-E lands.
 */
export function _connectNativeHost(): void {
  console.log('Native-messaging host (placeholder)', NATIVE_HOST_NAME);
}
