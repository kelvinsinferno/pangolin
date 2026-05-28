// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Typed helpers around chrome.storage.local for the handshake-token
// storage slot. Per plan-LOCK section 3.2 (Option 1, Q-a): on first
// popup open the user pastes the token printed by ; the popup stores it under
// chrome.storage.local extensionToken and uses it for every
// subsequent auth.handshake. On auth_failed the popup clears the
// stored value plus reverts to provisioning.
//
// L7 -- the API surface returns ONLY the token string or null. No
// error wraps the token value into a message.

const STORAGE_KEY = "extensionToken";

/**
 * Read the stored handshake token, returning null when nothing has
 * been provisioned yet.
 *
 * Errors from chrome.storage.local.get (which fire as
 * chrome.runtime.lastError) collapse to null -- the caller will
 * route to the provisioning flow, which is the correct fail-closed
 * behaviour.
 */
export async function loadToken(): Promise<string | null> {
  return new Promise<string | null>((resolve) => {
    try {
      chrome.storage.local.get([STORAGE_KEY], (items) => {
        const err = chrome.runtime.lastError;
        if (err !== undefined) {
          resolve(null);
          return;
        }
        const value = items[STORAGE_KEY];
        if (typeof value === "string" && value.length > 0) {
          resolve(value);
        } else {
          resolve(null);
        }
      });
    } catch {
      resolve(null);
    }
  });
}

/**
 * Persist the handshake token. Resolves true on success, false
 * if chrome.storage.local.set raised chrome.runtime.lastError.
 */
export async function saveToken(token: string): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    try {
      chrome.storage.local.set({ [STORAGE_KEY]: token }, () => {
        const err = chrome.runtime.lastError;
        resolve(err === undefined);
      });
    } catch {
      resolve(false);
    }
  });
}

/**
 * Remove the stored token. Used on auth_failed so the next popup
 * open shows the provisioning view.
 */
export async function clearToken(): Promise<void> {
  return new Promise<void>((resolve) => {
    try {
      chrome.storage.local.remove([STORAGE_KEY], () => {
        // Best-effort: surface no error to the caller. Worst case
        // the stored value lingers + the next handshake re-fails.
        resolve();
      });
    } catch {
      resolve();
    }
  });
}
