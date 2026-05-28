// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Display helpers for the popup account-list view. Extracted so the
// rendering logic can be tested without a full React tree.

import type { FfiAccountSummary } from "./native-host";

/**
 * Derive a single line of secondary text under the account display
 * name. Picks the first username, falling back to the first URL,
 * then to an empty string.
 */
export function accountSubtitle(a: FfiAccountSummary): string {
  if (a.usernames.length > 0 && a.usernames[0] !== undefined) {
    return a.usernames[0];
  }
  if (a.urls.length > 0 && a.urls[0] !== undefined) {
    return a.urls[0];
  }
  return "";
}

/** Sort accounts case-insensitively by display name (stable). */
export function sortAccounts(
  accounts: readonly FfiAccountSummary[],
): FfiAccountSummary[] {
  return [...accounts].sort((a, b) =>
    a.display_name.localeCompare(b.display_name, undefined, {
      sensitivity: "base",
    }),
  );
}
