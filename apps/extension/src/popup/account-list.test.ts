// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";

import type { FfiAccountSummary } from "./native-host";
import { accountSubtitle, sortAccounts } from "./account-list";

function makeAccount(p: Partial<FfiAccountSummary>): FfiAccountSummary {
  return {
    id: "0".repeat(64),
    display_name: "Account",
    tags: [],
    usernames: [],
    urls: [],
    password_history_count: 0,
    has_totp: false,
    current_password_changed_at: 0,
    ...p,
  };
}

describe("accountSubtitle", () => {
  it("returns the first username when present", () => {
    const a = makeAccount({ usernames: ["alice"], urls: ["x.com"] });
    expect(accountSubtitle(a)).toBe("alice");
  });
  it("falls back to the first URL when no usernames", () => {
    const a = makeAccount({ urls: ["x.com"] });
    expect(accountSubtitle(a)).toBe("x.com");
  });
  it("returns empty string when nothing is available", () => {
    const a = makeAccount({});
    expect(accountSubtitle(a)).toBe("");
  });
});

describe("sortAccounts", () => {
  it("sorts case-insensitively by display name", () => {
    const items = [
      makeAccount({ display_name: "twitter" }),
      makeAccount({ display_name: "GitHub" }),
      makeAccount({ display_name: "gmail" }),
    ];
    const sorted = sortAccounts(items);
    expect(sorted.map((a) => a.display_name)).toEqual([
      "GitHub",
      "gmail",
      "twitter",
    ]);
  });
});
