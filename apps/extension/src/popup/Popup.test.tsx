// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

import { Popup } from "./Popup";

interface ChromeStorageStub {
  data: Record<string, unknown>;
  get: (
    keys: string[],
    cb: (items: Record<string, unknown>) => void,
  ) => void;
  set: (items: Record<string, unknown>, cb: () => void) => void;
  remove: (keys: string[], cb: () => void) => void;
}

function installChromeStub(seed: Record<string, unknown> = {}): ChromeStorageStub {
  const store: ChromeStorageStub = {
    data: { ...seed },
    get(keys, cb) {
      const out: Record<string, unknown> = {};
      for (const k of keys) {
        if (k in this.data) out[k] = this.data[k];
      }
      cb(out);
    },
    set(items, cb) {
      Object.assign(this.data, items);
      cb();
    },
    remove(keys, cb) {
      for (const k of keys) delete this.data[k];
      cb();
    },
  };
  (globalThis as unknown as { chrome: unknown }).chrome = {
    storage: { local: store },
    runtime: {
      lastError: undefined,
      connectNative: () => {
        throw new Error("connectNative not stubbed for this test");
      },
    },
  };
  return store;
}

describe("Popup state machine", () => {
  let errorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    cleanup();
    errorSpy.mockRestore();
    delete (globalThis as unknown as { chrome?: unknown }).chrome;
  });

  it("shows the provisioning view with empty storage", async () => {
    installChromeStub({});
    render(<Popup />);
    const view = await screen.findByTestId("view-provisioning");
    expect(view).toBeInTheDocument();
    expect(screen.getByTestId("token-input")).toBeInTheDocument();
  });

  it("Save button is disabled when the input is empty", async () => {
    installChromeStub({});
    render(<Popup />);
    await screen.findByTestId("view-provisioning");
    const wrap = screen.getByTestId("save-button-wrap");
    const btn = wrap.querySelector("button");
    expect(btn).not.toBeNull();
    expect(btn!.disabled).toBe(true);
  });

  it("typing a token enables Save", async () => {
    installChromeStub({});
    render(<Popup />);
    await screen.findByTestId("view-provisioning");
    const input = screen.getByTestId("token-input") as HTMLTextAreaElement;
    fireEvent.change(input, { target: { value: "tok-123" } });
    const wrap = screen.getByTestId("save-button-wrap");
    const btn = wrap.querySelector("button")!;
    expect(btn.disabled).toBe(false);
  });

  it("renders without console.error in provisioning view", async () => {
    installChromeStub({});
    render(<Popup />);
    await screen.findByTestId("view-provisioning");
    expect(errorSpy).not.toHaveBeenCalled();
  });

  it("does not stay on provisioning when a token is already stored", async () => {
    installChromeStub({ extensionToken: "stored-tok" });
    render(<Popup />);
    await waitFor(
      () => {
        expect(screen.queryByTestId("view-loading")).not.toBeInTheDocument();
      },
      { timeout: 2000 },
    );
    // Because connectNative throws in this stub, the popup ends up
    // on the error view. The proof that the stored-token path was
    // taken is the absence of the provisioning view.
    const provisioning = screen.queryByTestId("view-provisioning");
    expect(provisioning).toBeNull();
  });
});
