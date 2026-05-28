// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";

import { NativeHostClient, NativeHostError } from "./native-host";

interface FakePort {
  messages: unknown[];
  listeners: ((msg: unknown) => void)[];
  disconnectListeners: (() => void)[];
  postMessage: (msg: unknown) => void;
  disconnect: () => void;
  onMessage: { addListener: (cb: (msg: unknown) => void) => void };
  onDisconnect: { addListener: (cb: () => void) => void };
  fireMessage: (msg: unknown) => void;
  fireDisconnect: () => void;
}

function makeFakePort(): FakePort {
  const p: FakePort = {
    messages: [],
    listeners: [],
    disconnectListeners: [],
    postMessage(msg) {
      this.messages.push(msg);
    },
    disconnect() {
      this.fireDisconnect();
    },
    onMessage: {
      addListener: (cb) => p.listeners.push(cb),
    },
    onDisconnect: {
      addListener: (cb) => p.disconnectListeners.push(cb),
    },
    fireMessage(msg) {
      for (const l of this.listeners) l(msg);
    },
    fireDisconnect() {
      for (const l of this.disconnectListeners) l();
    },
  };
  return p;
}

describe("NativeHostClient", () => {
  it("connect sends auth.handshake and resolves on a matching result", async () => {
    const port = makeFakePort();
    const client = new NativeHostClient(() => port, "test.host");
    const p = client.connect("tok");
    // After construction, one frame should be queued.
    expect(port.messages.length).toBe(1);
    const sent = port.messages[0] as { id: number; method: string; params: { token: string } };
    expect(sent.method).toBe("auth.handshake");
    expect(sent.params.token).toBe("tok");
    // Reply.
    port.fireMessage({
      jsonrpc: "2.0",
      id: sent.id,
      result: { host_version: "0.0.0", protocol_version: 1 },
    });
    await p;
    expect(client.isDisconnected()).toBe(false);
  });

  it("connect rejects with auth_failed when the server returns an error", async () => {
    const port = makeFakePort();
    const client = new NativeHostClient(() => port, "test.host");
    const p = client.connect("tok");
    const sent = port.messages[0] as { id: number };
    port.fireMessage({
      jsonrpc: "2.0",
      id: sent.id,
      error: { code: -32001, message: "auth_failed", data: null },
    });
    await expect(p).rejects.toBeInstanceOf(NativeHostError);
    try {
      await p;
    } catch (e) {
      expect((e as NativeHostError).label).toBe("auth_failed");
      expect((e as NativeHostError).code).toBe(-32001);
    }
  });

  it("sessionStatus returns the booleans after a successful response", async () => {
    const port = makeFakePort();
    const client = new NativeHostClient(() => port, "test.host");
    const cp = client.connect("tok");
    port.fireMessage({ jsonrpc: "2.0", id: 1, result: {} });
    await cp;
    const sp = client.sessionStatus();
    expect(port.messages.length).toBe(2);
    const sent = port.messages[1] as { id: number; method: string };
    expect(sent.method).toBe("session.status");
    port.fireMessage({
      jsonrpc: "2.0",
      id: sent.id,
      result: { vault_open: true, vault_unlocked: true },
    });
    const s = await sp;
    expect(s.vault_open).toBe(true);
    expect(s.vault_unlocked).toBe(true);
  });

  it("listAccounts returns the array after a successful response", async () => {
    const port = makeFakePort();
    const client = new NativeHostClient(() => port, "test.host");
    const cp = client.connect("tok");
    port.fireMessage({ jsonrpc: "2.0", id: 1, result: {} });
    await cp;
    const lp = client.listAccounts();
    const sent = port.messages[1] as { id: number; method: string };
    expect(sent.method).toBe("vault.list_accounts");
    port.fireMessage({
      jsonrpc: "2.0",
      id: sent.id,
      result: [
        {
          id: "a".repeat(64),
          display_name: "GitHub",
          tags: [],
          usernames: ["alice"],
          urls: [],
          password_history_count: 1,
          has_totp: false,
          current_password_changed_at: 0,
        },
      ],
    });
    const arr = await lp;
    expect(arr.length).toBe(1);
    expect(arr[0]!.display_name).toBe("GitHub");
  });

  it("copyPassword resolves to undefined and sends id in params", async () => {
    const port = makeFakePort();
    const client = new NativeHostClient(() => port, "test.host");
    const cp = client.connect("tok");
    port.fireMessage({ jsonrpc: "2.0", id: 1, result: {} });
    await cp;
    const id = "b".repeat(64);
    const cpp = client.copyPassword(id);
    const sent = port.messages[1] as { id: number; method: string; params: { id: string } };
    expect(sent.method).toBe("vault.copy_password");
    expect(sent.params.id).toBe(id);
    port.fireMessage({ jsonrpc: "2.0", id: sent.id, result: null });
    const out = await cpp;
    expect(out).toBeUndefined();
  });

  it("disconnect causes pending calls to reject with transport label", async () => {
    const port = makeFakePort();
    const client = new NativeHostClient(() => port, "test.host");
    const cp = client.connect("tok");
    // Reply to handshake.
    port.fireMessage({ jsonrpc: "2.0", id: 1, result: {} });
    await cp;
    const slow = client.listAccounts();
    client.disconnect();
    await expect(slow).rejects.toBeInstanceOf(NativeHostError);
    try {
      await slow;
    } catch (e) {
      expect((e as NativeHostError).label).toBe("transport");
    }
    expect(client.isDisconnected()).toBe(true);
  });

  it("does NOT expose a revealPassword method on the client class", () => {
    const port = makeFakePort();
    const client = new NativeHostClient(() => port, "test.host");
    const c = client as unknown as Record<string, unknown>;
    expect(c["revealPassword"]).toBeUndefined();
  });
});
