// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Framing-fidelity test (plan-LOCK §6, §7).
//
// The injected stdio connector frames messages the way Chrome's
// native-messaging protocol does — a 4-byte little-endian u32 length
// prefix followed by the UTF-8 JSON body. The host's frame.rs expects
// EXACTLY this. A divergent framing would make the integration test
// pass on a protocol production rejects, so we pin the byte layout
// here independently of the live host round-trip.

import { expect } from "chai";

import { deframeMessage, frameMessage } from "../setup/stdio-connector.js";

describe("native-messaging framing fidelity", () => {
  it("frames as [4-byte LE length][UTF-8 JSON]", () => {
    const msg = { jsonrpc: "2.0", id: 1, method: "auth.handshake", params: { token: "x" } };
    const framed = frameMessage(msg);
    const json = JSON.stringify(msg);
    const jsonBytes = Buffer.from(json, "utf8");

    // Header is exactly 4 bytes, little-endian, = body length.
    expect(framed.length).to.equal(4 + jsonBytes.length);
    expect(framed.readUInt32LE(0)).to.equal(jsonBytes.length);
    // Body is the verbatim UTF-8 JSON.
    expect(framed.subarray(4).toString("utf8")).to.equal(json);
  });

  it("round-trips frame → deframe to the original value", () => {
    const msg = { jsonrpc: "2.0", id: 42, result: { vault_open: true, vault_unlocked: true } };
    const framed = frameMessage(msg);
    const out = deframeMessage(framed);
    expect(out).to.not.equal(null);
    expect(out!.consumed).to.equal(framed.length);
    expect(out!.value).to.deep.equal(msg);
  });

  it("deframe returns null for an incomplete frame (length prefix only)", () => {
    const framed = frameMessage({ a: 1 });
    // Truncate to just the 4-byte header + 1 body byte.
    const partial = framed.subarray(0, 5);
    expect(deframeMessage(partial)).to.equal(null);
  });

  it("handles multi-byte UTF-8 in the body length correctly", () => {
    // The em-dash + non-ASCII chars must be counted as their UTF-8
    // byte length, NOT their JS string length.
    const msg = { note: "Pangolin — café 🦔" };
    const framed = frameMessage(msg);
    const jsonByteLen = Buffer.from(JSON.stringify(msg), "utf8").length;
    expect(framed.readUInt32LE(0)).to.equal(jsonByteLen);
    const out = deframeMessage(framed);
    expect(out!.value).to.deep.equal(msg);
  });
});
