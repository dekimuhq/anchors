import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { signCheckpoint, parseCheckpoint, verifyCheckpoint, checkpointBody } from "../src/checkpoint.ts";

function keys() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    pub: publicKey.export({ type: "spki", format: "pem" }).toString(),
    priv: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

test("sign → parse → verify round-trips", () => {
  const { pub, priv } = keys();
  const note = signCheckpoint({ origin: "dekimu-anchors-log-2026", size: 42, rootHashB64: "YWJj" }, "op-key-2026", priv);
  const parsed = parseCheckpoint(note);
  assert.equal(parsed.origin, "dekimu-anchors-log-2026");
  assert.equal(parsed.size, 42);
  assert.equal(parsed.signatures[0]?.keyHint, "op-key-2026");
  assert.ok(verifyCheckpoint(note, { "op-key-2026": pub }));
});

test("verify fails on a tampered size", () => {
  const { pub, priv } = keys();
  const note = signCheckpoint({ origin: "L", size: 42, rootHashB64: "YWJj" }, "k", priv);
  const tampered = note.replace("42", "43");
  assert.equal(verifyCheckpoint(tampered, { k: pub }), false);
});

test("verify fails when the signing key is unknown", () => {
  const { priv } = keys();
  const { pub: otherPub } = keys();
  const note = signCheckpoint({ origin: "L", size: 1, rootHashB64: "YWJj" }, "k", priv);
  assert.equal(verifyCheckpoint(note, { k: otherPub }), false);
});

// C1 regression: verifyCheckpoint must NEVER throw on hostile/malformed input
test("verifyCheckpoint returns false (never throws) on empty string", () => {
  assert.doesNotThrow(() => {
    const result = verifyCheckpoint("", {});
    assert.equal(result, false);
  });
});

test("verifyCheckpoint returns false (never throws) on single line", () => {
  assert.doesNotThrow(() => {
    const result = verifyCheckpoint("oneline", {});
    assert.equal(result, false);
  });
});

test("verifyCheckpoint returns false (never throws) on two lines (no newline-newline)", () => {
  assert.doesNotThrow(() => {
    const result = verifyCheckpoint("a\nb", {});
    assert.equal(result, false);
  });
});

test("verifyCheckpoint returns false (never throws) on arbitrary garbage", () => {
  assert.doesNotThrow(() => {
    const result = verifyCheckpoint("not a checkpoint", {});
    assert.equal(result, false);
  });
});

// I1 regression: parseCheckpoint must reject NaN size (non-integer string on line 2)
test("parseCheckpoint throws on non-numeric size line (I1 — caught at boundary by C1 fix)", () => {
  // "origin\nNaN-size\nrootHash\n\n" — head has 3 lines but size is not a number
  assert.throws(() => parseCheckpoint("origin\nNotANumber\nYWJj\n\n"), /integer/);
});
