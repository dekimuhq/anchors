import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { signPromise, verifyPromise } from "../src/promise.ts";
import { verifyInclusion, logStatus } from "../src/inclusion.ts";
import { merkleRoot, auditPath } from "../src/tree.ts";
import { signCheckpoint } from "../src/checkpoint.ts";
import { hashLeaf } from "../src/rfc6962.ts";

function keys() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    pub: publicKey.export({ type: "spki", format: "pem" }).toString(),
    priv: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

test("promise round-trips and fails on tamper", () => {
  const { pub, priv } = keys();
  const ts = "2026-01-01T00:00:00Z";
  const sig = signPromise("L", "sha256:ab", ts, priv);
  assert.ok(verifyPromise("L", "sha256:ab", { timestamp: ts, sig }, { "L": pub }));
  assert.equal(verifyPromise("L", "sha256:CHANGED", { timestamp: ts, sig }, { "L": pub }), false);
});

test("verifyInclusion accepts a real proof against a signed checkpoint", () => {
  const { pub, priv } = keys();
  const leaves = Array.from({ length: 5 }, (_, i) => hashLeaf(Buffer.from(`r${i}`)));
  const idx = 3;
  const root = merkleRoot(leaves);
  const note = signCheckpoint({ origin: "L", size: 5, rootHashB64: root.toString("base64") }, "L", priv);
  const proof = {
    index: idx,
    tree_size: 5,
    path: auditPath(leaves, idx).map((b) => `sha256:${b.toString("hex")}`),
    checkpoint: note,
  };
  const leafAtIdx = leaves[idx];
  if (!leafAtIdx) throw new Error(`leaf ${idx} undefined`);
  const leafSelfDescribing = `sha256:${leafAtIdx.toString("hex")}`;
  assert.ok(verifyInclusion(leafSelfDescribing, proof, { "L": pub }));
});

test("logStatus maps a missing block to not_logged", () => {
  assert.equal(logStatus(undefined), "not_logged");
});

// C1 regression: verifyInclusion + logStatus must NEVER throw on hostile checkpoint string
test("verifyInclusion returns false (never throws) when proof.checkpoint is junk", () => {
  assert.doesNotThrow(() => {
    const result = verifyInclusion("sha256:" + "00".repeat(32), {
      index: 0,
      tree_size: 1,
      path: [],
      checkpoint: "junk",
    }, {});
    assert.equal(result, false);
  });
});

test("logStatus returns incl_invalid (never throws) when proof.checkpoint is junk", () => {
  const { pub } = keys();
  assert.doesNotThrow(() => {
    const result = logStatus(
      {
        log_id: "L",
        leaf: "sha256:" + "00".repeat(32),
        proof: { index: 0, tree_size: 1, path: [], checkpoint: "junk" },
      },
      { L: pub },
    );
    assert.equal(result, "incl_invalid");
  });
});

// M2 regression: verifyInclusion must reject malformed leaf (no sha256: prefix)
test("verifyInclusion returns false for a leaf without sha256: prefix", () => {
  const result = verifyInclusion("deadbeef", {
    index: 0,
    tree_size: 1,
    path: [],
    checkpoint: "junk",
  }, {});
  assert.equal(result, false);
});

// M2 regression: verifyInclusion must reject a path entry without sha256: prefix
test("verifyInclusion returns false for a path entry without sha256: prefix", () => {
  const { pub, priv } = keys();
  const leaves = [hashLeaf(Buffer.from("a")), hashLeaf(Buffer.from("b"))];
  const root = merkleRoot(leaves);
  const note = signCheckpoint({ origin: "L", size: 2, rootHashB64: root.toString("base64") }, "L", priv);
  const ap = auditPath(leaves, 0);
  // Provide path entry without the sha256: prefix — should reject
  const result = verifyInclusion(`sha256:${leaves[0]!.toString("hex")}`, {
    index: 0,
    tree_size: 2,
    path: [ap[0]!.toString("hex")], // bare hex, no prefix
    checkpoint: note,
  }, { L: pub });
  assert.equal(result, false);
});

test("logStatus returns logged_proven for a valid proof, incl_invalid for a broken one", () => {
  const { pub, priv } = keys();
  const leaves = [hashLeaf(Buffer.from("a")), hashLeaf(Buffer.from("b"))];
  const root = merkleRoot(leaves);
  const note = signCheckpoint({ origin: "L", size: 2, rootHashB64: root.toString("base64") }, "L", priv);
  const l0 = leaves[0];
  const l1 = leaves[1];
  if (!l0 || !l1) throw new Error("leaves undefined");
  const incl = {
    log_id: "L",
    leaf: `sha256:${l0.toString("hex")}`,
    proof: { index: 0, tree_size: 2, path: [`sha256:${l1.toString("hex")}`], checkpoint: note },
  };
  assert.equal(logStatus(incl, { "L": pub }), "logged_proven");
  const broken = { ...incl, proof: { ...incl.proof, index: 1 } };
  assert.equal(logStatus(broken, { "L": pub }), "incl_invalid");
});
