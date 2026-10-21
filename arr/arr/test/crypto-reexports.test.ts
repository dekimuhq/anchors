import { test } from "node:test";
import assert from "node:assert/strict";
import {
  canonicalize,
  base64UrlEncode,
  base64UrlDecode,
  commit,
  verifyCommitment,
  randomSalt,
  buildTree,
  inclusionProof,
  verifyInclusion,
} from "../src/index.ts";

test("canonicalize re-exported from apr-verifier", () => {
  const out = canonicalize({ b: 2, a: 1 });
  assert.equal(out, '{"a":1,"b":2}');
});

test("base64UrlEncode + base64UrlDecode round-trip", () => {
  const bytes = new Uint8Array([1, 2, 3, 250]);
  const enc = base64UrlEncode(bytes);
  const dec = base64UrlDecode(enc);
  assert.deepEqual(Array.from(dec), [1, 2, 3, 250]);
});

test("commit + verifyCommitment round-trip (re-exported from acr-verifier)", () => {
  const salt = randomSalt();
  const c = commit(salt, "subject-42");
  assert.match(c, /^sha256:[0-9a-f]{64}$/);
  assert.equal(verifyCommitment(c, salt, "subject-42"), true);
  assert.equal(verifyCommitment(c, salt, "subject-43"), false);
});

test("buildTree of single leaf returns a tree with root", () => {
  const leaf = "sha256:" + "00".repeat(32);
  const tree = buildTree([leaf]);
  assert.match(tree.root, /^sha256:[0-9a-f]{64}$/);
  assert.equal(tree.leafCount, 1);
});

test("buildTree of two leaves is deterministic + inclusion proof verifies", () => {
  const a = "sha256:" + "00".repeat(32);
  const b = "sha256:" + "11".repeat(32);
  const t1 = buildTree([a, b]);
  const t2 = buildTree([a, b]);
  assert.equal(t1.root, t2.root);
  const proof = inclusionProof(t1, 0);
  assert.equal(verifyInclusion(a, proof, 0, 2, t1.root), true);
  assert.equal(verifyInclusion(b, proof, 0, 2, t1.root), false);
});
