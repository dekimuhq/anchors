import { test } from "node:test";
import assert from "node:assert/strict";
import { commit, randomSalt } from "../src/commit.ts";
import { buildTree, inclusionProof } from "../src/merkle.ts";
import { verifyDisclosureProof } from "../src/disclose.ts";
import type { DisclosureProof } from "../src/types.ts";

test("verifyDisclosureProof accepts a valid proof for a disclosed field", () => {
  const fields = [
    { field: "sub_commit", value: "alice@example.com", salt: randomSalt() },
    { field: "purposes[0]", value: "marketing-emails", salt: randomSalt() },
    { field: "policy_hash", value: "policy-v3-text", salt: randomSalt() },
  ];
  const leaves = fields.map((f) => commit(f.salt, f.value));
  const tree = buildTree(leaves);

  const proof: DisclosureProof = {
    disclosure: fields[1]!,
    merkle_path: inclusionProof(tree, 1),
    leaf_index: 1,
    leaf_count: leaves.length,
  };

  assert.equal(verifyDisclosureProof(proof, tree.root), true);
});

test("verifyDisclosureProof accepts proofs at every leaf position", () => {
  const fields = [
    { field: "sub_commit", value: "alice@example.com", salt: randomSalt() },
    { field: "purposes[0]", value: "marketing-emails", salt: randomSalt() },
    { field: "purposes[1]", value: "analytics", salt: randomSalt() },
    { field: "policy_hash", value: "policy-v3-text", salt: randomSalt() },
    { field: "lawful_basis", value: "6(1)(a)", salt: randomSalt() },
  ];
  const leaves = fields.map((f) => commit(f.salt, f.value));
  const tree = buildTree(leaves);

  for (let i = 0; i < fields.length; i++) {
    const proof: DisclosureProof = {
      disclosure: fields[i]!,
      merkle_path: inclusionProof(tree, i),
      leaf_index: i,
      leaf_count: leaves.length,
    };
    assert.equal(verifyDisclosureProof(proof, tree.root), true, `index ${i}`);
  }
});

test("verifyDisclosureProof rejects a tampered value", () => {
  const fields = [
    { field: "sub_commit", value: "alice@example.com", salt: randomSalt() },
  ];
  const leaves = fields.map((f) => commit(f.salt, f.value));
  const tree = buildTree(leaves);

  const proof: DisclosureProof = {
    disclosure: { ...fields[0]!, value: "bob@example.com" },
    merkle_path: inclusionProof(tree, 0),
    leaf_index: 0,
    leaf_count: 1,
  };

  assert.equal(verifyDisclosureProof(proof, tree.root), false);
});

test("verifyDisclosureProof rejects a tampered salt", () => {
  const fields = [
    { field: "sub_commit", value: "alice@example.com", salt: randomSalt() },
    { field: "purposes[0]", value: "marketing-emails", salt: randomSalt() },
  ];
  const leaves = fields.map((f) => commit(f.salt, f.value));
  const tree = buildTree(leaves);

  const proof: DisclosureProof = {
    disclosure: { ...fields[0]!, salt: randomSalt() },
    merkle_path: inclusionProof(tree, 0),
    leaf_index: 0,
    leaf_count: 2,
  };

  assert.equal(verifyDisclosureProof(proof, tree.root), false);
});

test("verifyDisclosureProof rejects a wrong root", () => {
  const fields = [
    { field: "sub_commit", value: "alice", salt: randomSalt() },
  ];
  const leaves = fields.map((f) => commit(f.salt, f.value));
  const tree = buildTree(leaves);

  const proof: DisclosureProof = {
    disclosure: fields[0]!,
    merkle_path: inclusionProof(tree, 0),
    leaf_index: 0,
    leaf_count: 1,
  };

  const wrongRoot = "sha256:" + "f".repeat(64);
  assert.equal(verifyDisclosureProof(proof, wrongRoot), false);
});

test("verifyDisclosureProof rejects a wrong leaf_index", () => {
  const fields = [
    { field: "sub_commit", value: "alice", salt: randomSalt() },
    { field: "purposes[0]", value: "marketing-emails", salt: randomSalt() },
    { field: "policy_hash", value: "policy-v3-text", salt: randomSalt() },
  ];
  const leaves = fields.map((f) => commit(f.salt, f.value));
  const tree = buildTree(leaves);

  const proof: DisclosureProof = {
    disclosure: fields[1]!,
    merkle_path: inclusionProof(tree, 1),
    leaf_index: 2, // lying about position
    leaf_count: leaves.length,
  };

  assert.equal(verifyDisclosureProof(proof, tree.root), false);
});

test("verifyDisclosureProof rejects a malformed salt without throwing", () => {
  const proof: DisclosureProof = {
    disclosure: {
      field: "sub_commit",
      value: "alice",
      salt: "!!!not-base64url!!!",
    },
    merkle_path: [],
    leaf_index: 0,
    leaf_count: 1,
  };
  assert.equal(verifyDisclosureProof(proof, "sha256:" + "a".repeat(64)), false);
});
