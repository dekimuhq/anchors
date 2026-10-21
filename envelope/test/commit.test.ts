import { test } from "node:test";
import assert from "node:assert/strict";
import { commit, verifyCommitment, randomSalt } from "../src/commit.ts";

test("commit is deterministic and verifyCommitment round-trips", () => {
  const salt = randomSalt();
  const c = commit(salt, "hello");
  assert.match(c, /^sha256:[0-9a-f]{64}$/);
  assert.equal(commit(salt, "hello"), c);
  assert.equal(verifyCommitment(c, salt, "hello"), true);
  assert.equal(verifyCommitment(c, salt, "hell0"), false);
});

test("different salt yields different commitment", () => {
  assert.notEqual(commit(randomSalt(), "x"), commit(randomSalt(), "x"));
});
