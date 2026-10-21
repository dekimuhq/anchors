import { test } from "node:test";
import assert from "node:assert/strict";
import { commit, verifyCommitment, randomSalt } from "../src/commit.ts";

test("commit is deterministic for the same salt+value", () => {
  const salt = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  const a = commit(salt, "hello");
  const b = commit(salt, "hello");
  assert.equal(a, b);
  assert.match(a, /^sha256:[0-9a-f]{64}$/);
});

test("commit differs for different values under same salt", () => {
  const salt = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  const a = commit(salt, "hello");
  const b = commit(salt, "world");
  assert.notEqual(a, b);
});

test("commit differs for same value under different salts", () => {
  const a = commit("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "hello");
  const b = commit("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "hello");
  assert.notEqual(a, b);
});

test("verifyCommitment matches commit output", () => {
  const salt = randomSalt();
  const c = commit(salt, "x");
  assert.equal(verifyCommitment(c, salt, "x"), true);
  assert.equal(verifyCommitment(c, salt, "y"), false);
});

test("randomSalt produces 32 bytes encoded as base64url (43 chars, no padding)", () => {
  const s = randomSalt();
  assert.match(s, /^[A-Za-z0-9_-]{43}$/);
});
