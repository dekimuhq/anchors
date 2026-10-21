import { test } from "node:test";
import assert from "node:assert/strict";
import { base64UrlDecode } from "@dekimuhq/anchors-envelope";
import { seedSaltSource, bundleSaltSource } from "../src/salt.ts";

const seed = new Uint8Array(32).fill(7);

test("seedSaltSource is deterministic per path", () => {
  const a = seedSaltSource(seed);
  const b = seedSaltSource(seed);
  assert.equal(a.saltFor("/purposes/0"), b.saltFor("/purposes/0"));
});

test("seedSaltSource gives distinct salts per path", () => {
  const s = seedSaltSource(seed);
  assert.notEqual(s.saltFor("/purposes/0"), s.saltFor("/purposes/1"));
  assert.notEqual(s.saltFor("/sub"), s.saltFor("/policy"));
});

test("different seeds give different salts for the same path", () => {
  const a = seedSaltSource(new Uint8Array(32).fill(1));
  const b = seedSaltSource(new Uint8Array(32).fill(2));
  assert.notEqual(a.saltFor("/sub"), b.saltFor("/sub"));
});

test("salt is base64url (no padding, url-safe alphabet)", () => {
  assert.match(seedSaltSource(seed).saltFor("/x"), /^[A-Za-z0-9_-]+$/);
});

test("bundleSaltSource returns stored salts and throws on unknown path", () => {
  const s = bundleSaltSource({ "/sub": "AAAA" });
  assert.equal(s.saltFor("/sub"), "AAAA");
  assert.throws(() => s.saltFor("/missing"));
});

test("HKDF-derived salt decodes to exactly 32 bytes", () => {
  const s = seedSaltSource(new Uint8Array(32).fill(7));
  const saltStr = s.saltFor("/some/path");
  const bytes = base64UrlDecode(saltStr);
  assert.equal(bytes.byteLength, 32);
});

test("seedSaltSource: 50 distinct paths produce 50 distinct salts (no collisions)", () => {
  const s = seedSaltSource(new Uint8Array(32).fill(42));
  const salts = Array.from({ length: 50 }, (_, i) => s.saltFor(`/field/${i}`));
  const unique = new Set(salts);
  assert.equal(unique.size, 50);
});
