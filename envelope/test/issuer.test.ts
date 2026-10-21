import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import {
  makeProfileAdapter,
  passthroughBodyValidator,
  isSha256Hex,
  generateReceiptId,
  keyObjectFromSeed,
  computeFieldRoot,
  type SigningKey,
} from "../src/issuer/index.ts";

describe("makeProfileAdapter", () => {
  it("returns ok: true when validate returns no errors", () => {
    const adapter = makeProfileAdapter(
      "test.profile.v1",
      () => ({ errors: [] }),
    );
    const result = adapter({} as never, {}, {});
    assert.deepStrictEqual(result, {
      profile_id: "test.profile.v1",
      ok: true,
    });
  });

  it("returns ok: false with first error as reason", () => {
    const adapter = makeProfileAdapter(
      "test.profile.v1",
      () => ({ errors: ["field_x.required", "field_y.invalid"] }),
    );
    const result = adapter({} as never, {}, {});
    assert.deepStrictEqual(result, {
      profile_id: "test.profile.v1",
      ok: false,
      reason: "field_x.required",
    });
  });

  it("passes body through to the validate function", () => {
    const calls: unknown[] = [];
    const adapter = makeProfileAdapter("test.v1", (body) => {
      calls.push(body);
      return { errors: [] };
    });
    const fakeBody = { kind: "test" };
    adapter({} as never, fakeBody, {});
    assert.equal(calls.length, 1);
    assert.strictEqual(calls[0], fakeBody);
  });
});

describe("passthroughBodyValidator", () => {
  it("always returns ok: true with the input cast to T", () => {
    interface TestBody { x: number }
    const validator = passthroughBodyValidator<TestBody>();
    const input = { x: 42 };
    const result = validator.validate(input);
    assert.deepStrictEqual(result, { ok: true, value: input });
  });

  it("returns a new instance on each call", () => {
    const a = passthroughBodyValidator();
    const b = passthroughBodyValidator();
    assert.notStrictEqual(a, b);
  });
});

describe("isSha256Hex", () => {
  it("accepts valid sha256:<hex64> string", () => {
    const hash = "sha256:" + "a".repeat(64);
    assert.equal(isSha256Hex(hash), true);
  });

  it("rejects wrong prefix", () => {
    assert.equal(isSha256Hex("md5:" + "a".repeat(64)), false);
  });

  it("rejects wrong hex length", () => {
    assert.equal(isSha256Hex("sha256:" + "a".repeat(63)), false);
  });

  it("rejects uppercase hex", () => {
    assert.equal(isSha256Hex("sha256:" + "A".repeat(64)), false);
  });

  it("rejects null", () => {
    assert.equal(isSha256Hex(null), false);
  });

  it("rejects undefined", () => {
    assert.equal(isSha256Hex(undefined), false);
  });

  it("rejects numbers", () => {
    assert.equal(isSha256Hex(42 as unknown), false);
  });

  it("narrows type to string (type guard)", () => {
    const v: unknown = "sha256:" + "b".repeat(64);
    if (isSha256Hex(v)) {
      assert.equal(v.startsWith("sha256:"), true);
    } else {
      assert.fail("expected isSha256Hex to return true");
    }
  });
});

describe("generateReceiptId (via /issuer re-export)", () => {
  it("returns a 26-char Crockford-Base32 ULID", () => {
    const id = generateReceiptId();
    assert.equal(id.length, 26);
    assert.match(id, /^[0-9A-HJKMNP-TV-Z]{26}$/);
  });

  it("generates unique IDs", () => {
    const ids = new Set(Array.from({ length: 100 }, () => generateReceiptId()));
    assert.equal(ids.size, 100);
  });
});

describe("keyObjectFromSeed (via /issuer re-export)", () => {
  it("returns a KeyObject + ed25519: fingerprint from 32-byte seed", () => {
    const seed = new Uint8Array(32);
    seed[0] = 1;
    const { privateKey, issKey } = keyObjectFromSeed(seed);
    assert.equal(privateKey.type, "private");
    assert.match(issKey, /^ed25519:[A-Za-z0-9_-]+$/);
  });

  it("is deterministic for the same seed", () => {
    const seed = new Uint8Array(32);
    seed[0] = 42;
    const a = keyObjectFromSeed(seed);
    const b = keyObjectFromSeed(seed);
    assert.equal(a.issKey, b.issKey);
  });
});

describe("computeFieldRoot (via /issuer re-export)", () => {
  it("returns sha256:<hex64> format", () => {
    const result = computeFieldRoot({ a: 1, b: "two" });
    assert.match(result, /^sha256:[0-9a-f]{64}$/);
  });

  it("is deterministic for the same input", () => {
    const body = { x: 1, y: [2, 3] };
    assert.equal(computeFieldRoot(body), computeFieldRoot(body));
  });

  it("canonicalizes key order (RFC 8785)", () => {
    const a = computeFieldRoot({ b: 2, a: 1 });
    const b = computeFieldRoot({ a: 1, b: 2 });
    assert.equal(a, b);
  });
});

describe("SigningKey type", () => {
  it("compiles with kid + 32-byte Uint8Array", () => {
    const key: SigningKey = {
      kid: "test-key-1",
      privateKey: new Uint8Array(32),
    };
    assert.equal(key.kid, "test-key-1");
    assert.equal(key.privateKey.length, 32);
  });
});
