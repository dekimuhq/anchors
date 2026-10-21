import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { parseKeyDoc, DidWebResolveError } from "../src/index.ts";

describe("parseKeyDoc", () => {
  const validDoc = {
    version: 1,
    keys: [
      {
        iss_key: "ed25519:AAAA",
        public_key_der_base64: "MCowBQYDK2VwAyEA",
        valid_from: "2026-05-17T00:00:00Z",
        valid_until: null,
      },
    ],
  };

  it("accepts a well-formed v1 doc", () => {
    const parsed = parseKeyDoc(validDoc);
    assert.equal(parsed.version, 1);
    assert.equal(parsed.keys.length, 1);
    assert.equal(parsed.keys[0]?.iss_key, "ed25519:AAAA");
  });

  it("rejects non-object root", () => {
    assert.throws(
      () => parseKeyDoc(null),
      (err: unknown) => err instanceof DidWebResolveError && err.code === "key_doc_invalid",
    );
    assert.throws(
      () => parseKeyDoc("string"),
      (err: unknown) => err instanceof DidWebResolveError && err.code === "key_doc_invalid",
    );
  });

  it("rejects unknown version", () => {
    assert.throws(
      () => parseKeyDoc({ ...validDoc, version: 2 }),
      (err: unknown) => err instanceof DidWebResolveError && err.code === "key_doc_invalid",
    );
  });

  it("rejects missing keys array", () => {
    assert.throws(
      () => parseKeyDoc({ version: 1 }),
      (err: unknown) => err instanceof DidWebResolveError && err.code === "key_doc_invalid",
    );
  });

  it("rejects entry missing iss_key", () => {
    const bad = { version: 1, keys: [{ public_key_der_base64: "MC", valid_from: "2026-01-01T00:00:00Z", valid_until: null }] };
    assert.throws(
      () => parseKeyDoc(bad),
      (err: unknown) => err instanceof DidWebResolveError && err.code === "key_doc_invalid",
    );
  });

  it("rejects entry missing public_key_der_base64", () => {
    const bad = { version: 1, keys: [{ iss_key: "ed25519:AAA", valid_from: "2026-01-01T00:00:00Z", valid_until: null }] };
    assert.throws(
      () => parseKeyDoc(bad),
      (err: unknown) => err instanceof DidWebResolveError && err.code === "key_doc_invalid",
    );
  });

  it("accepts valid_until ISO timestamp", () => {
    const doc = { version: 1, keys: [{ ...validDoc.keys[0], valid_until: "2027-01-01T00:00:00Z" }] };
    const parsed = parseKeyDoc(doc);
    assert.equal(parsed.keys[0]?.valid_until, "2027-01-01T00:00:00Z");
  });
});
