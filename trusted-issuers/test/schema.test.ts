import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { SIG_ALGS } from "@dekimuhq/anchors-envelope";
import { parseTrustedIssuerList } from "../src/index.ts";
import { makeSignedDoc, defaultIssuerRecord } from "./fixtures.ts";

describe("parseTrustedIssuerList — happy path", () => {
  it("accepts a fully-formed signed doc", () => {
    const { doc } = makeSignedDoc();
    const res = parseTrustedIssuerList(doc);
    assert.equal(res.ok, true);
    if (res.ok) {
      assert.equal(res.doc.kind, "ar.trusted_issuers.v1");
      assert.equal(res.doc.issuers.length, 1);
    }
  });

  it("accepts previous_sha256 as a hex string", () => {
    const { doc } = makeSignedDoc({
      previous_sha256: "sha256:" + "a".repeat(64),
    });
    const res = parseTrustedIssuerList(doc);
    assert.equal(res.ok, true);
  });

  it("accepts profiles_pinned as Record<string,string[]>", () => {
    const { doc } = makeSignedDoc({
      issuers: [
        defaultIssuerRecord({
          profiles_pinned: { "ar.provenance.v1": ["telemetry"] },
        }),
      ],
    });
    const res = parseTrustedIssuerList(doc);
    assert.equal(res.ok, true);
  });
});

describe("parseTrustedIssuerList — malformations", () => {
  // 1. kind wrong
  it("rejects wrong kind", () => {
    const { doc } = makeSignedDoc();
    const res = parseTrustedIssuerList({ ...doc, kind: "ar.wrong.v1" });
    assert.equal(res.ok, false);
    if (!res.ok) assert.match(res.reason, /kind/);
  });

  // 2. version not positive integer
  it("rejects non-integer version", () => {
    const { doc } = makeSignedDoc();
    const res = parseTrustedIssuerList({ ...doc, version: 1.5 });
    assert.equal(res.ok, false);
    if (!res.ok) assert.match(res.reason, /version/);
  });
  it("rejects zero version", () => {
    const { doc } = makeSignedDoc();
    const res = parseTrustedIssuerList({ ...doc, version: 0 });
    assert.equal(res.ok, false);
  });

  // 3. issued_at unparseable
  it("rejects malformed issued_at", () => {
    const { doc } = makeSignedDoc();
    const res = parseTrustedIssuerList({ ...doc, issued_at: "yesterday" });
    assert.equal(res.ok, false);
    if (!res.ok) assert.match(res.reason, /issued_at/);
  });

  // 4. valid_until unparseable
  it("rejects malformed valid_until", () => {
    const { doc } = makeSignedDoc();
    const res = parseTrustedIssuerList({ ...doc, valid_until: "later" });
    assert.equal(res.ok, false);
  });

  // 5. issued_at >= valid_until
  it("rejects issued_at >= valid_until", () => {
    const { doc } = makeSignedDoc();
    const res = parseTrustedIssuerList({
      ...doc,
      issued_at: "2026-07-01T00:00:00Z",
      valid_until: "2026-06-01T00:00:00Z",
    });
    assert.equal(res.ok, false);
    if (!res.ok) assert.match(res.reason, /issued_at.*valid_until|valid_until/);
  });

  // 6. publisher not did:web
  it("rejects non-did:web publisher", () => {
    const { doc } = makeSignedDoc();
    const res = parseTrustedIssuerList({ ...doc, publisher: "https://dekimu.com" });
    assert.equal(res.ok, false);
    if (!res.ok) assert.match(res.reason, /publisher/);
  });

  // 7. publisher_key wrong format
  it("rejects malformed publisher_key", () => {
    const { doc } = makeSignedDoc();
    const res = parseTrustedIssuerList({ ...doc, publisher_key: "rsa:abc" });
    assert.equal(res.ok, false);
    if (!res.ok) assert.match(res.reason, /publisher_key/);
  });

  // 7b. publisher_key with no algorithm prefix is rejected (v1.3 §L6).
  it("rejects publisher_key with no algorithm prefix", () => {
    const { doc } = makeSignedDoc();
    const res = parseTrustedIssuerList({ ...doc, publisher_key: "AbCdEf-_123" });
    assert.equal(res.ok, false);
    if (!res.ok) assert.match(res.reason, /publisher_key/);
  });

  // 7c. v1.3 §L6: the accepted publisher_key prefixes are EXACTLY the registered
  // SIG_ALGS — generated from the canonical list so a new algorithm widens the
  // format with no second list to drift. Accepting the format is independent of
  // whether verify.ts can yet verify that algorithm (see verify.test.ts).
  it("accepts a publisher_key under every registered SIG_ALG prefix", () => {
    const { doc } = makeSignedDoc();
    for (const alg of SIG_ALGS) {
      const res = parseTrustedIssuerList({ ...doc, publisher_key: `${alg}:AbCdEf-_123` });
      assert.equal(res.ok, true, `expected SIG_ALG "${alg}" prefix to be accepted`);
    }
  });

  it("rejects a publisher_key under an unregistered algorithm prefix", () => {
    const { doc } = makeSignedDoc();
    const res = parseTrustedIssuerList({ ...doc, publisher_key: "ml-dsa-87:AbCdEf-_123" });
    assert.equal(res.ok, false);
    if (!res.ok) assert.match(res.reason, /publisher_key/);
  });

  // 8. previous_sha256 wrong shape
  it("rejects malformed previous_sha256", () => {
    const { doc } = makeSignedDoc();
    const res = parseTrustedIssuerList({ ...doc, previous_sha256: "abc123" });
    assert.equal(res.ok, false);
    if (!res.ok) assert.match(res.reason, /previous_sha256/);
  });

  // 9. issuers not array
  it("rejects issuers not array", () => {
    const { doc } = makeSignedDoc();
    const res = parseTrustedIssuerList({ ...doc, issuers: "nope" });
    assert.equal(res.ok, false);
  });

  // 10. issuer record bad iss
  it("rejects issuer with non-did:web iss", () => {
    const { doc } = makeSignedDoc({
      issuers: [defaultIssuerRecord({ iss: "https://wrong" })],
    });
    const res = parseTrustedIssuerList(doc);
    assert.equal(res.ok, false);
    if (!res.ok) assert.match(res.reason, /iss/);
  });

  // 11. issuer record empty families
  it("rejects issuer with empty families", () => {
    const { doc } = makeSignedDoc({
      issuers: [defaultIssuerRecord({ families: [] })],
    });
    const res = parseTrustedIssuerList(doc);
    assert.equal(res.ok, false);
    if (!res.ok) assert.match(res.reason, /families/);
  });

  // 12. issuer record malformed profiles_pinned
  it("rejects issuer with profiles_pinned value not string[]", () => {
    const { doc } = makeSignedDoc({
      issuers: [
        defaultIssuerRecord({
          profiles_pinned: { "ar.provenance.v1": [123 as unknown as string] },
        }),
      ],
    });
    const res = parseTrustedIssuerList(doc);
    assert.equal(res.ok, false);
  });

  // 13. sig missing
  it("rejects empty sig", () => {
    const { doc } = makeSignedDoc();
    const res = parseTrustedIssuerList({ ...doc, sig: "" });
    assert.equal(res.ok, false);
    if (!res.ok) assert.match(res.reason, /sig/);
  });

  // 14. raw not object
  it("rejects non-object input", () => {
    const res = parseTrustedIssuerList("nope");
    assert.equal(res.ok, false);
  });
  it("rejects null input", () => {
    const res = parseTrustedIssuerList(null);
    assert.equal(res.ok, false);
  });
  it("rejects array input", () => {
    const res = parseTrustedIssuerList([]);
    assert.equal(res.ok, false);
  });
});
