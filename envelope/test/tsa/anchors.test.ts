/**
 * Tests for envelope/src/tsa/anchors.ts — Phase B Task 10.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, unlinkSync } from "node:fs";
import { loadTrustAnchors, defaultTrustAnchorPath } from "../../src/tsa/anchors.ts";

describe("loadTrustAnchors", () => {
  it("loads the bundled FreeTSA catalog and returns ≥1 anchor", () => {
    const anchors = loadTrustAnchors([defaultTrustAnchorPath()]);
    assert.ok(anchors.length >= 1, "expected at least one trust anchor");
    const a = anchors[0]!;
    assert.equal(typeof a.id, "string");
    assert.equal(typeof a.name, "string");
    assert.ok(a.cert_pem.startsWith("-----BEGIN CERTIFICATE-----"));
    assert.ok(a.cert_sha256_der.startsWith("sha256:"), "fingerprint should start with sha256:");
  });

  it("throws when cert_sha256_der does not match the PEM", () => {
    const goodAnchor = loadTrustAnchors([defaultTrustAnchorPath()])[0]!;
    // Tamper the pinned fingerprint
    const tampered = {
      source: "test",
      anchors: [
        {
          ...goodAnchor,
          cert_sha256_der: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        },
      ],
    };
    const tmpPath = "/tmp/freetsa-tampered-test.json";
    writeFileSync(tmpPath, JSON.stringify(tampered), "utf8");
    try {
      assert.throws(
        () => loadTrustAnchors([tmpPath]),
        (err: unknown) => {
          assert.ok(err instanceof Error);
          assert.ok(err.message.includes("sha mismatch"), `unexpected message: ${err.message}`);
          return true;
        },
      );
    } finally {
      unlinkSync(tmpPath);
    }
  });

  it("defaultTrustAnchorPath returns a path ending in data/freetsa-trust-anchor.json", () => {
    const p = defaultTrustAnchorPath();
    assert.ok(
      p.endsWith("data/freetsa-trust-anchor.json"),
      `expected path ending in data/freetsa-trust-anchor.json, got: ${p}`,
    );
  });
});
