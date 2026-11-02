/**
 * Tests for envelope/src/tsa/anchors.ts — Phase B Task 10.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, unlinkSync, existsSync, readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
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

  it("defaultTrustAnchorPath resolves inside the package (shipped), not the workspace root", () => {
    const pkgRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
    assert.equal(defaultTrustAnchorPath(), join(pkgRoot, "data", "freetsa-trust-anchor.json"));
    assert.ok(existsSync(defaultTrustAnchorPath()));
    assert.ok(loadTrustAnchors([defaultTrustAnchorPath()]).length > 0);
  });

  it("the shipped catalog is byte-equal to the workspace data/ catalog", () => {
    const pkgRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
    assert.deepEqual(
      readFileSync(join(pkgRoot, "data", "freetsa-trust-anchor.json")),
      readFileSync(join(pkgRoot, "..", "data", "freetsa-trust-anchor.json")),
    );
  });

  it("npm pack includes the default catalog", () => {
    const pkgRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
    const out = execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], { cwd: pkgRoot, encoding: "utf8" });
    const files = (JSON.parse(out) as Array<{ files: Array<{ path: string }> }>)[0]!.files.map((f) => f.path);
    assert.ok(files.includes("data/freetsa-trust-anchor.json"), files.join("\n"));
  });
});
