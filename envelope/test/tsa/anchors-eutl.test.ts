/**
 * Tests for multi-file trust-anchor loading (FreeTSA + EUTL) — Phase B Task 11.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { loadTrustAnchors } from "../../src/tsa/anchors.ts";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const FREETSA = resolve(here, "../../../data/freetsa-trust-anchor.json");
const EUTL = resolve(here, "../../../data/eutl-snapshot.json");

describe("loadTrustAnchors with FreeTSA + EUTL", () => {
  it("accepts FreeTSA + EUTL files together and returns ≥1 anchor", () => {
    const all = loadTrustAnchors([FREETSA, EUTL]);
    assert.ok(all.length >= 1, "expected at least the FreeTSA anchor");
  });

  it("tags EUTL entries with eutl_listed:true (currently zero, per Phase B Task 11 deferral)", () => {
    const all = loadTrustAnchors([FREETSA, EUTL]);
    const eutl = all.filter((a) => a.eutl_listed);
    // EUTL snapshot is a placeholder pending Wave 1 ingestion.
    // The assertion here is that the filter mechanism works — count >= 0 is trivially true,
    // so we assert that no FreeTSA anchor leaks in as eutl_listed:true.
    for (const a of eutl) {
      assert.notEqual(
        a.id,
        "freetsa-root-ca",
        "FreeTSA anchor must not be flagged eutl_listed",
      );
    }
  });

  it("loads EUTL snapshot with eutl_listed:false anchors (currently empty array)", () => {
    const all = loadTrustAnchors([FREETSA, EUTL]);
    const freetsa = all.filter((a) => !a.eutl_listed);
    // FreeTSA anchor is marked eutl_listed:false
    assert.ok(freetsa.length >= 1, "expected FreeTSA marked with eutl_listed:false");
    const ft = freetsa.find((a) => a.id === "freetsa-root-ca");
    assert.ok(ft, "FreeTSA anchor should be in the list");
    assert.equal(ft.eutl_listed, false, "FreeTSA must be marked eutl_listed:false");
  });
});
