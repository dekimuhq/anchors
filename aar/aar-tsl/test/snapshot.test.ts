import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import {
  buildSnapshotFromEntries,
  getProofBundle,
} from "../src/snapshot.ts";
import { parseTsl } from "../src/parse-tsl.ts";
import { verifyInclusion } from "../src/merkle.ts";

const TSL_ES = readFileSync(
  new URL("./fixtures/national-tsl-es.xml", import.meta.url),
  "utf8",
);

describe("snapshot", () => {
  const entries = parseTsl(TSL_ES, "ES");

  describe("buildSnapshotFromEntries", () => {
    it("builds a snapshot from parsed entries", () => {
      const snap = buildSnapshotFromEntries(entries);
      assert.ok(snap.root.startsWith("sha256:"));
      assert.equal(snap.tree_size, 3);
      assert.equal(snap.leaves.length, 3);
      assert.ok(snap.log_time.length > 0);
    });

    it("assigns sequential leaf indices", () => {
      const snap = buildSnapshotFromEntries(entries);
      for (let i = 0; i < snap.leaves.length; i++) {
        assert.equal(snap.leaves[i]!.index, i);
      }
    });

    it("is deterministic for same entries", () => {
      const a = buildSnapshotFromEntries(entries);
      const b = buildSnapshotFromEntries(entries);
      assert.equal(a.root, b.root);
    });

    it("each leaf hash is sha256-prefixed", () => {
      const snap = buildSnapshotFromEntries(entries);
      for (const leaf of snap.leaves) {
        assert.ok(leaf.hash.startsWith("sha256:"));
        assert.equal(leaf.hash.length, 7 + 64);
      }
    });
  });

  describe("getProofBundle", () => {
    it("returns a proof bundle for a known service", () => {
      const snap = buildSnapshotFromEntries(entries);
      const qes = entries.find((e) => e.service_type === "qes")!;
      const bundle = getProofBundle(snap, "ES", qes.service_type_identifier, qes.certificate_hashes[0]!);
      assert.ok(bundle);
      assert.equal(bundle.tsl_country, "ES");
      assert.ok(bundle.tsl_entry_hash.startsWith("sha256:"));
      assert.equal(bundle.tsl_signed_tree_head_root, snap.root);
      assert.equal(bundle.tsl_tree_size, snap.tree_size);
      assert.ok(Array.isArray(bundle.tsl_inclusion_proof));
      assert.ok(bundle.tsl_log_time.length > 0);
    });

    it("returns null for unknown country", () => {
      const snap = buildSnapshotFromEntries(entries);
      const bundle = getProofBundle(snap, "DE", "whatever", "whatever");
      assert.equal(bundle, null);
    });

    it("returns null for unknown cert hash", () => {
      const snap = buildSnapshotFromEntries(entries);
      const bundle = getProofBundle(snap, "ES", entries[0]!.service_type_identifier, "notahash");
      assert.equal(bundle, null);
    });

    it("proof bundle verifies against the tree", () => {
      const snap = buildSnapshotFromEntries(entries);
      const qes = entries.find((e) => e.service_type === "qes")!;
      const bundle = getProofBundle(snap, "ES", qes.service_type_identifier, qes.certificate_hashes[0]!)!;
      const leafIdx = snap.leaves.findIndex((l) => l.hash === bundle.tsl_entry_hash);
      const ok = verifyInclusion(
        bundle.tsl_entry_hash,
        bundle.tsl_inclusion_proof,
        leafIdx,
        bundle.tsl_tree_size,
        bundle.tsl_signed_tree_head_root,
      );
      assert.equal(ok, true);
    });

    it("returns bundles for all 3 services", () => {
      const snap = buildSnapshotFromEntries(entries);
      for (const entry of entries) {
        const bundle = getProofBundle(snap, entry.country, entry.service_type_identifier, entry.certificate_hashes[0]!);
        assert.ok(bundle, `no bundle for ${entry.service_name}`);
      }
    });

    it("handles empty entries gracefully", () => {
      const snap = buildSnapshotFromEntries([]);
      assert.equal(snap.tree_size, 0);
      assert.equal(snap.leaves.length, 0);
      const bundle = getProofBundle(snap, "ES", "anything", "anything");
      assert.equal(bundle, null);
    });
  });
});
