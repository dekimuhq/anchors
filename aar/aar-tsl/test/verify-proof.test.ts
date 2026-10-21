import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { verifyTslInclusionProof } from "../src/verify-proof.ts";
import { buildSnapshotFromEntries, getProofBundle } from "../src/snapshot.ts";
import { parseTsl } from "../src/parse-tsl.ts";

const TSL_ES = readFileSync(
  new URL("./fixtures/national-tsl-es.xml", import.meta.url),
  "utf8",
);

describe("verifyTslInclusionProof", () => {
  const entries = parseTsl(TSL_ES, "ES");
  const snapshot = buildSnapshotFromEntries(entries);

  it("verifies a valid proof bundle", () => {
    const qes = entries.find((e) => e.service_type === "qes")!;
    const bundle = getProofBundle(snapshot, "ES", qes.service_type_identifier, qes.certificate_hashes[0]!)!;
    assert.equal(verifyTslInclusionProof(bundle, snapshot.root), true);
  });

  it("verifies all services in snapshot", () => {
    for (const entry of entries) {
      const bundle = getProofBundle(
        snapshot,
        entry.country,
        entry.service_type_identifier,
        entry.certificate_hashes[0]!,
      )!;
      assert.ok(bundle, `no bundle for ${entry.service_name}`);
      assert.equal(
        verifyTslInclusionProof(bundle, snapshot.root),
        true,
        `proof failed for ${entry.service_name}`,
      );
    }
  });

  it("rejects proof against wrong root", () => {
    const qes = entries.find((e) => e.service_type === "qes")!;
    const bundle = getProofBundle(snapshot, "ES", qes.service_type_identifier, qes.certificate_hashes[0]!)!;
    const fakeRoot = "sha256:" + "f".repeat(64);
    assert.equal(verifyTslInclusionProof(bundle, fakeRoot), false);
  });

  it("rejects tampered entry hash", () => {
    const qes = entries.find((e) => e.service_type === "qes")!;
    const bundle = getProofBundle(snapshot, "ES", qes.service_type_identifier, qes.certificate_hashes[0]!)!;
    const tampered = { ...bundle, tsl_entry_hash: "sha256:" + "0".repeat(64) };
    assert.equal(verifyTslInclusionProof(tampered, snapshot.root), false);
  });

  it("rejects tampered proof path", () => {
    const qes = entries.find((e) => e.service_type === "qes")!;
    const bundle = getProofBundle(snapshot, "ES", qes.service_type_identifier, qes.certificate_hashes[0]!)!;
    const tampered = {
      ...bundle,
      tsl_inclusion_proof: bundle.tsl_inclusion_proof.map(() => "sha256:" + "0".repeat(64)),
    };
    assert.equal(verifyTslInclusionProof(tampered, snapshot.root), false);
  });
});
