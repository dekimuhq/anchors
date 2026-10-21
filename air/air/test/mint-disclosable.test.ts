import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyFieldCommit } from "@dekimuhq/anchors-envelope";
import { verifyReceipt } from "../src/index.ts";
import { mintAirV2 } from "../src/issue/mint-v2.ts";
import { mintAirV2Disclosable } from "../src/issue/mint-disclosable.ts";
import { baseCommon, makeSigningKey, makeResolveKey, H } from "./_helpers/common.ts";

// baseCommon supplies issuer/profile/air_receipt_id/processing_activity_id/policy_*/anchor.
function thresholdInput() {
  return {
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "dpia.threshold_triggered" as const,
    processing_activity_hash: H("a"),
    processing_start_at: "2026-05-19T00:00:00Z",
  };
}

test("mintAirV2Disclosable returns receipt + issuer-signed field_commit + 32-byte seed", async () => {
  const { receipt, fieldCommit, seed } = await mintAirV2Disclosable(thresholdInput());
  assert.equal(receipt.v, 2);
  assert.equal(receipt.claim_type, "ar.impact.v1");
  assert.equal(seed.length, 32);
  assert.equal(fieldCommit.kind, "ar.field_commit.v1");
  assert.equal(fieldCommit.family, "air");
  assert.equal(fieldCommit.id, receipt.id);
  assert.equal(fieldCommit.field_root, (receipt.body as { field_root: string }).field_root);
  assert.equal(fieldCommit.leaf_count, 3); // three declared AIR leaves (no profile in body)
  assert.equal(verifyFieldCommit(fieldCommit).valid, true);
});

test("disclosable field_root differs from the flat field_root (per-field tree, not whole-body)", async () => {
  const flat = await mintAirV2(thresholdInput());
  const { receipt: disc } = await mintAirV2Disclosable(thresholdInput());
  assert.notEqual(
    (flat.body as { field_root: string }).field_root,
    (disc.body as { field_root: string }).field_root,
  );
});

test("disclosable receipt still passes air-verifier (full-body signature intact)", async () => {
  const { receipt } = await mintAirV2Disclosable(thresholdInput());
  const r = await verifyReceipt(receipt, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("mintAirV2Disclosable rejects TSA in v0 (re-sign would invalidate the timestamp)", async () => {
  await assert.rejects(
    () => mintAirV2Disclosable({ ...thresholdInput(), tsa: {} as never, tsaFetcher: (async () => ({})) as never }),
    /TSA \+ disclosable/,
  );
});

test("mintAirV2 (non-disclosable) is unchanged: returns a bare Envelope, flat field_root", async () => {
  const out = await mintAirV2(thresholdInput());
  assert.equal("fieldCommit" in (out as object), false);
  assert.match((out.body as { field_root: string }).field_root, /^sha256:[0-9a-f]{64}$/);
});
