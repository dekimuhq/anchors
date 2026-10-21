import { test } from "node:test";
import assert from "node:assert/strict";
import { buildPresentation, verifyPresentation, seedSaltSource, AIR_DISCLOSURE_SCHEMA } from "@dekimuhq/anchors-disclosure";
import { mintAirV2Disclosable } from "../src/issue/mint-disclosable.ts";
import { baseCommon, makeSigningKey, H } from "./_helpers/common.ts";

function thresholdInput() {
  return {
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "dpia.threshold_triggered" as const,
    processing_activity_hash: H("a"),
    processing_start_at: "2026-05-19T00:00:00Z",
  };
}

// Holder rebuilds the tree from the body-minus-field_root + the seed.
function bodyNoRoot(receipt: { body: unknown }) {
  const { field_root: _r, ...rest } = receipt.body as Record<string, unknown>;
  return rest;
}

test("AIR disclosable receipt: reveal only /processing_activity_id + /event_type, hide the rest", async () => {
  const { receipt, fieldCommit, seed } = await mintAirV2Disclosable(thresholdInput());
  const presentation = buildPresentation({
    body: bodyNoRoot(receipt),
    schema: AIR_DISCLOSURE_SCHEMA,
    salts: seedSaltSource(seed),
    fieldCommit,
    reveal: ["/processing_activity_id", "/event_type"],
  });

  const r = verifyPresentation(presentation, { schema: AIR_DISCLOSURE_SCHEMA });
  assert.equal(r.valid, true);
  assert.deepEqual(r.revealed, { "/processing_activity_id": "PA-customer-analytics-v1", "/event_type": "dpia.threshold_triggered" });
  assert.equal(r.issuer, receipt.iss_key);
  // hidden leaf (/air_receipt_id) is absent from the wire
  assert.equal(presentation.revealed.length, 2);
});

test("AIR disclosable receipt: tampering a revealed value is rejected", async () => {
  const { receipt, fieldCommit, seed } = await mintAirV2Disclosable(thresholdInput());
  const p = buildPresentation({
    body: bodyNoRoot(receipt), schema: AIR_DISCLOSURE_SCHEMA, salts: seedSaltSource(seed), fieldCommit, reveal: ["/air_receipt_id"],
  });
  p.revealed[0]!.value = "AIR-FORGED";
  assert.equal(verifyPresentation(p).valid, false);
});

test("AIR disclosable receipt: an untrusted issuer is rejected", async () => {
  const { receipt, fieldCommit, seed } = await mintAirV2Disclosable(thresholdInput());
  const p = buildPresentation({
    body: bodyNoRoot(receipt), schema: AIR_DISCLOSURE_SCHEMA, salts: seedSaltSource(seed), fieldCommit, reveal: ["/processing_activity_id"],
  });
  const r = verifyPresentation(p, { trustIssuer: () => false });
  assert.equal(r.valid, false);
  assert.ok(r.reasons.includes("issuer_untrusted"));
});
