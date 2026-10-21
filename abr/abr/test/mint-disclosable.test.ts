import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyFieldCommit } from "@dekimuhq/anchors-envelope";
import { verifyReceipt } from "../src/index.ts";
import { mintAbrV2 } from "../src/issue/mint-v2.ts";
import { mintAbrV2Disclosable } from "../src/issue/mint-disclosable.ts";
import { baseCommon, makeSigningKey, makeResolveKey, H } from "./_helpers/common.ts";

// baseCommon supplies issuer/profile("breach.gdpr.art33")/incident_correlation_id/policy_*/anchor.
// breach.assessed: TSA RECOMMENDED (not mandatory) — fully verifies without TSA,
// which a disclosable receipt must omit (re-sign voids the timestamp). breach.detected
// mandates TSA at the verifier, so it cannot be both disclosable AND fully verified.
function assessedInput() {
  return {
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "breach.assessed" as const,
    severity_class: "high_risk" as const,
    assessment_method_hash: H("a"),
  };
}

test("mintAbrV2Disclosable returns receipt + issuer-signed field_commit + 32-byte seed", async () => {
  const { receipt, fieldCommit, seed } = await mintAbrV2Disclosable(assessedInput());
  assert.equal(receipt.v, 2);
  assert.equal(receipt.claim_type, "ar.breach.v1");
  assert.equal(seed.length, 32);
  assert.equal(fieldCommit.kind, "ar.field_commit.v1");
  assert.equal(fieldCommit.family, "abr");
  assert.equal(fieldCommit.id, receipt.id);
  assert.equal(fieldCommit.field_root, (receipt.body as { field_root: string }).field_root);
  assert.equal(fieldCommit.leaf_count, 4); // four declared ABR leaves
  assert.equal(verifyFieldCommit(fieldCommit).valid, true);
});

test("disclosable field_root differs from the flat field_root (per-field tree, not whole-body)", async () => {
  const flat = await mintAbrV2(assessedInput());
  const { receipt: disc } = await mintAbrV2Disclosable(assessedInput());
  assert.notEqual(
    (flat.body as { field_root: string }).field_root,
    (disc.body as { field_root: string }).field_root,
  );
});

test("disclosable receipt still passes abr-verifier (full-body signature intact)", async () => {
  const { receipt } = await mintAbrV2Disclosable(assessedInput());
  const r = await verifyReceipt(receipt, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("mintAbrV2Disclosable rejects TSA in v0 (re-sign would invalidate the timestamp)", async () => {
  await assert.rejects(
    () => mintAbrV2Disclosable({ ...assessedInput(), tsa: {} as never, tsaFetcher: (async () => ({})) as never }),
    /TSA \+ disclosable/,
  );
});

test("mintAbrV2 (non-disclosable) is unchanged: returns a bare Envelope, flat field_root", async () => {
  const out = await mintAbrV2(assessedInput());
  assert.equal("fieldCommit" in (out as object), false);
  assert.match((out.body as { field_root: string }).field_root, /^sha256:[0-9a-f]{64}$/);
});
