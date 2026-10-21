import { test } from "node:test";
import assert from "node:assert/strict";
import { buildPresentation, verifyPresentation, seedSaltSource, ABR_DISCLOSURE_SCHEMA } from "@dekimuhq/anchors-disclosure";
import { mintAbrV2Disclosable } from "../src/issue/mint-disclosable.ts";
import { baseCommon, makeSigningKey, H } from "./_helpers/common.ts";

// breach.assessed: TSA recommended (not mandatory) — see mint-disclosable.test.ts.
function assessedInput() {
  return {
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "breach.assessed" as const,
    severity_class: "high_risk" as const,
    assessment_method_hash: H("a"),
  };
}

// Holder rebuilds the tree from the body-minus-field_root + the seed.
function bodyNoRoot(receipt: { body: unknown }) {
  const { field_root: _r, ...rest } = receipt.body as Record<string, unknown>;
  return rest;
}

test("ABR disclosable receipt: reveal only /profile + /event_type, hide the rest", async () => {
  const { receipt, fieldCommit, seed } = await mintAbrV2Disclosable(assessedInput());
  const presentation = buildPresentation({
    body: bodyNoRoot(receipt),
    schema: ABR_DISCLOSURE_SCHEMA,
    salts: seedSaltSource(seed),
    fieldCommit,
    reveal: ["/profile", "/event_type"],
  });

  const r = verifyPresentation(presentation, { schema: ABR_DISCLOSURE_SCHEMA });
  assert.equal(r.valid, true);
  assert.deepEqual(r.revealed, { "/profile": "breach.gdpr.art33", "/event_type": "breach.assessed" });
  assert.equal(r.issuer, receipt.iss_key);
  // hidden leaves (/incident_correlation_id, /jurisdiction) are absent from the wire
  assert.equal(presentation.revealed.length, 2);
});

test("ABR disclosable receipt: tampering a revealed value is rejected", async () => {
  const { receipt, fieldCommit, seed } = await mintAbrV2Disclosable(assessedInput());
  const p = buildPresentation({
    body: bodyNoRoot(receipt), schema: ABR_DISCLOSURE_SCHEMA, salts: seedSaltSource(seed), fieldCommit, reveal: ["/incident_correlation_id"],
  });
  p.revealed[0]!.value = "INC-FORGED";
  assert.equal(verifyPresentation(p).valid, false);
});

test("ABR disclosable receipt: an untrusted issuer is rejected", async () => {
  const { receipt, fieldCommit, seed } = await mintAbrV2Disclosable(assessedInput());
  const p = buildPresentation({
    body: bodyNoRoot(receipt), schema: ABR_DISCLOSURE_SCHEMA, salts: seedSaltSource(seed), fieldCommit, reveal: ["/profile"],
  });
  const r = verifyPresentation(p, { trustIssuer: () => false });
  assert.equal(r.valid, false);
  assert.ok(r.reasons.includes("issuer_untrusted"));
});
