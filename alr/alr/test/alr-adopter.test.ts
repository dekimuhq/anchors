import { test } from "node:test";
import assert from "node:assert/strict";
import { buildPresentation, verifyPresentation, seedSaltSource, ALR_DISCLOSURE_SCHEMA } from "@dekimuhq/anchors-disclosure";
import { mintAlrV2Disclosable } from "../src/issue/mint-disclosable.ts";
import { baseCommon, makeSigningKey, H } from "./_helpers/common.ts";

function derivedInput() {
  return {
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "derived_from" as const,
    parents: [{ artifact_hash: H("b"), parent_apr_id: null, parent_alr_id: null, uri: null }],
    transform_claim: { summary: "joined two tables", uri: null },
  };
}

// Holder rebuilds the tree from the body-minus-field_root + the seed.
function bodyNoRoot(receipt: { body: unknown }) {
  const { field_root: _r, ...rest } = receipt.body as Record<string, unknown>;
  return rest;
}

test("ALR disclosable receipt: reveal only /profile + /event_type, hide the rest", async () => {
  const { receipt, fieldCommit, seed } = await mintAlrV2Disclosable(derivedInput());
  const presentation = buildPresentation({
    body: bodyNoRoot(receipt),
    schema: ALR_DISCLOSURE_SCHEMA,
    salts: seedSaltSource(seed),
    fieldCommit,
    reveal: ["/profile", "/event_type"],
  });

  const r = verifyPresentation(presentation, { schema: ALR_DISCLOSURE_SCHEMA });
  assert.equal(r.valid, true);
  assert.deepEqual(r.revealed, { "/profile": "gdpr.art13.transparency", "/event_type": "derived_from" });
  assert.equal(r.issuer, receipt.iss_key);
  // hidden leaves (/artifact_hash, /event_at) are absent from the wire
  assert.equal(presentation.revealed.length, 2);
});

test("ALR disclosable receipt: tampering a revealed value is rejected", async () => {
  const { receipt, fieldCommit, seed } = await mintAlrV2Disclosable(derivedInput());
  const p = buildPresentation({
    body: bodyNoRoot(receipt), schema: ALR_DISCLOSURE_SCHEMA, salts: seedSaltSource(seed), fieldCommit, reveal: ["/profile"],
  });
  p.revealed[0]!.value = "aiact.art13.transparency";
  assert.equal(verifyPresentation(p).valid, false);
});

test("ALR disclosable receipt: an untrusted issuer is rejected", async () => {
  const { receipt, fieldCommit, seed } = await mintAlrV2Disclosable(derivedInput());
  const p = buildPresentation({
    body: bodyNoRoot(receipt), schema: ALR_DISCLOSURE_SCHEMA, salts: seedSaltSource(seed), fieldCommit, reveal: ["/profile"],
  });
  const r = verifyPresentation(p, { trustIssuer: () => false });
  assert.equal(r.valid, false);
  assert.ok(r.reasons.includes("issuer_untrusted"));
});
