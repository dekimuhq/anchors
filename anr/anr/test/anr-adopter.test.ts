import { test } from "node:test";
import assert from "node:assert/strict";
import { buildPresentation, verifyPresentation, seedSaltSource, ANR_DISCLOSURE_SCHEMA } from "@dekimuhq/anchors-disclosure";
import { mintAnrV2Disclosable } from "../src/issue/mint-disclosable.ts";
import { baseCommon, makeSigningKey } from "./_helpers/common.ts";

function presentedInput() {
  return {
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "notice.presented" as const,
    jurisdiction: "EU",
    delivery_channel: "web" as const,
    render_uri: "https://example.test/n/v1",
    rights_surface: ["art15"],
  };
}

// Holder rebuilds the tree from the body-minus-field_root + the seed.
function bodyNoRoot(receipt: { body: unknown }) {
  const { field_root: _r, ...rest } = receipt.body as Record<string, unknown>;
  return rest;
}

test("ANR disclosable receipt: reveal only /profile + /lang_tag, hide the rest", async () => {
  const { receipt, fieldCommit, seed } = await mintAnrV2Disclosable(presentedInput());
  const presentation = buildPresentation({
    body: bodyNoRoot(receipt),
    schema: ANR_DISCLOSURE_SCHEMA,
    salts: seedSaltSource(seed),
    fieldCommit,
    reveal: ["/profile", "/lang_tag"],
  });

  const r = verifyPresentation(presentation, { schema: ANR_DISCLOSURE_SCHEMA });
  assert.equal(r.valid, true);
  assert.deepEqual(r.revealed, { "/profile": "notice.art13.collected_direct", "/lang_tag": "en-GB" });
  assert.equal(r.issuer, receipt.iss_key);
  // hidden leaves (/event_type, /jurisdiction) are absent from the wire
  assert.equal(presentation.revealed.length, 2);
});

test("ANR disclosable receipt: tampering a revealed value is rejected", async () => {
  const { receipt, fieldCommit, seed } = await mintAnrV2Disclosable(presentedInput());
  const p = buildPresentation({
    body: bodyNoRoot(receipt), schema: ANR_DISCLOSURE_SCHEMA, salts: seedSaltSource(seed), fieldCommit, reveal: ["/profile"],
  });
  p.revealed[0]!.value = "notice.FORGED";
  assert.equal(verifyPresentation(p).valid, false);
});

test("ANR disclosable receipt: an untrusted issuer is rejected", async () => {
  const { receipt, fieldCommit, seed } = await mintAnrV2Disclosable(presentedInput());
  const p = buildPresentation({
    body: bodyNoRoot(receipt), schema: ANR_DISCLOSURE_SCHEMA, salts: seedSaltSource(seed), fieldCommit, reveal: ["/profile"],
  });
  const r = verifyPresentation(p, { trustIssuer: () => false });
  assert.equal(r.valid, false);
  assert.ok(r.reasons.includes("issuer_untrusted"));
});
