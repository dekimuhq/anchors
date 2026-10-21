import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyFieldCommit } from "@dekimuhq/anchors-envelope";
import { verifyReceipt } from "../src/index.ts";
import { mintAlrV2 } from "../src/issue/mint-v2.ts";
import { mintAlrV2Disclosable } from "../src/issue/mint-disclosable.ts";
import { baseCommon, makeSigningKey, makeResolveKey, H } from "./_helpers/common.ts";

// baseCommon supplies issuer/profile("gdpr.art13.transparency")/artifact_hash/event_at/policy_*/anchor.
function derivedInput() {
  return {
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "derived_from" as const,
    parents: [{ artifact_hash: H("b"), parent_apr_id: null, parent_alr_id: null, uri: null }],
    transform_claim: { summary: "joined two tables", uri: null },
  };
}

test("mintAlrV2Disclosable returns receipt + issuer-signed field_commit + 32-byte seed", async () => {
  const { receipt, fieldCommit, seed } = await mintAlrV2Disclosable(derivedInput());
  assert.equal(receipt.v, 2);
  assert.equal(receipt.claim_type, "ar.lineage.v1");
  assert.equal(seed.length, 32);
  assert.equal(fieldCommit.kind, "ar.field_commit.v1");
  assert.equal(fieldCommit.family, "alr");
  assert.equal(fieldCommit.id, receipt.id);
  assert.equal(fieldCommit.field_root, (receipt.body as { field_root: string }).field_root);
  assert.equal(fieldCommit.leaf_count, 4); // four declared ALR leaves
  assert.equal(verifyFieldCommit(fieldCommit).valid, true);
});

test("disclosable field_root differs from the flat field_root (per-field tree, not whole-body)", async () => {
  const flat = await mintAlrV2(derivedInput());
  const { receipt: disc } = await mintAlrV2Disclosable(derivedInput());
  assert.notEqual(
    (flat.body as { field_root: string }).field_root,
    (disc.body as { field_root: string }).field_root,
  );
});

test("disclosable receipt still passes alr-verifier (full-body signature intact)", async () => {
  const { receipt } = await mintAlrV2Disclosable(derivedInput());
  const r = await verifyReceipt(receipt, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("mintAlrV2Disclosable rejects TSA in v0 (re-sign would invalidate the timestamp)", async () => {
  await assert.rejects(
    () => mintAlrV2Disclosable({ ...derivedInput(), tsa: {} as never, tsaFetcher: (async () => ({})) as never }),
    /TSA \+ disclosable/,
  );
});

test("mintAlrV2 (non-disclosable) is unchanged: returns a bare Envelope, flat field_root", async () => {
  const out = await mintAlrV2(derivedInput());
  assert.equal("fieldCommit" in (out as object), false);
  assert.match((out.body as { field_root: string }).field_root, /^sha256:[0-9a-f]{64}$/);
});
