import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyFieldCommit } from "@dekimuhq/anchors-envelope";
import { verifyReceipt } from "../src/index.ts";
import { mintAnrV2 } from "../src/issue/mint-v2.ts";
import { mintAnrV2Disclosable } from "../src/issue/mint-disclosable.ts";
import { baseCommon, makeSigningKey, makeResolveKey } from "./_helpers/common.ts";

// baseCommon supplies issuer/profile("notice.art13.collected_direct")/lang_tag("en-GB")/policy_*/anchor.
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

test("mintAnrV2Disclosable returns receipt + issuer-signed field_commit + 32-byte seed", async () => {
  const { receipt, fieldCommit, seed } = await mintAnrV2Disclosable(presentedInput());
  assert.equal(receipt.v, 2);
  assert.equal(receipt.claim_type, "ar.notice.v1");
  assert.equal(seed.length, 32);
  assert.equal(fieldCommit.kind, "ar.field_commit.v1");
  assert.equal(fieldCommit.family, "anr");
  assert.equal(fieldCommit.id, receipt.id);
  assert.equal(fieldCommit.field_root, (receipt.body as { field_root: string }).field_root);
  assert.equal(fieldCommit.leaf_count, 4); // four declared ANR leaves
  assert.equal(verifyFieldCommit(fieldCommit).valid, true);
});

test("disclosable field_root differs from the flat field_root (per-field tree, not whole-body)", async () => {
  const flat = await mintAnrV2(presentedInput());
  const { receipt: disc } = await mintAnrV2Disclosable(presentedInput());
  assert.notEqual(
    (flat.body as { field_root: string }).field_root,
    (disc.body as { field_root: string }).field_root,
  );
});

test("disclosable receipt still passes anr-verifier (full-body signature intact)", async () => {
  const { receipt } = await mintAnrV2Disclosable(presentedInput());
  const r = await verifyReceipt(receipt, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("mintAnrV2Disclosable rejects TSA in v0 (re-sign would invalidate the timestamp)", async () => {
  // Cast a minimal TsaConfig/fetcher — the reject fires before either is used.
  await assert.rejects(
    () => mintAnrV2Disclosable({ ...presentedInput(), tsa: {} as never, tsaFetcher: (async () => ({})) as never }),
    /TSA \+ disclosable/,
  );
});

test("mintAnrV2 (non-disclosable) is unchanged: returns a bare Envelope, flat field_root", async () => {
  const out = await mintAnrV2(presentedInput());
  assert.equal("fieldCommit" in (out as object), false);
  assert.match((out.body as { field_root: string }).field_root, /^sha256:[0-9a-f]{64}$/);
});
