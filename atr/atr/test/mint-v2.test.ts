/**
 * Tests for mintAtrV2 — covers all 4 event types, validation guards,
 * chain constraints, and round-trip verification.
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { mintAtrV2 } from "../src/issue/mint-v2.ts";
import { generateAtrKeypair } from "../src/issue/keys.ts";
import { verifyReceipt } from "../src/index.ts";
import { anchor, baseCommon, H, makeResolveKey, makeSigningKey } from "./_helpers/common.ts";

const { signingKey } = generateAtrKeypair("test-key-1");

const commonOpts = {
  ...baseCommon,
  signingKey,
  anchor: {
    proof: "sha256:" + "1".repeat(64),
    kind: "merkle" as const,
    root: "sha256:" + "2".repeat(64),
  },
};

// ── V1: arrangement mint ──────────────────────────────────────────────────────

test("V1: arrangement produces v=2, claim_type=ar.transfer.v1, subject=null", async () => {
  const env = await mintAtrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "arrangement",
    arrangement_id_commit: H("a"),
    recipient_commit: H("b"),
    destination_country: "US",
    mechanism_version: "scc-2021-c-pp",
    contract_doc_hash: H("c"),
    in_force_from: "2026-05-21T00:00:00Z",
    supplementary_measures_hash: H("d"),
  });
  assert.equal(env.v, 2);
  assert.equal(env.claim_type, "ar.transfer.v1");
  assert.equal(env.subject, null);
  assert.equal((env.body as { event_type: string }).event_type, "arrangement");
  assert.ok(env.sig.length > 0);
});

// ── V2: transfer mint ─────────────────────────────────────────────────────────

test("V2: transfer produces v=2, subject=sha256, body.event_type=transfer", async () => {
  const env = await mintAtrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "transfer",
    subject: H("a"),
    arrangement_hash: H("b"),
    destination_country: "US",
    recipient_commit: H("c"),
    data_categories: ["contact", "financial"],
    subject_count_bucket: "10_99",
    transfer_window_start: "2026-05-01T00:00:00Z",
    transfer_window_end: "2026-05-31T23:59:59Z",
  });
  assert.equal(env.v, 2);
  assert.equal(env.claim_type, "ar.transfer.v1");
  assert.equal(env.subject, H("a"));
  assert.equal((env.body as { event_type: string }).event_type, "transfer");
  assert.ok(env.sig.length > 0);
});

// ── V3: tia mint ──────────────────────────────────────────────────────────────

test("V3: tia produces v=2, subject=null, body.event_type=tia", async () => {
  const env = await mintAtrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "tia",
    arrangement_hash: H("b"),
    destination_country: "US",
    assessment_doc_hash: H("c"),
    surveillance_law_refs: ["FISA-702", "EO-12333"],
    assessment_outcome: "permitted_with_supplementary",
    supplementary_measures_hash: H("d"),
    valid_from: "2026-05-01T00:00:00Z",
    valid_until: "2027-05-01T00:00:00Z",
  });
  assert.equal(env.v, 2);
  assert.equal(env.subject, null);
  assert.equal((env.body as { event_type: string }).event_type, "tia");
  assert.ok(env.sig.length > 0);
});

// ── V4: suspension mint ───────────────────────────────────────────────────────

test("V4: suspension produces v=2, subject=null, prev set", async () => {
  const env = await mintAtrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "suspension",
    prev: "01HARRANGEMENT000000000",
    trigger: "dpa_order",
    trigger_ref_hash: H("e"),
    effective_at: "2026-05-21T12:00:00Z",
  });
  assert.equal(env.v, 2);
  assert.equal(env.subject, null);
  assert.equal(env.prev, "01HARRANGEMENT000000000");
  assert.equal((env.body as { event_type: string }).event_type, "suspension");
  assert.ok(env.sig.length > 0);
});

// ── V5: transfer without sha256 subject throws ────────────────────────────────

test("V5: transfer without sha256 subject throws", async () => {
  await assert.rejects(
    () =>
      mintAtrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "transfer",
        subject: "not-a-hash",
        arrangement_hash: H("b"),
        destination_country: "US",
        recipient_commit: H("c"),
        data_categories: ["contact"],
        subject_count_bucket: "10_99",
        transfer_window_start: "2026-05-01T00:00:00Z",
        transfer_window_end: "2026-05-31T23:59:59Z",
      }),
    /sha256/,
  );
});

// ── V6: arrangement with prev throws ─────────────────────────────────────────

test("V6: arrangement with prev throws (chain head constraint)", async () => {
  await assert.rejects(
    () =>
      mintAtrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "arrangement",
        prev: "01HSOME000000000000000",
        arrangement_id_commit: H("a"),
        recipient_commit: H("b"),
        destination_country: "US",
        mechanism_version: "scc-2021-c-pp",
        contract_doc_hash: H("c"),
        in_force_from: "2026-05-21T00:00:00Z",
        supplementary_measures_hash: H("d"),
      }),
    /chain head/,
  );
});

// ── V7: suspension without prev throws ───────────────────────────────────────

test("V7: suspension without prev throws", async () => {
  await assert.rejects(
    () =>
      mintAtrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "suspension",
        trigger: "dpa_order",
        trigger_ref_hash: H("e"),
        effective_at: "2026-05-21T12:00:00Z",
      }),
    /prev/,
  );
});

// ── V8: arrangement round-trips through verifyReceipt ────────────────────────

test("V8: arrangement round-trips through verifyReceipt", async () => {
  const sk = makeSigningKey();
  const env = await mintAtrV2({
    ...baseCommon,
    signingKey: sk,
    event_type: "arrangement",
    arrangement_id_commit: H("a"),
    recipient_commit: H("b"),
    destination_country: "GB",
    mechanism_version: "idta-2022",
    contract_doc_hash: H("c"),
    in_force_from: "2026-05-21T00:00:00Z",
    supplementary_measures_hash: H("d"),
  });
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── V9: transfer round-trips through verifyReceipt ───────────────────────────

test("V9: transfer round-trips through verifyReceipt", async () => {
  const sk = makeSigningKey();
  const env = await mintAtrV2({
    ...baseCommon,
    signingKey: sk,
    event_type: "transfer",
    subject: H("a"),
    arrangement_hash: H("b"),
    destination_country: "US",
    recipient_commit: H("c"),
    data_categories: ["contact", "financial"],
    subject_count_bucket: "100_999",
    transfer_window_start: "2026-05-01T00:00:00Z",
    transfer_window_end: "2026-05-31T23:59:59Z",
  });
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── V10: tia round-trips through verifyReceipt ───────────────────────────────

test("V10: tia round-trips through verifyReceipt", async () => {
  const sk = makeSigningKey();
  const env = await mintAtrV2({
    ...baseCommon,
    signingKey: sk,
    event_type: "tia",
    arrangement_hash: H("b"),
    destination_country: "US",
    assessment_doc_hash: H("c"),
    surveillance_law_refs: ["FISA-702"],
    assessment_outcome: "permitted_plain",
    supplementary_measures_hash: H("d"),
    valid_from: "2026-05-01T00:00:00Z",
    valid_until: "2027-05-01T00:00:00Z",
  });
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── V11: suspension round-trips through verifyReceipt ────────────────────────

test("V11: suspension round-trips through verifyReceipt", async () => {
  const sk = makeSigningKey();
  const env = await mintAtrV2({
    ...baseCommon,
    signingKey: sk,
    event_type: "suspension",
    prev: "01HARRANGEMENT000000000",
    trigger: "adequacy_repeal",
    trigger_ref_hash: H("e"),
    effective_at: "2026-05-21T00:00:00Z",
  });
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── V12: body carries field_root ──────────────────────────────────────────────

test("V12: arrangement body carries field_root", async () => {
  const env = await mintAtrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "arrangement",
    arrangement_id_commit: H("a"),
    recipient_commit: H("b"),
    destination_country: "DE",
    mechanism_version: "scc-2021-c-c",
    contract_doc_hash: H("c"),
    in_force_from: "2026-05-21T00:00:00Z",
    supplementary_measures_hash: H("d"),
  });
  const body = env.body as Record<string, unknown>;
  assert.ok(typeof body["field_root"] === "string");
  assert.ok((body["field_root"] as string).startsWith("sha256:"));
});

// ── V12b: arrangement with non-null qts_attestation_hash round-trips ─────────

test("V12b: arrangement with qts_attestation_hash round-trips", async () => {
  const sk = makeSigningKey();
  const QTS_HASH = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
  const env = await mintAtrV2({
    ...baseCommon,
    signingKey: sk,
    event_type: "arrangement",
    arrangement_id_commit: H("a"),
    recipient_commit: H("b"),
    destination_country: "DE",
    mechanism_version: "scc-2021-c-c",
    contract_doc_hash: H("c"),
    in_force_from: "2026-05-22T00:00:00Z",
    supplementary_measures_hash: H("d"),
    qts_attestation_hash: QTS_HASH,
  });
  const body = env.body as Record<string, unknown>;
  assert.equal(body["qts_attestation_hash"], QTS_HASH);
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── V13: guard — issuer required ──────────────────────────────────────────────

test("V13: throws when issuer missing", async () => {
  await assert.rejects(
    () =>
      mintAtrV2({
        ...baseCommon,
        issuer: "",
        signingKey: makeSigningKey(),
        event_type: "arrangement",
        arrangement_id_commit: H("a"),
        recipient_commit: H("b"),
        destination_country: "US",
        mechanism_version: "scc-2021-c-pp",
        contract_doc_hash: H("c"),
        in_force_from: "2026-05-21T00:00:00Z",
        supplementary_measures_hash: H("d"),
      }),
    /issuer required/,
  );
});

// ── V14: guard — signingKey.kid required ──────────────────────────────────────

test("V14: throws when signingKey.kid missing", async () => {
  await assert.rejects(
    () =>
      mintAtrV2({
        ...baseCommon,
        signingKey: { kid: "", privateKey: new Uint8Array(32) },
        event_type: "arrangement",
        arrangement_id_commit: H("a"),
        recipient_commit: H("b"),
        destination_country: "US",
        mechanism_version: "scc-2021-c-pp",
        contract_doc_hash: H("c"),
        in_force_from: "2026-05-21T00:00:00Z",
        supplementary_measures_hash: H("d"),
      }),
    /signingKey\.kid required/,
  );
});

// ── V15: guard — private key must be 32 bytes ─────────────────────────────────

test("V15: throws when private key seed is wrong length", async () => {
  await assert.rejects(
    () =>
      mintAtrV2({
        ...baseCommon,
        signingKey: { kid: "k", privateKey: new Uint8Array(16) },
        event_type: "arrangement",
        arrangement_id_commit: H("a"),
        recipient_commit: H("b"),
        destination_country: "US",
        mechanism_version: "scc-2021-c-pp",
        contract_doc_hash: H("c"),
        in_force_from: "2026-05-21T00:00:00Z",
        supplementary_measures_hash: H("d"),
      }),
    /must be 32 bytes/,
  );
});

// ── V16: envelope carries anchor and policy fields ────────────────────────────

test("V16: envelope carries anchor and policy fields from input", async () => {
  const env = await mintAtrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "arrangement",
    arrangement_id_commit: H("a"),
    recipient_commit: H("b"),
    destination_country: "FR",
    mechanism_version: "scc-2021-c-pp",
    contract_doc_hash: H("c"),
    in_force_from: "2026-05-21T00:00:00Z",
    supplementary_measures_hash: H("d"),
  });
  assert.deepEqual(env.anchor, baseCommon.anchor);
  assert.equal(env.policy_uri, baseCommon.policy_uri);
  assert.equal(env.iss, baseCommon.issuer);
});

test("V17: countersig_key is committed when provided, omitted when absent", async () => {
  const countersig_key = "ed25519:countersigPubKeyTestValue" as const;
  const arrangement = {
    event_type: "arrangement" as const,
    arrangement_id_commit: H("a"),
    recipient_commit: H("b"),
    destination_country: "FR",
    mechanism_version: "scc-2021-c-pp",
    contract_doc_hash: H("c"),
    in_force_from: "2026-05-21T00:00:00Z",
    supplementary_measures_hash: H("d"),
  };

  const withKey = await mintAtrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    ...arrangement,
    countersig_key,
  });
  assert.equal(withKey.countersig_key, countersig_key);

  // Absent ⇒ field omitted entirely (not null) so pre-countersig receipts stay byte-equal.
  const withoutKey = await mintAtrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    ...arrangement,
  });
  assert.equal("countersig_key" in withoutKey, false);
});
