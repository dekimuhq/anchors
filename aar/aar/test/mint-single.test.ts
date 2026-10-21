/**
 * Tests for the per-event-type convenience wrappers in mint-single.ts.
 * Each wrapper produces a receipt the verifier accepts and carries the
 * correct `event_type` discriminator in the body.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { mintIssuance, mintRevocation } from "../src/issue/index.ts";
import { verifyReceipt } from "../src/index.ts";
import { baseCommon, makeResolveKey, makeSigningKey } from "./_helpers/common.ts";

// qes requires: artefact_hash (sha256), signature_format, qcert_serial_commit
const baseIssuance = {
  service_type: "qes" as const,
  service_policy_oid: "0.4.0.1862.1.1",
  service_recipient_commit: "sha256:" + "b".repeat(64),
  artefact_hash: "sha256:" + "a".repeat(64),
  artefact_metadata_commit: "sha256:" + "c".repeat(64),
  signature_format: "pades_b_lta" as const,
  qcert_serial_commit: "sha256:" + "9".repeat(64),
  tsl_country: "ES",
  tsl_entry_hash: "sha256:" + "d".repeat(64),
  tsl_signed_tree_head_root: "sha256:" + "f".repeat(64),
  tsl_tree_size: 42,
  tsl_inclusion_proof: [],
  tsl_log_time: "2026-05-16T10:00:00Z",
};

// ── S1: mintIssuance mints without event_type ─────────────────────────────────

test("S1: mintIssuance mints without event_type, body.event_type='issuance', round-trip passes", async () => {
  const env = await mintIssuance({
    ...baseCommon,
    signingKey: makeSigningKey(),
    ...baseIssuance,
  });
  assert.equal((env.body as { event_type: string }).event_type, "issuance");
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── S2: mintRevocation mints without event_type ───────────────────────────────

test("S2: mintRevocation mints without event_type, body.event_type='revocation', round-trip passes", async () => {
  const env = await mintRevocation({
    ...baseCommon,
    signingKey: makeSigningKey(),
    prev: "01HISSUANCE00000000000000",
    reason: "tsl_delisted",
    tsl_country: "DE",
    tsl_entry_hash: "sha256:" + "d".repeat(64),
    tsl_signed_tree_head_root: "sha256:" + "f".repeat(64),
    tsl_tree_size: 10,
    tsl_inclusion_proof: [],
    tsl_log_time: "2026-05-16T14:00:00Z",
  });
  assert.equal((env.body as { event_type: string }).event_type, "revocation");
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});
