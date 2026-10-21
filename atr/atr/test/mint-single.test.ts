/**
 * Tests for the four per-event-type convenience wrappers in mint-single.ts.
 * Each wrapper produces a receipt the verifier accepts and carries the
 * correct `event_type` discriminator in the body.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  mintArrangement,
  mintTransfer,
  mintTia,
  mintSuspension,
} from "../src/issue/index.ts";
import { mintAtrV2 } from "../src/issue/mint-v2.ts";
import { verifyReceipt } from "../src/index.ts";
import { baseCommon, H, makeResolveKey, makeSigningKey } from "./_helpers/common.ts";

// ── S1: mintArrangement round-trips ───────────────────────────────────────────

test("S1: mintArrangement round-trips", async () => {
  const env = await mintArrangement({
    ...baseCommon,
    signingKey: makeSigningKey(),
    arrangement_id_commit: H("a"),
    recipient_commit: H("b"),
    destination_country: "US",
    mechanism_version: "scc-2021-c-pp",
    contract_doc_hash: H("c"),
    in_force_from: "2026-05-21T00:00:00Z",
    supplementary_measures_hash: H("d"),
  });
  assert.equal((env.body as { event_type: string }).event_type, "arrangement");
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── S2: mintTransfer round-trips ──────────────────────────────────────────────

test("S2: mintTransfer round-trips", async () => {
  const env = await mintTransfer({
    ...baseCommon,
    signingKey: makeSigningKey(),
    subject: H("a"),
    arrangement_hash: H("b"),
    destination_country: "US",
    recipient_commit: H("c"),
    data_categories: ["contact"],
    subject_count_bucket: "10_99",
    transfer_window_start: "2026-05-01T00:00:00Z",
    transfer_window_end: "2026-05-31T23:59:59Z",
  });
  assert.equal((env.body as { event_type: string }).event_type, "transfer");
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── S3: mintTia round-trips ───────────────────────────────────────────────────

test("S3: mintTia round-trips", async () => {
  const env = await mintTia({
    ...baseCommon,
    signingKey: makeSigningKey(),
    arrangement_hash: H("b"),
    destination_country: "US",
    assessment_doc_hash: H("c"),
    surveillance_law_refs: ["FISA-702"],
    assessment_outcome: "permitted_plain",
    supplementary_measures_hash: H("d"),
    valid_from: "2026-05-01T00:00:00Z",
    valid_until: "2027-05-01T00:00:00Z",
  });
  assert.equal((env.body as { event_type: string }).event_type, "tia");
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── S4: mintSuspension round-trips ────────────────────────────────────────────

test("S4: mintSuspension round-trips", async () => {
  const env = await mintSuspension({
    ...baseCommon,
    signingKey: makeSigningKey(),
    prev: "01HARRANGEMENT000000000",
    trigger: "dpa_order",
    trigger_ref_hash: H("e"),
    effective_at: "2026-05-21T12:00:00Z",
  });
  assert.equal((env.body as { event_type: string }).event_type, "suspension");
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── S5: mintArrangement convenience matches mintAtrV2 structure ───────────────

test("S5: mintArrangement convenience matches mintAtrV2 structure", async () => {
  const signingKey = makeSigningKey();
  const inputBase = {
    ...baseCommon,
    signingKey,
    arrangement_id_commit: H("a"),
    recipient_commit: H("b"),
    destination_country: "DE",
    mechanism_version: "scc-2021-c-c",
    contract_doc_hash: H("c"),
    in_force_from: "2026-05-21T00:00:00Z",
    supplementary_measures_hash: H("d"),
  };

  const envConvenience = await mintArrangement(inputBase);
  const envDirect = await mintAtrV2({ ...inputBase, event_type: "arrangement" });

  assert.equal(envConvenience.claim_type, envDirect.claim_type);
  assert.equal(
    (envConvenience.body as { event_type: string }).event_type,
    (envDirect.body as { event_type: string }).event_type,
  );
});
