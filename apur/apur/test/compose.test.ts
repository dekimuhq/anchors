/**
 * Tests for composeApur (spec §7.2 — chain-walk compose-warnings).
 *
 * Coverage:
 *   C1 — No resolver supplied → returns { ok: true } (no-op).
 *   C2 — Single binding receipt → returns { ok: true } (no warnings).
 *   C3 — Binding + repurpose chain → returns { ok: true }.
 *   C4 — Aborted retest (compat_conclusion="incompatible_aborted") without
 *        unbinding → warning "apur.aborted_retest_still_open" surfaced.
 *   C5 — Aborted retest + unbinding → no warning.
 *   C6 — Non-projectable resolved object → graceful no-op.
 *   C7 — Resolver returns null (dangling ref) → graceful no-op.
 *   C8 — Null body on projection → graceful no-op.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { composeApur } from "../src/compose.ts";
import type { ApurBindingBody, ApurRepurposeBody, ApurUnbindingBody } from "../src/types.ts";

const STUB_RESOLVE_KEY = async () => new Uint8Array(0);

const BINDING_BODY: ApurBindingBody = {
  event_type: "binding",
  activity_id_commit: "sha256:" + "a".repeat(64),
  purpose_commit: "sha256:" + "b".repeat(64),
  purpose_class: "marketing",
  lawful_basis: "consent",
  data_categories: ["contact"],
  data_subjects_class: "customers",
  policy_hash: "sha256:" + "c".repeat(64),
  minimisation_hash: "sha256:" + "d".repeat(64),
  consent_receipt_hash: null,
  retention_receipt_hash: null,
  transfer_arrangement_hash: null,
  bound_at: "2026-01-01T00:00:00Z",
  qts_attestation_hash: null,
};

const REPURPOSE_BODY: ApurRepurposeBody = {
  event_type: "repurpose",
  new_purpose_commit: "sha256:" + "e".repeat(64),
  new_purpose_class: "analytics",
  compat_link_hash: "sha256:" + "f".repeat(64),
  compat_context_hash: "sha256:" + "g".repeat(64),
  compat_subjects_reasonable_hash: "sha256:" + "h".repeat(64),
  compat_consequences_hash: "sha256:" + "i".repeat(64),
  compat_safeguards_hash: "sha256:" + "j".repeat(64),
  compat_conclusion: "compatible",
  minimisation_hash: "sha256:" + "k".repeat(64),
  tested_at: "2026-02-01T00:00:00Z",
  qts_attestation_hash: null,
};

const ABORTED_REPURPOSE_BODY: ApurRepurposeBody = {
  ...REPURPOSE_BODY,
  compat_conclusion: "incompatible_aborted",
};

const UNBINDING_BODY: ApurUnbindingBody = {
  event_type: "unbinding",
  reason: "purpose_fulfilled",
  downstream_arr_receipt_hash: null,
  unbound_at: "2026-03-01T00:00:00Z",
  qts_attestation_hash: null,
};

function makeEnvelope(
  id: string,
  prev: string | null,
  body: ApurBindingBody | ApurRepurposeBody | ApurUnbindingBody,
) {
  return {
    id,
    claim_type: "ar.purpose.v1",
    iss: "did:web:dekimu.com",
    iat: "2026-01-15T10:00:00Z",
    prev,
    subject: "sha256:" + "z".repeat(64),
    body,
  };
}

test("C1 — no resolver → returns { ok: true }", async () => {
  const result = await composeApur({
    envelope: makeEnvelope("r-001", null, BINDING_BODY),
    opts: { resolveKey: STUB_RESOLVE_KEY },
  });
  assert.deepEqual(result, { ok: true });
});

test("C2 — single binding receipt → returns { ok: true } (no warnings)", async () => {
  const result = await composeApur({
    envelope: makeEnvelope("r-001", null, BINDING_BODY),
    opts: {
      resolveKey: STUB_RESOLVE_KEY,
      resolveReceiptById: async (_id: string) => null,
    },
  });
  assert.deepEqual(result, { ok: true });
});

test("C3 — binding + repurpose chain → returns { ok: true }", async () => {
  const binding = makeEnvelope("r-001", null, BINDING_BODY);
  const repurpose = makeEnvelope("r-002", "r-001", REPURPOSE_BODY);

  const corpus: Record<string, unknown> = {
    "r-001": binding,
  };

  const result = await composeApur({
    envelope: repurpose,
    opts: {
      resolveKey: STUB_RESOLVE_KEY,
      resolveReceiptById: async (id: string) => corpus[id] ?? null,
    },
  });
  assert.deepEqual(result, { ok: true });
});

test("C4 — aborted retest without unbinding → warning apur.aborted_retest_still_open", async () => {
  const binding = makeEnvelope("r-001", null, BINDING_BODY);
  const repurpose = makeEnvelope("r-002", "r-001", ABORTED_REPURPOSE_BODY);

  const corpus: Record<string, unknown> = {
    "r-001": binding,
  };

  const result = await composeApur({
    envelope: repurpose,
    opts: {
      resolveKey: STUB_RESOLVE_KEY,
      resolveReceiptById: async (id: string) => corpus[id] ?? null,
    },
  });
  assert.deepEqual(result, { ok: true, warnings: ["apur.aborted_retest_still_open"] });
});

test("C5 — aborted retest + unbinding → no warning", async () => {
  const binding = makeEnvelope("r-001", null, BINDING_BODY);
  const repurpose = makeEnvelope("r-002", "r-001", ABORTED_REPURPOSE_BODY);
  const unbinding = makeEnvelope("r-003", "r-002", UNBINDING_BODY);

  const corpus: Record<string, unknown> = {
    "r-001": binding,
    "r-002": repurpose,
  };

  const result = await composeApur({
    envelope: unbinding,
    opts: {
      resolveKey: STUB_RESOLVE_KEY,
      resolveReceiptById: async (id: string) => corpus[id] ?? null,
    },
  });
  assert.deepEqual(result, { ok: true });
});

test("C6 — non-projectable resolved object → graceful no-op", async () => {
  // prev points to something with no body.event_type
  const malformed = { id: "r-001", iss: "did:web:dekimu.com", iat: "2026-01-01T00:00:00Z", prev: null, body: 42 };

  const result = await composeApur({
    envelope: makeEnvelope("r-002", "r-001", REPURPOSE_BODY),
    opts: {
      resolveKey: STUB_RESOLVE_KEY,
      resolveReceiptById: async (_id: string) => malformed,
    },
  });
  assert.deepEqual(result, { ok: true });
});

test("C7 — resolver returns null (dangling ref) → graceful no-op", async () => {
  const result = await composeApur({
    envelope: makeEnvelope("r-002", "r-001", REPURPOSE_BODY),
    opts: {
      resolveKey: STUB_RESOLVE_KEY,
      resolveReceiptById: async (_id: string) => null,
    },
  });
  assert.deepEqual(result, { ok: true });
});

test("C8 — null body on projection → graceful no-op", async () => {
  // Envelope itself has null body — projectChainReceipt will return null
  const result = await composeApur({
    envelope: {
      id: "r-001",
      claim_type: "ar.purpose.v1",
      iss: "did:web:dekimu.com",
      iat: "2026-01-15T10:00:00Z",
      prev: null,
      subject: null,
      body: null as unknown as ApurBindingBody,
    },
    opts: {
      resolveKey: STUB_RESOLVE_KEY,
      resolveReceiptById: async (_id: string) => null,
    },
  });
  assert.deepEqual(result, { ok: true });
});
