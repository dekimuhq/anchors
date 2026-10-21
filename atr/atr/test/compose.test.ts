/**
 * Tests for composeAtr (spec §7 — chain-walk compose-warnings).
 *
 * Coverage:
 *   C1 — No resolver supplied → returns { ok: true } (no-op).
 *   C2 — Transfer event → skip chain walk → returns { ok: true }.
 *   C3 — TIA event → skip chain walk → returns { ok: true }.
 *   C4 — Resolver returns null for prev → returns { ok: true } (dangling ref,
 *        no crash).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { composeAtr } from "../src/compose.ts";
import type { AtrBody } from "../src/types.ts";

const STUB_RESOLVE_KEY = async () => new Uint8Array(0);

function makeEnvelope(eventType: string, prev: string | null = null) {
  const body: AtrBody =
    eventType === "arrangement"
      ? {
          event_type: "arrangement",
          arrangement_id_commit: "sha256:" + "a".repeat(64),
          recipient_commit: "sha256:" + "b".repeat(64),
          destination_country: "US",
          mechanism_version: "scc-2021-c-pp",
          contract_doc_hash: "sha256:" + "c".repeat(64),
          in_force_from: "2026-01-01T00:00:00Z",
          in_force_until: null,
          supplementary_measures_hash: "sha256:" + "d".repeat(64),
          qts_attestation_hash: null,
        }
      : eventType === "transfer"
        ? {
            event_type: "transfer",
            arrangement_hash: "sha256:" + "a".repeat(64),
            tia_hash: null,
            destination_country: "US",
            recipient_commit: "sha256:" + "b".repeat(64),
            data_categories: ["contact"],
            subject_count_bucket: "1",
            transfer_window_start: "2026-01-01T00:00:00Z",
            transfer_window_end: "2026-06-01T00:00:00Z",
            artifact_apr_hash: null,
            consent_receipt_hash: null,
            purpose_binding_hash: null,
            qts_attestation_hash: null,
          }
        : eventType === "tia"
          ? {
              event_type: "tia",
              arrangement_hash: "sha256:" + "a".repeat(64),
              destination_country: "US",
              assessment_doc_hash: "sha256:" + "e".repeat(64),
              surveillance_law_refs: [],
              assessment_outcome: "permitted_plain",
              supplementary_measures_hash: "sha256:" + "f".repeat(64),
              valid_from: "2026-01-01T00:00:00Z",
              valid_until: "2027-01-01T00:00:00Z",
              qts_attestation_hash: null,
            }
          : {
              event_type: "suspension",
              trigger: "dpa_order",
              trigger_ref_hash: "sha256:" + "g".repeat(64),
              effective_at: "2026-03-01T00:00:00Z",
              qts_attestation_hash: null,
            };

  return {
    id: "r-001",
    claim_type: "ar.transfer.v1",
    iss: "did:web:dekimu.com",
    iat: "2026-05-21T10:00:00Z",
    prev,
    subject: null,
    profile: "gdpr.art46.scc",
    body,
  };
}

test("C1 — no resolver → returns { ok: true }", async () => {
  const result = await composeAtr({
    envelope: makeEnvelope("arrangement"),
    opts: { resolveKey: STUB_RESOLVE_KEY },
  });
  assert.deepEqual(result, { ok: true });
});

test("C2 — transfer event → skip chain walk → returns { ok: true }", async () => {
  const resolver = async (_id: string) => {
    throw new Error("should not be called for transfer event");
  };
  const result = await composeAtr({
    envelope: makeEnvelope("transfer"),
    opts: {
      resolveKey: STUB_RESOLVE_KEY,
      resolveReceiptById: resolver,
    },
  });
  assert.deepEqual(result, { ok: true });
});

test("C3 — tia event → skip chain walk → returns { ok: true }", async () => {
  const resolver = async (_id: string) => {
    throw new Error("should not be called for tia event");
  };
  const result = await composeAtr({
    envelope: makeEnvelope("tia"),
    opts: {
      resolveKey: STUB_RESOLVE_KEY,
      resolveReceiptById: resolver,
    },
  });
  assert.deepEqual(result, { ok: true });
});

test("C4 — resolver returns null for prev → returns { ok: true } (dangling ref)", async () => {
  const result = await composeAtr({
    envelope: makeEnvelope("arrangement", "r-prev-missing"),
    opts: {
      resolveKey: STUB_RESOLVE_KEY,
      resolveReceiptById: async (_id: string) => null,
    },
  });
  assert.deepEqual(result, { ok: true });
});
