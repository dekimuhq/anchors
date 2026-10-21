/**
 * Tests for the gdpr.art49.derogation profile validator (ATR §5.6).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { AtrBody } from "@dekimuhq/atr-profiles";
import {
  GDPR_ART49_DEROGATION_PROFILE_ID,
  validateGdprArt49Derogation,
  validateGdprArt49DerogationProfile,
} from "../src/gdpr-art49-derogation.ts";

function makeArrangementBody(): AtrBody {
  return {
    event_type: "arrangement",
    arrangement_id_commit: "h:abc",
    recipient_commit: "h:def",
    destination_country: "US",
    mechanism_version: "art49-1-a",
    contract_doc_hash: "h:ghi",
    in_force_from: "2026-01-01T00:00:00Z",
    in_force_until: null,
    supplementary_measures_hash: "h:jkl",
    qts_attestation_hash: null,
  } as AtrBody;
}

function makeTransferBody(): AtrBody {
  return {
    event_type: "transfer",
    arrangement_hash: "h:arr",
    tia_hash: null,
    destination_country: "US",
    recipient_commit: "h:def",
    data_categories: ["contact"],
    subject_count_bucket: "1",
    transfer_window_start: "2026-01-01T00:00:00Z",
    transfer_window_end: "2026-01-02T00:00:00Z",
    artifact_apr_hash: null,
    consent_receipt_hash: null,
    purpose_binding_hash: null,
    qts_attestation_hash: null,
  } as AtrBody;
}

function makeTiaBody(): AtrBody {
  return {
    event_type: "tia",
    arrangement_hash: "h:arr",
    destination_country: "US",
    assessment_doc_hash: "h:doc",
    surveillance_law_refs: ["ref1"],
    assessment_outcome: "permitted_plain",
    supplementary_measures_hash: "h:sup",
    valid_from: "2026-01-01T00:00:00Z",
    valid_until: "2027-01-01T00:00:00Z",
    qts_attestation_hash: null,
  } as AtrBody;
}

// ── Pass through for all event types ─────────────────────────────────────────

test("gdpr-art49-derogation: arrangement event passes with no errors", () => {
  const out = validateGdprArt49Derogation(makeArrangementBody());
  assert.deepEqual(out.errors, []);
});

test("gdpr-art49-derogation: transfer event passes with no errors", () => {
  const out = validateGdprArt49Derogation(makeTransferBody());
  assert.deepEqual(out.errors, []);
});

test("gdpr-art49-derogation: tia event passes with no errors", () => {
  const out = validateGdprArt49Derogation(makeTiaBody());
  assert.deepEqual(out.errors, []);
});

// ── Adapter ───────────────────────────────────────────────────────────────────

test("gdpr-art49-derogation adapter: ok=true on arrangement event", () => {
  const out = validateGdprArt49DerogationProfile({} as never, makeArrangementBody(), {});
  assert.equal(out.profile_id, GDPR_ART49_DEROGATION_PROFILE_ID);
  assert.equal(out.ok, true);
  assert.equal(out.reason, undefined);
});

test("gdpr-art49-derogation adapter: ok=true on transfer event", () => {
  const out = validateGdprArt49DerogationProfile({} as never, makeTransferBody(), {});
  assert.equal(out.ok, true);
});

test("gdpr-art49-derogation adapter: ok=true on tia event", () => {
  const out = validateGdprArt49DerogationProfile({} as never, makeTiaBody(), {});
  assert.equal(out.ok, true);
});
