/**
 * Tests for the gdpr.art45.adequacy profile validator (ATR §5.1).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { AtrBody } from "@dekimuhq/atr-profiles";
import {
  GDPR_ART45_ADEQUACY_PROFILE_ID,
  validateGdprArt45Adequacy,
  validateGdprArt45AdequacyProfile,
} from "../src/gdpr-art45-adequacy.ts";

function makeArrangementBody(
  overrides?: Record<string, unknown>,
): AtrBody {
  return {
    event_type: "arrangement",
    arrangement_id_commit: "h:abc",
    recipient_commit: "h:def",
    destination_country: "CH",
    mechanism_version: "adequacy:CH",
    contract_doc_hash: "h:ghi",
    in_force_from: "2026-01-01T00:00:00Z",
    in_force_until: null,
    supplementary_measures_hash: "h:jkl",
    qts_attestation_hash: null,
    ...overrides,
  } as AtrBody;
}

function makeTransferBody(): AtrBody {
  return {
    event_type: "transfer",
    arrangement_hash: "h:arr",
    tia_hash: null,
    destination_country: "CH",
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

// ── Happy path ────────────────────────────────────────────────────────────────

test("gdpr-art45-adequacy: adequacy:CH passes", () => {
  const out = validateGdprArt45Adequacy(makeArrangementBody({ mechanism_version: "adequacy:CH" }));
  assert.deepEqual(out.errors, []);
});

test("gdpr-art45-adequacy: adequacy:UK passes", () => {
  const out = validateGdprArt45Adequacy(makeArrangementBody({ mechanism_version: "adequacy:UK" }));
  assert.deepEqual(out.errors, []);
});

test("gdpr-art45-adequacy: adequacy:JP passes", () => {
  const out = validateGdprArt45Adequacy(makeArrangementBody({ mechanism_version: "adequacy:JP" }));
  assert.deepEqual(out.errors, []);
});

// ── Invalid mechanism_version ─────────────────────────────────────────────────

test("gdpr-art45-adequacy: scc-2021-c-pp is invalid for this profile", () => {
  const out = validateGdprArt45Adequacy(makeArrangementBody({ mechanism_version: "scc-2021-c-pp" }));
  assert.ok(out.errors.includes("gdpr.art45.adequacy.mechanism_version_invalid"));
});

test("gdpr-art45-adequacy: lower-case country code is invalid", () => {
  const out = validateGdprArt45Adequacy(makeArrangementBody({ mechanism_version: "adequacy:ch" }));
  assert.ok(out.errors.includes("gdpr.art45.adequacy.mechanism_version_invalid"));
});

test("gdpr-art45-adequacy: missing country code is invalid", () => {
  const out = validateGdprArt45Adequacy(makeArrangementBody({ mechanism_version: "adequacy:" }));
  assert.ok(out.errors.includes("gdpr.art45.adequacy.mechanism_version_invalid"));
});

test("gdpr-art45-adequacy: three-letter country code is invalid", () => {
  const out = validateGdprArt45Adequacy(makeArrangementBody({ mechanism_version: "adequacy:CHE" }));
  assert.ok(out.errors.includes("gdpr.art45.adequacy.mechanism_version_invalid"));
});

// ── Non-arrangement events pass through ───────────────────────────────────────

test("gdpr-art45-adequacy: transfer event passes through with no errors", () => {
  const out = validateGdprArt45Adequacy(makeTransferBody());
  assert.deepEqual(out.errors, []);
});

// ── Adapter ───────────────────────────────────────────────────────────────────

test("gdpr-art45-adequacy adapter: ok=true on adequacy:CH arrangement", () => {
  const out = validateGdprArt45AdequacyProfile({} as never, makeArrangementBody(), {});
  assert.equal(out.profile_id, GDPR_ART45_ADEQUACY_PROFILE_ID);
  assert.equal(out.ok, true);
  assert.equal(out.reason, undefined);
});

test("gdpr-art45-adequacy adapter: ok=false and reason set on invalid version", () => {
  const out = validateGdprArt45AdequacyProfile(
    {} as never,
    makeArrangementBody({ mechanism_version: "scc-2021-c-pp" }),
    {},
  );
  assert.equal(out.ok, false);
  assert.equal(out.reason, "gdpr.art45.adequacy.mechanism_version_invalid");
});

test("gdpr-art45-adequacy adapter: ok=true on non-arrangement event", () => {
  const out = validateGdprArt45AdequacyProfile({} as never, makeTransferBody(), {});
  assert.equal(out.ok, true);
});
