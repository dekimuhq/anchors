/**
 * Tests for the gdpr.art47.bcr_authorised profile validator (ATR §5.5).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { AtrBody } from "@dekimuhq/atr-profiles";
import {
  GDPR_ART47_BCR_AUTHORISED_PROFILE_ID,
  validateGdprArt47BcrAuthorised,
  validateGdprArt47BcrAuthorisedProfile,
} from "../src/gdpr-art47-bcr-authorised.ts";

function makeArrangementBody(
  overrides?: Record<string, unknown>,
): AtrBody {
  return {
    event_type: "arrangement",
    arrangement_id_commit: "h:abc",
    recipient_commit: "h:def",
    destination_country: "US",
    mechanism_version: "bcr-c-authorised",
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

// ── Happy path ────────────────────────────────────────────────────────────────

test("gdpr-art47-bcr-authorised: bcr-c-authorised passes", () => {
  const out = validateGdprArt47BcrAuthorised(makeArrangementBody({ mechanism_version: "bcr-c-authorised" }));
  assert.deepEqual(out.errors, []);
});

test("gdpr-art47-bcr-authorised: bcr-p-authorised passes", () => {
  const out = validateGdprArt47BcrAuthorised(makeArrangementBody({ mechanism_version: "bcr-p-authorised" }));
  assert.deepEqual(out.errors, []);
});

// ── Invalid mechanism_version ─────────────────────────────────────────────────

test("gdpr-art47-bcr-authorised: bcr-c (non-authorised) is invalid for this profile", () => {
  const out = validateGdprArt47BcrAuthorised(makeArrangementBody({ mechanism_version: "bcr-c" }));
  assert.ok(out.errors.includes("gdpr.art47.bcr_authorised.mechanism_version_invalid"));
});

test("gdpr-art47-bcr-authorised: bcr-p (non-authorised) is invalid for this profile", () => {
  const out = validateGdprArt47BcrAuthorised(makeArrangementBody({ mechanism_version: "bcr-p" }));
  assert.ok(out.errors.includes("gdpr.art47.bcr_authorised.mechanism_version_invalid"));
});

test("gdpr-art47-bcr-authorised: scc-2021-c-pp is invalid for this profile", () => {
  const out = validateGdprArt47BcrAuthorised(makeArrangementBody({ mechanism_version: "scc-2021-c-pp" }));
  assert.ok(out.errors.includes("gdpr.art47.bcr_authorised.mechanism_version_invalid"));
});

// ── Non-arrangement events pass through ───────────────────────────────────────

test("gdpr-art47-bcr-authorised: transfer event passes through with no errors", () => {
  const out = validateGdprArt47BcrAuthorised(makeTransferBody());
  assert.deepEqual(out.errors, []);
});

// ── Adapter ───────────────────────────────────────────────────────────────────

test("gdpr-art47-bcr-authorised adapter: ok=true on bcr-c-authorised", () => {
  const out = validateGdprArt47BcrAuthorisedProfile({} as never, makeArrangementBody(), {});
  assert.equal(out.profile_id, GDPR_ART47_BCR_AUTHORISED_PROFILE_ID);
  assert.equal(out.ok, true);
  assert.equal(out.reason, undefined);
});

test("gdpr-art47-bcr-authorised adapter: ok=false and reason set on bcr-c", () => {
  const out = validateGdprArt47BcrAuthorisedProfile(
    {} as never,
    makeArrangementBody({ mechanism_version: "bcr-c" }),
    {},
  );
  assert.equal(out.ok, false);
  assert.equal(out.reason, "gdpr.art47.bcr_authorised.mechanism_version_invalid");
});

test("gdpr-art47-bcr-authorised adapter: ok=true on non-arrangement event", () => {
  const out = validateGdprArt47BcrAuthorisedProfile({} as never, makeTransferBody(), {});
  assert.equal(out.ok, true);
});
