/**
 * Tests for the gdpr.art46.idta profile validator (ATR §5.4).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { AtrBody } from "@dekimuhq/atr-profiles";
import {
  GDPR_ART46_IDTA_PROFILE_ID,
  validateGdprArt46Idta,
  validateGdprArt46IdtaProfile,
} from "../src/gdpr-art46-idta.ts";

function makeArrangementBody(
  overrides?: Record<string, unknown>,
): AtrBody {
  return {
    event_type: "arrangement",
    arrangement_id_commit: "h:abc",
    recipient_commit: "h:def",
    destination_country: "GB",
    mechanism_version: "idta-2022",
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
    destination_country: "GB",
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

test("gdpr-art46-idta: idta-2022 passes", () => {
  const out = validateGdprArt46Idta(makeArrangementBody({ mechanism_version: "idta-2022" }));
  assert.deepEqual(out.errors, []);
});

test("gdpr-art46-idta: addendum-2022 passes", () => {
  const out = validateGdprArt46Idta(makeArrangementBody({ mechanism_version: "addendum-2022" }));
  assert.deepEqual(out.errors, []);
});

// ── Invalid mechanism_version ─────────────────────────────────────────────────

test("gdpr-art46-idta: scc-2021-c-pp is invalid for this profile", () => {
  const out = validateGdprArt46Idta(makeArrangementBody({ mechanism_version: "scc-2021-c-pp" }));
  assert.ok(out.errors.includes("gdpr.art46.idta.mechanism_version_invalid"));
});

test("gdpr-art46-idta: bcr-c is invalid for this profile", () => {
  const out = validateGdprArt46Idta(makeArrangementBody({ mechanism_version: "bcr-c" }));
  assert.ok(out.errors.includes("gdpr.art46.idta.mechanism_version_invalid"));
});

test("gdpr-art46-idta: unknown string is invalid", () => {
  const out = validateGdprArt46Idta(makeArrangementBody({ mechanism_version: "unknown" }));
  assert.ok(out.errors.includes("gdpr.art46.idta.mechanism_version_invalid"));
});

// ── Non-arrangement events pass through ───────────────────────────────────────

test("gdpr-art46-idta: transfer event passes through with no errors", () => {
  const out = validateGdprArt46Idta(makeTransferBody());
  assert.deepEqual(out.errors, []);
});

// ── Adapter ───────────────────────────────────────────────────────────────────

test("gdpr-art46-idta adapter: ok=true on idta-2022", () => {
  const out = validateGdprArt46IdtaProfile({} as never, makeArrangementBody(), {});
  assert.equal(out.profile_id, GDPR_ART46_IDTA_PROFILE_ID);
  assert.equal(out.ok, true);
  assert.equal(out.reason, undefined);
});

test("gdpr-art46-idta adapter: ok=false and reason set on invalid version", () => {
  const out = validateGdprArt46IdtaProfile(
    {} as never,
    makeArrangementBody({ mechanism_version: "scc-2021-c-pp" }),
    {},
  );
  assert.equal(out.ok, false);
  assert.equal(out.reason, "gdpr.art46.idta.mechanism_version_invalid");
});

test("gdpr-art46-idta adapter: ok=true on non-arrangement event", () => {
  const out = validateGdprArt46IdtaProfile({} as never, makeTransferBody(), {});
  assert.equal(out.ok, true);
});
