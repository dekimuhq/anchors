/**
 * Tests for the gdpr.dpf profile validator (ATR §5.7).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { AtrBody } from "@dekimuhq/atr-profiles";
import {
  GDPR_DPF_PROFILE_ID,
  validateGdprDpf,
  validateGdprDpfProfile,
} from "../src/gdpr-dpf.ts";

function makeArrangementBody(
  overrides?: Record<string, unknown>,
): AtrBody {
  return {
    event_type: "arrangement",
    arrangement_id_commit: "h:abc",
    recipient_commit: "h:def",
    destination_country: "US",
    mechanism_version: "dpf-2023",
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

test("gdpr-dpf: dpf-2023 passes", () => {
  const out = validateGdprDpf(makeArrangementBody({ mechanism_version: "dpf-2023" }));
  assert.deepEqual(out.errors, []);
});

// ── Invalid mechanism_version ─────────────────────────────────────────────────

test("gdpr-dpf: scc-2021-c-pp is invalid for this profile", () => {
  const out = validateGdprDpf(makeArrangementBody({ mechanism_version: "scc-2021-c-pp" }));
  assert.ok(out.errors.includes("gdpr.dpf.mechanism_version_invalid"));
});

test("gdpr-dpf: adequacy:US is invalid for this profile", () => {
  const out = validateGdprDpf(makeArrangementBody({ mechanism_version: "adequacy:US" }));
  assert.ok(out.errors.includes("gdpr.dpf.mechanism_version_invalid"));
});

test("gdpr-dpf: dpf-2022 (wrong year) is invalid", () => {
  const out = validateGdprDpf(makeArrangementBody({ mechanism_version: "dpf-2022" }));
  assert.ok(out.errors.includes("gdpr.dpf.mechanism_version_invalid"));
});

test("gdpr-dpf: unknown string is invalid", () => {
  const out = validateGdprDpf(makeArrangementBody({ mechanism_version: "unknown" }));
  assert.ok(out.errors.includes("gdpr.dpf.mechanism_version_invalid"));
});

// ── Non-arrangement events pass through ───────────────────────────────────────

test("gdpr-dpf: transfer event passes through with no errors", () => {
  const out = validateGdprDpf(makeTransferBody());
  assert.deepEqual(out.errors, []);
});

// ── Adapter ───────────────────────────────────────────────────────────────────

test("gdpr-dpf adapter: ok=true on dpf-2023", () => {
  const out = validateGdprDpfProfile({} as never, makeArrangementBody(), {});
  assert.equal(out.profile_id, GDPR_DPF_PROFILE_ID);
  assert.equal(out.ok, true);
  assert.equal(out.reason, undefined);
});

test("gdpr-dpf adapter: ok=false and reason set on invalid version", () => {
  const out = validateGdprDpfProfile(
    {} as never,
    makeArrangementBody({ mechanism_version: "scc-2021-c-pp" }),
    {},
  );
  assert.equal(out.ok, false);
  assert.equal(out.reason, "gdpr.dpf.mechanism_version_invalid");
});

test("gdpr-dpf adapter: ok=true on non-arrangement event", () => {
  const out = validateGdprDpfProfile({} as never, makeTransferBody(), {});
  assert.equal(out.ok, true);
});
