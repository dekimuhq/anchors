/**
 * Tests for the schremsii.tia profile validator (ATR §5.8).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { AtrBody } from "@dekimuhq/atr-profiles";
import {
  SCHREMSII_TIA_PROFILE_ID,
  validateSchremsiiTia,
  validateSchremsiiTiaProfile,
} from "../src/schremsii-tia.ts";

function makeTiaBody(overrides?: Record<string, unknown>): AtrBody {
  return {
    event_type: "tia",
    arrangement_hash: "h:arr",
    destination_country: "US",
    assessment_doc_hash: "h:doc",
    surveillance_law_refs: ["FISA-702", "EO-12333"],
    assessment_outcome: "permitted_with_supplementary",
    supplementary_measures_hash: "h:sup",
    valid_from: "2026-01-01T00:00:00Z",
    valid_until: "2027-01-01T00:00:00Z",
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

function makeArrangementBody(): AtrBody {
  return {
    event_type: "arrangement",
    arrangement_id_commit: "h:abc",
    recipient_commit: "h:def",
    destination_country: "US",
    mechanism_version: "scc-2021-c-pp",
    contract_doc_hash: "h:ghi",
    in_force_from: "2026-01-01T00:00:00Z",
    in_force_until: null,
    supplementary_measures_hash: "h:jkl",
    qts_attestation_hash: null,
  } as AtrBody;
}

// ── Happy path ────────────────────────────────────────────────────────────────

test("schremsii-tia: permitted_with_supplementary + refs passes", () => {
  const out = validateSchremsiiTia(makeTiaBody());
  assert.deepEqual(out.errors, []);
});

test("schremsii-tia: permitted_plain + single ref passes", () => {
  const out = validateSchremsiiTia(
    makeTiaBody({ assessment_outcome: "permitted_plain", surveillance_law_refs: ["FISA-702"] }),
  );
  assert.deepEqual(out.errors, []);
});

test("schremsii-tia: not_permitted + refs passes", () => {
  const out = validateSchremsiiTia(
    makeTiaBody({ assessment_outcome: "not_permitted", surveillance_law_refs: ["EO-12333"] }),
  );
  assert.deepEqual(out.errors, []);
});

// ── Invalid assessment_outcome ────────────────────────────────────────────────

test("schremsii-tia: unknown outcome produces assessment_outcome_invalid", () => {
  const out = validateSchremsiiTia(
    makeTiaBody({ assessment_outcome: "maybe_permitted" }),
  );
  assert.ok(out.errors.includes("schremsii.tia.assessment_outcome_invalid"));
});

test("schremsii-tia: empty string outcome produces assessment_outcome_invalid", () => {
  const out = validateSchremsiiTia(
    makeTiaBody({ assessment_outcome: "" }),
  );
  assert.ok(out.errors.includes("schremsii.tia.assessment_outcome_invalid"));
});

// ── Invalid surveillance_law_refs ─────────────────────────────────────────────

test("schremsii-tia: empty surveillance_law_refs array produces refs_invalid", () => {
  const out = validateSchremsiiTia(
    makeTiaBody({ surveillance_law_refs: [] }),
  );
  assert.ok(out.errors.includes("schremsii.tia.surveillance_law_refs_invalid"));
});

// ── Multiple errors ───────────────────────────────────────────────────────────

test("schremsii-tia: invalid outcome + empty refs produces both errors", () => {
  const out = validateSchremsiiTia(
    makeTiaBody({ assessment_outcome: "bad", surveillance_law_refs: [] }),
  );
  assert.ok(out.errors.includes("schremsii.tia.assessment_outcome_invalid"));
  assert.ok(out.errors.includes("schremsii.tia.surveillance_law_refs_invalid"));
  assert.equal(out.errors.length, 2);
});

// ── Non-TIA events pass through ───────────────────────────────────────────────

test("schremsii-tia: transfer event passes through with no errors", () => {
  const out = validateSchremsiiTia(makeTransferBody());
  assert.deepEqual(out.errors, []);
});

test("schremsii-tia: arrangement event passes through with no errors", () => {
  const out = validateSchremsiiTia(makeArrangementBody());
  assert.deepEqual(out.errors, []);
});

// ── Adapter ───────────────────────────────────────────────────────────────────

test("schremsii-tia adapter: ok=true on valid tia body", () => {
  const out = validateSchremsiiTiaProfile({} as never, makeTiaBody(), {});
  assert.equal(out.profile_id, SCHREMSII_TIA_PROFILE_ID);
  assert.equal(out.ok, true);
  assert.equal(out.reason, undefined);
});

test("schremsii-tia adapter: ok=false on invalid outcome", () => {
  const out = validateSchremsiiTiaProfile(
    {} as never,
    makeTiaBody({ assessment_outcome: "bad" }),
    {},
  );
  assert.equal(out.ok, false);
  assert.equal(out.reason, "schremsii.tia.assessment_outcome_invalid");
});

test("schremsii-tia adapter: ok=false on empty refs", () => {
  const out = validateSchremsiiTiaProfile(
    {} as never,
    makeTiaBody({ surveillance_law_refs: [] }),
    {},
  );
  assert.equal(out.ok, false);
  assert.equal(out.reason, "schremsii.tia.surveillance_law_refs_invalid");
});

test("schremsii-tia adapter: ok=true on non-tia event", () => {
  const out = validateSchremsiiTiaProfile({} as never, makeTransferBody(), {});
  assert.equal(out.ok, true);
});
