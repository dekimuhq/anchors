/**
 * Tests for the ATR chain walker + transfer validity (spec §7).
 *
 * Coverage:
 *   - Arrangement chain: happy path, suspension chain, dangling prev, cycle,
 *     issuer inconsistency
 *   - Transfer validity §7.2: valid, arrangement not in force, arrangement
 *     suspended, TIA expired, missing arrangement, TIA required but absent,
 *     transfer window spans suspension
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type {
  AtrArrangementBody,
  AtrChainReceipt,
  AtrSuspensionBody,
  AtrTiaBody,
  AtrTransferBody,
} from "../src/types.ts";
import {
  buildAtrChainIndex,
  checkTransferValidity,
  walkAtrArrangementChain,
} from "../src/chain.ts";

// ── Fixture helpers ───────────────────────────────────────────────────────────

const ISS = "did:web:dekimu.com";
const SUBJECT = "sha256:" + "a".repeat(64);

function makeArrangement(
  overrides: Partial<AtrChainReceipt> & { id?: string } = {},
): AtrChainReceipt {
  const body: AtrArrangementBody = {
    event_type: "arrangement",
    arrangement_id_commit: "sha256:" + "b".repeat(64),
    recipient_commit: "sha256:" + "c".repeat(64),
    destination_country: "US",
    mechanism_version: "scc-2021-c-pp",
    contract_doc_hash: "sha256:" + "d".repeat(64),
    in_force_from: "2026-01-01T00:00:00Z",
    in_force_until: null,
    supplementary_measures_hash: "sha256:" + "e".repeat(64),
    qts_attestation_hash: null,
    ...(overrides.body as Partial<AtrArrangementBody> | undefined),
  };
  return {
    id: overrides.id ?? "arr-1",
    iss: overrides.iss ?? ISS,
    iat: overrides.iat ?? "2026-01-01T00:00:00Z",
    prev: overrides.prev ?? null,
    subject: overrides.subject ?? SUBJECT,
    profile: overrides.profile ?? "gdpr.art46.scc",
    body,
  };
}

function makeSuspension(
  overrides: Partial<AtrChainReceipt> & { id?: string } = {},
): AtrChainReceipt {
  const bodyOverrides = (overrides.body ?? {}) as Partial<AtrSuspensionBody>;
  const body: AtrSuspensionBody = {
    event_type: "suspension",
    trigger: bodyOverrides.trigger ?? "cjeu_judgment",
    trigger_ref_hash:
      bodyOverrides.trigger_ref_hash ?? "sha256:" + "f".repeat(64),
    effective_at:
      bodyOverrides.effective_at ?? "2026-07-16T00:00:00Z",
    qts_attestation_hash: bodyOverrides.qts_attestation_hash ?? null,
  };
  return {
    id: overrides.id ?? "susp-1",
    iss: overrides.iss ?? ISS,
    iat: overrides.iat ?? "2026-07-16T00:00:00Z",
    prev: overrides.prev ?? "arr-1",
    subject: overrides.subject ?? SUBJECT,
    profile: overrides.profile ?? "gdpr.art46.scc",
    body,
  };
}

function makeTia(
  overrides: Partial<AtrChainReceipt> & { id?: string } = {},
): AtrChainReceipt {
  const bodyOverrides = (overrides.body ?? {}) as Partial<AtrTiaBody>;
  const body: AtrTiaBody = {
    event_type: "tia",
    arrangement_hash:
      bodyOverrides.arrangement_hash ?? "arr-1",
    destination_country: bodyOverrides.destination_country ?? "US",
    assessment_doc_hash:
      bodyOverrides.assessment_doc_hash ?? "sha256:" + "g".repeat(64),
    surveillance_law_refs: bodyOverrides.surveillance_law_refs ?? ["FISA 702"],
    assessment_outcome: bodyOverrides.assessment_outcome ?? "permitted_with_supplementary",
    supplementary_measures_hash:
      bodyOverrides.supplementary_measures_hash ?? "sha256:" + "h".repeat(64),
    valid_from: bodyOverrides.valid_from ?? "2026-04-01T00:00:00Z",
    valid_until: bodyOverrides.valid_until ?? "2027-04-01T00:00:00Z",
    qts_attestation_hash: bodyOverrides.qts_attestation_hash ?? null,
  };
  return {
    id: overrides.id ?? "tia-1",
    iss: overrides.iss ?? ISS,
    iat: overrides.iat ?? "2026-04-01T00:00:00Z",
    prev: overrides.prev ?? null,
    subject: overrides.subject ?? SUBJECT,
    profile: overrides.profile ?? "gdpr.art46.scc",
    body,
  };
}

function makeTransfer(
  overrides: Partial<AtrChainReceipt> & { id?: string } = {},
): AtrChainReceipt {
  const bodyOverrides = (overrides.body ?? {}) as Partial<AtrTransferBody>;
  const body: AtrTransferBody = {
    event_type: "transfer",
    arrangement_hash: bodyOverrides.arrangement_hash ?? "arr-1",
    tia_hash: bodyOverrides.tia_hash !== undefined ? bodyOverrides.tia_hash : "tia-1",
    destination_country: bodyOverrides.destination_country ?? "US",
    recipient_commit:
      bodyOverrides.recipient_commit ?? "sha256:" + "i".repeat(64),
    data_categories: bodyOverrides.data_categories ?? ["contact"],
    subject_count_bucket: bodyOverrides.subject_count_bucket ?? "1",
    transfer_window_start:
      bodyOverrides.transfer_window_start ?? "2026-05-16T00:00:00Z",
    transfer_window_end:
      bodyOverrides.transfer_window_end ?? "2026-05-16T23:59:59Z",
    artifact_apr_hash: bodyOverrides.artifact_apr_hash ?? null,
    consent_receipt_hash: bodyOverrides.consent_receipt_hash ?? null,
    purpose_binding_hash: bodyOverrides.purpose_binding_hash ?? null,
    qts_attestation_hash: bodyOverrides.qts_attestation_hash ?? null,
  };
  return {
    id: overrides.id ?? "xfer-1",
    iss: overrides.iss ?? ISS,
    iat: overrides.iat ?? "2026-05-16T12:00:00Z",
    prev: overrides.prev ?? null,
    subject: overrides.subject ?? SUBJECT,
    profile: overrides.profile ?? "gdpr.art46.scc",
    body,
  };
}

// ── Arrangement chain tests ───────────────────────────────────────────────────

test("arrangement chain: valid arrangement (no suspension) → ok", () => {
  const arr = makeArrangement();
  const idx = buildAtrChainIndex([arr]);
  const res = walkAtrArrangementChain("arr-1", idx);
  assert.equal(res.ok, true, res.hard_invalid_reasons.join("|"));
  assert.equal(res.warnings.length, 0);
});

test("arrangement chain: arrangement with suspension chains correctly → ok", () => {
  const arr = makeArrangement({ id: "arr-1" });
  const susp = makeSuspension({ id: "susp-1", prev: "arr-1" });
  const idx = buildAtrChainIndex([arr, susp]);
  // Walk from the suspension back to the arrangement
  const res = walkAtrArrangementChain("susp-1", idx);
  assert.equal(res.ok, true, res.hard_invalid_reasons.join("|"));
});

test("arrangement chain: dangling prev → atr.chain_prev_unresolved", () => {
  const susp = makeSuspension({ id: "susp-1", prev: "arr-missing" });
  const idx = buildAtrChainIndex([susp]);
  const res = walkAtrArrangementChain("susp-1", idx);
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("atr.chain_prev_unresolved"));
});

test("arrangement chain: cycle → atr.chain_cycle_detected", () => {
  const arr = makeArrangement({ id: "arr-1", prev: "susp-1" });
  const susp = makeSuspension({ id: "susp-1", prev: "arr-1" });
  const idx = buildAtrChainIndex([arr, susp]);
  const res = walkAtrArrangementChain("susp-1", idx);
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("atr.chain_cycle_detected"));
});

test("arrangement chain: issuer inconsistency → atr.issuer_inconsistent", () => {
  const arr = makeArrangement({ id: "arr-1", iss: "did:web:other.com" });
  const susp = makeSuspension({ id: "susp-1", prev: "arr-1", iss: ISS });
  const idx = buildAtrChainIndex([arr, susp]);
  const res = walkAtrArrangementChain("susp-1", idx);
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("atr.issuer_inconsistent"));
});

// ── Transfer validity tests (spec §7.2) ───────────────────────────────────────

test("transfer validity: valid — arrangement in force, TIA valid → valid", () => {
  const arr = makeArrangement({ id: "arr-1" });
  const tia = makeTia({ id: "tia-1" });
  const xfer = makeTransfer({ id: "xfer-1" });
  const idx = buildAtrChainIndex([arr, tia, xfer]);
  const res = checkTransferValidity("xfer-1", idx);
  assert.equal(res.valid, true, res.reasons.join("|"));
});

test("transfer validity: arrangement not in force yet → atr.arrangement_not_in_force", () => {
  // in_force_from after the transfer window
  const arrBody: AtrArrangementBody = {
    event_type: "arrangement",
    arrangement_id_commit: "sha256:" + "b".repeat(64),
    recipient_commit: "sha256:" + "c".repeat(64),
    destination_country: "US",
    mechanism_version: "scc-2021-c-pp",
    contract_doc_hash: "sha256:" + "d".repeat(64),
    in_force_from: "2026-08-01T00:00:00Z", // after transfer window
    in_force_until: null,
    supplementary_measures_hash: "sha256:" + "e".repeat(64),
    qts_attestation_hash: null,
  };
  const arr = makeArrangement({ id: "arr-1", body: arrBody });
  const tia = makeTia({ id: "tia-1" });
  const xfer = makeTransfer({ id: "xfer-1" });
  const idx = buildAtrChainIndex([arr, tia, xfer]);
  const res = checkTransferValidity("xfer-1", idx);
  assert.equal(res.valid, false);
  assert.ok(res.reasons.includes("atr.arrangement_not_in_force"));
});

test("transfer validity: arrangement suspended before transfer → atr.arrangement_suspended", () => {
  const arr = makeArrangement({ id: "arr-1" });
  const tia = makeTia({ id: "tia-1" });
  // Suspension effective before the transfer window (2026-03-01 < 2026-05-16)
  const susp = makeSuspension({
    id: "susp-1",
    prev: "arr-1",
    body: {
      event_type: "suspension",
      trigger: "cjeu_judgment",
      trigger_ref_hash: "sha256:" + "f".repeat(64),
      effective_at: "2026-03-01T00:00:00Z",
      qts_attestation_hash: null,
    },
  });
  const xfer = makeTransfer({ id: "xfer-1" });
  const idx = buildAtrChainIndex([arr, tia, susp, xfer]);
  const res = checkTransferValidity("xfer-1", idx);
  assert.equal(res.valid, false);
  assert.ok(res.reasons.includes("atr.arrangement_suspended"));
});

test("transfer validity: TIA expired before transfer → atr.tia_expired", () => {
  const arr = makeArrangement({ id: "arr-1" });
  // TIA expired before transfer window
  const tiaBody: AtrTiaBody = {
    event_type: "tia",
    arrangement_hash: "arr-1",
    destination_country: "US",
    assessment_doc_hash: "sha256:" + "g".repeat(64),
    surveillance_law_refs: ["FISA 702"],
    assessment_outcome: "permitted_with_supplementary",
    supplementary_measures_hash: "sha256:" + "h".repeat(64),
    valid_from: "2026-01-01T00:00:00Z",
    valid_until: "2026-04-01T00:00:00Z", // expires before the transfer window
    qts_attestation_hash: null,
  };
  const tia = makeTia({ id: "tia-1", body: tiaBody });
  const xfer = makeTransfer({ id: "xfer-1" });
  const idx = buildAtrChainIndex([arr, tia, xfer]);
  const res = checkTransferValidity("xfer-1", idx);
  assert.equal(res.valid, false);
  assert.ok(res.reasons.includes("atr.tia_expired"));
});

test("transfer validity: missing arrangement → atr.arrangement_not_found", () => {
  const tia = makeTia({ id: "tia-1" });
  // No arrangement in the index
  const xfer = makeTransfer({ id: "xfer-1" });
  const idx = buildAtrChainIndex([tia, xfer]);
  const res = checkTransferValidity("xfer-1", idx);
  assert.equal(res.valid, false);
  assert.ok(res.reasons.includes("atr.arrangement_not_found"));
});

test("transfer validity: profile requires TIA but tia_hash is null → atr.tia_required", () => {
  const arr = makeArrangement({ id: "arr-1" });
  const tia = makeTia({ id: "tia-1" });
  const xfer = makeTransfer({
    id: "xfer-1",
    profile: "gdpr.art46.scc", // TIA-required profile
    body: {
      event_type: "transfer",
      arrangement_hash: "arr-1",
      tia_hash: null, // absent
      destination_country: "US",
      recipient_commit: "sha256:" + "i".repeat(64),
      data_categories: ["contact"],
      subject_count_bucket: "1",
      transfer_window_start: "2026-05-16T00:00:00Z",
      transfer_window_end: "2026-05-16T23:59:59Z",
      artifact_apr_hash: null,
      consent_receipt_hash: null,
      purpose_binding_hash: null,
      qts_attestation_hash: null,
    },
  });
  const idx = buildAtrChainIndex([arr, tia, xfer]);
  const res = checkTransferValidity("xfer-1", idx);
  assert.equal(res.valid, false);
  assert.ok(res.reasons.includes("atr.tia_required"));
});

test("transfer validity: transfer window spans suspension event → atr.transfer_spans_suspension (warning)", () => {
  const arr = makeArrangement({ id: "arr-1" });
  const tia = makeTia({ id: "tia-1" });
  // Suspension effective during the transfer window (18:00 is within 00:00–23:59)
  const susp = makeSuspension({
    id: "susp-1",
    prev: "arr-1",
    body: {
      event_type: "suspension",
      trigger: "dpa_order",
      trigger_ref_hash: "sha256:" + "f".repeat(64),
      effective_at: "2026-05-16T18:00:00Z",
      qts_attestation_hash: null,
    },
  });
  const xfer = makeTransfer({ id: "xfer-1" });
  const idx = buildAtrChainIndex([arr, tia, susp, xfer]);
  const res = checkTransferValidity("xfer-1", idx);
  // Transfer is still valid (suspension starts after window_start), but warns
  assert.equal(res.valid, true, res.reasons.join("|"));
  assert.ok(res.reasons.includes("atr.transfer_spans_suspension"));
});
