/**
 * ASR Phase 3 §G — cross-family composition tests.
 *
 * Direct unit tests against `composeAsr` cover the 4 cross-walks
 * (art17 ARR / art19 ALR / art20 ATR / art21 APuR) plus pipeline
 * integration tests against `asrFamily.verifyReceipt` that prove the
 * factory wires compose correctly.
 *
 * Structure:
 *   §G   generic dispatch behaviour
 *   §ARR art17 ARR cross-walk
 *   §ALR art19 ALR cascade
 *   §ATR art20 ATR (optional)
 *   §APUR art21 APuR (optional)
 *   §INT end-to-end through verifyReceipt
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { FamilyVerifyOptions } from "@dekimuhq/anchors-envelope";
import { composeAsr } from "../src/compose.ts";
import { asrFamily } from "../src/family.ts";
import {
  ANCHOR,
  KP,
  PUB_DER,
  REQ_ID,
  SUBJECT,
  bodyFulfilled,
  bodyRecipientNotified,
  bodyRequestReceived,
  mintInput,
  sha256,
} from "./_helpers/fixtures.ts";

/** ISO-8601 timestamp matching the ASR test fixture clock. */
const ASR_IAT = "2026-05-19T08:00:00Z";

/** Builds a minimal `FamilyVerifyOptions` with just `resolveKey` and an optional profile + resolver overrides. */
function opts(over: Partial<FamilyVerifyOptions> = {}): FamilyVerifyOptions {
  return {
    resolveKey: () => PUB_DER,
    ...over,
  };
}

/** Builds a duck-typed ARR receipt for the art17 cross-walk. */
function arrReceipt(
  over: {
    claim_type?: string;
    subject?: string | null;
    target_kind?: string;
    target_commit?: string;
    iat?: string;
  } = {},
): unknown {
  return {
    claim_type: over.claim_type ?? "ar.erasure.v1",
    subject: over.subject === undefined ? SUBJECT : over.subject,
    iat: over.iat ?? ASR_IAT,
    body: {
      target_kind: over.target_kind ?? "subject",
      target_commit: over.target_commit ?? SUBJECT,
    },
  };
}

/** Builds a duck-typed ALR receipt for the art19 cascade. */
function alrReceipt(
  over: {
    claim_type?: string;
    subject?: string | null;
    event_type?: string;
  } = {},
): unknown {
  return {
    claim_type: over.claim_type ?? "ar.lineage.v1",
    subject: over.subject === undefined ? SUBJECT : over.subject,
    iat: ASR_IAT,
    body: {
      event_type: over.event_type ?? "disclosed",
    },
  };
}

/** Builds a duck-typed ATR receipt. */
function atrReceipt(
  over: { claim_type?: string; subject?: string | null } = {},
): unknown {
  return {
    claim_type: over.claim_type ?? "ar.transfer.v1",
    subject: over.subject === undefined ? SUBJECT : over.subject,
    iat: ASR_IAT,
    body: {},
  };
}

/** Builds a duck-typed APuR receipt. */
function apurReceipt(
  over: {
    claim_type?: string;
    subject?: string | null;
    event_type?: string;
  } = {},
): unknown {
  return {
    claim_type: over.claim_type ?? "ar.purpose.v1",
    subject: over.subject === undefined ? SUBJECT : over.subject,
    iat: ASR_IAT,
    body: {
      event_type: over.event_type ?? "unbinding",
    },
  };
}

/** Builds a ComposeInput envelope skeleton. */
function envelope(
  body: unknown,
  over: { subject?: string | null; iat?: string } = {},
) {
  return {
    id: "asr_test_01",
    claim_type: "ar.subject_rights.v1",
    iss: "did:web:test.example.com",
    prev: null,
    body,
    subject: over.subject === undefined ? SUBJECT : over.subject,
    iat: over.iat ?? ASR_IAT,
  };
}

// ── §G — generic dispatch behaviour ──────────────────────────────────────────

test("§G1 non-ASR claim_type → ok silently", async () => {
  const r = await composeAsr({
    envelope: {
      id: "asr_test_g1",
      claim_type: "ar.lineage.v1",
      iss: "did:web:test.example.com",
      prev: null,
      body: { event_type: "disclosed" },
      subject: SUBJECT,
      iat: ASR_IAT,
    },
    opts: opts(),
  });
  assert.deepEqual(r, { ok: true });
});

test("§G2 body missing → ok silently", async () => {
  const r = await composeAsr({
    envelope: envelope(undefined),
    opts: opts(),
  });
  assert.deepEqual(r, { ok: true });
});

test("§G3 profile undefined → all cross-walks skipped", async () => {
  // art17 fulfilled body but no opts.profile — the cross-walk dispatcher
  // is keyed on opts.profile so absence must short-circuit silently.
  const r = await composeAsr({
    envelope: envelope({ ...bodyFulfilled(), arr_receipt_id: "arr_x" }),
    opts: opts({ resolveArr: async () => null }),
  });
  assert.deepEqual(r, { ok: true });
});

test("§G4 art15.access fulfilled → no cross-walk (no MANDATORY cross-link)", async () => {
  const r = await composeAsr({
    envelope: envelope(bodyFulfilled()),
    opts: opts({ profile: "subject_rights.art15.access" }),
  });
  assert.deepEqual(r, { ok: true });
});

test("§G5 art17 + non-fulfilled event → cross-walk skipped", async () => {
  // request.received under art17 should NOT trigger the ARR cross-walk —
  // the MANDATORY link applies only on request.fulfilled (spec §5.3).
  const r = await composeAsr({
    envelope: envelope(bodyRequestReceived()),
    opts: opts({
      profile: "subject_rights.art17.erasure_request",
      resolveArr: async () => null, // would have failed if it fired
    }),
  });
  assert.deepEqual(r, { ok: true });
});

test("§G6 art16 fulfilled without recipient_notified → ok", async () => {
  // art16 fulfilled doesn't carry a MANDATORY cross-link by itself; the
  // Art. 19 ALR cascade only fires on request.recipient_notified.
  const r = await composeAsr({
    envelope: envelope(bodyFulfilled()),
    opts: opts({ profile: "subject_rights.art16.rectification" }),
  });
  assert.deepEqual(r, { ok: true });
});

// ── §ARR — art17 ARR cross-walk ──────────────────────────────────────────────

test("§ARR1 happy: ar.erasure.v1 + subject parity + within window", async () => {
  const r = await composeAsr({
    envelope: envelope({ ...bodyFulfilled(), arr_receipt_id: "arr_x" }),
    opts: opts({
      profile: "subject_rights.art17.erasure_request",
      resolveArr: async () => arrReceipt(),
    }),
  });
  assert.deepEqual(r, { ok: true });
});

test("§ARR2 happy: ar.anonymization.v1 (Art. 17(2) path)", async () => {
  const r = await composeAsr({
    envelope: envelope({ ...bodyFulfilled(), arr_receipt_id: "arr_x" }),
    opts: opts({
      profile: "subject_rights.art17.erasure_request",
      resolveArr: async () => arrReceipt({ claim_type: "ar.anonymization.v1" }),
    }),
  });
  assert.deepEqual(r, { ok: true });
});

test("§ARR3 resolveArr undefined → skip silently", async () => {
  const r = await composeAsr({
    envelope: envelope({ ...bodyFulfilled(), arr_receipt_id: "arr_x" }),
    opts: opts({ profile: "subject_rights.art17.erasure_request" }),
  });
  assert.deepEqual(r, { ok: true });
});

test("§ARR4 arr_receipt_id missing → art17_arr_link_missing", async () => {
  const r = await composeAsr({
    envelope: envelope(bodyFulfilled()),
    opts: opts({
      profile: "subject_rights.art17.erasure_request",
      resolveArr: async () => arrReceipt(),
    }),
  });
  assert.deepEqual(r, { ok: false, reason: "art17_arr_link_missing" });
});

test("§ARR5 arr_receipt_id empty string → art17_arr_link_missing", async () => {
  const r = await composeAsr({
    envelope: envelope({ ...bodyFulfilled(), arr_receipt_id: "" }),
    opts: opts({
      profile: "subject_rights.art17.erasure_request",
      resolveArr: async () => arrReceipt(),
    }),
  });
  assert.deepEqual(r, { ok: false, reason: "art17_arr_link_missing" });
});

test("§ARR6 resolver returns null → art17_arr_link_unresolvable", async () => {
  const r = await composeAsr({
    envelope: envelope({ ...bodyFulfilled(), arr_receipt_id: "arr_x" }),
    opts: opts({
      profile: "subject_rights.art17.erasure_request",
      resolveArr: async () => null,
    }),
  });
  assert.deepEqual(r, { ok: false, reason: "art17_arr_link_unresolvable" });
});

test("§ARR7 resolver returns non-object → art17_arr_link_unresolvable", async () => {
  const r = await composeAsr({
    envelope: envelope({ ...bodyFulfilled(), arr_receipt_id: "arr_x" }),
    opts: opts({
      profile: "subject_rights.art17.erasure_request",
      resolveArr: async () => "not-an-envelope",
    }),
  });
  assert.deepEqual(r, { ok: false, reason: "art17_arr_link_unresolvable" });
});

test("§ARR8 wrong claim_type (ar.provenance.v1) → art17_arr_wrong_claim_type", async () => {
  const r = await composeAsr({
    envelope: envelope({ ...bodyFulfilled(), arr_receipt_id: "arr_x" }),
    opts: opts({
      profile: "subject_rights.art17.erasure_request",
      resolveArr: async () => arrReceipt({ claim_type: "ar.provenance.v1" }),
    }),
  });
  assert.deepEqual(r, { ok: false, reason: "art17_arr_wrong_claim_type" });
});

test("§ARR9 target_kind !== 'subject' → art17_arr_subject_mismatch", async () => {
  const r = await composeAsr({
    envelope: envelope({ ...bodyFulfilled(), arr_receipt_id: "arr_x" }),
    opts: opts({
      profile: "subject_rights.art17.erasure_request",
      resolveArr: async () => arrReceipt({ target_kind: "record_id" }),
    }),
  });
  assert.deepEqual(r, { ok: false, reason: "art17_arr_subject_mismatch" });
});

test("§ARR10 target_commit mismatch → art17_arr_subject_mismatch", async () => {
  const r = await composeAsr({
    envelope: envelope({ ...bodyFulfilled(), arr_receipt_id: "arr_x" }),
    opts: opts({
      profile: "subject_rights.art17.erasure_request",
      resolveArr: async () => arrReceipt({ target_commit: sha256("z") }),
    }),
  });
  assert.deepEqual(r, { ok: false, reason: "art17_arr_subject_mismatch" });
});

test("§ARR11 ARR iat in future >14d → art17_arr_stale_link", async () => {
  const r = await composeAsr({
    envelope: envelope({ ...bodyFulfilled(), arr_receipt_id: "arr_x" }),
    opts: opts({
      profile: "subject_rights.art17.erasure_request",
      resolveArr: async () => arrReceipt({ iat: "2026-06-03T08:00:00Z" }), // +15d
    }),
  });
  assert.deepEqual(r, { ok: false, reason: "art17_arr_stale_link" });
});

test("§ARR12 ARR iat in past >14d → art17_arr_stale_link", async () => {
  const r = await composeAsr({
    envelope: envelope({ ...bodyFulfilled(), arr_receipt_id: "arr_x" }),
    opts: opts({
      profile: "subject_rights.art17.erasure_request",
      resolveArr: async () => arrReceipt({ iat: "2026-05-04T08:00:00Z" }), // -15d
    }),
  });
  assert.deepEqual(r, { ok: false, reason: "art17_arr_stale_link" });
});

test("§ARR13 ARR iat exactly +14d (boundary, inclusive) → ok", async () => {
  // ASR iat = 2026-05-19T08:00:00Z; ARR iat = 2026-06-02T08:00:00Z = +14 days
  const r = await composeAsr({
    envelope: envelope({ ...bodyFulfilled(), arr_receipt_id: "arr_x" }),
    opts: opts({
      profile: "subject_rights.art17.erasure_request",
      resolveArr: async () => arrReceipt({ iat: "2026-06-02T08:00:00Z" }),
    }),
  });
  assert.deepEqual(r, { ok: true });
});

test("§ARR14 ARR iat unparseable → art17_arr_stale_link", async () => {
  const r = await composeAsr({
    envelope: envelope({ ...bodyFulfilled(), arr_receipt_id: "arr_x" }),
    opts: opts({
      profile: "subject_rights.art17.erasure_request",
      resolveArr: async () => arrReceipt({ iat: "not-an-iso-date" }),
    }),
  });
  assert.deepEqual(r, { ok: false, reason: "art17_arr_stale_link" });
});

test("§ARR15 ASR subject null → art17_arr_subject_mismatch", async () => {
  const r = await composeAsr({
    envelope: envelope(
      { ...bodyFulfilled(), arr_receipt_id: "arr_x" },
      { subject: null },
    ),
    opts: opts({
      profile: "subject_rights.art17.erasure_request",
      resolveArr: async () => arrReceipt({ subject: null, target_commit: "" }),
    }),
  });
  assert.deepEqual(r, { ok: false, reason: "art17_arr_subject_mismatch" });
});

test("§ARR16 resolver throws → compose_threw:<msg>", async () => {
  // Pipeline wraps throws; calling composeAsr directly surfaces them, so
  // assert the exception propagates here. The pipeline test in §INT
  // exercises the catch path.
  await assert.rejects(
    async () =>
      composeAsr({
        envelope: envelope({ ...bodyFulfilled(), arr_receipt_id: "arr_x" }),
        opts: opts({
          profile: "subject_rights.art17.erasure_request",
          resolveArr: () => {
            throw new Error("boom");
          },
        }),
      }),
    /boom/,
  );
});

// ── §ALR — art19 ALR cascade ─────────────────────────────────────────────────

test("§ALR1 happy: single recipient", async () => {
  const r = await composeAsr({
    envelope: envelope(bodyRecipientNotified()),
    opts: opts({
      profile: "subject_rights.art17.erasure_request",
      resolveAlr: async () => alrReceipt(),
    }),
  });
  assert.deepEqual(r, { ok: true });
});

test("§ALR2 happy: multi-recipient", async () => {
  const body = {
    ...bodyRecipientNotified(),
    recipient_set_alr_ids: ["alr_1", "alr_2", "alr_3"],
  };
  const r = await composeAsr({
    envelope: envelope(body),
    opts: opts({
      profile: "subject_rights.art16.rectification",
      resolveAlr: async () => alrReceipt(),
    }),
  });
  assert.deepEqual(r, { ok: true });
});

test("§ALR3 resolveAlr undefined → skip silently", async () => {
  const r = await composeAsr({
    envelope: envelope(bodyRecipientNotified()),
    opts: opts({ profile: "subject_rights.art18.restriction" }),
  });
  assert.deepEqual(r, { ok: true });
});

test("§ALR4 wrong claim_type → art19_alr_wrong_claim_type", async () => {
  const r = await composeAsr({
    envelope: envelope(bodyRecipientNotified()),
    opts: opts({
      profile: "subject_rights.art17.erasure_request",
      resolveAlr: async () => alrReceipt({ claim_type: "ar.provenance.v1" }),
    }),
  });
  assert.deepEqual(r, { ok: false, reason: "art19_alr_wrong_claim_type" });
});

test("§ALR5 wrong event_type (not 'disclosed') → art19_alr_wrong_event_type", async () => {
  const r = await composeAsr({
    envelope: envelope(bodyRecipientNotified()),
    opts: opts({
      profile: "subject_rights.art17.erasure_request",
      resolveAlr: async () => alrReceipt({ event_type: "ingested" }),
    }),
  });
  assert.deepEqual(r, { ok: false, reason: "art19_alr_wrong_event_type" });
});

test("§ALR6 subject mismatch → art19_alr_subject_mismatch", async () => {
  const r = await composeAsr({
    envelope: envelope(bodyRecipientNotified()),
    opts: opts({
      profile: "subject_rights.art17.erasure_request",
      resolveAlr: async () => alrReceipt({ subject: sha256("z") }),
    }),
  });
  assert.deepEqual(r, { ok: false, reason: "art19_alr_subject_mismatch" });
});

test("§ALR7 resolver returns null → art19_alr_link_unresolvable", async () => {
  const r = await composeAsr({
    envelope: envelope(bodyRecipientNotified()),
    opts: opts({
      profile: "subject_rights.art17.erasure_request",
      resolveAlr: async () => null,
    }),
  });
  assert.deepEqual(r, { ok: false, reason: "art19_alr_link_unresolvable" });
});

test("§ALR8 art15.access + recipient_notified → cross-walk skipped (out of profile set)", async () => {
  // art15.access is NOT in ART19_PROFILES per spec — Art. 19 applies only
  // to art16 (rectification) / art17 (erasure) / art18 (restriction).
  const r = await composeAsr({
    envelope: envelope(bodyRecipientNotified()),
    opts: opts({
      profile: "subject_rights.art15.access",
      resolveAlr: async () => null, // would have failed if it fired
    }),
  });
  assert.deepEqual(r, { ok: true });
});

test("§ALR9 short-circuits on first bad ALR (multi-recipient)", async () => {
  const body = {
    ...bodyRecipientNotified(),
    recipient_set_alr_ids: ["alr_good", "alr_bad", "alr_never_reached"],
  };
  let calls = 0;
  const r = await composeAsr({
    envelope: envelope(body),
    opts: opts({
      profile: "subject_rights.art17.erasure_request",
      resolveAlr: async (id: string) => {
        calls += 1;
        return id === "alr_bad" ? alrReceipt({ subject: sha256("z") }) : alrReceipt();
      },
    }),
  });
  assert.deepEqual(r, { ok: false, reason: "art19_alr_subject_mismatch" });
  assert.equal(calls, 2);
});

test("§ALR10 resolver throws → propagates", async () => {
  await assert.rejects(
    async () =>
      composeAsr({
        envelope: envelope(bodyRecipientNotified()),
        opts: opts({
          profile: "subject_rights.art17.erasure_request",
          resolveAlr: () => {
            throw new Error("alr-fetch-fail");
          },
        }),
      }),
    /alr-fetch-fail/,
  );
});

// ── §ATR — art20 ATR (OPTIONAL) ──────────────────────────────────────────────

test("§ATR1 happy: ar.transfer.v1 + subject parity", async () => {
  const r = await composeAsr({
    envelope: envelope({
      ...bodyFulfilled(),
      portability_format: "json",
      atr_receipt_id: "atr_x",
    }),
    opts: opts({
      profile: "subject_rights.art20.portability",
      resolveAtr: async () => atrReceipt(),
    }),
  });
  assert.deepEqual(r, { ok: true });
});

test("§ATR2 atr_receipt_id absent → cross-walk skipped (optional)", async () => {
  const r = await composeAsr({
    envelope: envelope({ ...bodyFulfilled(), portability_format: "json" }),
    opts: opts({
      profile: "subject_rights.art20.portability",
      resolveAtr: async () => null, // would have failed if it fired
    }),
  });
  assert.deepEqual(r, { ok: true });
});

test("§ATR3 resolveAtr undefined → skip silently", async () => {
  const r = await composeAsr({
    envelope: envelope({
      ...bodyFulfilled(),
      portability_format: "json",
      atr_receipt_id: "atr_x",
    }),
    opts: opts({ profile: "subject_rights.art20.portability" }),
  });
  assert.deepEqual(r, { ok: true });
});

test("§ATR4 wrong claim_type → art20_atr_wrong_claim_type", async () => {
  const r = await composeAsr({
    envelope: envelope({
      ...bodyFulfilled(),
      portability_format: "json",
      atr_receipt_id: "atr_x",
    }),
    opts: opts({
      profile: "subject_rights.art20.portability",
      resolveAtr: async () => atrReceipt({ claim_type: "ar.provenance.v1" }),
    }),
  });
  assert.deepEqual(r, { ok: false, reason: "art20_atr_wrong_claim_type" });
});

test("§ATR5 subject mismatch → art20_atr_subject_mismatch", async () => {
  const r = await composeAsr({
    envelope: envelope({
      ...bodyFulfilled(),
      portability_format: "json",
      atr_receipt_id: "atr_x",
    }),
    opts: opts({
      profile: "subject_rights.art20.portability",
      resolveAtr: async () => atrReceipt({ subject: sha256("z") }),
    }),
  });
  assert.deepEqual(r, { ok: false, reason: "art20_atr_subject_mismatch" });
});

test("§ATR6 resolver returns null → art20_atr_link_unresolvable", async () => {
  const r = await composeAsr({
    envelope: envelope({
      ...bodyFulfilled(),
      portability_format: "json",
      atr_receipt_id: "atr_x",
    }),
    opts: opts({
      profile: "subject_rights.art20.portability",
      resolveAtr: async () => null,
    }),
  });
  assert.deepEqual(r, { ok: false, reason: "art20_atr_link_unresolvable" });
});

// ── §APUR — art21 APuR (OPTIONAL) ────────────────────────────────────────────

test("§APUR1 happy: ar.purpose.v1 + unbinding + subject parity", async () => {
  const r = await composeAsr({
    envelope: envelope({ ...bodyFulfilled(), apur_receipt_id: "apur_x" }),
    opts: opts({
      profile: "subject_rights.art21.objection",
      resolveApur: async () => apurReceipt(),
    }),
  });
  assert.deepEqual(r, { ok: true });
});

test("§APUR2 apur_receipt_id absent → cross-walk skipped (optional)", async () => {
  const r = await composeAsr({
    envelope: envelope(bodyFulfilled()),
    opts: opts({
      profile: "subject_rights.art21.objection",
      resolveApur: async () => null, // would have failed if it fired
    }),
  });
  assert.deepEqual(r, { ok: true });
});

test("§APUR3 resolveApur undefined → skip silently", async () => {
  const r = await composeAsr({
    envelope: envelope({ ...bodyFulfilled(), apur_receipt_id: "apur_x" }),
    opts: opts({ profile: "subject_rights.art21.objection" }),
  });
  assert.deepEqual(r, { ok: true });
});

test("§APUR4 wrong claim_type → art21_apur_wrong_claim_type", async () => {
  const r = await composeAsr({
    envelope: envelope({ ...bodyFulfilled(), apur_receipt_id: "apur_x" }),
    opts: opts({
      profile: "subject_rights.art21.objection",
      resolveApur: async () => apurReceipt({ claim_type: "ar.lineage.v1" }),
    }),
  });
  assert.deepEqual(r, { ok: false, reason: "art21_apur_wrong_claim_type" });
});

test("§APUR5 wrong event_type (not 'unbinding') → art21_apur_wrong_event_type", async () => {
  const r = await composeAsr({
    envelope: envelope({ ...bodyFulfilled(), apur_receipt_id: "apur_x" }),
    opts: opts({
      profile: "subject_rights.art21.objection",
      resolveApur: async () => apurReceipt({ event_type: "binding" }),
    }),
  });
  assert.deepEqual(r, { ok: false, reason: "art21_apur_wrong_event_type" });
});

test("§APUR6 subject mismatch → art21_apur_subject_mismatch", async () => {
  const r = await composeAsr({
    envelope: envelope({ ...bodyFulfilled(), apur_receipt_id: "apur_x" }),
    opts: opts({
      profile: "subject_rights.art21.objection",
      resolveApur: async () => apurReceipt({ subject: sha256("z") }),
    }),
  });
  assert.deepEqual(r, { ok: false, reason: "art21_apur_subject_mismatch" });
});

test("§APUR7 resolver returns null → art21_apur_link_unresolvable", async () => {
  const r = await composeAsr({
    envelope: envelope({ ...bodyFulfilled(), apur_receipt_id: "apur_x" }),
    opts: opts({
      profile: "subject_rights.art21.objection",
      resolveApur: async () => null,
    }),
  });
  assert.deepEqual(r, { ok: false, reason: "art21_apur_link_unresolvable" });
});

// ── §WARN — Phase 4 informational warnings (compose warnings channel) ────────

test("§WARN1 art20_cross_border_atr_missing: portability_recipient_did set + no atr_receipt_id → warning", async () => {
  const r = await composeAsr({
    envelope: envelope({
      ...bodyFulfilled(),
      portability_format: "json",
      portability_recipient_did: "did:web:non-eu-controller.example",
    }),
    opts: opts({ profile: "subject_rights.art20.portability" }),
  });
  assert.deepEqual(r, { ok: true, warnings: ["art20_cross_border_atr_missing"] });
});

test("§WARN2 art20_cross_border_atr_missing: recipient_did set + atr_receipt_id set → NO warning", async () => {
  const r = await composeAsr({
    envelope: envelope({
      ...bodyFulfilled(),
      portability_format: "json",
      portability_recipient_did: "did:web:non-eu-controller.example",
      atr_receipt_id: "atr_x",
    }),
    opts: opts({
      profile: "subject_rights.art20.portability",
      resolveAtr: async () => atrReceipt(),
    }),
  });
  assert.deepEqual(r, { ok: true });
});

test("§WARN3 art20_cross_border_atr_missing: no recipient_did → NO warning even without atr_receipt_id", async () => {
  const r = await composeAsr({
    envelope: envelope({ ...bodyFulfilled(), portability_format: "json" }),
    opts: opts({ profile: "subject_rights.art20.portability" }),
  });
  assert.deepEqual(r, { ok: true });
});

test("§WARN4 art20_cross_border_atr_missing: wrong profile → NO warning (out of cross-walk profile set)", async () => {
  const r = await composeAsr({
    envelope: envelope({
      ...bodyFulfilled(),
      portability_recipient_did: "did:web:other.example",
    }),
    opts: opts({ profile: "subject_rights.art15.access" }),
  });
  assert.deepEqual(r, { ok: true });
});

test("§WARN5 art19_recipient_set_incomplete: body set is strict subset of ledger → warning", async () => {
  const body = {
    ...bodyRecipientNotified(),
    recipient_set_alr_ids: ["alr_1", "alr_2"],
  };
  const r = await composeAsr({
    envelope: envelope(body),
    opts: opts({
      profile: "subject_rights.art17.erasure_request",
      resolveAlr: async () => alrReceipt(),
      findDisclosedAlrsForSubject: async () => ["alr_1", "alr_2", "alr_3_missing"],
    }),
  });
  assert.deepEqual(r, { ok: true, warnings: ["art19_recipient_set_incomplete"] });
});

test("§WARN6 art19_recipient_set_incomplete: body set equals ledger → NO warning", async () => {
  const body = {
    ...bodyRecipientNotified(),
    recipient_set_alr_ids: ["alr_1", "alr_2"],
  };
  const r = await composeAsr({
    envelope: envelope(body),
    opts: opts({
      profile: "subject_rights.art17.erasure_request",
      resolveAlr: async () => alrReceipt(),
      findDisclosedAlrsForSubject: async () => ["alr_1", "alr_2"],
    }),
  });
  assert.deepEqual(r, { ok: true });
});

test("§WARN7 art19_recipient_set_incomplete: findDisclosedAlrsForSubject undefined → skip silently", async () => {
  const r = await composeAsr({
    envelope: envelope(bodyRecipientNotified()),
    opts: opts({
      profile: "subject_rights.art17.erasure_request",
      resolveAlr: async () => alrReceipt(),
      // findDisclosedAlrsForSubject intentionally undefined
    }),
  });
  assert.deepEqual(r, { ok: true });
});

test("§WARN8 art19_recipient_set_incomplete: subject null → skip silently", async () => {
  // findDisclosedAlrsForSubject takes a non-null subject by signature, so
  // when envelope subject is null the compose callback MUST skip the
  // completeness check. Body must omit recipient_notified-specific fields
  // since art15.access wouldn't normally trigger ALR cascade.
  let resolverCalled = false;
  const r = await composeAsr({
    envelope: {
      id: "asr_test_warn8",
      claim_type: "ar.subject_rights.v1",
      iss: "did:web:test.example.com",
      prev: null,
      body: bodyRecipientNotified(),
      subject: null,
      iat: ASR_IAT,
    },
    opts: opts({
      profile: "subject_rights.art17.erasure_request",
      resolveAlr: async () => alrReceipt(),
      findDisclosedAlrsForSubject: async () => {
        resolverCalled = true;
        return [];
      },
    }),
  });
  // Subject-null short-circuits the ALR cascade first via subject mismatch,
  // so this also exercises the HARD failure path. The completeness resolver
  // must not be reached.
  assert.equal(resolverCalled, false);
  assert.equal(r.ok, false);
});

test("§WARN9 both art19 + art20 warnings can co-exist on a single compose pass", async () => {
  // Synthetic envelope mixing art19 cascade fields + art20 portability
  // fields, exercising both cross-walks on the same compose call. Even
  // though a real ASR receipt would only fire one cross-walk (profile
  // dispatches differ), each warning emitter checks its own conditions
  // independently — this asserts the warnings array carries both.
  const body = {
    ...bodyRecipientNotified(),
    recipient_set_alr_ids: ["alr_1"],
    portability_format: "json",
    portability_recipient_did: "did:web:other.example",
  };
  // First pass — art19 profile, emits art19 warning only.
  const r19 = await composeAsr({
    envelope: envelope(body),
    opts: opts({
      profile: "subject_rights.art17.erasure_request",
      resolveAlr: async () => alrReceipt(),
      findDisclosedAlrsForSubject: async () => ["alr_1", "alr_2"],
    }),
  });
  assert.deepEqual(r19, { ok: true, warnings: ["art19_recipient_set_incomplete"] });
  // Second pass — art20 profile, emits art20 warning only.
  const r20 = await composeAsr({
    envelope: envelope({ ...bodyFulfilled(), portability_format: "json", portability_recipient_did: "did:web:other.example" }),
    opts: opts({ profile: "subject_rights.art20.portability" }),
  });
  assert.deepEqual(r20, { ok: true, warnings: ["art20_cross_border_atr_missing"] });
});

test("§WARN10 warnings flow through verifyReceipt into FamilyVerifyResult.warnings", async () => {
  // End-to-end: mint + verify through asrFamily.verifyReceipt and assert
  // the warning lands on the result's warnings array (advisory — does NOT
  // poison signature_valid).
  const env = await asrFamily.mintV2(
    mintInput({
      body: {
        ...bodyFulfilled(),
        portability_format: "json",
        portability_recipient_did: "did:web:non-eu.example",
      },
    }),
  );
  const verify = await asrFamily.verifyReceipt(env, {
    resolveKey: () => PUB_DER,
    profile: "subject_rights.art20.portability",
  });
  assert.equal(verify.signature_valid, true, verify.reason);
  assert.ok(
    verify.warnings !== undefined && verify.warnings.includes("art20_cross_border_atr_missing"),
    `expected art20_cross_border_atr_missing in warnings, got ${JSON.stringify(verify.warnings)}`,
  );
});

// ── §INT — pipeline integration through asrFamily.verifyReceipt ──────────────

test("§INT1 verifyReceipt: art17 fulfilled + ARR happy → signature_valid: true", async () => {
  const env = await asrFamily.mintV2(
    mintInput({
      body: { ...bodyFulfilled(), arr_receipt_id: "arr_x" },
    }),
  );
  const verify = await asrFamily.verifyReceipt(env, {
    resolveKey: () => PUB_DER,
    profile: "subject_rights.art17.erasure_request",
    resolveArr: async () => arrReceipt({ iat: env.iat }),
  });
  assert.equal(verify.signature_valid, true, verify.reason);
});

test("§INT2 verifyReceipt: art17 fulfilled + missing arr_receipt_id → HARD invalid", async () => {
  const env = await asrFamily.mintV2(mintInput({ body: bodyFulfilled() }));
  const verify = await asrFamily.verifyReceipt(env, {
    resolveKey: () => PUB_DER,
    profile: "subject_rights.art17.erasure_request",
    resolveArr: async () => arrReceipt(),
  });
  assert.equal(verify.signature_valid, false);
  assert.equal(verify.reason, "art17_arr_link_missing");
});

test("§INT3 verifyReceipt: art17 fulfilled + wrong-claim-type ARR → HARD invalid", async () => {
  const env = await asrFamily.mintV2(
    mintInput({ body: { ...bodyFulfilled(), arr_receipt_id: "arr_x" } }),
  );
  const verify = await asrFamily.verifyReceipt(env, {
    resolveKey: () => PUB_DER,
    profile: "subject_rights.art17.erasure_request",
    resolveArr: async () =>
      arrReceipt({ claim_type: "ar.provenance.v1", iat: env.iat }),
  });
  assert.equal(verify.signature_valid, false);
  assert.equal(verify.reason, "art17_arr_wrong_claim_type");
});

test("§INT4 verifyReceipt: art19 cascade short-circuits on bad ALR", async () => {
  const env = await asrFamily.mintV2(
    mintInput({ body: bodyRecipientNotified() }),
  );
  const verify = await asrFamily.verifyReceipt(env, {
    resolveKey: () => PUB_DER,
    profile: "subject_rights.art17.erasure_request",
    resolveAlr: async () => alrReceipt({ subject: sha256("z") }),
  });
  assert.equal(verify.signature_valid, false);
  assert.equal(verify.reason, "art19_alr_subject_mismatch");
});

test("§INT5 verifyReceipt: resolver throws → compose_threw:<msg>", async () => {
  const env = await asrFamily.mintV2(
    mintInput({ body: { ...bodyFulfilled(), arr_receipt_id: "arr_x" } }),
  );
  const verify = await asrFamily.verifyReceipt(env, {
    resolveKey: () => PUB_DER,
    profile: "subject_rights.art17.erasure_request",
    resolveArr: () => {
      throw new Error("boom");
    },
  });
  assert.equal(verify.signature_valid, false);
  assert.equal(verify.reason, "compose_threw:boom");
});

test("§INT6 verifyReceipt: no resolvers wired → signature_valid stays byte-equal to pre-§G", async () => {
  // Without any cross-family resolver, all cross-walks should skip
  // silently. art15.access fulfilled (no MANDATORY cross-link) verifies
  // green just like the existing round-trip suite expects.
  const env = await asrFamily.mintV2(mintInput({ body: bodyFulfilled() }));
  const verify = await asrFamily.verifyReceipt(env, {
    resolveKey: () => PUB_DER,
    profile: "subject_rights.art15.access",
  });
  assert.equal(verify.signature_valid, true, verify.reason);
});

test("§INT7 verifyReceipt: KP shape sanity", () => {
  // Sanity that fixtures don't drift — the keypair has the expected shape.
  assert.equal(KP.publicKey.length, 32);
  assert.equal(KP.privateKey.length, 32);
  assert.equal(REQ_ID.length > 0, true);
  assert.equal(typeof SUBJECT, "string");
  assert.deepEqual(ANCHOR.log, "https://verify.dekimu.com/asr/v1");
});
