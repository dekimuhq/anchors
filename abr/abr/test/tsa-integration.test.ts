/**
 * TSA integration + per-event mandate matrix tests for @dekimuhq/abr-verifier.
 * Phase 3 §D — sister test of `anr/anr-verifier/test/tsa-integration.test.ts`
 * and `alr/alr-verifier/test/tsa-integration.test.ts`.
 *
 * Coverage:
 *   T1 — envelope without tsa → `tsa_state: "tsa_absent"` (pre-mandate),
 *        upgraded by the §D matrix per event_type.
 *   T3 — injected (imprint-mismatched) tsa block → `tsa_state: "tsa_imprint_mismatch"`,
 *        `signature_valid` remains true. Mandate is a no-op (real TSA reason wins).
 *   M  — per-event mandate matrix:
 *        `breach.detected`                    → MANDATORY (D10-ABR-2 — 72-hour clock).
 *        all seven other events               → RECOMMENDED (warning only).
 *
 * T2 is intentionally skipped — happy-path TSA verification is covered at the
 * unit level in `envelope/test/tsa/verify.test.ts`. Mirrors the ALR / ANR
 * tsa-integration test layout.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { base64UrlEncode } from "@dekimuhq/anchors-envelope";
import { loadTrustAnchors, parseTimeStampResp } from "@dekimuhq/anchors-envelope/tsa";
import { verifyReceipt } from "../src/index.ts";
import {
  ABR_TSA_MANDATE,
  tsaMandateLevel,
  applyAbrTsaMandate,
  type AbrTsaMandateTarget,
} from "../src/tsa-mandate.ts";
import type { AbrBody, AbrEventType } from "../src/types.ts";
import { mintValidAbr, makeResolveKey } from "./_helpers/v2-receipt.ts";

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── FreeTSA fixture (real RFC 3161 response; wrong imprint for our envelope) ─

const tsrPath = resolve(__dirname, "../../../envelope/test/tsa/fixtures/freetsa-sample.tsr");
const sampleTsrB64 = base64UrlEncode(new Uint8Array(readFileSync(tsrPath)));

const anchorPath = resolve(__dirname, "../../../data/freetsa-trust-anchor.json");
const anchors = loadTrustAnchors([anchorPath]);

const ALL_EVENTS: readonly AbrEventType[] = [
  "breach.detected",
  "breach.assessed",
  "breach.dpa_notified",
  "breach.dpa_delayed",
  "breach.subject_notified",
  "breach.subject_notification_exempted",
  "breach.contained",
  "breach.closed",
];

const RECOMMENDED_EVENTS: readonly AbrEventType[] = [
  "breach.assessed",
  "breach.dpa_notified",
  "breach.dpa_delayed",
  "breach.subject_notified",
  "breach.subject_notification_exempted",
  "breach.contained",
  "breach.closed",
];

// ── T1 — absent TSA + RECOMMENDED event surfaces as "tsa_recommended" ────────

for (const event of RECOMMENDED_EVENTS) {
  test(`abr tsa-integration: ${event} without tsa → tsa_recommended, sig valid`, async () => {
    const { envelope, publicKey } = await mintValidAbr(event);
    assert.equal(envelope.tsa, null);

    const result = await verifyReceipt(envelope, {
      resolveKey: makeResolveKey(publicKey),
      tsaAnchors: anchors,
    });
    assert.equal(result.signature_valid, true);
    assert.equal(
      result.tsa_state,
      "tsa_recommended",
      "RECOMMENDED event must upgrade tsa_absent to tsa_recommended",
    );
    assert.equal(result.tsa_listed, false);
    assert.equal(result.reason, undefined);
  });
}

// ── T1b — absent TSA + MANDATORY event (breach.detected) poisons the sig ─────

test("abr tsa-integration: breach.detected without tsa → tsa_required, sig poisoned (D10-ABR-2)", async () => {
  const { envelope, publicKey } = await mintValidAbr("breach.detected");
  assert.equal(envelope.tsa, null);

  const result = await verifyReceipt(envelope, {
    resolveKey: makeResolveKey(publicKey),
    tsaAnchors: anchors,
  });
  assert.equal(
    result.signature_valid,
    false,
    "MANDATORY event must poison signature_valid when tsa absent",
  );
  assert.equal(result.reason, "tsa_required");
  assert.equal(result.tsa_state, "tsa_required");
  assert.equal(result.tsa_listed, false);
});

// ── T3 — injected TSR with mismatched imprint (mandate is no-op) ─────────────

test("abr tsa-integration: injected tsa with mismatched imprint → tsa_imprint_mismatch, sig valid (RECOMMENDED event)", async () => {
  const { envelope, publicKey } = await mintValidAbr("breach.assessed");

  const injected = {
    ...envelope,
    tsa: {
      v: 1 as const,
      tsr: sampleTsrB64,
      alg: "sha-256" as const,
      tsa_url: "https://freetsa.org/tsr",
      tsa_cert_chain_sha256: [],
      issued_at: "2026-05-19T09:06:45Z",
    },
  };

  const parsed = parseTimeStampResp(new Uint8Array(readFileSync(tsrPath)));
  assert.ok(parsed.granted, "fixture setup: tsr must be granted");
  const refTime = new Date(parsed.tstInfo.genTime);

  const result = await verifyReceipt(injected as never, {
    resolveKey: makeResolveKey(publicKey),
    tsaAnchors: anchors,
    tsaDriftToleranceSec: 300,
    tsaReferenceTime: refTime,
  });

  assert.equal(result.signature_valid, true, "sig must remain valid when tsa is corrupted");
  assert.equal(
    result.tsa_state,
    "tsa_imprint_mismatch",
    "real TSA reason must win over RECOMMENDED mandate matrix",
  );
  assert.equal(result.tsa_listed, false);
  assert.equal(result.tsa_policy_oid, "1.2.3.4.1");
});

test("abr tsa-integration: injected tsa with mismatched imprint → mandate no-op even for breach.detected", async () => {
  const { envelope, publicKey } = await mintValidAbr("breach.detected");

  const injected = {
    ...envelope,
    tsa: {
      v: 1 as const,
      tsr: sampleTsrB64,
      alg: "sha-256" as const,
      tsa_url: "https://freetsa.org/tsr",
      tsa_cert_chain_sha256: [],
      issued_at: "2026-05-19T09:06:45Z",
    },
  };

  const parsed = parseTimeStampResp(new Uint8Array(readFileSync(tsrPath)));
  assert.ok(parsed.granted, "fixture setup: tsr must be granted");
  const refTime = new Date(parsed.tstInfo.genTime);

  const result = await verifyReceipt(injected as never, {
    resolveKey: makeResolveKey(publicKey),
    tsaAnchors: anchors,
    tsaDriftToleranceSec: 300,
    tsaReferenceTime: refTime,
  });

  assert.equal(
    result.signature_valid,
    true,
    "real TSA reason must NOT trigger MANDATORY-mandate poisoning",
  );
  assert.equal(result.tsa_state, "tsa_imprint_mismatch");
  assert.equal(result.reason, undefined);
});

// ── M — matrix declares one MANDATORY + seven RECOMMENDED ────────────────────

test("abr tsa-mandate: matrix shape — one MANDATORY (breach.detected) + seven RECOMMENDED", () => {
  const levels = ALL_EVENTS.map((e) => ABR_TSA_MANDATE[e]);
  const mandatory = levels.filter((l) => l === "MANDATORY").length;
  const recommended = levels.filter((l) => l === "RECOMMENDED").length;
  const optional = levels.filter((l) => l === "OPTIONAL").length;
  assert.equal(mandatory, 1);
  assert.equal(recommended, 7);
  assert.equal(optional, 0);
  assert.equal(ABR_TSA_MANDATE["breach.detected"], "MANDATORY");
});

for (const event of ALL_EVENTS) {
  test(`abr tsa-mandate: lookup ${event}`, () => {
    const expected: "MANDATORY" | "RECOMMENDED" =
      event === "breach.detected" ? "MANDATORY" : "RECOMMENDED";
    assert.equal(tsaMandateLevel(event), expected);
  });
}

// ── Unit coverage for the mandate helper (independent of envelope-v2) ────────

function detectedBody(): AbrBody {
  return {
    profile: "breach.gdpr.art33",
    incident_correlation_id: "incident-test",
    qts_attestation_hash: null,
    event_type: "breach.detected",
    detected_at: "2026-05-19T08:00:00Z",
    severity_class: "high_risk",
    affected_data_categories: ["email"],
    affected_data_hash: "sha256:" + "a".repeat(64),
    affected_count: 1,
    jurisdiction: "EU",
    affected_aer_ids: null,
    assessment_method_hash: null,
    notification_uri: null,
    notification_hash: null,
    dpa_reference_id: null,
    notification_phase: null,
    delay_reason_hash: null,
    delay_until_at: null,
    subject_batch_root: null,
    subject_batch_size: null,
    exemption_ground: null,
    justification_hash: null,
    public_communication_uri: null,
    containment_at: null,
    containment_summary_hash: null,
    containment_attestation: null,
    closed_at: null,
    closure_dpa_reference_id: null,
    containment_remediation_arr_ids: null,
    transfer_suspension_atr_ids: null,
    post_breach_anr_id: null,
    qes_aar_id: null,
  };
}

function assessedBody(): AbrBody {
  return {
    profile: "breach.gdpr.art33",
    incident_correlation_id: "incident-test",
    qts_attestation_hash: null,
    event_type: "breach.assessed",
    severity_class: "risk",
    assessment_method_hash: "sha256:" + "b".repeat(64),
    detected_at: null,
    affected_data_categories: null,
    affected_data_hash: null,
    affected_count: null,
    jurisdiction: null,
    notification_uri: null,
    notification_hash: null,
    dpa_reference_id: null,
    notification_phase: null,
    delay_reason_hash: null,
    delay_until_at: null,
    subject_batch_root: null,
    subject_batch_size: null,
    exemption_ground: null,
    justification_hash: null,
    public_communication_uri: null,
    containment_at: null,
    containment_summary_hash: null,
    containment_attestation: null,
    closed_at: null,
    closure_dpa_reference_id: null,
    affected_aer_ids: null,
    containment_remediation_arr_ids: null,
    transfer_suspension_atr_ids: null,
    post_breach_anr_id: null,
    qes_aar_id: null,
  };
}

test("abr tsa-mandate: applyAbrTsaMandate flips signature on MANDATORY (breach.detected) + absent", () => {
  const body = detectedBody();
  const out: AbrTsaMandateTarget = {
    signature_valid: true,
    tsa_state: "tsa_absent",
  };
  applyAbrTsaMandate(out, body);
  assert.equal(out.signature_valid, false);
  assert.equal(out.reason, "tsa_required");
  assert.equal(out.tsa_state, "tsa_required");
});

test("abr tsa-mandate: applyAbrTsaMandate adds tsa_recommended on RECOMMENDED + absent", () => {
  const body = assessedBody();
  const out: AbrTsaMandateTarget = {
    signature_valid: true,
    tsa_state: "tsa_absent",
  };
  applyAbrTsaMandate(out, body);
  assert.equal(out.signature_valid, true, "RECOMMENDED must not poison signature_valid");
  assert.equal(out.reason, undefined);
  assert.equal(out.tsa_state, "tsa_recommended");
});

test("abr tsa-mandate: applyAbrTsaMandate no-op when tsa_state is a real TSA reason (MANDATORY event)", () => {
  const body = detectedBody();
  const out: AbrTsaMandateTarget = {
    signature_valid: true,
    tsa_state: "tsa_imprint_mismatch",
  };
  applyAbrTsaMandate(out, body);
  assert.equal(out.signature_valid, true, "real TSA reason must win over MANDATORY mandate");
  assert.equal(out.tsa_state, "tsa_imprint_mismatch");
  assert.equal(out.reason, undefined);
});

test("abr tsa-mandate: applyAbrTsaMandate no-op when tsa_state is a real TSA reason (RECOMMENDED event)", () => {
  const body = assessedBody();
  const out: AbrTsaMandateTarget = {
    signature_valid: true,
    tsa_state: "tsa_anchor_expired",
  };
  applyAbrTsaMandate(out, body);
  assert.equal(out.signature_valid, true);
  assert.equal(out.tsa_state, "tsa_anchor_expired");
  assert.equal(out.reason, undefined);
});

test("abr tsa-mandate: applyAbrTsaMandate no-op when tsa_state is undefined (e.g. tsa present)", () => {
  const body = detectedBody();
  const out: AbrTsaMandateTarget = { signature_valid: true };
  applyAbrTsaMandate(out, body);
  assert.equal(out.signature_valid, true);
  assert.equal(out.tsa_state, undefined);
  assert.equal(out.reason, undefined);
});

test("abr tsa-mandate: applyAbrTsaMandate defensive — unknown event_type is a no-op", () => {
  const body = assessedBody();
  // Cast through Record because TS won't let us assign a non-AbrEventType literal.
  (body as unknown as Record<string, string>).event_type = "breach.bogus";
  const out: AbrTsaMandateTarget = {
    signature_valid: true,
    tsa_state: "tsa_absent",
  };
  applyAbrTsaMandate(out, body);
  assert.equal(out.signature_valid, true, "unknown event_type must not poison signature");
  assert.equal(out.tsa_state, "tsa_absent");
  assert.equal(out.reason, undefined);
});
