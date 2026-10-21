/**
 * TSA integration + per-event mandate matrix tests for @dekimuhq/air-verifier.
 * Phase 5 §D — sister test of `abr/abr-verifier/test/tsa-integration.test.ts`,
 * `anr/anr-verifier/test/tsa-integration.test.ts`, and
 * `alr/alr-verifier/test/tsa-integration.test.ts`.
 *
 * Coverage:
 *   T1 — envelope without tsa → `tsa_state: "tsa_absent"` (pre-mandate),
 *        upgraded by the §D matrix per event_type.
 *   T3 — injected (imprint-mismatched) tsa block → `tsa_state: "tsa_imprint_mismatch"`,
 *        `signature_valid` remains true. Mandate is a no-op (real TSA reason wins).
 *   M  — per-event mandate matrix:
 *        `dpia.completed`                      → RECOMMENDED (DPIA sequence clock).
 *        `dpia.prior_consultation_initiated`   → RECOMMENDED (Art. 36 submission clock).
 *        `dpia.prior_consultation_resolved`    → RECOMMENDED (Art. 36 advice receipt clock).
 *        all eight other events                → OPTIONAL.
 *        AIR v1 has NO MANDATORY event — contrast with ABR `breach.detected`.
 *
 * T2 is intentionally skipped — happy-path TSA verification is covered at the
 * unit level in `envelope/test/tsa/verify.test.ts`. Mirrors the ABR / ALR / ANR
 * tsa-integration test layout.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { base64UrlEncode } from "@dekimuhq/anchors-envelope";
import type { FamilyVerifyResult } from "@dekimuhq/anchors-envelope";
import { loadTrustAnchors, parseTimeStampResp } from "@dekimuhq/anchors-envelope/tsa";
import { verifyReceipt } from "../src/index.ts";
import {
  AIR_TSA_MANDATE,
  tsaMandateLevel,
  applyAirTsaMandate,
  type AirTsaMandateTarget,
} from "../src/tsa-mandate.ts";
import type { AirBody, AirEventType } from "../src/types.ts";
import { mintValidAir, makeResolveKey } from "./_helpers/v2-receipt.ts";
import { completed, dpoAdvised, thresholdTriggered } from "./_helpers/bodies.ts";

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── FreeTSA fixture (real RFC 3161 response; wrong imprint for our envelope) ─

const tsrPath = resolve(__dirname, "../../../envelope/test/tsa/fixtures/freetsa-sample.tsr");
const sampleTsrB64 = base64UrlEncode(new Uint8Array(readFileSync(tsrPath)));

const anchorPath = resolve(__dirname, "../../../data/freetsa-trust-anchor.json");
const anchors = loadTrustAnchors([anchorPath]);

const ALL_EVENTS: readonly AirEventType[] = [
  "dpia.threshold_triggered",
  "dpia.scope_locked",
  "dpia.dpo_advised",
  "dpia.stakeholders_consulted",
  "dpia.completed",
  "dpia.reviewed",
  "dpia.prior_consultation_initiated",
  "dpia.prior_consultation_resolved",
  "dpia.processing_authorised",
  "dpia.processing_blocked",
  "dpia.terminated",
];

const RECOMMENDED_EVENTS: readonly AirEventType[] = [
  "dpia.completed",
  "dpia.prior_consultation_initiated",
  "dpia.prior_consultation_resolved",
];

const OPTIONAL_EVENTS: readonly AirEventType[] = [
  "dpia.threshold_triggered",
  "dpia.scope_locked",
  "dpia.dpo_advised",
  "dpia.stakeholders_consulted",
  "dpia.reviewed",
  "dpia.processing_authorised",
  "dpia.processing_blocked",
  "dpia.terminated",
];

// ── T1 — absent TSA + RECOMMENDED event surfaces as "tsa_recommended" ────────

for (const event of RECOMMENDED_EVENTS) {
  test(`air tsa-integration: ${event} without tsa → tsa_recommended, sig valid`, async () => {
    const { envelope, publicKey } = await mintValidAir(event);
    assert.equal(envelope.tsa, null);

    const result = await verifyReceipt(envelope, {
      resolveKey: makeResolveKey(publicKey),
      tsaAnchors: anchors,
    }) as FamilyVerifyResult;
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

// ── T1b — absent TSA + OPTIONAL event leaves tsa_state untouched (tsa_absent) ─

for (const event of OPTIONAL_EVENTS) {
  test(`air tsa-integration: ${event} without tsa → tsa_absent, sig valid (OPTIONAL)`, async () => {
    const { envelope, publicKey } = await mintValidAir(event);
    assert.equal(envelope.tsa, null);

    const result = await verifyReceipt(envelope, {
      resolveKey: makeResolveKey(publicKey),
      tsaAnchors: anchors,
    }) as FamilyVerifyResult;
    assert.equal(result.signature_valid, true);
    assert.equal(
      result.tsa_state,
      "tsa_absent",
      "OPTIONAL event must leave tsa_absent untouched",
    );
    assert.equal(result.tsa_listed, false);
    assert.equal(result.reason, undefined);
  });
}

// ── T3 — injected TSR with mismatched imprint (mandate is no-op on RECOMMENDED) ─

test("air tsa-integration: injected tsa with mismatched imprint → tsa_imprint_mismatch, sig valid (RECOMMENDED event)", async () => {
  const { envelope, publicKey } = await mintValidAir("dpia.completed");

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
  }) as FamilyVerifyResult;

  assert.equal(result.signature_valid, true, "sig must remain valid when tsa is corrupted");
  assert.equal(
    result.tsa_state,
    "tsa_imprint_mismatch",
    "real TSA reason must win over RECOMMENDED mandate matrix",
  );
  assert.equal(result.tsa_listed, false);
  assert.equal(result.tsa_policy_oid, "1.2.3.4.1");
});

test("air tsa-integration: injected tsa with mismatched imprint → mandate no-op for OPTIONAL event too", async () => {
  const { envelope, publicKey } = await mintValidAir("dpia.threshold_triggered");

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
  }) as FamilyVerifyResult;

  assert.equal(
    result.signature_valid,
    true,
    "OPTIONAL + real TSA reason → mandate is a no-op",
  );
  assert.equal(result.tsa_state, "tsa_imprint_mismatch");
  assert.equal(result.reason, undefined);
});

// ── M — matrix shape: zero MANDATORY + three RECOMMENDED + eight OPTIONAL ────

test("air tsa-mandate: matrix shape — zero MANDATORY + three RECOMMENDED + eight OPTIONAL", () => {
  const levels = ALL_EVENTS.map((e) => AIR_TSA_MANDATE[e]);
  const mandatory = levels.filter((l) => l === "MANDATORY").length;
  const recommended = levels.filter((l) => l === "RECOMMENDED").length;
  const optional = levels.filter((l) => l === "OPTIONAL").length;
  assert.equal(mandatory, 0, "AIR v1 has no MANDATORY event");
  assert.equal(recommended, 3);
  assert.equal(optional, 8);
  assert.equal(AIR_TSA_MANDATE["dpia.completed"], "RECOMMENDED");
  assert.equal(AIR_TSA_MANDATE["dpia.prior_consultation_initiated"], "RECOMMENDED");
  assert.equal(AIR_TSA_MANDATE["dpia.prior_consultation_resolved"], "RECOMMENDED");
});

for (const event of ALL_EVENTS) {
  test(`air tsa-mandate: lookup ${event}`, () => {
    const expected: "RECOMMENDED" | "OPTIONAL" = RECOMMENDED_EVENTS.includes(event)
      ? "RECOMMENDED"
      : "OPTIONAL";
    assert.equal(tsaMandateLevel(event), expected);
  });
}

// ── Unit coverage for the mandate helper (independent of envelope-v2) ────────

test("air tsa-mandate: applyAirTsaMandate adds tsa_recommended on RECOMMENDED + absent", () => {
  const body: AirBody = completed();
  const out: AirTsaMandateTarget = {
    signature_valid: true,
    tsa_state: "tsa_absent",
  };
  applyAirTsaMandate(out, body);
  assert.equal(out.signature_valid, true, "RECOMMENDED must not poison signature_valid");
  assert.equal(out.reason, undefined);
  assert.equal(out.tsa_state, "tsa_recommended");
});

test("air tsa-mandate: applyAirTsaMandate is a no-op on OPTIONAL + absent (tsa_state unchanged)", () => {
  const body: AirBody = thresholdTriggered();
  const out: AirTsaMandateTarget = {
    signature_valid: true,
    tsa_state: "tsa_absent",
  };
  applyAirTsaMandate(out, body);
  assert.equal(out.signature_valid, true);
  assert.equal(out.reason, undefined);
  assert.equal(out.tsa_state, "tsa_absent");
});

test("air tsa-mandate: applyAirTsaMandate no-op when tsa_state is a real TSA reason (RECOMMENDED event)", () => {
  const body: AirBody = completed();
  const out: AirTsaMandateTarget = {
    signature_valid: true,
    tsa_state: "tsa_imprint_mismatch",
  };
  applyAirTsaMandate(out, body);
  assert.equal(out.signature_valid, true, "real TSA reason must win over RECOMMENDED mandate");
  assert.equal(out.tsa_state, "tsa_imprint_mismatch");
  assert.equal(out.reason, undefined);
});

test("air tsa-mandate: applyAirTsaMandate no-op when tsa_state is a real TSA reason (OPTIONAL event)", () => {
  const body: AirBody = dpoAdvised();
  const out: AirTsaMandateTarget = {
    signature_valid: true,
    tsa_state: "tsa_anchor_expired",
  };
  applyAirTsaMandate(out, body);
  assert.equal(out.signature_valid, true);
  assert.equal(out.tsa_state, "tsa_anchor_expired");
  assert.equal(out.reason, undefined);
});

test("air tsa-mandate: applyAirTsaMandate no-op when tsa_state is undefined (e.g. tsa present)", () => {
  const body: AirBody = completed();
  const out: AirTsaMandateTarget = { signature_valid: true };
  applyAirTsaMandate(out, body);
  assert.equal(out.signature_valid, true);
  assert.equal(out.tsa_state, undefined);
  assert.equal(out.reason, undefined);
});

test("air tsa-mandate: applyAirTsaMandate defensive — unknown event_type is a no-op", () => {
  const body: AirBody = dpoAdvised();
  // Cast through Record because TS won't let us assign a non-AirEventType literal.
  (body as unknown as Record<string, string>).event_type = "dpia.bogus";
  const out: AirTsaMandateTarget = {
    signature_valid: true,
    tsa_state: "tsa_absent",
  };
  applyAirTsaMandate(out, body);
  assert.equal(out.signature_valid, true, "unknown event_type must not poison signature");
  assert.equal(out.tsa_state, "tsa_absent");
  assert.equal(out.reason, undefined);
});
