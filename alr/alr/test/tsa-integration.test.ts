/**
 * TSA integration tests for @dekimuhq/alr-verifier — Phase 1 §D.
 *
 * Coverage:
 *   T1 — envelope without tsa → `tsa_state: "tsa_absent"`, `tsa_listed: false`.
 *   T3 — injected (imprint-mismatched) tsa block → `tsa_state: "tsa_imprint_mismatch"`,
 *        `signature_valid` remains true (TSA failure does not poison sig).
 *   M  — per-event mandate matrix: every ALR event type is OPTIONAL in v1
 *        (FAMILY-CONSISTENCY.md §2), so absent TSA never upgrades to
 *        `tsa_required` or `tsa_recommended`.
 *
 * T2 is intentionally skipped — happy-path TSA verification is covered at
 * the unit level in `envelope/test/tsa/verify.test.ts`. Mirrors the ARR
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
  ALR_TSA_MANDATE,
  tsaMandateLevel,
  applyAlrTsaMandate,
} from "../src/tsa-mandate.ts";
import type { AlrEventType } from "../src/types.ts";
import { mintValidAlr, makeResolveKey } from "./_helpers/v2-receipt.ts";

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── FreeTSA fixture (real RFC 3161 response; wrong imprint for our envelope) ─

const tsrPath = resolve(__dirname, "../../../envelope/test/tsa/fixtures/freetsa-sample.tsr");
const sampleTsrB64 = base64UrlEncode(new Uint8Array(readFileSync(tsrPath)));

const anchorPath = resolve(__dirname, "../../../data/freetsa-trust-anchor.json");
const anchors = loadTrustAnchors([anchorPath]);

// ── T1 — absent TSA surfaces as "tsa_absent" ─────────────────────────────────

test("alr tsa-integration: envelope without tsa returns tsa_state absent", async () => {
  const { envelope, publicKey } = await mintValidAlr();
  assert.equal(envelope.tsa, null);

  const result = await verifyReceipt(envelope, {
    resolveKey: makeResolveKey(publicKey),
    tsaAnchors: anchors,
  }) as FamilyVerifyResult;
  assert.equal(result.signature_valid, true);
  assert.equal(result.tsa_state, "tsa_absent");
  assert.equal(result.tsa_listed, false);
});

// ── T3 — injected TSR with mismatched imprint ────────────────────────────────

test("alr tsa-integration: injected tsa with mismatched imprint → tsa_imprint_mismatch, sig valid", async () => {
  const { envelope, publicKey } = await mintValidAlr();

  const injected = {
    ...envelope,
    tsa: {
      v: 1 as const,
      tsr: sampleTsrB64,
      alg: "sha-256" as const,
      tsa_url: "https://freetsa.org/tsr",
      tsa_cert_chain_sha256: [],
      issued_at: "2026-05-17T09:06:45Z",
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
  assert.equal(result.tsa_state, "tsa_imprint_mismatch");
  assert.equal(result.tsa_listed, false);
  // FreeTSA fixture policy OID surfaces past the granted check.
  assert.equal(result.tsa_policy_oid, "1.2.3.4.1");
});

// ── M — per-event mandate matrix ─────────────────────────────────────────────

test("alr tsa-mandate: matrix declares OPTIONAL for every event type", () => {
  const allOpt = (Object.values(ALR_TSA_MANDATE) as string[]).every(
    (v) => v === "OPTIONAL",
  );
  assert.equal(allOpt, true);
});

const EVENT_TYPES: readonly AlrEventType[] = [
  "derived_from",
  "forked_from",
  "superseded_by",
  "disclosed",
];

for (const event_type of EVENT_TYPES) {
  test(`alr tsa-mandate: ${event_type} → no upgrade when tsa absent`, async () => {
    const { envelope, publicKey } = await mintValidAlr(event_type);
    const result = await verifyReceipt(envelope, {
      resolveKey: makeResolveKey(publicKey),
      tsaAnchors: anchors,
    }) as FamilyVerifyResult;
    assert.equal(result.signature_valid, true);
    assert.equal(
      result.tsa_state,
      "tsa_absent",
      "ALR v1 mandate is OPTIONAL — absent tsa must not upgrade to required/recommended",
    );
    assert.equal(tsaMandateLevel(event_type), "OPTIONAL");
  });
}

// ── Unit coverage for the mandate helper (in case the matrix is tightened later) ──

test("alr tsa-mandate: applyAlrTsaMandate flips signature on MANDATORY + absent", () => {
  // Simulate a future-state MANDATORY mapping by calling the helper directly
  // with a manually constructed body. The matrix itself stays OPTIONAL in v1
  // (the previous test enforces that). This test guarantees the upgrade path
  // still works the day someone flips an event to MANDATORY.
  const body = {
    profile: "aiact.art13.transparency" as const,
    artifact_hash: "sha256:" + "c".repeat(64),
    event_at: "2026-05-16T14:23:00Z",
    qts_attestation_hash: null,
    event_type: "derived_from" as const,
    parents: [
      {
        artifact_hash: "sha256:" + "a".repeat(64),
        parent_apr_id: null,
        parent_alr_id: null,
        uri: null,
      },
    ],
    successor: null,
    transform_claim: { summary: "x", uri: null },
    disclosure: null,
  };
  // Pretend the matrix mapped derived_from to MANDATORY for this assertion.
  const origLevel = ALR_TSA_MANDATE.derived_from;
  (ALR_TSA_MANDATE as Record<string, string>).derived_from = "MANDATORY";
  try {
    const out: { signature_valid: boolean; reason?: string; tsa_state?: string } = {
      signature_valid: true,
      tsa_state: "tsa_absent",
    };
    applyAlrTsaMandate(out, body);
    assert.equal(out.signature_valid, false);
    assert.equal(out.reason, "tsa_required");
    assert.equal(out.tsa_state, "tsa_required");
  } finally {
    (ALR_TSA_MANDATE as Record<string, string>).derived_from = origLevel;
  }
});

test("alr tsa-mandate: applyAlrTsaMandate adds tsa_recommended on RECOMMENDED + absent", () => {
  const body = {
    profile: "aiact.art13.transparency" as const,
    artifact_hash: "sha256:" + "c".repeat(64),
    event_at: "2026-05-16T14:23:00Z",
    qts_attestation_hash: null,
    event_type: "forked_from" as const,
    parents: [
      {
        artifact_hash: "sha256:" + "a".repeat(64),
        parent_apr_id: null,
        parent_alr_id: null,
        uri: null,
      },
    ],
    successor: null,
    transform_claim: { summary: "x", uri: null },
    disclosure: null,
  };
  const origLevel = ALR_TSA_MANDATE.forked_from;
  (ALR_TSA_MANDATE as Record<string, string>).forked_from = "RECOMMENDED";
  try {
    const out: { signature_valid: boolean; reason?: string; tsa_state?: string } = {
      signature_valid: true,
      tsa_state: "tsa_absent",
    };
    applyAlrTsaMandate(out, body);
    assert.equal(out.signature_valid, true, "RECOMMENDED must not poison signature_valid");
    assert.equal(out.reason, undefined);
    assert.equal(out.tsa_state, "tsa_recommended");
  } finally {
    (ALR_TSA_MANDATE as Record<string, string>).forked_from = origLevel;
  }
});

test("alr tsa-mandate: applyAlrTsaMandate no-op when tsa_state is a real TSA reason", () => {
  const body = {
    profile: "aiact.art13.transparency" as const,
    artifact_hash: "sha256:" + "c".repeat(64),
    event_at: "2026-05-16T14:23:00Z",
    qts_attestation_hash: null,
    event_type: "derived_from" as const,
    parents: [
      {
        artifact_hash: "sha256:" + "a".repeat(64),
        parent_apr_id: null,
        parent_alr_id: null,
        uri: null,
      },
    ],
    successor: null,
    transform_claim: { summary: "x", uri: null },
    disclosure: null,
  };
  const origLevel = ALR_TSA_MANDATE.derived_from;
  (ALR_TSA_MANDATE as Record<string, string>).derived_from = "MANDATORY";
  try {
    const out: { signature_valid: boolean; reason?: string; tsa_state?: string } = {
      signature_valid: true,
      tsa_state: "tsa_imprint_mismatch",
    };
    applyAlrTsaMandate(out, body);
    assert.equal(out.signature_valid, true, "real TSA reason must win over mandate matrix");
    assert.equal(out.tsa_state, "tsa_imprint_mismatch");
    assert.equal(out.reason, undefined);
  } finally {
    (ALR_TSA_MANDATE as Record<string, string>).derived_from = origLevel;
  }
});
