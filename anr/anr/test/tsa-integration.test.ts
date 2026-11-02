/**
 * TSA integration + per-profile mandate matrix tests for @dekimuhq/anr-verifier.
 * Phase 2 §D — sister test of `alr/alr-verifier/test/tsa-integration.test.ts`.
 *
 * Coverage:
 *   T1 — envelope without tsa → `tsa_state: "tsa_absent"` (pre-mandate),
 *        upgraded by the §D matrix per profile.
 *   T3 — injected (imprint-mismatched) tsa block → `tsa_state: "tsa_imprint_mismatch"`.
 *        RECOMMENDED profiles: `signature_valid` remains true (real TSA reason
 *        surfaced as-is). MANDATORY (art50): fails closed — `signature_valid:
 *        false`, `reason: "tsa_required"`, real `tsa_state` kept.
 *   M  — per-profile mandate matrix:
 *        `notice.aiact.art50_transparency`     → MANDATORY (poisons sig when tsa absent).
 *        all four other profiles               → RECOMMENDED (warning only).
 *
 * T2 is intentionally skipped — happy-path TSA verification is covered at the
 * unit level in `envelope/test/tsa/verify.test.ts`. Mirrors the ALR / ARR
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
  ANR_TSA_MANDATE,
  tsaMandateLevel,
  applyAnrTsaMandate,
  type AnrTsaMandateTarget,
} from "../src/tsa-mandate.ts";
import type { AnrBody, AnrProfile } from "../src/types.ts";
import { mintValidAnr, makeResolveKey } from "./_helpers/v2-receipt.ts";

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── FreeTSA fixture (real RFC 3161 response; wrong imprint for our envelope) ─

const tsrPath = resolve(__dirname, "../../../envelope/test/tsa/fixtures/freetsa-sample.tsr");
const sampleTsrB64 = base64UrlEncode(new Uint8Array(readFileSync(tsrPath)));

const anchorPath = resolve(__dirname, "../../../data/freetsa-trust-anchor.json");
const anchors = loadTrustAnchors([anchorPath]);

const ALL_PROFILES: readonly AnrProfile[] = [
  "notice.art13.collected_direct",
  "notice.art14.collected_indirect",
  "notice.art26.joint_controller_essence",
  "notice.layered_transparency",
  "notice.aiact.art50_transparency",
];

const RECOMMENDED_PROFILES: readonly AnrProfile[] = [
  "notice.art13.collected_direct",
  "notice.art14.collected_indirect",
  "notice.art26.joint_controller_essence",
  "notice.layered_transparency",
];

// ── T1 — absent TSA + RECOMMENDED profile surfaces as "tsa_recommended" ──────

for (const profile of RECOMMENDED_PROFILES) {
  test(`anr tsa-integration: ${profile} without tsa → tsa_recommended, sig valid`, async () => {
    const { envelope, publicKey } = await mintValidAnr(profile);
    assert.equal(envelope.tsa, null);

    const result = await verifyReceipt(envelope, {
      resolveKey: makeResolveKey(publicKey),
      tsaAnchors: anchors,
    }) as FamilyVerifyResult;
    assert.equal(result.signature_valid, true);
    assert.equal(
      result.tsa_state,
      "tsa_recommended",
      "RECOMMENDED profile must upgrade tsa_absent to tsa_recommended",
    );
    assert.equal(result.tsa_listed, false);
    assert.equal(result.reason, undefined);
  });
}

// ── T1b — absent TSA + MANDATORY profile poisons the signature ───────────────

test("anr tsa-integration: notice.aiact.art50_transparency without tsa → tsa_required, sig poisoned", async () => {
  const { envelope, publicKey } = await mintValidAnr("notice.aiact.art50_transparency");
  assert.equal(envelope.tsa, null);

  const result = await verifyReceipt(envelope, {
    resolveKey: makeResolveKey(publicKey),
    tsaAnchors: anchors,
  }) as FamilyVerifyResult;
  assert.equal(
    result.signature_valid,
    false,
    "MANDATORY profile must poison signature_valid when tsa absent",
  );
  assert.equal(result.reason, "tsa_required");
  assert.equal(result.tsa_state, "tsa_required");
  assert.equal(result.tsa_listed, false);
});

// ── T3 — injected TSR with mismatched imprint ────────────────────────────────

test("anr tsa-integration: injected tsa with mismatched imprint → tsa_imprint_mismatch, sig valid (RECOMMENDED profile)", async () => {
  const { envelope, publicKey } = await mintValidAnr("notice.art13.collected_direct");

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
  assert.equal(
    result.tsa_state,
    "tsa_imprint_mismatch",
    "real TSA reason must win over RECOMMENDED mandate matrix",
  );
  assert.equal(result.tsa_listed, false);
  assert.equal(result.tsa_policy_oid, "1.2.3.4.1");
});

test("anr tsa-integration: injected tsa with mismatched imprint on MANDATORY profile → tsa_required, fail closed", async () => {
  const { envelope, publicKey } = await mintValidAnr("notice.aiact.art50_transparency");

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

  assert.equal(
    result.signature_valid,
    false,
    "MANDATORY must fail closed on an unverified (attached) tsa block",
  );
  assert.equal(result.reason, "tsa_required");
  assert.equal(result.tsa_state, "tsa_imprint_mismatch", "real TSA reason must be preserved");
});

for (const [profile, mandatory] of [
  ["notice.aiact.art50_transparency", true],
  ["notice.art13.collected_direct", false],
] as const) {
  test(`anr tsa-integration: garbage tsr on ${profile} → ${mandatory ? "tsa_required (fail closed)" : "not poisoned"}, tsa_state tsa_malformed`, async () => {
    const { envelope, publicKey } = await mintValidAnr(profile);
    const injected = {
      ...envelope,
      tsa: {
        v: 1 as const,
        tsr: "AAAA",
        alg: "sha-256" as const,
        tsa_url: "https://tsa.example",
        tsa_cert_chain_sha256: [],
        issued_at: "2026-05-17T09:06:45Z",
      },
    };
    const result = await verifyReceipt(injected as never, {
      resolveKey: makeResolveKey(publicKey),
      tsaAnchors: anchors,
    }) as FamilyVerifyResult;
    assert.equal(result.signature_valid, !mandatory);
    assert.equal(result.reason, mandatory ? "tsa_required" : undefined);
    assert.equal(result.tsa_state, "tsa_malformed");
  });
}

// ── M — matrix declares one MANDATORY + four RECOMMENDED ─────────────────────

test("anr tsa-mandate: matrix shape — one MANDATORY (art50) + four RECOMMENDED", () => {
  const levels = ALL_PROFILES.map((p) => ANR_TSA_MANDATE[p]);
  const mandatory = levels.filter((l) => l === "MANDATORY").length;
  const recommended = levels.filter((l) => l === "RECOMMENDED").length;
  const optional = levels.filter((l) => l === "OPTIONAL").length;
  assert.equal(mandatory, 1);
  assert.equal(recommended, 4);
  assert.equal(optional, 0);
  assert.equal(ANR_TSA_MANDATE["notice.aiact.art50_transparency"], "MANDATORY");
});

for (const profile of ALL_PROFILES) {
  test(`anr tsa-mandate: lookup ${profile}`, () => {
    const expected: "MANDATORY" | "RECOMMENDED" =
      profile === "notice.aiact.art50_transparency" ? "MANDATORY" : "RECOMMENDED";
    assert.equal(tsaMandateLevel(profile), expected);
  });
}

// ── Unit coverage for the mandate helper (independent of envelope-v2) ────────

function bodyOnly(profile: AnrProfile): AnrBody {
  return {
    profile,
    lang_tag: "en-GB",
    lang_inferred: null,
    qts_attestation_hash: null,
    event_type: "notice.presented",
    jurisdiction: "EU",
    delivery_channel: "web",
    render_uri: "https://example.test/notice/v1",
    rights_surface: ["art15"],
    subject_age_band: profile === "notice.art13.collected_direct" ? "adult" : null,
    data_source: null,
    collection_horizon: null,
    data_acquired_at: null,
    layer_uris: null,
    ai_system_kind: profile === "notice.aiact.art50_transparency" ? "interaction" : null,
    ai_system_provider_did:
      profile === "notice.aiact.art50_transparency" ? "did:web:ai.example" : null,
    aer_id: null,
    supersedes_anr_id: null,
    base_anr_id: null,
    ack_method: null,
    joint_controllers: null,
    cessation_reason: null,
    translation_provenance_alr_id: null,
  };
}

test("anr tsa-mandate: applyAnrTsaMandate flips signature on MANDATORY + absent", () => {
  const body = bodyOnly("notice.aiact.art50_transparency");
  const out: AnrTsaMandateTarget = {
    signature_valid: true,
    tsa_state: "tsa_absent",
  };
  applyAnrTsaMandate(out, body);
  assert.equal(out.signature_valid, false);
  assert.equal(out.reason, "tsa_required");
  assert.equal(out.tsa_state, "tsa_required");
});

test("anr tsa-mandate: applyAnrTsaMandate adds tsa_recommended on RECOMMENDED + absent", () => {
  const body = bodyOnly("notice.art13.collected_direct");
  const out: AnrTsaMandateTarget = {
    signature_valid: true,
    tsa_state: "tsa_absent",
  };
  applyAnrTsaMandate(out, body);
  assert.equal(out.signature_valid, true, "RECOMMENDED must not poison signature_valid");
  assert.equal(out.reason, undefined);
  assert.equal(out.tsa_state, "tsa_recommended");
});

for (const state of ["tsa_imprint_mismatch", "tsa_malformed", "tsa_unrecognised_anchor", "tsa_drift_exceeded"]) {
  test(`anr tsa-mandate: applyAnrTsaMandate fails closed on MANDATORY + ${state} (tsa_state preserved)`, () => {
    const body = bodyOnly("notice.aiact.art50_transparency");
    const out: AnrTsaMandateTarget = { signature_valid: true, tsa_state: state };
    applyAnrTsaMandate(out, body);
    assert.equal(out.signature_valid, false, "MANDATORY must fail closed on an unverified tsa");
    assert.equal(out.reason, "tsa_required");
    assert.equal(out.tsa_state, state, "real TSA reason must be preserved");
  });
}

test("anr tsa-mandate: applyAnrTsaMandate passes MANDATORY + tsa_verified", () => {
  const body = bodyOnly("notice.aiact.art50_transparency");
  const out: AnrTsaMandateTarget = { signature_valid: true, tsa_state: "tsa_verified" };
  applyAnrTsaMandate(out, body);
  assert.equal(out.signature_valid, true);
  assert.equal(out.tsa_state, "tsa_verified");
  assert.equal(out.reason, undefined);
});

test("anr tsa-mandate: applyAnrTsaMandate keeps an earlier failure reason on MANDATORY", () => {
  const body = bodyOnly("notice.aiact.art50_transparency");
  const out: AnrTsaMandateTarget = { signature_valid: false, reason: "subject_missing", tsa_state: "tsa_malformed" };
  applyAnrTsaMandate(out, body);
  assert.equal(out.signature_valid, false);
  assert.equal(out.reason, "subject_missing");
  assert.equal(out.tsa_state, "tsa_malformed");
});

test("anr tsa-mandate: applyAnrTsaMandate no-op when tsa_state is a real TSA reason (RECOMMENDED profile)", () => {
  const body = bodyOnly("notice.art14.collected_indirect");
  const out: AnrTsaMandateTarget = {
    signature_valid: true,
    tsa_state: "tsa_anchor_expired",
  };
  applyAnrTsaMandate(out, body);
  assert.equal(out.signature_valid, true);
  assert.equal(out.tsa_state, "tsa_anchor_expired");
  assert.equal(out.reason, undefined);
});

test("anr tsa-mandate: applyAnrTsaMandate fails closed when tsa_state is undefined on MANDATORY", () => {
  const body = bodyOnly("notice.aiact.art50_transparency");
  const out: AnrTsaMandateTarget = { signature_valid: true };
  applyAnrTsaMandate(out, body);
  assert.equal(out.signature_valid, false);
  assert.equal(out.tsa_state, "tsa_required");
  assert.equal(out.reason, "tsa_required");
});

test("anr tsa-mandate: applyAnrTsaMandate defensive — unknown profile is a no-op", () => {
  const body = bodyOnly("notice.art13.collected_direct");
  // Cast through Record because TS won't let us assign a non-AnrProfile literal.
  (body as unknown as Record<string, string>).profile = "notice.unknown.bogus";
  const out: AnrTsaMandateTarget = {
    signature_valid: true,
    tsa_state: "tsa_absent",
  };
  applyAnrTsaMandate(out, body);
  assert.equal(out.signature_valid, true, "unknown profile must not poison signature");
  assert.equal(out.tsa_state, "tsa_absent");
  assert.equal(out.reason, undefined);
});
