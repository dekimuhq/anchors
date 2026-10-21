/**
 * v1.1 cross-family conformance vector tests.
 *
 * Loads deterministic JSON vectors from vectors-v1-1/ and asserts each
 * verifier's output matches the expected fields. Vectors cover:
 *   - APR v=1 and v=2 provenance
 *   - ACR v=1 consent, v=2 consent, v=2 withdrawal (chained)
 *   - ARR v=1 erasure, v=2 erasure, v=2 erasure with TSA (Phase E Task 23)
 *   - ARR v=2 TSA failure modes — imprint mismatch, anchor expired, drift exceeded
 *     (v1.2 deferred — brief 2026-05-17-anchors-v1-2-deferred-conformance-vectors.md)
 *   - ARR v=2 Status List 2021 variants — active, revoked, chain-revoked-list-stale,
 *     stale (active_stale), unreachable (v1.2 deferred — same brief)
 *
 * Vectors carrying a `verify_opts` block route through `_helpers/mock-status.ts`,
 * which translates the wire-format options into verifier options and (for stale/
 * unreachable) patches `globalThis.fetch` for the duration of the test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyReceipt as verifyApr } from "@dekimuhq/apr";
import { verifyReceipt as verifyAcr } from "@dekimuhq/acr";
import { verifyReceipt as verifyArr } from "@dekimuhq/arr";
import { verifyReceipt as verifyAlr } from "@dekimuhq/alr";
import { verifyReceipt as verifyAnr } from "@dekimuhq/anr";
import { verifyReceipt as verifyAbr } from "@dekimuhq/abr";
import { asrFamily } from "@dekimuhq/asr";
import { verifyReceipt as verifyAir } from "@dekimuhq/air";
import type { ClaimKeyResolver } from "@dekimuhq/apr";
import { prepareVerify, type VerifyOptsWire } from "./_helpers/mock-status.ts";

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTOR_DIR = join(__dirname, "vectors-v1-1");

interface Vector {
  name: string;
  family: "apr" | "acr" | "arr" | "alr" | "anr" | "abr" | "asr" | "air";
  envelope_version: 1 | 2;
  receipt: unknown;
  publicKey_b64url: string;
  verify_opts?: VerifyOptsWire;
  /**
   * ASR-only — profile id passed through to `asrFamily.verifyReceipt` opts
   * (ASR is the only family that selects profile at verify-call level rather
   * than via `body.profile`). Other families ignore it.
   */
  profile?: string;
  expected: Record<string, unknown>;
}

function load(name: string): Vector {
  return JSON.parse(readFileSync(join(VECTOR_DIR, name), "utf8")) as Vector;
}

const VECTORS: string[] = [
  // Phase E Task 23 — 8 baseline cross-family vectors.
  "apr-v1.json",
  "apr-v2.json",
  "acr-consent-v1.json",
  "acr-consent-v2.json",
  "acr-withdrawal-v2.json",
  "arr-erasure-v1.json",
  "arr-erasure-v2.json",
  "arr-erasure-v2-tsa.json",
  // v1.2 deferred — 3 TSA failure modes.
  "arr-erasure-v2-tsa-imprint-mismatch.json",
  "arr-erasure-v2-tsa-anchor-expired.json",
  "arr-erasure-v2-tsa-drift-exceeded.json",
  // v1.2 deferred — 5 Status List 2021 variants.
  "arr-erasure-v2-statuslist-active.json",
  "arr-erasure-v2-statuslist-revoked.json",
  "arr-erasure-v2-statuslist-chain-revoked-list-stale.json",
  "arr-erasure-v2-statuslist-stale.json",
  "arr-erasure-v2-statuslist-unreachable.json",
  // §J — 3 positive + 2 cross-issuer + 3 negative ALR vectors.
  "alr-derived-from-v2.json",
  "alr-forked-from-v2.json",
  "alr-disclosed-v2.json",
  "alr-derived-from-v2-apr-covered.json",
  "alr-derived-from-v2-mixed-parents.json",
  "alr-neg-tampered-sig.json",
  "alr-neg-unknown-profile.json",
  "alr-neg-subject-present.json",
  // §J.1 — 3 positive + 2 cross-issuer + 3 negative ANR vectors.
  "anr-presented-v2.json",
  "anr-joint-controller-essence-v2.json",
  "anr-withdrawn-v2.json",
  "anr-translated-v2-alr-provenance.json",
  "anr-acknowledged-v2-on-presented.json",
  "anr-neg-tampered-sig.json",
  "anr-neg-ack-subject-null.json",
  "anr-neg-art50-no-tsa.json",
  // §J.2 — 3 positive + 2 cross-issuer + 3 negative ABR vectors.
  "abr-assessed-v2.json",
  "abr-dpa-notified-v2-nis2.json",
  "abr-subject-notified-v2.json",
  "abr-contained-v2-arr-composed.json",
  "abr-closed-v2-anr-composed.json",
  "abr-neg-tampered-sig.json",
  "abr-neg-detected-no-tsa.json",
  "abr-neg-subject-notified-null.json",
  // §J.3 — 30 positive (5 × 6 profiles) + 3 negative ASR vectors.
  // art15.access (5)
  "asr-art15-received.json",
  "asr-art15-identity-verified.json",
  "asr-art15-fulfilled.json",
  "asr-art15-extended.json",
  "asr-art15-recipient-notified.json",
  // art16.rectification (5)
  "asr-art16-received.json",
  "asr-art16-scope-clarified.json",
  "asr-art16-fulfilled.json",
  "asr-art16-partially-honoured.json",
  "asr-art16-refused.json",
  // art17.erasure_request (5) — fulfilled cites a sibling ARR receipt id.
  "asr-art17-received.json",
  "asr-art17-identity-verified.json",
  "asr-art17-fulfilled-arr-composed.json",
  "asr-art17-extended.json",
  "asr-art17-escalated.json",
  // art18.restriction (5)
  "asr-art18-received.json",
  "asr-art18-scope-clarified.json",
  "asr-art18-fulfilled-accuracy-contested.json",
  "asr-art18-fulfilled-objection-pending.json",
  "asr-art18-recipient-notified.json",
  // art20.portability (5) — two fulfilled variants exercise the closed-enum
  // `portability_format` and the `other`-requires-detail branch.
  "asr-art20-received.json",
  "asr-art20-identity-verified.json",
  "asr-art20-fulfilled-json.json",
  "asr-art20-fulfilled-other-with-detail.json",
  "asr-art20-fulfilled-fhir.json",
  // art21.objection (5) — three fulfilled variants cover the closed-enum
  // `objection_scope` (direct-marketing, general-legit-with-balancing, research).
  "asr-art21-received.json",
  "asr-art21-fulfilled-direct-marketing.json",
  "asr-art21-fulfilled-general-legit-balancing.json",
  "asr-art21-fulfilled-research.json",
  "asr-art21-refused.json",
  // Negatives (3) — D10-ASR-5 subject_missing / subject_invalid_form +
  // tampered-sig.
  "asr-neg-tampered-sig.json",
  "asr-neg-subject-null.json",
  "asr-neg-subject-malformed.json",
  // §J.4 — 25 positive (5 × 5 profiles) + 2 cross-issuer + 3 negative AIR
  // vectors. Each profile picks a distinct slice of the 11-event lifecycle so
  // every event_type appears at least once across the 25 positives.
  // impact.art35_3_a_automated_decisions (5)
  "air-a-threshold-triggered.json",
  "air-a-scope-locked.json",
  "air-a-dpo-advised.json",
  "air-a-stakeholders-rep-org.json",
  "air-a-processing-authorised.json",
  // impact.art35_3_b_large_scale_special_categories (5)
  "air-b-threshold-triggered.json",
  "air-b-dpo-advised.json",
  "air-b-completed-high.json",
  "air-b-reviewed-no-material-change.json",
  "air-b-processing-authorised.json",
  // impact.art35_3_c_public_monitoring (5) — high-risk pathway exercises the
  // RECOMMENDED-TSA matrix on completed/prior_consultation_initiated/
  // prior_consultation_resolved.
  "air-c-threshold-triggered.json",
  "air-c-completed-high.json",
  "air-c-prior-consultation-initiated.json",
  "air-c-prior-consultation-resolved.json",
  "air-c-processing-authorised.json",
  // impact.art35_4_dpa_list (5) — terminal trio coverage.
  "air-dpa-threshold-triggered.json",
  "air-dpa-scope-locked.json",
  "air-dpa-completed-low.json",
  "air-dpa-processing-blocked.json",
  "air-dpa-terminated.json",
  // impact.voluntary (5) — survey method confirms subject:null carve-out
  // negative space (no D10-AIR-6 anchoring on non-bearing methods).
  "air-vol-threshold-triggered.json",
  "air-vol-dpo-advised.json",
  "air-vol-stakeholders-survey.json",
  "air-vol-completed-medium.json",
  "air-vol-reviewed-material-change.json",
  // Cross-issuer composition (2) — completed cites a sibling ALR id;
  // reviewed cites a sibling ABR id. Walker semantics are caller-side; the
  // verifier accepts these as opaque.
  "air-completed-alr-composed.json",
  "air-reviewed-abr-composed.json",
  // Negatives (3) — FAMILY-CONSISTENCY §3 subject_present + D10-AIR-6 method
  // gating + tampered-sig.
  "air-neg-tampered-sig.json",
  "air-neg-subject-present-on-completed.json",
  "air-neg-stakeholders-method-mismatch.json",
];

for (const file of VECTORS) {
  test(`vector ${file}`, async () => {
    const v = load(file);
    let result: unknown;

    const publicKeyBytes = new Uint8Array(Buffer.from(v.publicKey_b64url, "base64url"));
    // Build the SPKI DER bytes for Ed25519 from the raw 32-byte public key.
    // 12-byte Ed25519 SPKI prefix: SEQUENCE { SEQUENCE { OID 1.3.101.112 } BIT STRING 0x00 }
    const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
    const spkiDer = new Uint8Array(
      Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(publicKeyBytes)]),
    );
    // Widen the resolveKey parameter to `unknown` so the same closure satisfies
    // both the legacy per-family signature (`(issKey: string) => Promise<Uint8Array>`)
    // and the factory's `FamilyVerifyOptions.resolveKey` shape (`(envelope: unknown) => …`),
    // landed in envelope 0.7.0 for the ASR greenfield consumer.
    const resolveKey = async (_envOrIssKey: unknown): Promise<Uint8Array> => spkiDer;

    const prepared = prepareVerify(v.verify_opts);
    try {
      if (v.family === "apr") {
        // APR v=1 requires claimKeyResolver; v=2 requires resolveKey.
        if (v.envelope_version === 1) {
          const claimKeyResolver: ClaimKeyResolver = (kid) => ({
            kid: kid ?? "unknown",
            publicKey: publicKeyBytes,
            issuer: "did:web:test-issuer.example",
          });
          result = await verifyApr(v.receipt, { v1Opts: { claimKeyResolver } });
        } else {
          result = await verifyApr(v.receipt, { resolveKey });
        }
      } else if (v.family === "acr") {
        // ACR v=1 is self-contained (key in iss_key); v=2 requires resolveKey.
        if (v.envelope_version === 1) {
          result = await verifyAcr(v.receipt);
        } else {
          result = await verifyAcr(v.receipt, { resolveKey });
        }
      } else if (v.family === "alr") {
        // ALR is v=2-only. Subject MUST be null per FAMILY-CONSISTENCY §3 — the
        // verifier nulls it back out internally before signature verification.
        result = await verifyAlr(v.receipt, { resolveKey });
      } else if (v.family === "anr") {
        // ANR is v=2-only. Subject is per-event-split per FAMILY-CONSISTENCY §3
        // (notice.acknowledged MUST be `sha256:<hex>`; other events MAY be
        // `sha256:<hex>` OR null). Subject reconciliation lives in
        // applyAnrSubjectPresence in the verifier.
        result = await verifyAnr(v.receipt, { resolveKey });
      } else if (v.family === "abr") {
        // ABR is v=2-only. Subject is per-event-split per FAMILY-CONSISTENCY §3
        // (breach.subject_notified MUST be `sha256:<hex>` bound to
        // body.subject_batch_root; every other event MUST be null). Subject
        // reconciliation lives in applyAbrSubjectPresence in the verifier;
        // the §D MANDATORY TSA mandate on breach.detected runs in the same
        // verify path.
        result = await verifyAbr(v.receipt, { resolveKey });
      } else if (v.family === "air") {
        // AIR is v=2-only. Subject is per-event-split per FAMILY-CONSISTENCY §3
        // + D10-AIR-6 (subject MUST be null on every event EXCEPT
        // dpia.stakeholders_consulted, where subject MAY be `sha256:<hex>`
        // AND only when consultation_method ∈ {representative_org, ngo_review}).
        // Reconciliation lives in applyAirSubjectPresence in the verifier.
        // No MANDATORY-TSA event in v1; the §D matrix upgrades `tsa_absent`
        // to `tsa_recommended` on `dpia.completed`,
        // `dpia.prior_consultation_initiated`, and
        // `dpia.prior_consultation_resolved` (positive vectors assert this).
        // Composition (AER ADM / ATR transfers / ALR data-flows / APuR purpose
        // / ABR breach-triggered review) is opaque at envelope-verify time.
        result = await verifyAir(v.receipt, { resolveKey });
      } else if (v.family === "asr") {
        // ASR is v=2-only (factory-from-day-1 via defineFamily()).
        // D10-ASR-5: subject MUST be `sha256:<hex>` on EVERY event;
        // checkAsrSubjectPresence reports `subject_missing` / `subject_invalid_form`.
        // Profile is passed via opts.profile (not body.profile) — ASR is the
        // only family with profile-at-call-level dispatch. No TSA mandate is
        // registered on the family manifest, so positives surface
        // `tsa_state: "tsa_absent"`. Composition (Art. 17 ARR link,
        // Art. 19 ALR cascade, Art. 20 ATR pair, Art. 21 APuR back-ref) is
        // deferred to Phase 3 §G; the verifier accepts cross-issuer ids as
        // opaque here.
        result = await asrFamily.verifyReceipt(v.receipt, {
          resolveKey,
          ...(v.profile ? { profile: v.profile } : {}),
        });
      } else {
        // ARR — v=1 requires anchorInclusionTime; v=2 requires resolveKey.
        if (v.envelope_version === 1) {
          result = await verifyArr(v.receipt, {
            v1Opts: { anchorInclusionTime: "2026-05-17T12:00:00Z" },
          });
        } else {
          // Auto-pin tsaReferenceTime to TSR.issued_at when the receipt carries
          // a TSA block AND the vector didn't already specify a reference time.
          // This keeps the original arr-erasure-v2-tsa.json passing without
          // requiring a verify_opts block.
          const receipt = v.receipt as { tsa?: { issued_at?: string } | null };
          const autoTsaRefTime =
            !prepared.opts.tsaReferenceTime && receipt.tsa?.issued_at
              ? new Date(receipt.tsa.issued_at)
              : undefined;
          result = await verifyArr(v.receipt, {
            resolveKey,
            ...prepared.opts,
            ...(autoTsaRefTime ? { tsaReferenceTime: autoTsaRefTime } : {}),
          });
        }
      }

      const r = result as Record<string, unknown>;
      for (const [k, expected] of Object.entries(v.expected)) {
        assert.equal(
          r[k],
          expected,
          `${file}: field "${k}" expected ${JSON.stringify(expected)} got ${JSON.stringify(r[k])}`,
        );
      }
    } finally {
      prepared.teardown();
    }
  });
}
