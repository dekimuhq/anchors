/**
 * v1.3 R3 Phase 2 — issuer PQC-migration enforcement reaches APR's PUBLIC
 * `verifyReceipt` (the legacy-verifier "backport" slice).
 *
 * APR was migrated to `defineFamily()` (Phase A.3): its public `verifyReceipt`
 * (src/index.ts) types options as `Partial<FamilyVerifyOptions>` and, on the
 * v=2 branch, spreads them into `aprFamily.verifyReceipt` — the SHARED
 * `family-verify-pipeline.ts` whose Step 5.6 already carries the PQC seam
 * (commit 800f5c1c). So `verifyIssuerPqc` flows through with no source change.
 * These tests are the regression guard proving that — a future refactor that
 * stopped forwarding the option (e.g. an explicit field whitelist) would fail
 * here. Mirrors the shared pipeline's §18 (envelope/test/family-verify-pipeline)
 * adapted to the family's public surface; the pure policy + the makeVerifyIssuerPqc
 * factory e2e are covered in @dekimuhq/anchors-trusted-issuers' own suite (that
 * package does not resolve from a family, so the seam is driven with stubs here).
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/envelope
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type {
  VerifyIssuerTrust,
  IssuerTrustResult,
  TrustedIssuerRecord,
  VerifyIssuerPqc,
  VerifyIssuerPqcInput,
  FamilyVerifyResult,
} from "@dekimuhq/anchors-envelope";
import { verifyReceipt } from "../src/index.ts";
import v2Fixture from "./fixtures/v2-apr-provenance.ts";

const { envelope, publicKey } = v2Fixture;
const resolveKey = async () => publicKey;

function makeRecord(): TrustedIssuerRecord {
  return {
    iss: "did:web:commander.example",
    added_at: "2025-01-01T00:00:00Z",
    revoked_at: null,
    families: ["provenance"],
    profiles_pinned: null,
    notes: null,
  };
}

function makeTrust(
  outcome: "valid_trusted" | "valid_untrusted",
  record: TrustedIssuerRecord | null,
): VerifyIssuerTrust {
  return async () =>
    ({
      outcome,
      iss: "did:web:commander.example",
      iss_key: "ed25519:dummy",
      spki: publicKey,
      matched_record: record,
      reason: outcome,
    }) satisfies IssuerTrustResult;
}

test("APR public verifyReceipt: verifyIssuerPqc receives the matched record + verified ed25519 alg", async () => {
  let seen: VerifyIssuerPqcInput | undefined;
  const record = makeRecord();
  const verifyIssuerPqc: VerifyIssuerPqc = (input) => {
    seen = input;
    return { ok: true };
  };
  const r = (await verifyReceipt(envelope, {
    resolveKey,
    verifyIssuerTrust: makeTrust("valid_trusted", record),
    verifyIssuerPqc,
  })) as FamilyVerifyResult;

  assert.equal(r.signature_valid, true);
  assert.ok(seen, "callback threaded through the family wrapper");
  assert.equal(seen.receiptSigAlg, "ed25519"); // alg the pipeline derived from validAlgs (§18 proves verified, not self-described)
  assert.deepEqual(seen.record, record);
});

test("APR public verifyReceipt: ok:false → HARD FAIL, reason surfaced verbatim", async () => {
  const verifyIssuerPqc: VerifyIssuerPqc = () => ({
    ok: false,
    reason: "issuer_pqc_mandatory:ml-dsa-65",
  });
  const r = (await verifyReceipt(envelope, {
    resolveKey,
    verifyIssuerTrust: makeTrust("valid_trusted", makeRecord()),
    verifyIssuerPqc,
  })) as FamilyVerifyResult;

  assert.equal(r.signature_valid, false);
  assert.equal(r.reason, "issuer_pqc_mandatory:ml-dsa-65");
  assert.equal(r.trust_outcome, "valid_trusted"); // trust resolved fine; PQC is the failure
});

test("APR public verifyReceipt: async ok:false verdict is awaited", async () => {
  const verifyIssuerPqc: VerifyIssuerPqc = async () => ({
    ok: false,
    reason: "issuer_pqc_unsatisfiable:future-alg",
  });
  const r = (await verifyReceipt(envelope, {
    resolveKey,
    verifyIssuerTrust: makeTrust("valid_trusted", makeRecord()),
    verifyIssuerPqc,
  })) as FamilyVerifyResult;

  assert.equal(r.signature_valid, false);
  assert.equal(r.reason, "issuer_pqc_unsatisfiable:future-alg");
});

test("APR public verifyReceipt: verifyIssuerPqc omitted → inert (valid)", async () => {
  const r = (await verifyReceipt(envelope, {
    resolveKey,
    verifyIssuerTrust: makeTrust("valid_trusted", makeRecord()),
  })) as FamilyVerifyResult;

  assert.equal(r.signature_valid, true);
});

test("APR public verifyReceipt: verifyIssuerPqc set but no verifyIssuerTrust → fail-closed misconfig guard", async () => {
  // Envelope §18.7 (fail-closed since anchors-envelope 585293eb): supplying the
  // PQC hook WITHOUT a trust dispatch would silently enforce nothing, so the
  // pipeline rejects with issuer_pqc_requires_trust_dispatch before the hook runs.
  let called = false;
  const verifyIssuerPqc: VerifyIssuerPqc = () => {
    called = true;
    return { ok: true };
  };
  const r = (await verifyReceipt(envelope, { resolveKey, verifyIssuerPqc })) as FamilyVerifyResult;

  assert.equal(r.signature_valid, false);
  assert.equal(r.reason, "issuer_pqc_requires_trust_dispatch");
  assert.equal(called, false, "guard fires before the hook — no record source to enforce against");
});
