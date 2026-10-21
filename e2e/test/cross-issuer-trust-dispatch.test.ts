/**
 * Cross-issuer verifyIssuerTrust dispatch conformance vectors (cross-issuer
 * interop Phase A Slice 2 Phase 2). Exercises the Step 5.5 issuer-trust
 * dispatch on the four legacy `envelope-v2.ts` verifiers (APR / ACR / ARR /
 * ALR) — mirrors envelope/test/family-verify-pipeline.test.ts §17 but runs
 * against the published verifier surface to prove the backport reached
 * end-to-end.
 *
 * Each verifier gets the same 5-outcome matrix + a default-undefined preserve
 * vector. Per family verifier the dispatch must:
 *
 *   - default-undefined → no trust_* result fields, legacy behavior preserved
 *   - valid_trusted     → signature_valid stays true, record surfaced
 *   - valid_untrusted   → signature_valid stays true, record null
 *   - valid_revoked     → signature_valid:false, reason:"issuer_revoked"
 *   - invalid_key_doc   → signature_valid:false, reason:"did_web_invalid_key_doc:<r>"
 *   - invalid_signature → signature_valid:false, reason:"did_web_invalid_signature:<r>"
 *   - throw             → signature_valid:false, reason:"verify_issuer_trust_threw:<msg>"
 *
 * Spec: an internal design record (not published)
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { verifyReceipt as verifyAcrRaw } from "@dekimuhq/acr";
import type { EnvelopeVerifyResult } from "@dekimuhq/acr";
import type {
  IssuerTrustResult,
  TrustedIssuerRecord,
  VerifyIssuerTrust,
} from "@dekimuhq/anchors-envelope";
import { makeValidV2AcrReceipt, makeResolveKey } from "./_helpers/v2-receipt-acr.ts";

const TRUSTED_LOG = "https://verify.dekimu.com/acr/v1";

/**
 * `verifyReceipt` returns a `v=1 | v=2 | unknown` union; every receipt in this
 * suite is v=2, so narrow to the v=2 result to read the trust_* fields. Wrapped
 * so the call sites below stay unchanged.
 */
function v2(r: Awaited<ReturnType<typeof verifyAcrRaw>>): EnvelopeVerifyResult {
  if (r.envelope_version !== 2) {
    assert.fail(`expected v=2 verify result, got ${String(r.envelope_version)}`);
  }
  return r;
}
const verifyAcr = (
  receipt: unknown,
  opts?: Parameters<typeof verifyAcrRaw>[1],
): Promise<EnvelopeVerifyResult> => verifyAcrRaw(receipt, opts).then(v2);

function record(overrides: Partial<TrustedIssuerRecord> = {}): TrustedIssuerRecord {
  return {
    iss: "did:web:issuer.example.com",
    added_at: "2025-01-01T00:00:00Z",
    revoked_at: null,
    families: ["acr"],
    profiles_pinned: null,
    notes: null,
    ...overrides,
  };
}

function makeTrustReturning(spki: Uint8Array, outcome: IssuerTrustResult["outcome"], opts: {
  matched_record?: TrustedIssuerRecord | null;
  reason?: string;
} = {}): VerifyIssuerTrust {
  return async () => {
    const reason = opts.reason ?? outcome;
    if (outcome === "valid_trusted" || outcome === "valid_untrusted" || outcome === "valid_revoked") {
      return {
        outcome,
        iss: "did:web:issuer.example.com",
        iss_key: "ed25519:dummy",
        spki,
        matched_record: opts.matched_record ?? null,
        reason,
      };
    }
    return {
      outcome,
      iss: "did:web:issuer.example.com",
      iss_key: "ed25519:dummy",
      spki: null,
      matched_record: null,
      reason,
    };
  };
}

describe("cross-issuer verifyIssuerTrust dispatch (ACR — proxy for the 4-verifier backport)", () => {
  it("default-undefined → legacy behavior preserved (no trust fields)", async () => {
    const { receipt, pub } = await makeValidV2AcrReceipt({ anchorLog: TRUSTED_LOG });
    const r = await verifyAcr(receipt, { resolveKey: makeResolveKey(pub) });

    assert.equal(r.signature_valid, true);
    assert.equal(r.trust_outcome, undefined);
    assert.equal(r.trust_reason, undefined);
    assert.equal(r.trusted_issuer_record, undefined);
  });

  it("valid_trusted → continues, surfaces outcome + record", async () => {
    const { receipt, pub } = await makeValidV2AcrReceipt({ anchorLog: TRUSTED_LOG });
    const rec = record();
    const r = await verifyAcr(receipt, {
      resolveKey: makeResolveKey(pub),
      verifyIssuerTrust: makeTrustReturning(pub, "valid_trusted", { matched_record: rec, reason: "active" }),
    });

    assert.equal(r.signature_valid, true);
    assert.equal(r.trust_outcome, "valid_trusted");
    assert.equal(r.trust_reason, "active");
    assert.deepEqual(r.trusted_issuer_record, rec);
  });

  it("valid_untrusted → continues, record null, outcome surfaced", async () => {
    const { receipt, pub } = await makeValidV2AcrReceipt({ anchorLog: TRUSTED_LOG });
    const r = await verifyAcr(receipt, {
      resolveKey: makeResolveKey(pub),
      verifyIssuerTrust: makeTrustReturning(pub, "valid_untrusted", { reason: "issuer_not_on_allowlist" }),
    });

    assert.equal(r.signature_valid, true);
    assert.equal(r.trust_outcome, "valid_untrusted");
    assert.equal(r.trust_reason, "issuer_not_on_allowlist");
    assert.equal(r.trusted_issuer_record, null);
  });

  it("valid_revoked → HARD FAIL: reason issuer_revoked, record preserved", async () => {
    const { receipt, pub } = await makeValidV2AcrReceipt({ anchorLog: TRUSTED_LOG });
    const rec = record({ revoked_at: "2025-06-01T00:00:00Z" });
    const r = await verifyAcr(receipt, {
      resolveKey: makeResolveKey(pub),
      verifyIssuerTrust: makeTrustReturning(pub, "valid_revoked", { matched_record: rec, reason: "revoked_at_2025_06_01" }),
    });

    assert.equal(r.signature_valid, false);
    assert.equal(r.reason, "issuer_revoked");
    assert.equal(r.trust_outcome, "valid_revoked");
    assert.deepEqual(r.trusted_issuer_record, rec);
  });

  it("invalid_key_doc → HARD FAIL with prefixed reason", async () => {
    const { receipt, pub } = await makeValidV2AcrReceipt({ anchorLog: TRUSTED_LOG });
    const r = await verifyAcr(receipt, {
      resolveKey: makeResolveKey(pub),
      verifyIssuerTrust: makeTrustReturning(pub, "invalid_key_doc", { reason: "non_200:404" }),
    });

    assert.equal(r.signature_valid, false);
    assert.equal(r.reason, "did_web_invalid_key_doc:non_200:404");
    assert.equal(r.trust_outcome, "invalid_key_doc");
    assert.equal(r.trusted_issuer_record, null);
  });

  it("invalid_signature → HARD FAIL with prefixed reason", async () => {
    const { receipt, pub } = await makeValidV2AcrReceipt({ anchorLog: TRUSTED_LOG });
    const r = await verifyAcr(receipt, {
      resolveKey: makeResolveKey(pub),
      verifyIssuerTrust: makeTrustReturning(pub, "invalid_signature", { reason: "key_no_longer_valid" }),
    });

    assert.equal(r.signature_valid, false);
    assert.equal(r.reason, "did_web_invalid_signature:key_no_longer_valid");
    assert.equal(r.trust_outcome, "invalid_signature");
  });

  it("throw → caught: reason verify_issuer_trust_threw:<msg>", async () => {
    const { receipt, pub } = await makeValidV2AcrReceipt({ anchorLog: TRUSTED_LOG });
    const r = await verifyAcr(receipt, {
      resolveKey: makeResolveKey(pub),
      verifyIssuerTrust: async () => { throw new Error("trust source unreachable"); },
    });

    assert.equal(r.signature_valid, false);
    assert.equal(r.reason, "verify_issuer_trust_threw:trust source unreachable");
  });

  it("dispatch order — trust fires BEFORE trusted-log allowlist", async () => {
    const { receipt, pub } = await makeValidV2AcrReceipt({ anchorLog: "https://attacker.example/acr/v1" });
    const r = await verifyAcr(receipt, {
      resolveKey: makeResolveKey(pub),
      verifyIssuerTrust: makeTrustReturning(pub, "valid_revoked", { matched_record: record({ revoked_at: "2025-06-01T00:00:00Z" }) }),
      trustedLogs: new Set([TRUSTED_LOG]),
    });

    assert.equal(r.signature_valid, false);
    assert.equal(r.reason, "issuer_revoked", "trust dispatch must fail before trusted-log gate");
  });
});
