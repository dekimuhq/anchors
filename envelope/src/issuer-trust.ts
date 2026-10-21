/**
 * issuer-trust.ts — type-only structural mirror of `@dekimuhq/did-web-resolver`'s
 * trust types.
 *
 * Envelope intentionally does NOT depend on `did-web-resolver` at runtime — that
 * would cycle (`did-web-resolver` depends on `@dekimuhq/anchors-envelope` for
 * `Envelope` typings). Instead we mirror the surface here as type-only
 * interfaces. Any conformant resolver — `did-web-resolver`'s `verifyIssuerKey`
 * or a hand-rolled equivalent — produces results that are structurally
 * assignable to `IssuerTrustResult`.
 *
 * Spec reference: an internal design record (not published)
 * Plan reference: an internal design record (not published) §1.4
 */

import type { SigAlg } from "./envelope-types.ts";

export interface TrustedIssuerRecord {
  iss: string;
  added_at: string;
  revoked_at: string | null;
  /**
   * Family slugs this issuer is trusted for. Loose `string[]` here (not the
   * strict `FamilySlug` union from `continuity.ts`) so that third-party
   * trust sources publishing for the closed 13-family taxonomy are assignable
   * to the same shape as forward-compatible sources that may carry future slugs.
   */
  families: string[];
  profiles_pinned: Record<string, string[]> | null;
  notes: string | null;
}

/**
 * Trust outcome — five-way discriminator matching did-web-resolver's
 * `verifyIssuerKey` output. Family verifiers map these as follows:
 *
 *   valid_trusted    → continue pipeline, surface record + outcome
 *   valid_untrusted  → continue pipeline, surface outcome with record=null
 *   valid_revoked    → HARD FAIL: signature_valid:false, reason:"issuer_revoked"
 *   invalid_key_doc  → HARD FAIL: signature_valid:false, reason:"did_web_invalid_key_doc:<r>"
 *   invalid_signature→ HARD FAIL: signature_valid:false, reason:"did_web_invalid_signature:<r>"
 */
export type IssuerTrustOutcome =
  | "valid_trusted"
  | "valid_untrusted"
  | "valid_revoked"
  | "invalid_key_doc"
  | "invalid_signature";

export interface IssuerTrustResultValid {
  outcome: "valid_trusted" | "valid_untrusted" | "valid_revoked";
  iss: string;
  iss_key: string;
  spki: Uint8Array;
  matched_record: TrustedIssuerRecord | null;
  reason: string;
}

export interface IssuerTrustResultInvalid {
  outcome: "invalid_key_doc" | "invalid_signature";
  iss: string;
  iss_key: string;
  spki: null;
  matched_record: null;
  reason: string;
}

export type IssuerTrustResult = IssuerTrustResultValid | IssuerTrustResultInvalid;

/**
 * Callback shape consumed by `FamilyVerifyOptions.verifyIssuerTrust`.
 *
 * Receives the receipt envelope (typed as `unknown` because the orchestrator
 * passes the parsed envelope after Step 1 unknown-field rejection). Returns
 * an `IssuerTrustResult` covering all five outcomes.
 */
export type VerifyIssuerTrust = (envelope: unknown) => Promise<IssuerTrustResult>;

/**
 * Verdict from the issuer PQC-migration enforcement callback. `ok:false` carries
 * the policy reason (e.g. `issuer_pqc_mandatory:ml-dsa-65`,
 * `issuer_pqc_unsatisfiable:<declared>`) which the pipeline surfaces verbatim.
 */
export type IssuerPqcVerdict = { ok: true } | { ok: false; reason: string };

/**
 * Input to the issuer PQC-migration enforcement callback (R3 Phase 2). The
 * verify pipeline assembles this AFTER both signature verification (Step 5) and
 * issuer-trust resolution (Step 5.5) — the only point where both the matched
 * trust record and the *verified* signature algorithm are known.
 */
export interface VerifyIssuerPqcInput {
  /**
   * The matched trusted-issuer record (carries the optional `pqc_mandatory`
   * posture, read by the policy — not by the pipeline). Loose-typed via the
   * structural mirror above; a record from any conformant source is assignable.
   */
  record: TrustedIssuerRecord;
  /**
   * The highest-rank VALID signature algorithm on the receipt — derived by the
   * pipeline from `HybridVerifyResult.validAlgs`, never from the receipt's
   * self-described fields. This is what the policy ranks against the mandate.
   */
  receiptSigAlg: SigAlg;
  /**
   * The parsed receipt envelope — passed so the integration can source a
   * quantum-trustworthy effective-time from it (e.g. a transparency-log
   * inclusion proof). NEVER use its self-claimed `issued_at` as the cutover
   * time: that is attacker-controlled in the CRQC forgery scenario.
   */
  envelope: unknown;
}

/**
 * Issuer PQC-migration enforcement callback (R3 Phase 2 — the inert→enforced
 * flip). When supplied to the pipeline it is invoked after issuer-trust resolves
 * to a record; a non-ok verdict fails the receipt (`signature_valid:false`,
 * reason surfaced).
 *
 * Envelope intentionally does NOT depend on `@dekimuhq/anchors-trusted-issuers`
 * (it would cycle), so the policy (`satisfiesIssuerPqc`) cannot be called
 * directly here — it is injected through this seam. The default composition
 * lives in `@dekimuhq/anchors-trusted-issuers`'s `makeVerifyIssuerPqc`, which
 * binds the policy to a caller-supplied (quantum-trustworthy) effective-time.
 */
export type VerifyIssuerPqc = (
  input: VerifyIssuerPqcInput,
) => IssuerPqcVerdict | Promise<IssuerPqcVerdict>;
