/**
 * Per-claim-type policy field validation matrix for the v=2 envelope.
 *
 * Plan: an internal design record (not published) §Task 14
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/envelope §7
 *
 * Three behaviour buckets:
 *
 *   1. POLICY_BOUND (8 claim types) — `policy_uri`, `policy_hash`, `policy_version`
 *      MUST all be non-empty strings; `policy_hash` MUST start with "sha256:".
 *      Members: ar.consent.v1, ar.modification.v1, ar.withdrawal.v1,
 *               ar.erasure.v1, ar.expiry.v1, ar.hold.v1,
 *               ar.anonymization.v1, ar.archive.v1.
 *
 *   2. POLICY_FORBIDDEN — `ar.provenance.v1`. All three fields MUST be
 *      null/undefined; presence rejects with `policy_fields_forbidden_for_apr`.
 *
 *   3. NEITHER — `ar.batch.v1`. Per-item policy lives inside the body;
 *      envelope-level fields are not enforced.
 *
 * Unknown claim types are not expected here (`isKnownClaimType` gates upstream
 * in the dispatcher) but the defensive branch returns `unknown_claim_type` for
 * safety.
 */

import { createHash } from "node:crypto";
import type { ClaimType, Envelope } from "./envelope-types.ts";

const POLICY_BOUND: ReadonlySet<ClaimType> = new Set<ClaimType>([
  "ar.consent.v1",
  "ar.modification.v1",
  "ar.withdrawal.v1",
  "ar.erasure.v1",
  "ar.expiry.v1",
  "ar.hold.v1",
  "ar.anonymization.v1",
  "ar.archive.v1",
  // Closure-set additions: each new family declares its policy bucket as it
  // ships. ALR (`ar.lineage.v1`) is POLICY_BOUND per spec §3 — added during
  // Phase 1 §D when the first end-to-end v=2 verifier dispatch exercised the
  // matrix. ANR (`ar.notice.v1`) is POLICY_BOUND per spec D10-ANR-3 — the
  // notice itself is the policy artifact, so policy_uri/hash/version are
  // required. Added during Phase 2 §D (same end-to-end gap as ALR).
  // ABR (`ar.breach.v1`) is POLICY_BOUND per spec §3.1 — `policy_uri`
  // references the controller's published incident-response policy under
  // which the receipt is issued. Added during Phase 3 §D (same end-to-end
  // gap as ALR / ANR).
  // AIR (`ar.impact.v1`) is POLICY_BOUND per spec §3.1 — `policy_uri`
  // references the controller's published DPIA methodology under which the
  // receipt is issued. Added during Phase 5 §D (same end-to-end gap as
  // ALR / ANR / ABR).
  // ASR (`ar.subject_rights.v1`) is POLICY_BOUND per spec §3.1 — `policy_uri`
  // references the controller's published subject-rights policy under which
  // the receipt is issued. Added during defineFamily() A.2-full Phase 3 §D
  // (same end-to-end gap as ALR / ANR / ABR / AIR).
  // Other closure-set claim_types remain unclassified until their family's
  // Phase B lands.
  "ar.lineage.v1",
  "ar.notice.v1",
  "ar.breach.v1",
  "ar.impact.v1",
  "ar.subject_rights.v1",
  // ATR (`ar.transfer.v1`) is POLICY_BOUND per spec §3 — `policy_uri`
  // references the controller's published transfer/TIA policy under which the
  // receipt is issued. Added during Task 9 (atr-issuer-kit) end-to-end gap.
  "ar.transfer.v1",
  // ATokR (`ar.tokenization.v1`) is POLICY_BOUND per spec §3 — `policy_uri`
  // references the controller's published tokenization policy under which the
  // receipt is issued. Added during Phase 8 (issuer-kit) end-to-end gap.
  "ar.tokenization.v1",
  // APuR (`ar.purpose.v1`) is POLICY_BOUND per spec §3 — `policy_uri`
  // references the controller's published purpose-limitation policy under which
  // the receipt is issued. Added during Task 10 (apur-issuer-kit) end-to-end gap.
  "ar.purpose.v1",
  // AAR (`ar.attestation.v1`) is POLICY_BOUND per spec §3 — `policy_uri`
  // references the QTSP's published attestation policy under which the
  // receipt is issued. Added during Task 9 (aar-issuer-kit) end-to-end gap.
  "ar.attestation.v1",
  // ADR (`ar.delegation.v1`) is POLICY_BOUND per spec §3 — `policy_uri`
  // references the delegating principal's published delegation policy under
  // which the receipt is issued. Added during Task 10 (adr-issuer-kit) end-to-end gap.
  "ar.delegation.v1",
  // AActR (`ar.action.v1`) is POLICY_BOUND per spec §4.1 — `policy_uri`
  // references the Hub automations surface and `policy_hash` the recipe-catalog
  // version under which the autonomous action was authorized.
  "ar.action.v1",
]);

/** ar.batch.v1: envelope-level policy fields are not enforced (per-item lives in body). */
const POLICY_BATCH: ClaimType = "ar.batch.v1";

/** ar.provenance.v1: policy fields are forbidden. */
const POLICY_APR: ClaimType = "ar.provenance.v1";

/**
 * POLICY_OPTIONAL: claim types where envelope-level policy fields are
 * permitted but not required. Validation returns ok regardless of presence.
 *
 * AER (`ar.evaluation.v1`) — AI Act conformity/transparency events may
 * optionally cite a policy_uri (e.g. conformity assessment methodology),
 * but the AI Act itself does not mandate a single policy document anchor
 * the way GDPR Art. 30 records do. Optional per AER spec §3.
 *
 * AQR (`ar.quality.v1`) — evaluation-provenance receipts may cite the
 * eval/threshold config (`policy_uri`/`policy_hash`/`policy_version`) but the
 * fields are unvalidated passthrough and NOT required. Optional per AQR
 * spec §5 (chip 16).
 *
 * AGR (`ar.guard.v1`) — guard-verdict receipts carry a `ruleset_hash` inside
 * the body (not in `policy_uri`). Envelope-level policy fields are permitted
 * passthrough but NOT required. Optional per AGR spec §3 (chip 17).
 *
 * AGrR (`ar.grounding.v1`) — grounding receipts carry their reproducibility anchor (scorer identity) in the body; no external policy_uri required.
 *
 * AgTR (`ar.trace.v1`) — agent-trace receipts record execution spans; the
 * policy_uri MAY cite the agent's published behaviour policy but is NOT
 * required. Optional per AgTR spec §3 (chip 19).
 *
 * AgTR v2 (`ar.trace.v2`) — OTel-compatible signed span tree; same posture
 * as v1: policy_uri MAY cite the agent's published behaviour policy but is
 * NOT required. Optional per AgTR spec §3 (chip 19).
 *
 * APIIR (`ar.redaction.v1`) — redaction-provenance; policy citation optional (chip 20).
 *
 * ACBR (`ar.compliance.v1`) — compliance bundle receipts reference external
 * artifacts (RoPA hash, DPIA receipts, obligation reports) via body BundleRefs.
 * Envelope-level policy fields are permitted passthrough but NOT required.
 * Optional per ACBR spec §4 (chip 21).
 */
const POLICY_OPTIONAL: ReadonlySet<ClaimType> = new Set<ClaimType>([
  "ar.evaluation.v1",
  "ar.quality.v1",
  "ar.guard.v1",
  "ar.grounding.v1",
  "ar.trace.v1",
  "ar.trace.v2",
  // APIIR (ar.redaction.v1) — redaction-provenance; policy citation optional.
  "ar.redaction.v1",
  // ACBR (ar.compliance.v1) — compliance bundle; envelope policy optional.
  "ar.compliance.v1",
]);

export { POLICY_BOUND, POLICY_OPTIONAL };

export interface PolicyValidationResult {
  ok: boolean;
  reason?: string;
}

/**
 * Validate the policy_* triple against the per-claim-type matrix.
 *
 * The caller passes only the four fields needed; the function does not
 * inspect signature, anchor, body, or any other envelope state.
 */
export function validatePolicyFields(
  e: Pick<Envelope, "claim_type" | "policy_uri" | "policy_hash" | "policy_version">,
): PolicyValidationResult {
  const ct = e.claim_type;

  if (ct === POLICY_APR) {
    // Truthiness, not `!== undefined` (plan body uses the latter). `null` and
    // `undefined` both pass; empty string rejects — symmetric with the
    // POLICY_BOUND truthiness check below, so empty strings can't sneak past
    // APR's forbidden contract.
    if (e.policy_uri || e.policy_hash || e.policy_version) {
      return { ok: false, reason: "policy_fields_forbidden_for_apr" };
    }
    return { ok: true };
  }

  if (POLICY_BOUND.has(ct)) {
    if (!e.policy_uri) return { ok: false, reason: "policy_fields_required:policy_uri" };
    if (!e.policy_hash) return { ok: false, reason: "policy_fields_required:policy_hash" };
    if (!e.policy_version) return { ok: false, reason: "policy_fields_required:policy_version" };
    if (!e.policy_hash.startsWith("sha256:")) {
      return { ok: false, reason: "policy_hash_alg_unsupported" };
    }
    return { ok: true };
  }

  if (ct === POLICY_BATCH) {
    // Per-item policy is carried inside the body for ar.batch.v1 — envelope-level
    // policy_* slots are intentionally not enforced here (see plan §Task 14).
    return { ok: true };
  }

  if (POLICY_OPTIONAL.has(ct)) {
    // Policy fields are permitted but not required.
    return { ok: true };
  }

  // isKnownClaimType already gates upstream — this branch is defensive.
  return { ok: false, reason: "unknown_claim_type" };
}

/**
 * Optional verifier-side fetch + recompute of the policy document hash.
 *
 * Returns `false` on any network failure, non-2xx response, or hash mismatch.
 * Never throws — callers map the boolean to `policy_fetched_match`.
 *
 * Default: callers do NOT invoke this. The hash inside the envelope is the
 * trust anchor; fetch + recompute is opt-in (`opts.fetchPolicy = true`) for
 * auditor / forensic re-check flows.
 */
export async function fetchAndCheckPolicy(
  uri: string,
  expectedHash: string,
): Promise<boolean> {
  try {
    const res = await fetch(uri);
    if (!res.ok) return false;
    const body = await res.text();
    const sha = "sha256:" + createHash("sha256").update(body).digest("hex");
    return sha === expectedHash;
  } catch {
    return false;
  }
}
