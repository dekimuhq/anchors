/**
 * APuR (Anchored Purpose Receipts) body-type definitions.
 *
 * Body shape — what goes in `Envelope.body` — plus the discriminated union
 * keyed on `event_type` that the verifier's per-event body validator dispatches
 * on, and the profile-id union the profile validators are keyed by.
 *
 * These types live in `@dekimuhq/apur-profiles` (not the verifier) so the
 * profile validators can import the body shape without depending on the
 * verifier package — the verifier imports profile *values* (`family.ts`), so a
 * profiles→verifier type edge would form an import cycle that blocks the
 * topological built-`dist` publish. `@dekimuhq/apur` re-exports every
 * symbol here, so its public API is unchanged for downstream consumers.
 *
 * Envelope-level fields (`v`, `id`, `claim_type`, `iss`, `iss_key`, `iat`,
 * `iat_ms`, `subject`, `policy_uri`, `policy_hash`, `policy_version`,
 * `field_root`, `prev`, `credentialStatus`, `tsa`, `anchor`, `sig`,
 * `countersig`, `countersig_key`, `kind`, `cause`, `predicate`) are provided by
 * `@dekimuhq/anchors-envelope` and are NOT repeated here.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/apur.
 */

// ── Claim type ──────────────────────────────────────────────────────────────────

export type ApurClaimType = "ar.purpose.v1";

// ── Event types (spec §4, §3 audit note) ────────────────────────────────────────

export type ApurEventType = "binding" | "repurpose" | "unbinding";

// ── Profiles (spec §5) ─────────────────────────────────────────────────────────

export type ApurProfile =
  | "purpose.gdpr.art5"
  | "purpose.gdpr.art6_4"
  | "purpose.hipaa.minimum_necessary"
  | "purpose.lgpd.art6";

// ── Compatibility conclusion (spec §4.2, D12-APuR) ─────────────────────────────

export type ApurCompatConclusion =
  | "compatible"
  | "incompatible_requires_new_basis"
  | "incompatible_aborted";

// ── Unbinding reason (spec §4.3) ────────────────────────────────────────────────

export type ApurUnbindingReason =
  | "purpose_fulfilled"
  | "consent_withdrawn"
  | "controller_decision"
  | "retention_expired"
  | "subject_request_art17"
  | "regulator_order"
  | "mechanism_struck_down";

// ── Data subjects class (spec §4.4) ─────────────────────────────────────────────

export type ApurDataSubjectsClass =
  | "customers"
  | "employees"
  | "prospects"
  | "minors"
  | "vulnerable"
  | "vendors"
  | "visitors"
  | "mixed";

// ── Body variants (discriminated union on event_type) ──────────────────────────

/** binding — spec §4.1. Chain head (prev MUST be null). */
export interface ApurBindingBody {
  event_type: "binding";
  activity_id_commit: string;
  purpose_commit: string;
  purpose_class: string;
  lawful_basis: string;
  data_categories: string[];
  data_subjects_class: string;
  policy_hash: string;
  minimisation_hash: string;
  consent_receipt_hash: string | null;
  retention_receipt_hash: string | null;
  transfer_arrangement_hash: string | null;
  bound_at: string;
  /** SHA-256 hash of an AAR receipt attesting QTS posture. `null` when absent. */
  qts_attestation_hash: string | null;
  // Profile-conditional (hipaa.minimum_necessary §5.4):
  covered_entity_commit?: string;
  workforce_role_class?: string;
}

/** repurpose — spec §4.2. Compatible secondary use test (Art 6(4)). */
export interface ApurRepurposeBody {
  event_type: "repurpose";
  new_purpose_commit: string;
  new_purpose_class: string;
  compat_link_hash: string;
  compat_context_hash: string;
  compat_subjects_reasonable_hash: string;
  compat_consequences_hash: string;
  compat_safeguards_hash: string;
  compat_conclusion: string;
  minimisation_hash: string;
  tested_at: string;
  /** SHA-256 hash of an AAR receipt attesting QTS posture. `null` when absent. */
  qts_attestation_hash: string | null;
}

/** unbinding — spec §4.3. Terminal — no further events valid. */
export interface ApurUnbindingBody {
  event_type: "unbinding";
  reason: string;
  downstream_arr_receipt_hash: string | null;
  unbound_at: string;
  /** SHA-256 hash of an AAR receipt attesting QTS posture. `null` when absent. */
  qts_attestation_hash: string | null;
}

/** Discriminated union of all 3 event types. */
export type ApurBody =
  | ApurBindingBody
  | ApurRepurposeBody
  | ApurUnbindingBody;
