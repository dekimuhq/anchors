/**
 * ATokR (Anchored Tokenization Receipts) body-type definitions.
 *
 * Body shape — what goes in `Envelope.body` — plus the discriminated union
 * keyed on `event_type` that the verifier's per-event body validator dispatches
 * on, and the profile-id union the profile validators are keyed by.
 *
 * These types live in `@dekimuhq/atokr-profiles` (not the verifier) so the
 * profile validators can import the body shape without depending on the
 * verifier package — the verifier imports profile *values* (`family.ts`), so a
 * profiles→verifier type edge would form an import cycle that blocks the
 * topological built-`dist` publish. `@dekimuhq/atokr` re-exports every
 * symbol here, so its public API is unchanged for downstream consumers.
 *
 * Envelope-level fields (`v`, `id`, `claim_type`, `iss`, `iss_key`, `iat`,
 * `iat_ms`, `subject`, `policy_uri`, `policy_hash`, `policy_version`,
 * `field_root`, `prev`, `credentialStatus`, `tsa`, `anchor`, `sig`,
 * `countersig`, `countersig_key`, `kind`, `cause`, `predicate`) are provided by
 * `@dekimuhq/anchors-envelope` and are NOT repeated here.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/atokr.
 * Family invariants: `meta/FAMILY-CONSISTENCY.md`.
 */

// ── Claim type ────────────────────────────────────────────────────────────────

export type AtokrClaimType = "ar.tokenization.v1";

// ── Event types (spec §4, D10-ATokR-1) ──────────────────────────────────────────

export type AtokrEventType =
  | "token.issued"
  | "token.redeemed"
  | "token.revoked"
  | "token.rotated";

// ── Profiles (spec §5) ─────────────────────────────────────────────────────────

export type AtokrProfile =
  | "tokenization.gdpr.art32"
  | "tokenization.gdpr.art4_5"
  | "tokenization.pci.dss_v4"
  | "tokenization.eudi.wallet_arf"
  | "tokenization.sector.health";

// ── Format class (spec §1, D10-ATokR-4) ────────────────────────────────────────

export type AtokrFormatClass =
  | "pan"
  | "email"
  | "iban"
  | "phone"
  | "national_id"
  | "freeform";

// ── PCI environment (spec §5.3) ────────────────────────────────────────────────

export type AtokrPciEnvironment = "cde" | "connected" | "out_of_scope";

// ── EUDI attribute category (spec §5.4) ────────────────────────────────────────

export type AtokrAttributeCategory = "pid" | "qeaa" | "eaa" | "pda";

// ── Health data-use category (spec §5.5) ───────────────────────────────────────

export type AtokrDataUseCategory =
  | "primary_care"
  | "secondary_research"
  | "clinical_trial"
  | "public_health";

// ── Scope (spec §1, D10-ATokR-3) ──────────────────────────────────────────────

export interface AtokrScope {
  audience: string;
  purpose: string;
  valid_from: string;
  valid_until: string | null;
  single_use: boolean;
}

// ── Body variants (discriminated union on event_type) ──────────────────────────

/** token.issued — spec §4.1. Chain head (prev MUST be null). */
export interface AtokrIssuedBody {
  event_type: "token.issued";
  token_id: string;
  format_class: AtokrFormatClass;
  scope: AtokrScope;
  rotation_of: null;
  redemption_audit_ref: null;
  asr_ref: string | null;
  arr_ref: null;
  alr_ref: string | null;
  apur_ref: string | null;
  /** SHA-256 hash of an AAR receipt attesting QTS posture. `null` when absent. */
  qts_attestation_hash: string | null;
  // Profile-conditional fields (present only under specific profiles):
  separation_attestation?: boolean;            // tokenization.gdpr.art4_5 §5.2
  pci_environment?: AtokrPciEnvironment;       // tokenization.pci.dss_v4 §5.3
  wallet_provider_did?: string;                // tokenization.eudi.wallet_arf §5.4
  attribute_category?: AtokrAttributeCategory; // tokenization.eudi.wallet_arf §5.4
  data_use_category?: AtokrDataUseCategory;    // tokenization.sector.health §5.5
  pseudonymisation_standard?: string;          // tokenization.sector.health §5.5
}

/** token.redeemed — spec §4.2. Non-terminal (repeats unless single_use). */
export interface AtokrRedeemedBody {
  event_type: "token.redeemed";
  token_id: string;
  format_class: AtokrFormatClass | null;
  scope: AtokrScope;
  rotation_of: null;
  redemption_audit_ref: string | null;
  asr_ref: string | null;
  arr_ref: null;
  alr_ref: null;
  apur_ref: string | null;
  /** SHA-256 hash of an AAR receipt attesting QTS posture. `null` when absent. */
  qts_attestation_hash: string | null;
  separation_attestation?: boolean;
  pci_environment?: AtokrPciEnvironment;
  wallet_provider_did?: string;
  attribute_category?: AtokrAttributeCategory;
  data_use_category?: AtokrDataUseCategory;
  pseudonymisation_standard?: string;
}

/** token.revoked — spec §4.3. Terminal — no further events valid. */
export interface AtokrRevokedBody {
  event_type: "token.revoked";
  token_id: string;
  format_class: AtokrFormatClass | null;
  scope: AtokrScope;
  rotation_of: null;
  redemption_audit_ref: null;
  asr_ref: string | null;
  arr_ref: string | null;
  alr_ref: null;
  apur_ref: string | null;
  /** SHA-256 hash of an AAR receipt attesting QTS posture. `null` when absent. */
  qts_attestation_hash: string | null;
  separation_attestation?: boolean;
  pci_environment?: AtokrPciEnvironment;
  wallet_provider_did?: string;
  attribute_category?: AtokrAttributeCategory;
  data_use_category?: AtokrDataUseCategory;
  pseudonymisation_standard?: string;
}

/** token.rotated — spec §4.4. Closes prior chain, opens new one. */
export interface AtokrRotatedBody {
  event_type: "token.rotated";
  token_id: string;
  format_class: AtokrFormatClass;
  scope: AtokrScope;
  rotation_of: string;
  redemption_audit_ref: null;
  asr_ref: null;
  arr_ref: null;
  alr_ref: string | null;
  apur_ref: string | null;
  /** SHA-256 hash of an AAR receipt attesting QTS posture. `null` when absent. */
  qts_attestation_hash: string | null;
  separation_attestation?: boolean;
  pci_environment?: AtokrPciEnvironment;
  wallet_provider_did?: string;
  attribute_category?: AtokrAttributeCategory;
  data_use_category?: AtokrDataUseCategory;
  pseudonymisation_standard?: string;
}

/** Discriminated union of all 4 event types. */
export type AtokrBody =
  | AtokrIssuedBody
  | AtokrRedeemedBody
  | AtokrRevokedBody
  | AtokrRotatedBody;
