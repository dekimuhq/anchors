/**
 * ALR (Anchored Lineage Receipts) type definitions.
 *
 * This module defines the ALR body shape — what goes in `Envelope.body` —
 * plus the discriminated union by `event_type` that §C's per-event-type body
 * verifier dispatches on.
 *
 * Envelope-level fields (`v`, `id`, `claim_type`, `iss`, `iss_key`, `iat`,
 * `iat_ms`, `subject`, `policy_uri`, `policy_hash`, `policy_version`,
 * `field_root`, `prev`, `credentialStatus`, `tsa`, `anchor`, `sig`,
 * `kind`, `cause`, `predicate`) are provided by `@dekimuhq/anchors-envelope`
 * and are NOT repeated here.
 */

// ── Claim type ────────────────────────────────────────────────────────────────

/** ALR v=2 claim_type — the only registered discriminator for this family. */
export type AlrClaimType = "ar.lineage.v1";

// ── Event types ───────────────────────────────────────────────────────────────

/**
 * The four lineage event types defined in ALR §4.
 *
 * - `derived_from`    — A new artifact produced from ≥1 parents via transformation (§4.1).
 * - `forked_from`     — A branch of exactly one parent; divergent future is the intent (§4.2).
 * - `superseded_by`   — The receipt's artifact is the OLD one; `successor` points forward (§4.3).
 * - `disclosed`       — Records a disclosure of this artifact to a named recipient (§4.4).
 */
export type AlrEventType =
  | "derived_from"
  | "forked_from"
  | "superseded_by"
  | "disclosed";

// ── Profile union ─────────────────────────────────────────────────────────────

/**
 * The five v1 regulatory profiles (§5). Profile validators ship in the
 * separate `@dekimuhq/alr-profiles` package; the verifier loads them
 * dynamically. The verifier rejects any receipt with an unregistered profile.
 */
export type AlrProfile =
  | "gdpr.art13.transparency"
  | "aiact.art13.transparency"
  | "aiact.art53.gpai-training"
  | "c2pa.non-media"
  | "disclosure.recipients";

// ── ParentRef ─────────────────────────────────────────────────────────────────

/**
 * A reference to a parent artifact. Used in `parents[]` (for `derived_from`
 * and `forked_from`) and in `successor` (for `superseded_by`).
 *
 * - `artifact_hash` is the canonical `sha256:<hex>` content address.
 * - `parent_apr_id` links to an APR receipt (composition with APR family).
 * - `parent_alr_id` links to an upstream ALR receipt (e.g. fork lineage).
 * - `uri` is an optional resolver hint.
 */
export interface AlrParentRef {
  /** Content address of the parent artifact — `sha256:<hex>`. REQUIRED. */
  artifact_hash: string;
  /** APR receipt ID for this parent. `null` if no APR coverage. */
  parent_apr_id: string | null;
  /** Upstream ALR receipt ID for this parent. `null` if absent. */
  parent_alr_id: string | null;
  /** Resolver hint URI. `null` if absent. */
  uri: string | null;
}

// ── Disclosure sub-record ─────────────────────────────────────────────────────

/**
 * Populated only when `event_type === "disclosed"`. All four sub-fields
 * are REQUIRED when the disclosure block is present (§4.4).
 *
 * `basis` carries GDPR Art 6 lawful bases (`gdpr.art6.1.a` … `gdpr.art6.1.f`)
 * or `gdpr.art9.2.*` for special-category data.
 */
export interface AlrDisclosure {
  recipient: string;
  recipient_role: string;
  scope_hash: string;
  basis: string;
}

// ── Transform claim ───────────────────────────────────────────────────────────

/**
 * Describes the transformation that produced the derived/forked/superseding
 * artifact. `summary` MUST be a non-empty string. `uri` is optional.
 *
 * MUST be `null` when `event_type === "disclosed"`.
 */
export interface AlrTransformClaim {
  /** Human-readable summary of the transformation. Non-empty. */
  summary: string;
  /** Optional URI pointing to a detailed transformation record. */
  uri: string | null;
}

// ── Per-event-type body variants ──────────────────────────────────────────────

/**
 * Fields common to all four event_type bodies.
 *
 * `artifact_hash` is the SHA-256 content address of the artifact THIS receipt
 * is about (NOT a parent). REQUIRED on all four event types.
 *
 * `event_at` is the RFC 3339 issuer-claimed timestamp of the lineage event.
 * It is distinct from envelope `iat` (receipt issuance time) — see spec §3
 * audit note. Kept in body per the audit note.
 *
 * `profile` pins the receipt to one of the five v1 regulatory rationales.
 */
interface AlrBodyBase {
  profile: AlrProfile;
  artifact_hash: string;
  /** RFC 3339 issuer-claimed event timestamp. Distinct from envelope `iat`. */
  event_at: string;
  /** SHA-256 hash of an AAR receipt attesting QTS posture. `null` when absent. */
  qts_attestation_hash: string | null;
}

/**
 * Body for `derived_from` (§4.1).
 *
 * - `parents` — MUST contain ≥1 `AlrParentRef`, sorted lexicographically by
 *   `artifact_hash`. No duplicate `artifact_hash` values allowed.
 * - `successor` — MUST be `null`.
 * - `transform_claim` — REQUIRED (non-null). `summary` MUST be non-empty.
 * - `disclosure` — MUST be `null`.
 */
export interface AlrDerivedFromBody extends AlrBodyBase {
  event_type: "derived_from";
  parents: AlrParentRef[];
  successor: null;
  transform_claim: AlrTransformClaim;
  disclosure: null;
}

/**
 * Body for `forked_from` (§4.2).
 *
 * - `parents` — MUST contain exactly 1 `AlrParentRef`.
 * - `successor` — MUST be `null`.
 * - `transform_claim` — recommended but not required; MAY be `null`.
 * - `disclosure` — MUST be `null`.
 */
export interface AlrForkedFromBody extends AlrBodyBase {
  event_type: "forked_from";
  parents: AlrParentRef[];
  successor: null;
  transform_claim: AlrTransformClaim | null;
  disclosure: null;
}

/**
 * Body for `superseded_by` (§4.3).
 *
 * The receipt's `artifact_hash` is the OLD artifact. `successor.artifact_hash`
 * is its replacement.
 *
 * - `parents` — MUST be `[]`.
 * - `successor` — MUST be populated (non-null).
 * - `transform_claim` — REQUIRED (non-null). `summary` MUST be non-empty.
 * - `disclosure` — MUST be `null`.
 */
export interface AlrSupersededByBody extends AlrBodyBase {
  event_type: "superseded_by";
  parents: [];
  successor: AlrParentRef;
  transform_claim: AlrTransformClaim;
  disclosure: null;
}

/**
 * Body for `disclosed` (§4.4).
 *
 * - `parents` — MUST be `[]`.
 * - `successor` — MUST be `null`.
 * - `transform_claim` — MUST be `null`.
 * - `disclosure` — MUST be populated (non-null). All four sub-fields required.
 */
export interface AlrDisclosedBody extends AlrBodyBase {
  event_type: "disclosed";
  parents: [];
  successor: null;
  transform_claim: null;
  disclosure: AlrDisclosure;
}

/**
 * Discriminated union of all four ALR body variants.
 * §C dispatches on `body.event_type`.
 */
export type AlrBody =
  | AlrDerivedFromBody
  | AlrForkedFromBody
  | AlrSupersededByBody
  | AlrDisclosedBody;

// ── Status-list state ─────────────────────────────────────────────────────────

/**
 * On-list interpretation of the 2-bit status pair (§6.3).
 *
 * | Bits | State              | Meaning                                        |
 * |------|--------------------|------------------------------------------------|
 * | `00` | `active`           | Receipt is valid; lineage claim stands         |
 * | `01` | `revoked`          | Issuer revoked the receipt                     |
 * | `10` | `lineage_degraded` | At least one ancestor was tombstoned (Art 17)  |
 * | `11` | `superseded`       | Fast-filter flag; same info as walking chain   |
 *
 * The runtime status-list check is performed by `verifyCredentialStatus` from
 * `@dekimuhq/anchors-envelope/status`. This type names the on-list states for
 * ALR-specific audit tooling and §C body verification.
 */
export type AlrStatusState =
  | "active"
  | "revoked"
  | "lineage_degraded"
  | "superseded";

// ── Depth-limit constants ─────────────────────────────────────────────────────

/**
 * Default verifier DAG traversal depth limit (§6.2).
 * Real-world lineages are 5–30 deep; 256 catches pathology.
 */
export const ALR_DEFAULT_DEPTH_LIMIT = 256;

/** Minimum configurable depth limit (§6.2). */
export const ALR_DEPTH_LIMIT_MIN = 32;

/** Maximum configurable depth limit (§6.2). */
export const ALR_DEPTH_LIMIT_MAX = 1024;
