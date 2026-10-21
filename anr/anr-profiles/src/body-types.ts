/**
 * ANR (Anchored Notice Receipts) type definitions.
 *
 * Body shape — what goes in `Envelope.body` — plus the discriminated union
 * keyed on `event_type` that §C's per-event body verifier dispatches on.
 *
 * Envelope-level fields (`v`, `id`, `claim_type`, `iss`, `iss_key`, `iat`,
 * `iat_ms`, `subject`, `policy_uri`, `policy_hash`, `policy_version`,
 * `field_root`, `prev`, `credentialStatus`, `tsa`, `anchor`, `sig`,
 * `countersig`, `kind`, `cause`, `predicate`) are provided by
 * `@dekimuhq/anchors-envelope` and are NOT repeated here.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/anr.
 * Family invariants: `meta/FAMILY-CONSISTENCY.md` (chip #10,
 * subject-presence per-event split, TSA mandate rows for ANR, status-list
 * consumer #4).
 */

// ── Claim type ────────────────────────────────────────────────────────────────

/** ANR v=2 claim_type — the only registered discriminator for this family. */
export type AnrClaimType = "ar.notice.v1";

// ── Event types ───────────────────────────────────────────────────────────────

/**
 * The six notice-lifecycle event types defined in ANR spec §4.
 *
 * - `notice.presented`               — initial delivery of a notice version (§4.1).
 * - `notice.re_presented`            — material change re-surface (§4.2).
 * - `notice.acknowledged`            — subject acknowledgement (§4.3).
 * - `notice.withdrawn`               — controller deprecation (§4.4).
 * - `notice.translated`              — translation of a base notice (§4.5).
 * - `notice.joint_controller_essence`— Art. 26(2) essence disclosure (§4.6).
 */
export type AnrEventType =
  | "notice.presented"
  | "notice.re_presented"
  | "notice.acknowledged"
  | "notice.withdrawn"
  | "notice.translated"
  | "notice.joint_controller_essence";

// ── Profile union ─────────────────────────────────────────────────────────────

/**
 * The five v1 regulatory profiles (spec §5). Profile validators ship in the
 * separate `@dekimuhq/anr-profiles` package; the verifier loads them
 * dynamically. The verifier rejects any receipt with an unregistered profile.
 */
export type AnrProfile =
  | "notice.art13.collected_direct"
  | "notice.art14.collected_indirect"
  | "notice.art26.joint_controller_essence"
  | "notice.layered_transparency"
  | "notice.aiact.art50_transparency";

// ── Closed enums (body sub-fields) ────────────────────────────────────────────

/** How the notice was rendered to the subject (spec §3.1). */
export type AnrDeliveryChannel =
  | "web"
  | "email"
  | "in_app"
  | "paper_qr"
  | "api";

/** Subject acknowledgement method (spec §4.3). */
export type AnrAckMethod = "checkbox" | "double_opt_in" | "paper_signed";

/** Optional age band carried by the `notice.art13.collected_direct` profile (spec §5.1). */
export type AnrSubjectAgeBand = "adult" | "13_to_15" | "under_13";

/** Art. 14(3) collection clock applied to indirect-collection notices (spec §5.2). */
export type AnrCollectionHorizon =
  | "one_month"
  | "first_communication"
  | "disclosure_to_third_party";

/** AI Act Art. 50 disclosure kind (spec §5.5). */
export type AnrAiSystemKind =
  | "interaction"
  | "synthetic_content"
  | "emotion_recognition"
  | "biometric_categorisation"
  | "deepfake";

// ── Sub-records ───────────────────────────────────────────────────────────────

/**
 * One rendered layer in a `notice.layered_transparency` receipt (spec §5.4).
 *
 * `hash` is the SHA-256 of the layer render. The envelope-level
 * `policy_hash` is SHA-256 over the concatenation of layer hashes in
 * `layer` order (`summary` first).
 */
export interface AnrLayerUri {
  layer: "summary" | "full" | "jit";
  uri: string;
  hash: string;
}

/**
 * A joint controller as carried in `notice.joint_controller_essence` events
 * (spec §4.6) and in the `notice.art26.joint_controller_essence` profile (§5.3).
 *
 * `adr_id` is OPTIONAL. When set, the verifier cross-references the
 * corresponding ADR receipt's `iss` (spec §8.5). Verifier does NOT
 * fail-hard on mismatch — joint controllers may not all participate in
 * the anchor family.
 */
export interface AnrJointController {
  did: string;
  role: string;
  contact_point_uri: string;
  adr_id: string | null;
}

// ── Status List 2021 on-list state (spec §6.3) ────────────────────────────────

/**
 * On-list interpretation of the Status List 2021 bit value for ANR.
 *
 * | State        | When issued                                                   |
 * |--------------|---------------------------------------------------------------|
 * | `active`     | default; downstream ACR receipts surface no warning           |
 * | `withdrawn`  | `notice.withdrawn` with `cessation_reason` (no successor)     |
 * | `superseded` | `notice.withdrawn` with `supersedes_anr_id` set               |
 * | `revoked`    | controller-side revocation for fraud / error / compromise     |
 *
 * The runtime status-list check is performed by `verifyCredentialStatus`
 * from `@dekimuhq/anchors-envelope/status`. This type names the on-list
 * states for ANR-specific audit tooling and downstream ACR composition.
 */
export type AnrStatusState =
  | "active"
  | "withdrawn"
  | "superseded"
  | "revoked";

// ── Per-event-type body variants ──────────────────────────────────────────────

/**
 * Fields common to all six event-type bodies (spec §3.1 + §4 + D10-ANR-2).
 *
 * `profile` pins the receipt to one of the five v1 regulatory rationales.
 * `lang_tag` is BCP 47 and is REQUIRED on every event (D10-ANR-2).
 * `lang_inferred` is the server-side `Accept-Language` derivation, optional.
 */
interface AnrBodyBase {
  profile: AnrProfile;
  lang_tag: string;
  lang_inferred: string | null;
  /** SHA-256 hash of an AAR receipt attesting QTS posture. `null` when absent. */
  qts_attestation_hash: string | null;
}

/**
 * Body for `notice.presented` (spec §4.1).
 *
 * Required: `delivery_channel`, `render_uri`, `rights_surface`, `jurisdiction`.
 * Profile-conditional optional fields are pinned to `null` when the active
 * profile does not use them; §C body verifier asserts the pins.
 */
export interface AnrPresentedBody extends AnrBodyBase {
  event_type: "notice.presented";
  jurisdiction: string;
  delivery_channel: AnrDeliveryChannel;
  render_uri: string;
  rights_surface: readonly string[];

  /** Art. 13 (§5.1). `null` on non-art13 profiles. */
  subject_age_band: AnrSubjectAgeBand | null;

  /** Art. 14 source-of-data (§5.2). `null` on non-art14 profiles. */
  data_source: string | null;
  /** Art. 14 collection clock (§5.2). `null` on non-art14 profiles. */
  collection_horizon: AnrCollectionHorizon | null;
  /** Art. 14 issuer-claimed acquisition time (§5.2). `null` when unknown. */
  data_acquired_at: string | null;

  /** Layered-transparency layer hashes (§5.4). `null` on non-layered profiles. */
  layer_uris: readonly AnrLayerUri[] | null;

  /** AI Act Art. 50 disclosure kind (§5.5). `null` on non-aiact profiles. */
  ai_system_kind: AnrAiSystemKind | null;
  /** AI Act Art. 50 AI provider DID (§5.5). `null` on non-aiact profiles. */
  ai_system_provider_did: string | null;
  /** AI Act Art. 50 cross-ref to AER receipt (§8.4). `null` when absent. */
  aer_id: string | null;

  // Cross-event-pinned fields (always null on `notice.presented`).
  supersedes_anr_id: null;
  base_anr_id: null;
  ack_method: null;
  joint_controllers: null;
  cessation_reason: null;
  translation_provenance_alr_id: null;
}

/**
 * Body for `notice.re_presented` (spec §4.2).
 *
 * Same shape as `notice.presented` plus a REQUIRED `supersedes_anr_id`
 * referencing the most recent `notice.presented` (or `notice.re_presented`)
 * in the same subject's chain.
 */
export interface AnrRePresentedBody extends AnrBodyBase {
  event_type: "notice.re_presented";
  jurisdiction: string;
  delivery_channel: AnrDeliveryChannel;
  render_uri: string;
  rights_surface: readonly string[];
  supersedes_anr_id: string;

  subject_age_band: AnrSubjectAgeBand | null;
  data_source: string | null;
  collection_horizon: AnrCollectionHorizon | null;
  data_acquired_at: string | null;
  layer_uris: readonly AnrLayerUri[] | null;
  ai_system_kind: AnrAiSystemKind | null;
  ai_system_provider_did: string | null;
  aer_id: string | null;

  // Cross-event-pinned fields.
  base_anr_id: null;
  ack_method: null;
  joint_controllers: null;
  cessation_reason: null;
  translation_provenance_alr_id: null;
}

/**
 * Body for `notice.acknowledged` (spec §4.3).
 *
 * Required: `ack_method` plus the envelope-level `subject` field set to
 * `"sha256:<hex>"` (FAMILY-CONSISTENCY §3 — enforced in §E
 * subject-presence). `prev` MUST reference the receipt being acknowledged
 * — enforced in §C chain walker.
 *
 * `delivery_channel` / `render_uri` / `rights_surface` are not redisplayed
 * on an acknowledgement; they are pinned `null`.
 */
export interface AnrAcknowledgedBody extends AnrBodyBase {
  event_type: "notice.acknowledged";
  jurisdiction: string;
  ack_method: AnrAckMethod;

  // Cross-event-pinned fields.
  delivery_channel: null;
  render_uri: null;
  rights_surface: null;
  subject_age_band: null;
  data_source: null;
  collection_horizon: null;
  data_acquired_at: null;
  layer_uris: null;
  ai_system_kind: null;
  ai_system_provider_did: null;
  aer_id: null;
  supersedes_anr_id: null;
  base_anr_id: null;
  joint_controllers: null;
  cessation_reason: null;
  translation_provenance_alr_id: null;
}

/**
 * Body for `notice.withdrawn` (spec §4.4).
 *
 * The withdrawal is either a supersession (a successor notice exists) or
 * a cessation (processing has stopped). Exactly one of
 * `supersedes_anr_id` and `cessation_reason` MUST be non-null; the other
 * MUST be `null`. §C body verifier asserts the XOR.
 */
export interface AnrWithdrawnBody extends AnrBodyBase {
  event_type: "notice.withdrawn";
  jurisdiction: string;
  /** Set when a successor notice supersedes this one (mutually exclusive with `cessation_reason`). */
  supersedes_anr_id: string | null;
  /** Set when processing has ceased without a successor (mutually exclusive with `supersedes_anr_id`). */
  cessation_reason: string | null;

  // Cross-event-pinned fields.
  delivery_channel: null;
  render_uri: null;
  rights_surface: null;
  subject_age_band: null;
  data_source: null;
  collection_horizon: null;
  data_acquired_at: null;
  layer_uris: null;
  ai_system_kind: null;
  ai_system_provider_did: null;
  aer_id: null;
  base_anr_id: null;
  ack_method: null;
  joint_controllers: null;
  translation_provenance_alr_id: null;
}

/**
 * Body for `notice.translated` (spec §4.5).
 *
 * `lang_tag` is the new translation's language. `base_anr_id` references
 * the base-language receipt. Per D10-ANR-5, `prev` is NULL on a
 * `notice.translated` event — translations branch from the base, they do
 * not extend the base chain linearly. The §C chain walker enforces this.
 *
 * Spec §4.5 explicitly omits `jurisdiction` from the required-field set
 * because a translation is locale-scoped rather than jurisdiction-scoped;
 * `jurisdiction` is `null` here. Per D10-ANR-2, `lang_tag` remains required.
 */
export interface AnrTranslatedBody extends AnrBodyBase {
  event_type: "notice.translated";
  base_anr_id: string;
  jurisdiction: null;

  /** Optional ALR `derived_from` reference anchoring translation provenance (§8.3). */
  translation_provenance_alr_id: string | null;

  // Cross-event-pinned fields.
  delivery_channel: null;
  render_uri: null;
  rights_surface: null;
  subject_age_band: null;
  data_source: null;
  collection_horizon: null;
  data_acquired_at: null;
  layer_uris: null;
  ai_system_kind: null;
  ai_system_provider_did: null;
  aer_id: null;
  supersedes_anr_id: null;
  ack_method: null;
  joint_controllers: null;
  cessation_reason: null;
}

/**
 * Body for `notice.joint_controller_essence` (spec §4.6).
 *
 * Required: `joint_controllers` (array of `AnrJointController`).
 * Used with the `notice.art26.joint_controller_essence` profile.
 */
export interface AnrJointControllerEssenceBody extends AnrBodyBase {
  event_type: "notice.joint_controller_essence";
  jurisdiction: string;
  joint_controllers: readonly AnrJointController[];

  // Cross-event-pinned fields.
  delivery_channel: null;
  render_uri: null;
  rights_surface: null;
  subject_age_band: null;
  data_source: null;
  collection_horizon: null;
  data_acquired_at: null;
  layer_uris: null;
  ai_system_kind: null;
  ai_system_provider_did: null;
  aer_id: null;
  supersedes_anr_id: null;
  base_anr_id: null;
  ack_method: null;
  cessation_reason: null;
  translation_provenance_alr_id: null;
}

/**
 * Discriminated union of all six ANR body variants.
 * §C body verifier dispatches on `body.event_type`.
 */
export type AnrBody =
  | AnrPresentedBody
  | AnrRePresentedBody
  | AnrAcknowledgedBody
  | AnrWithdrawnBody
  | AnrTranslatedBody
  | AnrJointControllerEssenceBody;

// ── Chain walker depth limits (spec §6.2) ─────────────────────────────────────

/** Default cap on the number of envelope-`prev` hops the walker traverses. */
export const ANR_DEFAULT_DEPTH_LIMIT = 256;

/** Floor for the depth-limit option; values below this are clamped up. */
export const ANR_DEPTH_LIMIT_MIN = 32;

/** Ceiling for the depth-limit option; values above this are clamped down. */
export const ANR_DEPTH_LIMIT_MAX = 1024;
