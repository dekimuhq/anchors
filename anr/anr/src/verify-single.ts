/**
 * Per-event-type ANR body verifier (spec §3.1 + §4 + D10-ANR-1/D10-ANR-2).
 *
 * Validates the discriminated union on `body.event_type` and the cross-event
 * pinning invariants the discriminated union enforces at the type level
 * (every variant pins all non-applicable fields to `null`). Called by
 * `verifyV2` after envelope-level checks pass; also exported for callers
 * that hold a body in hand.
 *
 * ANR is v=2 only — there is no v=1 body shape. Profile-specific validation
 * lives in `@dekimuhq/anr-profiles`; this module only confirms the active
 * profile string is one of the five spec §5 literals and that the base
 * fields (profile, lang_tag, lang_inferred) are well-typed.
 *
 * §C scope: per-event required-field assertions + pinned-null assertions.
 * §D, §E, §G enforce TSA-mandate / subject-presence / composition; those
 * checks ride on envelope state and live in their own modules.
 */

import type {
  AnrAckMethod,
  AnrAiSystemKind,
  AnrBody,
  AnrCollectionHorizon,
  AnrDeliveryChannel,
  AnrJointController,
  AnrLayerUri,
  AnrProfile,
  AnrSubjectAgeBand,
} from "./types.ts";

// ── Public surface ────────────────────────────────────────────────────────────

export interface VerifyBodyResult {
  /** True iff every structural check in §3.1 + §4 passes. */
  valid: boolean;
  /** Stable, machine-readable failure codes. Empty when `valid === true`. */
  errors: string[];
  /** Narrowed body when valid; null otherwise. */
  body: AnrBody | null;
}

/**
 * Validate an ANR `body` against spec §3.1 (shared fields) and §4
 * (per-event-type rules). Returns the narrowed discriminated-union body on
 * success.
 */
export function verifyAnrBody(body: unknown): VerifyBodyResult {
  const errors: string[] = [];

  if (typeof body !== "object" || body === null) {
    return { valid: false, errors: ["body.not_object"], body: null };
  }
  const b = body as Record<string, unknown>;

  // ── Base fields shared by every event type (D10-ANR-2) ─────────────────────
  if (!isAnrProfile(b.profile)) errors.push("profile.unregistered");
  if (!isNonEmptyString(b.lang_tag)) errors.push("lang_tag.invalid");
  if (b.lang_inferred !== null && typeof b.lang_inferred !== "string") {
    errors.push("lang_inferred.invalid");
  }

  // ── Event-type dispatch (D10-ANR-1) ────────────────────────────────────────
  switch (b.event_type) {
    case "notice.presented":
      validatePresented(b, errors);
      break;
    case "notice.re_presented":
      validateRePresented(b, errors);
      break;
    case "notice.acknowledged":
      validateAcknowledged(b, errors);
      break;
    case "notice.withdrawn":
      validateWithdrawn(b, errors);
      break;
    case "notice.translated":
      validateTranslated(b, errors);
      break;
    case "notice.joint_controller_essence":
      validateJointControllerEssence(b, errors);
      break;
    default:
      errors.push("event_type.unknown");
  }

  if (errors.length > 0) return { valid: false, errors, body: null };
  return { valid: true, errors: [], body: b as unknown as AnrBody };
}

// ── §4.1 notice.presented ─────────────────────────────────────────────────────

function validatePresented(b: Record<string, unknown>, errors: string[]): void {
  validatePresentationFields(b, errors);
  // `supersedes_anr_id` is pinned-null on the initial presentation event.
  if (b.supersedes_anr_id !== null) errors.push("supersedes_anr_id.must_be_null");
  validatePresentedPins(b, errors);
}

// ── §4.2 notice.re_presented ──────────────────────────────────────────────────

function validateRePresented(b: Record<string, unknown>, errors: string[]): void {
  validatePresentationFields(b, errors);
  // §4.2: `supersedes_anr_id` is REQUIRED — must reference the prior receipt.
  if (!isNonEmptyString(b.supersedes_anr_id)) {
    errors.push("supersedes_anr_id.required");
  }
  validatePresentedPins(b, errors);
}

// ── §4.3 notice.acknowledged ──────────────────────────────────────────────────

function validateAcknowledged(b: Record<string, unknown>, errors: string[]): void {
  if (!isNonEmptyString(b.jurisdiction)) errors.push("jurisdiction.required");
  if (!isAckMethod(b.ack_method)) errors.push("ack_method.invalid");

  // Acknowledgements do not redisplay presentation fields.
  if (b.delivery_channel !== null) errors.push("delivery_channel.must_be_null");
  if (b.render_uri !== null) errors.push("render_uri.must_be_null");
  if (b.rights_surface !== null) errors.push("rights_surface.must_be_null");
  pinNull(b, "subject_age_band", errors);
  pinNull(b, "data_source", errors);
  pinNull(b, "collection_horizon", errors);
  pinNull(b, "data_acquired_at", errors);
  pinNull(b, "layer_uris", errors);
  pinNull(b, "ai_system_kind", errors);
  pinNull(b, "ai_system_provider_did", errors);
  pinNull(b, "aer_id", errors);
  pinNull(b, "supersedes_anr_id", errors);
  pinNull(b, "base_anr_id", errors);
  pinNull(b, "joint_controllers", errors);
  pinNull(b, "cessation_reason", errors);
  pinNull(b, "translation_provenance_alr_id", errors);
}

// ── §4.4 notice.withdrawn ─────────────────────────────────────────────────────

function validateWithdrawn(b: Record<string, unknown>, errors: string[]): void {
  if (!isNonEmptyString(b.jurisdiction)) errors.push("jurisdiction.required");

  // §4.4 XOR: exactly one of supersedes_anr_id / cessation_reason MUST be set.
  const supSet = isNonEmptyString(b.supersedes_anr_id);
  const cesSet = isNonEmptyString(b.cessation_reason);
  if (supSet && cesSet) {
    errors.push("withdrawn.both_set");
  } else if (!supSet && !cesSet) {
    errors.push("withdrawn.neither_set");
  } else {
    // Non-active half must be exactly null.
    if (!supSet && b.supersedes_anr_id !== null) errors.push("supersedes_anr_id.must_be_null");
    if (!cesSet && b.cessation_reason !== null) errors.push("cessation_reason.must_be_null");
  }

  if (b.delivery_channel !== null) errors.push("delivery_channel.must_be_null");
  if (b.render_uri !== null) errors.push("render_uri.must_be_null");
  if (b.rights_surface !== null) errors.push("rights_surface.must_be_null");
  pinNull(b, "subject_age_band", errors);
  pinNull(b, "data_source", errors);
  pinNull(b, "collection_horizon", errors);
  pinNull(b, "data_acquired_at", errors);
  pinNull(b, "layer_uris", errors);
  pinNull(b, "ai_system_kind", errors);
  pinNull(b, "ai_system_provider_did", errors);
  pinNull(b, "aer_id", errors);
  pinNull(b, "base_anr_id", errors);
  pinNull(b, "ack_method", errors);
  pinNull(b, "joint_controllers", errors);
  pinNull(b, "translation_provenance_alr_id", errors);
}

// ── §4.5 notice.translated ────────────────────────────────────────────────────

function validateTranslated(b: Record<string, unknown>, errors: string[]): void {
  // Translations are locale-scoped, not jurisdiction-scoped (spec §4.5).
  if (b.jurisdiction !== null) errors.push("jurisdiction.must_be_null");
  if (!isNonEmptyString(b.base_anr_id)) errors.push("base_anr_id.required");
  if (
    b.translation_provenance_alr_id !== null &&
    typeof b.translation_provenance_alr_id !== "string"
  ) {
    errors.push("translation_provenance_alr_id.invalid");
  }

  // All presentation + acknowledgement + withdrawal + joint-controller fields
  // are pinned-null on a translation receipt.
  if (b.delivery_channel !== null) errors.push("delivery_channel.must_be_null");
  if (b.render_uri !== null) errors.push("render_uri.must_be_null");
  if (b.rights_surface !== null) errors.push("rights_surface.must_be_null");
  pinNull(b, "subject_age_band", errors);
  pinNull(b, "data_source", errors);
  pinNull(b, "collection_horizon", errors);
  pinNull(b, "data_acquired_at", errors);
  pinNull(b, "layer_uris", errors);
  pinNull(b, "ai_system_kind", errors);
  pinNull(b, "ai_system_provider_did", errors);
  pinNull(b, "aer_id", errors);
  pinNull(b, "supersedes_anr_id", errors);
  pinNull(b, "ack_method", errors);
  pinNull(b, "joint_controllers", errors);
  pinNull(b, "cessation_reason", errors);
}

// ── §4.6 notice.joint_controller_essence ──────────────────────────────────────

function validateJointControllerEssence(b: Record<string, unknown>, errors: string[]): void {
  if (!isNonEmptyString(b.jurisdiction)) errors.push("jurisdiction.required");

  const jcs = readJointControllers(b.joint_controllers, errors);
  if (jcs !== null && jcs.length === 0) errors.push("joint_controllers.empty");

  if (b.delivery_channel !== null) errors.push("delivery_channel.must_be_null");
  if (b.render_uri !== null) errors.push("render_uri.must_be_null");
  if (b.rights_surface !== null) errors.push("rights_surface.must_be_null");
  pinNull(b, "subject_age_band", errors);
  pinNull(b, "data_source", errors);
  pinNull(b, "collection_horizon", errors);
  pinNull(b, "data_acquired_at", errors);
  pinNull(b, "layer_uris", errors);
  pinNull(b, "ai_system_kind", errors);
  pinNull(b, "ai_system_provider_did", errors);
  pinNull(b, "aer_id", errors);
  pinNull(b, "supersedes_anr_id", errors);
  pinNull(b, "base_anr_id", errors);
  pinNull(b, "ack_method", errors);
  pinNull(b, "cessation_reason", errors);
  pinNull(b, "translation_provenance_alr_id", errors);
}

// ── Shared presentation validators (shared by presented + re_presented) ───────

function validatePresentationFields(b: Record<string, unknown>, errors: string[]): void {
  if (!isNonEmptyString(b.jurisdiction)) errors.push("jurisdiction.required");
  if (!isDeliveryChannel(b.delivery_channel)) errors.push("delivery_channel.invalid");
  if (!isNonEmptyString(b.render_uri)) errors.push("render_uri.required");
  if (!isStringArray(b.rights_surface)) {
    errors.push("rights_surface.invalid");
  }

  // Optional / profile-conditional fields — typed when present.
  if (b.subject_age_band !== null && !isSubjectAgeBand(b.subject_age_band)) {
    errors.push("subject_age_band.invalid");
  }
  if (b.data_source !== null && typeof b.data_source !== "string") {
    errors.push("data_source.invalid");
  }
  if (b.collection_horizon !== null && !isCollectionHorizon(b.collection_horizon)) {
    errors.push("collection_horizon.invalid");
  }
  if (b.data_acquired_at !== null && !isIsoTimestamp(b.data_acquired_at)) {
    errors.push("data_acquired_at.invalid");
  }
  if (b.layer_uris !== null && !isLayerUriArray(b.layer_uris)) {
    errors.push("layer_uris.invalid");
  }
  if (b.ai_system_kind !== null && !isAiSystemKind(b.ai_system_kind)) {
    errors.push("ai_system_kind.invalid");
  }
  if (b.ai_system_provider_did !== null && typeof b.ai_system_provider_did !== "string") {
    errors.push("ai_system_provider_did.invalid");
  }
  if (b.aer_id !== null && typeof b.aer_id !== "string") errors.push("aer_id.invalid");
}

function validatePresentedPins(b: Record<string, unknown>, errors: string[]): void {
  pinNull(b, "base_anr_id", errors);
  pinNull(b, "ack_method", errors);
  pinNull(b, "joint_controllers", errors);
  pinNull(b, "cessation_reason", errors);
  pinNull(b, "translation_provenance_alr_id", errors);
}

// ── Shape predicates ──────────────────────────────────────────────────────────

const ANR_PROFILES = new Set<string>([
  "notice.art13.collected_direct",
  "notice.art14.collected_indirect",
  "notice.art26.joint_controller_essence",
  "notice.layered_transparency",
  "notice.aiact.art50_transparency",
]);

function isAnrProfile(v: unknown): v is AnrProfile {
  return typeof v === "string" && ANR_PROFILES.has(v);
}

const DELIVERY_CHANNELS = new Set<string>(["web", "email", "in_app", "paper_qr", "api"]);

function isDeliveryChannel(v: unknown): v is AnrDeliveryChannel {
  return typeof v === "string" && DELIVERY_CHANNELS.has(v);
}

const ACK_METHODS = new Set<string>(["checkbox", "double_opt_in", "paper_signed"]);

function isAckMethod(v: unknown): v is AnrAckMethod {
  return typeof v === "string" && ACK_METHODS.has(v);
}

const SUBJECT_AGE_BANDS = new Set<string>(["adult", "13_to_15", "under_13"]);

function isSubjectAgeBand(v: unknown): v is AnrSubjectAgeBand {
  return typeof v === "string" && SUBJECT_AGE_BANDS.has(v);
}

const COLLECTION_HORIZONS = new Set<string>([
  "one_month",
  "first_communication",
  "disclosure_to_third_party",
]);

function isCollectionHorizon(v: unknown): v is AnrCollectionHorizon {
  return typeof v === "string" && COLLECTION_HORIZONS.has(v);
}

const AI_SYSTEM_KINDS = new Set<string>([
  "interaction",
  "synthetic_content",
  "emotion_recognition",
  "biometric_categorisation",
  "deepfake",
]);

function isAiSystemKind(v: unknown): v is AnrAiSystemKind {
  return typeof v === "string" && AI_SYSTEM_KINDS.has(v);
}

const LAYER_NAMES = new Set<string>(["summary", "full", "jit"]);

function isLayerUriShape(v: unknown): v is AnrLayerUri {
  if (typeof v !== "object" || v === null) return false;
  const r = v as Record<string, unknown>;
  if (typeof r.layer !== "string" || !LAYER_NAMES.has(r.layer)) return false;
  if (typeof r.uri !== "string" || r.uri.length === 0) return false;
  if (typeof r.hash !== "string" || r.hash.length === 0) return false;
  return true;
}

function isLayerUriArray(v: unknown): v is readonly AnrLayerUri[] {
  if (!Array.isArray(v)) return false;
  for (const item of v) {
    if (!isLayerUriShape(item)) return false;
  }
  return true;
}

function isJointControllerShape(v: unknown): v is AnrJointController {
  if (typeof v !== "object" || v === null) return false;
  const r = v as Record<string, unknown>;
  if (typeof r.did !== "string" || r.did.length === 0) return false;
  if (typeof r.role !== "string" || r.role.length === 0) return false;
  if (typeof r.contact_point_uri !== "string" || r.contact_point_uri.length === 0) return false;
  if (r.adr_id !== null && typeof r.adr_id !== "string") return false;
  return true;
}

function readJointControllers(
  v: unknown,
  errors: string[],
): readonly AnrJointController[] | null {
  if (!Array.isArray(v)) {
    errors.push("joint_controllers.not_array");
    return null;
  }
  for (let i = 0; i < v.length; i++) {
    if (!isJointControllerShape(v[i])) {
      errors.push(`joint_controllers[${i}].invalid`);
      return null;
    }
  }
  return v as readonly AnrJointController[];
}

function isStringArray(v: unknown): v is readonly string[] {
  if (!Array.isArray(v)) return false;
  for (const item of v) {
    if (typeof item !== "string") return false;
  }
  return true;
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.length > 0;
}

function isIsoTimestamp(v: unknown): boolean {
  if (typeof v !== "string") return false;
  const ms = Date.parse(v);
  return !Number.isNaN(ms);
}

function pinNull(b: Record<string, unknown>, field: string, errors: string[]): void {
  if (b[field] !== null) errors.push(`${field}.must_be_null`);
}

// Re-export the variant interfaces so callers narrowing on event_type get the
// per-variant shape without reaching into ./types.ts.
export type {
  AnrAcknowledgedBody,
  AnrJointControllerEssenceBody,
  AnrPresentedBody,
  AnrRePresentedBody,
  AnrTranslatedBody,
  AnrWithdrawnBody,
} from "./types.ts";
