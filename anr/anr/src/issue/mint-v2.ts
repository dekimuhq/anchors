/**
 * ANR v=2 mint path — produces v=2 Envelopes for Anchored Notice Receipts.
 *
 * Single export surface: `mintAnrV2(input)` with event_type-discriminated input.
 * ANR is v=2 only (no v=1 legacy) and has no batch claim_type — all minting
 * goes through this single function. Per-event-type convenience wrappers live
 * in `mint-single.ts`.
 *
 * Per FAMILY-CONSISTENCY §3 the envelope `subject` is per-event-split:
 *   - `notice.acknowledged` → REQUIRED `"sha256:<hex>"` from caller.
 *   - every other event_type → MAY be `"sha256:<hex>"` OR `null` (default null).
 *
 * Per D10-ANR-5 a `notice.translated` envelope's `prev` is forced to `null`
 * (translations branch from `base_anr_id`, not from the linear chain).
 *
 * `field_root` is computed over the body fields and embedded inside the body
 * (`AnrV2BodyOut`). The anr-verifier types do not yet declare it; the verifier
 * ignores extra fields per its field-by-field check approach.
 *
 * Phase 2 §H of the 10-spec batch.
 */

import {
  generateReceiptId,
  keyObjectFromSeed,
  computeFieldRoot,
  isSha256Hex,
  signEnvelope,
  type Envelope,
  type AnchorProof,
  type Kind,
  type Cause,
  type JsonLogicAst,
} from "@dekimuhq/anchors-envelope";
import {
  TsaMintError,
  attachTsaBlock,
  type TsaFetcher,
  type TsaConfig,
} from "@dekimuhq/anchors-envelope/tsa";
import {
  attachCredentialStatus,
  type StatusListConfig,
  attachSuspensionStatus,
  type SuspensionListConfig,
} from "@dekimuhq/anchors-envelope/status";
import type {
  AnrBody,
  AnrPresentedBody,
  AnrRePresentedBody,
  AnrAcknowledgedBody,
  AnrWithdrawnBody,
  AnrTranslatedBody,
  AnrJointControllerEssenceBody,
  AnrProfile,
  AnrDeliveryChannel,
  AnrAckMethod,
  AnrSubjectAgeBand,
  AnrCollectionHorizon,
  AnrAiSystemKind,
  AnrLayerUri,
  AnrJointController,
} from "../types.ts";
import { anrFamily } from "../family.ts";

// Phase 2 canary: bind the claim_type literal through the family manifest
// instead of a hand-rolled string constant. Symbolic delegation only —
// `mintAnrV2` retains its KeyObject-based API and per-event-type body
// builders. The factory's `anrFamily.mintV2` is incompatible with this
// surface (it takes a Uint8Array seed and a pre-built body); a full
// collapse is Phase 4 wrapper work, not Phase 2 scope.
const ANR_CLAIM_TYPE = anrFamily.meta.claim_types[0]!;

export type { StatusListConfig, SuspensionListConfig, TsaFetcher };
export { TsaMintError };

import type { SigningKey } from "@dekimuhq/anchors-envelope/issuer";
export type { SigningKey };

// ── v=2 body shape (issuer side adds field_root) ──────────────────────────────

/**
 * Body emitted by the ANR v=2 mint surface. Identical to the verifier's
 * `AnrBody` discriminated union with a `field_root` commitment appended.
 * Verifier ignores extra fields today; future verifier hardening will
 * adopt this shape directly.
 */
export type AnrV2BodyOut = AnrBody & { field_root: string };

// ── Input interfaces ──────────────────────────────────────────────────────────

interface MintAnrV2Common {
  /** Issuer DID or short identifier. */
  issuer: string;
  /** Ed25519 signing key (32-byte seed). */
  signingKey: SigningKey;
  /** ANR regulatory profile (spec §5). */
  profile: AnrProfile;
  /** BCP-47 language tag of the notice version this receipt is about. */
  lang_tag: string;
  /** Server-side Accept-Language derivation, or `null` when unknown. */
  lang_inferred?: string | null;
  /** Envelope-level policy URI (POLICY_BOUND on ar.notice.v1). */
  policy_uri: string;
  /** SHA-256 hash of the rendered notice. */
  policy_hash: string;
  /** Semantic version of the notice / policy. */
  policy_version: string;
  /** Anchor proof (caller supplies; log worker replaces post-mint). */
  anchor: AnchorProof;
  /** Optional: previous receipt ID for chain linkage. Forced to `null` on translations. */
  prev?: string | null;
  /**
   * Optional: subject HMAC commitment. REQUIRED for `notice.acknowledged`
   * (FAMILY-CONSISTENCY §3); for every other event_type the caller may pass
   * `"sha256:<hex>"` for per-subject anchoring or omit to default to `null`
   * (jurisdiction-level notice with no subject context).
   */
  subject?: string | null;
  /** Optional: expiry ISO 8601 UTC. */
  exp?: string | null;
  /** Optional: TSA configuration. If present, tsaFetcher must also be provided. */
  tsa?: TsaConfig;
  /** Optional: TSA fetcher (caller-provided; required if `tsa` is set). */
  tsaFetcher?: TsaFetcher;
  /**
   * Optional: W3C Bitstring Status List 2021 pointer config. Attached BEFORE
   * signing per spec §6.3. ANR is status-list consumer position #4.
   */
  statusList?: StatusListConfig;
  /**
   * Optional: Suspension List configuration. When provided, a W3C Bitstring
   * Status List 2021 Entry pointer with statusPurpose "suspension" is minted
   * and embedded BEFORE signing. Suspension is two-way (suspend/unsuspend),
   * unlike revocation which is permanent.
   */
  suspensionList?: SuspensionListConfig;
  /**
   * v1.2 §4.1: receipt classification — observation vs decision. ANR receipts
   * default to `"decision"` (the issuer is asserting that a notice was served).
   * Pass `null` to opt out (v1.1-compat).
   */
  envelope_kind?: Kind | null;
  /** v1.2 §4.2: typed trigger (closed enum). Optional. */
  cause?: Cause | null;
  /** v1.2 §4.3: optional JSON Logic predicate. Operators MUST be inside the v1.2 allowlist. */
  predicate?: JsonLogicAst | null;
  /** Optional: SHA-256 hash of an AAR receipt attesting QTS posture. */
  qts_attestation_hash?: string | null;
}

export interface MintAnrV2PresentedInput extends MintAnrV2Common {
  event_type: "notice.presented";
  /** Jurisdiction code (e.g. `"EU"`, `"DE"`). */
  jurisdiction: string;
  delivery_channel: AnrDeliveryChannel;
  render_uri: string;
  rights_surface: readonly string[];
  /** Art. 13 — optional age band. */
  subject_age_band?: AnrSubjectAgeBand | null;
  /** Art. 14 — collection source. */
  data_source?: string | null;
  collection_horizon?: AnrCollectionHorizon | null;
  data_acquired_at?: string | null;
  /** Required when `profile === "notice.layered_transparency"`. */
  layer_uris?: readonly AnrLayerUri[] | null;
  /** Required when `profile === "notice.aiact.art50_transparency"`. */
  ai_system_kind?: AnrAiSystemKind | null;
  ai_system_provider_did?: string | null;
  /** Optional AER cross-reference (spec §8.4). */
  aer_id?: string | null;
}

export interface MintAnrV2RePresentedInput extends MintAnrV2Common {
  event_type: "notice.re_presented";
  jurisdiction: string;
  delivery_channel: AnrDeliveryChannel;
  render_uri: string;
  rights_surface: readonly string[];
  /** REQUIRED — the prior `notice.presented` / `notice.re_presented` this one supersedes. */
  supersedes_anr_id: string;
  subject_age_band?: AnrSubjectAgeBand | null;
  data_source?: string | null;
  collection_horizon?: AnrCollectionHorizon | null;
  data_acquired_at?: string | null;
  layer_uris?: readonly AnrLayerUri[] | null;
  ai_system_kind?: AnrAiSystemKind | null;
  ai_system_provider_did?: string | null;
  aer_id?: string | null;
}

export interface MintAnrV2AcknowledgedInput extends MintAnrV2Common {
  event_type: "notice.acknowledged";
  /** REQUIRED for ack — FAMILY-CONSISTENCY §3 enforces `"sha256:<hex>"`. */
  subject: string;
  jurisdiction: string;
  ack_method: AnrAckMethod;
}

export interface MintAnrV2WithdrawnInput extends MintAnrV2Common {
  event_type: "notice.withdrawn";
  jurisdiction: string;
  /** XOR with `cessation_reason` — exactly one MUST be non-null. */
  supersedes_anr_id?: string | null;
  /** XOR with `supersedes_anr_id` — exactly one MUST be non-null. */
  cessation_reason?: string | null;
}

export interface MintAnrV2TranslatedInput extends MintAnrV2Common {
  event_type: "notice.translated";
  /** REQUIRED — the base-language receipt this one translates. */
  base_anr_id: string;
  /** Optional ALR `derived_from` cross-reference (spec §8.3). */
  translation_provenance_alr_id?: string | null;
}

export interface MintAnrV2JointControllerEssenceInput extends MintAnrV2Common {
  event_type: "notice.joint_controller_essence";
  jurisdiction: string;
  /** Non-empty list of joint controllers (spec §4.6 + §8.5). */
  joint_controllers: readonly AnrJointController[];
}

export type MintAnrV2Input =
  | MintAnrV2PresentedInput
  | MintAnrV2RePresentedInput
  | MintAnrV2AcknowledgedInput
  | MintAnrV2WithdrawnInput
  | MintAnrV2TranslatedInput
  | MintAnrV2JointControllerEssenceInput;

// ── Internal helpers ──────────────────────────────────────────────────────────

function baseBodyCommon(input: MintAnrV2Common): {
  profile: AnrProfile;
  lang_tag: string;
  lang_inferred: string | null;
  qts_attestation_hash: string | null;
} {
  return {
    profile: input.profile,
    lang_tag: input.lang_tag,
    lang_inferred: input.lang_inferred ?? null,
    qts_attestation_hash: input.qts_attestation_hash ?? null,
  };
}

function buildBody(input: MintAnrV2Input): AnrBody {
  switch (input.event_type) {
    case "notice.presented": {
      const body: AnrPresentedBody = {
        ...baseBodyCommon(input),
        event_type: "notice.presented",
        jurisdiction: input.jurisdiction,
        delivery_channel: input.delivery_channel,
        render_uri: input.render_uri,
        rights_surface: input.rights_surface,
        subject_age_band: input.subject_age_band ?? null,
        data_source: input.data_source ?? null,
        collection_horizon: input.collection_horizon ?? null,
        data_acquired_at: input.data_acquired_at ?? null,
        layer_uris: input.layer_uris ?? null,
        ai_system_kind: input.ai_system_kind ?? null,
        ai_system_provider_did: input.ai_system_provider_did ?? null,
        aer_id: input.aer_id ?? null,
        supersedes_anr_id: null,
        base_anr_id: null,
        ack_method: null,
        joint_controllers: null,
        cessation_reason: null,
        translation_provenance_alr_id: null,
      };
      return body;
    }
    case "notice.re_presented": {
      const body: AnrRePresentedBody = {
        ...baseBodyCommon(input),
        event_type: "notice.re_presented",
        jurisdiction: input.jurisdiction,
        delivery_channel: input.delivery_channel,
        render_uri: input.render_uri,
        rights_surface: input.rights_surface,
        supersedes_anr_id: input.supersedes_anr_id,
        subject_age_band: input.subject_age_band ?? null,
        data_source: input.data_source ?? null,
        collection_horizon: input.collection_horizon ?? null,
        data_acquired_at: input.data_acquired_at ?? null,
        layer_uris: input.layer_uris ?? null,
        ai_system_kind: input.ai_system_kind ?? null,
        ai_system_provider_did: input.ai_system_provider_did ?? null,
        aer_id: input.aer_id ?? null,
        base_anr_id: null,
        ack_method: null,
        joint_controllers: null,
        cessation_reason: null,
        translation_provenance_alr_id: null,
      };
      return body;
    }
    case "notice.acknowledged": {
      const body: AnrAcknowledgedBody = {
        ...baseBodyCommon(input),
        event_type: "notice.acknowledged",
        jurisdiction: input.jurisdiction,
        ack_method: input.ack_method,
        delivery_channel: null,
        render_uri: null,
        rights_surface: null,
        subject_age_band: null,
        data_source: null,
        collection_horizon: null,
        data_acquired_at: null,
        layer_uris: null,
        ai_system_kind: null,
        ai_system_provider_did: null,
        aer_id: null,
        supersedes_anr_id: null,
        base_anr_id: null,
        joint_controllers: null,
        cessation_reason: null,
        translation_provenance_alr_id: null,
      };
      return body;
    }
    case "notice.withdrawn": {
      const body: AnrWithdrawnBody = {
        ...baseBodyCommon(input),
        event_type: "notice.withdrawn",
        jurisdiction: input.jurisdiction,
        supersedes_anr_id: input.supersedes_anr_id ?? null,
        cessation_reason: input.cessation_reason ?? null,
        delivery_channel: null,
        render_uri: null,
        rights_surface: null,
        subject_age_band: null,
        data_source: null,
        collection_horizon: null,
        data_acquired_at: null,
        layer_uris: null,
        ai_system_kind: null,
        ai_system_provider_did: null,
        aer_id: null,
        base_anr_id: null,
        ack_method: null,
        joint_controllers: null,
        translation_provenance_alr_id: null,
      };
      return body;
    }
    case "notice.translated": {
      const body: AnrTranslatedBody = {
        ...baseBodyCommon(input),
        event_type: "notice.translated",
        base_anr_id: input.base_anr_id,
        jurisdiction: null,
        translation_provenance_alr_id: input.translation_provenance_alr_id ?? null,
        delivery_channel: null,
        render_uri: null,
        rights_surface: null,
        subject_age_band: null,
        data_source: null,
        collection_horizon: null,
        data_acquired_at: null,
        layer_uris: null,
        ai_system_kind: null,
        ai_system_provider_did: null,
        aer_id: null,
        supersedes_anr_id: null,
        ack_method: null,
        joint_controllers: null,
        cessation_reason: null,
      };
      return body;
    }
    case "notice.joint_controller_essence": {
      const body: AnrJointControllerEssenceBody = {
        ...baseBodyCommon(input),
        event_type: "notice.joint_controller_essence",
        jurisdiction: input.jurisdiction,
        joint_controllers: input.joint_controllers,
        delivery_channel: null,
        render_uri: null,
        rights_surface: null,
        subject_age_band: null,
        data_source: null,
        collection_horizon: null,
        data_acquired_at: null,
        layer_uris: null,
        ai_system_kind: null,
        ai_system_provider_did: null,
        aer_id: null,
        supersedes_anr_id: null,
        base_anr_id: null,
        ack_method: null,
        cessation_reason: null,
        translation_provenance_alr_id: null,
      };
      return body;
    }
  }
}

// ── mintAnrV2 ─────────────────────────────────────────────────────────────────

export async function mintAnrV2(input: MintAnrV2Input): Promise<Envelope> {
  if (!input.issuer) throw new Error("mintAnrV2: issuer required");
  if (!input.signingKey?.kid) {
    throw new Error("mintAnrV2: signingKey.kid required");
  }
  if (input.signingKey.privateKey.length !== 32) {
    throw new Error("mintAnrV2: signingKey.privateKey must be 32 bytes");
  }
  if (!input.anchor) throw new Error("mintAnrV2: anchor required");
  if (!input.lang_tag) throw new Error("mintAnrV2: lang_tag required (D10-ANR-2)");

  // Event-specific validation.
  switch (input.event_type) {
    case "notice.presented":
    case "notice.re_presented":
      if (!input.delivery_channel) {
        throw new Error(`mintAnrV2: ${input.event_type} requires delivery_channel`);
      }
      if (!input.render_uri) {
        throw new Error(`mintAnrV2: ${input.event_type} requires render_uri`);
      }
      if (!input.rights_surface || input.rights_surface.length === 0) {
        throw new Error(`mintAnrV2: ${input.event_type} requires non-empty rights_surface`);
      }
      if (input.profile === "notice.layered_transparency" && !input.layer_uris) {
        throw new Error(
          "mintAnrV2: notice.layered_transparency profile requires layer_uris",
        );
      }
      if (
        input.profile === "notice.aiact.art50_transparency" &&
        (!input.ai_system_kind || !input.ai_system_provider_did)
      ) {
        throw new Error(
          "mintAnrV2: notice.aiact.art50_transparency profile requires ai_system_kind + ai_system_provider_did",
        );
      }
      if (input.event_type === "notice.re_presented" && !input.supersedes_anr_id) {
        throw new Error("mintAnrV2: notice.re_presented requires supersedes_anr_id");
      }
      break;
    case "notice.acknowledged":
      if (!isSha256Hex(input.subject)) {
        throw new Error(
          "mintAnrV2: notice.acknowledged requires subject as `sha256:<64-hex>` (FAMILY-CONSISTENCY §3)",
        );
      }
      if (!input.ack_method) {
        throw new Error("mintAnrV2: notice.acknowledged requires ack_method");
      }
      break;
    case "notice.withdrawn": {
      const sup = input.supersedes_anr_id ?? null;
      const ces = input.cessation_reason ?? null;
      const hasSup = sup !== null && sup.length > 0;
      const hasCes = ces !== null && ces.length > 0;
      if (hasSup === hasCes) {
        throw new Error(
          "mintAnrV2: notice.withdrawn requires exactly one of supersedes_anr_id / cessation_reason",
        );
      }
      break;
    }
    case "notice.translated":
      if (!input.base_anr_id) {
        throw new Error("mintAnrV2: notice.translated requires base_anr_id");
      }
      break;
    case "notice.joint_controller_essence":
      if (!input.joint_controllers || input.joint_controllers.length === 0) {
        throw new Error(
          "mintAnrV2: notice.joint_controller_essence requires non-empty joint_controllers",
        );
      }
      break;
  }

  // Non-ack events: subject MUST be either sha256:<hex> or null. Reject raw strings.
  if (
    input.event_type !== "notice.acknowledged" &&
    input.subject !== undefined &&
    input.subject !== null &&
    !isSha256Hex(input.subject)
  ) {
    throw new Error(
      "mintAnrV2: subject must be `sha256:<64-hex>` or null on non-ack events (FAMILY-CONSISTENCY §3)",
    );
  }

  if (input.tsa !== undefined && input.tsaFetcher === undefined) {
    throw new Error(
      "mintAnrV2: tsaFetcher is required when tsa config is provided",
    );
  }

  const id = generateReceiptId();
  const iat = new Date().toISOString();
  const { privateKey, issKey } = keyObjectFromSeed(input.signingKey.privateKey);

  const baseBody = buildBody(input);
  const field_root = computeFieldRoot(baseBody);
  const bodyOut: AnrV2BodyOut = { ...baseBody, field_root };

  const envelopeKindOut: Kind | null =
    input.envelope_kind === undefined ? "decision" : input.envelope_kind;

  // D10-ANR-5 — `notice.translated` branches from base_anr_id, not from the
  // linear chain; envelope `prev` is forced to null regardless of caller input.
  const prevOut: string | null =
    input.event_type === "notice.translated" ? null : (input.prev ?? null);

  // FAMILY-CONSISTENCY §3 subject resolution.
  // - acknowledged: caller-supplied sha256:<hex> (validated above).
  // - other events: caller-supplied sha256:<hex> OR null (default null).
  const subjectOut: string | null =
    input.event_type === "notice.acknowledged"
      ? input.subject
      : input.subject ?? null;

  let preSign: Envelope = {
    v: 2,
    id,
    iat,
    iat_ms: Date.parse(iat),
    claim_type: ANR_CLAIM_TYPE,
    iss: input.issuer,
    iss_key: issKey,
    subject: subjectOut as unknown as string,
    exp: input.exp ?? null,
    prev: prevOut,
    policy_uri: input.policy_uri,
    policy_hash: input.policy_hash,
    policy_version: input.policy_version,
    kind: envelopeKindOut,
    cause: input.cause ?? null,
    predicate: input.predicate ?? null,
    tsa: null,
    credentialStatus: null,
    anchor: input.anchor,
    sig: "",
    countersig: null,
    body: bodyOut,
  };

  if (input.statusList !== undefined) {
    preSign = await attachCredentialStatus(preSign, input.statusList);
  }

  if (input.suspensionList !== undefined) {
    preSign = await attachSuspensionStatus(preSign, input.suspensionList);
  }

  const signed = await signEnvelope(preSign, privateKey);

  if (input.tsa !== undefined) {
    return attachTsaBlock(signed, input.tsa, input.tsaFetcher!);
  }

  return signed;
}
