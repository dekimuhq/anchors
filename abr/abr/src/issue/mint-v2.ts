/**
 * ABR v=2 mint path — produces v=2 Envelopes for Anchored Breach Receipts.
 *
 * Single export surface: `mintAbrV2(input)` with `event_type`-discriminated
 * input. ABR is v=2 only (no v=1 legacy). Per-event-type convenience wrappers
 * live in `mint-single.ts`.
 *
 * Per FAMILY-CONSISTENCY §3 + ABR §E:
 *   - `breach.subject_notified` → envelope `subject` MUST be `"sha256:<hex>"`,
 *     bound to `body.subject_batch_root` (D10-ABR-4). The mint helper sets
 *     `envelope.subject = body.subject_batch_root` automatically and rejects a
 *     caller-supplied subject that disagrees.
 *   - every other event_type     → envelope `subject` MUST be `null`. The mint
 *     helper hard-pins `null` and rejects any caller-supplied subject.
 *
 * Per ABR §D + FAMILY-CONSISTENCY §2:
 *   - `breach.detected`          → TSA MANDATORY (verifier-enforced). The kit
 *     does not block minting without TSA — staging environments need that
 *     escape hatch — but the verifier surfaces `tsa_missing` downstream when
 *     the receipt is presented for verification.
 *   - every other event_type     → TSA RECOMMENDED.
 *
 * `field_root` is computed over the body fields and embedded inside the body
 * (`AbrV2BodyOut`). The abr-verifier types do not yet declare it; the verifier
 * ignores extra fields per its field-by-field check approach.
 *
 * Phase 3 §H of the 10-spec batch.
 */

import {
  computeFieldRoot,
  isSha256Hex,
  type Envelope,
  type AnchorProof,
  type Kind,
  type Cause,
  type JsonLogicAst,
} from "@dekimuhq/anchors-envelope";
import { TsaMintError, type TsaFetcher, type TsaConfig } from "@dekimuhq/anchors-envelope/tsa";
import type { StatusListConfig } from "@dekimuhq/anchors-envelope/status";
import type { SuspensionListConfig } from "@dekimuhq/anchors-envelope/status";
import type {
  AbrBody,
  AbrDetectedBody,
  AbrAssessedBody,
  AbrDpaNotifiedBody,
  AbrDpaDelayedBody,
  AbrSubjectNotifiedBody,
  AbrSubjectNotificationExemptedBody,
  AbrContainedBody,
  AbrClosedBody,
  AbrProfile,
  AbrSeverityClass,
  AbrExemptionGround,
  AbrNotificationPhase,
} from "../index.ts";
import { abrFamily } from "../index.ts";

const ABR_CLAIM_TYPE = "ar.breach.v1" as const;

export type { StatusListConfig, SuspensionListConfig, TsaFetcher };
export { TsaMintError };

import type { SigningKey } from "@dekimuhq/anchors-envelope/issuer";
export type { SigningKey };

// ── v=2 body shape (issuer side adds field_root) ──────────────────────────────

/**
 * Body emitted by the ABR v=2 mint surface. Identical to the verifier's
 * `AbrBody` discriminated union with a `field_root` commitment appended.
 * Verifier ignores extra fields today; future verifier hardening will adopt
 * this shape directly.
 */
export type AbrV2BodyOut = AbrBody & { field_root: string };

// ── Input interfaces ──────────────────────────────────────────────────────────

interface MintAbrV2Common {
  /** Issuer DID or short identifier. */
  issuer: string;
  /** Ed25519 signing key (32-byte seed). */
  signingKey: SigningKey;
  /** ABR regulatory profile (spec §5). */
  profile: AbrProfile;
  /**
   * Incident correlation id — MUST be identical across every receipt in an
   * incident-chain (D10-ABR-3). §C chain walker enforces parity.
   */
  incident_correlation_id: string;
  /** Envelope-level policy URI (POLICY_BOUND on ar.breach.v1). */
  policy_uri: string;
  /** SHA-256 hash of the rendered breach policy / playbook document. */
  policy_hash: string;
  /** Semantic version of the breach playbook / policy. */
  policy_version: string;
  /** Anchor proof (caller supplies; log worker replaces post-mint). */
  anchor: AnchorProof;
  /** Optional: previous receipt ID for chain linkage. */
  prev?: string | null;
  /** Optional: expiry ISO 8601 UTC. */
  exp?: string | null;
  /** Optional: TSA configuration. If present, tsaFetcher must also be provided. */
  tsa?: TsaConfig;
  /** Optional: TSA fetcher (caller-provided; required if `tsa` is set). */
  tsaFetcher?: TsaFetcher;
  /**
   * Optional: W3C Bitstring Status List 2021 pointer config. Attached BEFORE
   * signing per spec §6.3. ABR is status-list consumer position #5.
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
   * v1.2 §4.1: receipt classification — observation vs decision. ABR receipts
   * default to `"decision"` (the issuer is asserting that a breach lifecycle
   * event occurred). Pass `null` to opt out (v1.1-compat).
   */
  envelope_kind?: Kind | null;
  /** v1.2 §4.2: typed trigger (closed enum). Optional. */
  cause?: Cause | null;
  /** v1.2 §4.3: optional JSON Logic predicate. Operators MUST be inside the v1.2 allowlist. */
  predicate?: JsonLogicAst | null;
  /** Optional: SHA-256 hash of an AAR receipt attesting QTS posture. */
  qts_attestation_hash?: string | null;
}

export interface MintAbrV2DetectedInput extends MintAbrV2Common {
  event_type: "breach.detected";
  detected_at: string;
  severity_class: AbrSeverityClass;
  affected_data_categories: readonly string[];
  affected_data_hash: string;
  /** Integer; `-1` when undetermined at time of receipt. */
  affected_count: number;
  jurisdiction: string;
  /** Composition: affected AER (`ar.evaluation.v1`) receipt ids (§8.4). */
  affected_aer_ids?: readonly string[] | null;
}

export interface MintAbrV2AssessedInput extends MintAbrV2Common {
  event_type: "breach.assessed";
  severity_class: AbrSeverityClass;
  assessment_method_hash: string;
}

export interface MintAbrV2DpaNotifiedInput extends MintAbrV2Common {
  event_type: "breach.dpa_notified";
  notification_uri: string;
  notification_hash: string;
  /** `null` when the DPA has not yet assigned a case id at submission time. */
  dpa_reference_id?: string | null;
  /** Non-null only on the NIS2 profile (early-warning / full / final). */
  notification_phase?: AbrNotificationPhase | null;
  /** Composition: AAR receipt id (`ar.attestation.v1`) for QES-signed filings (§8.2). */
  qes_aar_id?: string | null;
}

export interface MintAbrV2DpaDelayedInput extends MintAbrV2Common {
  event_type: "breach.dpa_delayed";
  delay_reason_hash: string;
  delay_until_at: string;
}

export interface MintAbrV2SubjectNotifiedInput extends MintAbrV2Common {
  event_type: "breach.subject_notified";
  /**
   * Merkle root over `sub_commit` leaves. MUST be `"sha256:<64-hex>"`. The
   * envelope `subject` is bound to this value automatically (D10-ABR-4).
   */
  subject_batch_root: string;
  /** Integer; leaf count of `subject_batch_root` (max 65 536). */
  subject_batch_size: number;
  notification_uri: string;
  notification_hash: string;
}

export interface MintAbrV2SubjectNotificationExemptedInput extends MintAbrV2Common {
  event_type: "breach.subject_notification_exempted";
  exemption_ground: AbrExemptionGround;
  justification_hash: string;
  /** Required when `exemption_ground === "art34_3_c_disproportionate"`; else `null`. */
  public_communication_uri?: string | null;
}

export interface MintAbrV2ContainedInput extends MintAbrV2Common {
  event_type: "breach.contained";
  containment_at: string;
  containment_summary_hash: string;
  /** Composition: optional AAR receipt id for independent attestation (§8.1). */
  containment_attestation?: string | null;
  /** Composition: ARR (`ar.erasure.v1`/`ar.anonymization.v1`) receipt ids (§8.3). */
  containment_remediation_arr_ids?: readonly string[] | null;
  /** Composition: ATR (`ar.transfer.v1`) receipt ids for transfer suspensions (§8.3). */
  transfer_suspension_atr_ids?: readonly string[] | null;
}

export interface MintAbrV2ClosedInput extends MintAbrV2Common {
  event_type: "breach.closed";
  closed_at: string;
  /** `null` when no DPA was notified (low-risk path per §4.2). */
  closure_dpa_reference_id?: string | null;
  /** Composition: ANR (`ar.notice.v1`) receipt id for post-breach notice update (§8.5). */
  post_breach_anr_id?: string | null;
}

export type MintAbrV2Input =
  | MintAbrV2DetectedInput
  | MintAbrV2AssessedInput
  | MintAbrV2DpaNotifiedInput
  | MintAbrV2DpaDelayedInput
  | MintAbrV2SubjectNotifiedInput
  | MintAbrV2SubjectNotificationExemptedInput
  | MintAbrV2ContainedInput
  | MintAbrV2ClosedInput;

// ── Internal helpers ──────────────────────────────────────────────────────────

function baseBodyCommon(input: MintAbrV2Common): {
  profile: AbrProfile;
  incident_correlation_id: string;
  qts_attestation_hash: string | null;
} {
  return {
    profile: input.profile,
    incident_correlation_id: input.incident_correlation_id,
    qts_attestation_hash: input.qts_attestation_hash ?? null,
  };
}

function buildBody(input: MintAbrV2Input): AbrBody {
  switch (input.event_type) {
    case "breach.detected": {
      const body: AbrDetectedBody = {
        ...baseBodyCommon(input),
        event_type: "breach.detected",
        detected_at: input.detected_at,
        severity_class: input.severity_class,
        affected_data_categories: input.affected_data_categories,
        affected_data_hash: input.affected_data_hash,
        affected_count: input.affected_count,
        jurisdiction: input.jurisdiction,
        affected_aer_ids: input.affected_aer_ids ?? null,
        assessment_method_hash: null,
        notification_uri: null,
        notification_hash: null,
        dpa_reference_id: null,
        notification_phase: null,
        delay_reason_hash: null,
        delay_until_at: null,
        subject_batch_root: null,
        subject_batch_size: null,
        exemption_ground: null,
        justification_hash: null,
        public_communication_uri: null,
        containment_at: null,
        containment_summary_hash: null,
        containment_attestation: null,
        closed_at: null,
        closure_dpa_reference_id: null,
        containment_remediation_arr_ids: null,
        transfer_suspension_atr_ids: null,
        post_breach_anr_id: null,
        qes_aar_id: null,
      };
      return body;
    }
    case "breach.assessed": {
      const body: AbrAssessedBody = {
        ...baseBodyCommon(input),
        event_type: "breach.assessed",
        severity_class: input.severity_class,
        assessment_method_hash: input.assessment_method_hash,
        detected_at: null,
        affected_data_categories: null,
        affected_data_hash: null,
        affected_count: null,
        jurisdiction: null,
        notification_uri: null,
        notification_hash: null,
        dpa_reference_id: null,
        notification_phase: null,
        delay_reason_hash: null,
        delay_until_at: null,
        subject_batch_root: null,
        subject_batch_size: null,
        exemption_ground: null,
        justification_hash: null,
        public_communication_uri: null,
        containment_at: null,
        containment_summary_hash: null,
        containment_attestation: null,
        closed_at: null,
        closure_dpa_reference_id: null,
        affected_aer_ids: null,
        containment_remediation_arr_ids: null,
        transfer_suspension_atr_ids: null,
        post_breach_anr_id: null,
        qes_aar_id: null,
      };
      return body;
    }
    case "breach.dpa_notified": {
      const body: AbrDpaNotifiedBody = {
        ...baseBodyCommon(input),
        event_type: "breach.dpa_notified",
        notification_uri: input.notification_uri,
        notification_hash: input.notification_hash,
        dpa_reference_id: input.dpa_reference_id ?? null,
        notification_phase: input.notification_phase ?? null,
        qes_aar_id: input.qes_aar_id ?? null,
        detected_at: null,
        severity_class: null,
        affected_data_categories: null,
        affected_data_hash: null,
        affected_count: null,
        jurisdiction: null,
        assessment_method_hash: null,
        delay_reason_hash: null,
        delay_until_at: null,
        subject_batch_root: null,
        subject_batch_size: null,
        exemption_ground: null,
        justification_hash: null,
        public_communication_uri: null,
        containment_at: null,
        containment_summary_hash: null,
        containment_attestation: null,
        closed_at: null,
        closure_dpa_reference_id: null,
        affected_aer_ids: null,
        containment_remediation_arr_ids: null,
        transfer_suspension_atr_ids: null,
        post_breach_anr_id: null,
      };
      return body;
    }
    case "breach.dpa_delayed": {
      const body: AbrDpaDelayedBody = {
        ...baseBodyCommon(input),
        event_type: "breach.dpa_delayed",
        delay_reason_hash: input.delay_reason_hash,
        delay_until_at: input.delay_until_at,
        detected_at: null,
        severity_class: null,
        affected_data_categories: null,
        affected_data_hash: null,
        affected_count: null,
        jurisdiction: null,
        assessment_method_hash: null,
        notification_uri: null,
        notification_hash: null,
        dpa_reference_id: null,
        notification_phase: null,
        subject_batch_root: null,
        subject_batch_size: null,
        exemption_ground: null,
        justification_hash: null,
        public_communication_uri: null,
        containment_at: null,
        containment_summary_hash: null,
        containment_attestation: null,
        closed_at: null,
        closure_dpa_reference_id: null,
        affected_aer_ids: null,
        containment_remediation_arr_ids: null,
        transfer_suspension_atr_ids: null,
        post_breach_anr_id: null,
        qes_aar_id: null,
      };
      return body;
    }
    case "breach.subject_notified": {
      const body: AbrSubjectNotifiedBody = {
        ...baseBodyCommon(input),
        event_type: "breach.subject_notified",
        subject_batch_root: input.subject_batch_root,
        subject_batch_size: input.subject_batch_size,
        notification_uri: input.notification_uri,
        notification_hash: input.notification_hash,
        detected_at: null,
        severity_class: null,
        affected_data_categories: null,
        affected_data_hash: null,
        affected_count: null,
        jurisdiction: null,
        assessment_method_hash: null,
        dpa_reference_id: null,
        notification_phase: null,
        delay_reason_hash: null,
        delay_until_at: null,
        exemption_ground: null,
        justification_hash: null,
        public_communication_uri: null,
        containment_at: null,
        containment_summary_hash: null,
        containment_attestation: null,
        closed_at: null,
        closure_dpa_reference_id: null,
        affected_aer_ids: null,
        containment_remediation_arr_ids: null,
        transfer_suspension_atr_ids: null,
        post_breach_anr_id: null,
        qes_aar_id: null,
      };
      return body;
    }
    case "breach.subject_notification_exempted": {
      const body: AbrSubjectNotificationExemptedBody = {
        ...baseBodyCommon(input),
        event_type: "breach.subject_notification_exempted",
        exemption_ground: input.exemption_ground,
        justification_hash: input.justification_hash,
        public_communication_uri: input.public_communication_uri ?? null,
        detected_at: null,
        severity_class: null,
        affected_data_categories: null,
        affected_data_hash: null,
        affected_count: null,
        jurisdiction: null,
        assessment_method_hash: null,
        notification_uri: null,
        notification_hash: null,
        dpa_reference_id: null,
        notification_phase: null,
        delay_reason_hash: null,
        delay_until_at: null,
        subject_batch_root: null,
        subject_batch_size: null,
        containment_at: null,
        containment_summary_hash: null,
        containment_attestation: null,
        closed_at: null,
        closure_dpa_reference_id: null,
        affected_aer_ids: null,
        containment_remediation_arr_ids: null,
        transfer_suspension_atr_ids: null,
        post_breach_anr_id: null,
        qes_aar_id: null,
      };
      return body;
    }
    case "breach.contained": {
      const body: AbrContainedBody = {
        ...baseBodyCommon(input),
        event_type: "breach.contained",
        containment_at: input.containment_at,
        containment_summary_hash: input.containment_summary_hash,
        containment_attestation: input.containment_attestation ?? null,
        containment_remediation_arr_ids: input.containment_remediation_arr_ids ?? null,
        transfer_suspension_atr_ids: input.transfer_suspension_atr_ids ?? null,
        detected_at: null,
        severity_class: null,
        affected_data_categories: null,
        affected_data_hash: null,
        affected_count: null,
        jurisdiction: null,
        assessment_method_hash: null,
        notification_uri: null,
        notification_hash: null,
        dpa_reference_id: null,
        notification_phase: null,
        delay_reason_hash: null,
        delay_until_at: null,
        subject_batch_root: null,
        subject_batch_size: null,
        exemption_ground: null,
        justification_hash: null,
        public_communication_uri: null,
        closed_at: null,
        closure_dpa_reference_id: null,
        affected_aer_ids: null,
        post_breach_anr_id: null,
        qes_aar_id: null,
      };
      return body;
    }
    case "breach.closed": {
      const body: AbrClosedBody = {
        ...baseBodyCommon(input),
        event_type: "breach.closed",
        closed_at: input.closed_at,
        closure_dpa_reference_id: input.closure_dpa_reference_id ?? null,
        post_breach_anr_id: input.post_breach_anr_id ?? null,
        detected_at: null,
        severity_class: null,
        affected_data_categories: null,
        affected_data_hash: null,
        affected_count: null,
        jurisdiction: null,
        assessment_method_hash: null,
        notification_uri: null,
        notification_hash: null,
        dpa_reference_id: null,
        notification_phase: null,
        delay_reason_hash: null,
        delay_until_at: null,
        subject_batch_root: null,
        subject_batch_size: null,
        exemption_ground: null,
        justification_hash: null,
        public_communication_uri: null,
        containment_at: null,
        containment_summary_hash: null,
        containment_attestation: null,
        affected_aer_ids: null,
        containment_remediation_arr_ids: null,
        transfer_suspension_atr_ids: null,
        qes_aar_id: null,
      };
      return body;
    }
  }
}

// ── mintAbrV2 ─────────────────────────────────────────────────────────────────

export async function mintAbrV2(input: MintAbrV2Input): Promise<Envelope> {
  if (!input.issuer) throw new Error("mintAbrV2: issuer required");
  if (!input.signingKey?.kid) {
    throw new Error("mintAbrV2: signingKey.kid required");
  }
  if (!input.anchor) throw new Error("mintAbrV2: anchor required");
  if (!input.incident_correlation_id) {
    throw new Error("mintAbrV2: incident_correlation_id required (D10-ABR-3)");
  }

  // Event-specific validation.
  switch (input.event_type) {
    case "breach.detected":
      if (!input.detected_at) {
        throw new Error("mintAbrV2: breach.detected requires detected_at");
      }
      if (!input.affected_data_categories || input.affected_data_categories.length === 0) {
        throw new Error(
          "mintAbrV2: breach.detected requires non-empty affected_data_categories",
        );
      }
      if (!isSha256Hex(input.affected_data_hash)) {
        throw new Error(
          "mintAbrV2: breach.detected requires affected_data_hash as `sha256:<64-hex>`",
        );
      }
      if (!Number.isInteger(input.affected_count)) {
        throw new Error(
          "mintAbrV2: breach.detected requires integer affected_count (use -1 if undetermined)",
        );
      }
      if (!input.jurisdiction) {
        throw new Error("mintAbrV2: breach.detected requires jurisdiction");
      }
      break;
    case "breach.assessed":
      if (!isSha256Hex(input.assessment_method_hash)) {
        throw new Error(
          "mintAbrV2: breach.assessed requires assessment_method_hash as `sha256:<64-hex>`",
        );
      }
      break;
    case "breach.dpa_notified":
      if (!input.notification_uri) {
        throw new Error("mintAbrV2: breach.dpa_notified requires notification_uri");
      }
      if (!isSha256Hex(input.notification_hash)) {
        throw new Error(
          "mintAbrV2: breach.dpa_notified requires notification_hash as `sha256:<64-hex>`",
        );
      }
      if (input.profile === "breach.nis2.art23" && !input.notification_phase) {
        throw new Error(
          "mintAbrV2: breach.dpa_notified under breach.nis2.art23 requires notification_phase",
        );
      }
      if (input.profile !== "breach.nis2.art23" && input.notification_phase) {
        throw new Error(
          "mintAbrV2: notification_phase only permitted on breach.nis2.art23 profile",
        );
      }
      break;
    case "breach.dpa_delayed":
      if (!isSha256Hex(input.delay_reason_hash)) {
        throw new Error(
          "mintAbrV2: breach.dpa_delayed requires delay_reason_hash as `sha256:<64-hex>`",
        );
      }
      if (!input.delay_until_at) {
        throw new Error("mintAbrV2: breach.dpa_delayed requires delay_until_at");
      }
      break;
    case "breach.subject_notified":
      if (!isSha256Hex(input.subject_batch_root)) {
        throw new Error(
          "mintAbrV2: breach.subject_notified requires subject_batch_root as `sha256:<64-hex>`",
        );
      }
      if (!Number.isInteger(input.subject_batch_size) || input.subject_batch_size <= 0) {
        throw new Error(
          "mintAbrV2: breach.subject_notified requires positive integer subject_batch_size",
        );
      }
      if (input.subject_batch_size > 65536) {
        throw new Error(
          "mintAbrV2: breach.subject_notified subject_batch_size > 65536 (D10-ABR-4) — split into multiple receipts",
        );
      }
      if (!input.notification_uri) {
        throw new Error("mintAbrV2: breach.subject_notified requires notification_uri");
      }
      if (!isSha256Hex(input.notification_hash)) {
        throw new Error(
          "mintAbrV2: breach.subject_notified requires notification_hash as `sha256:<64-hex>`",
        );
      }
      break;
    case "breach.subject_notification_exempted":
      if (!isSha256Hex(input.justification_hash)) {
        throw new Error(
          "mintAbrV2: breach.subject_notification_exempted requires justification_hash as `sha256:<64-hex>`",
        );
      }
      if (
        input.exemption_ground === "art34_3_c_disproportionate" &&
        !input.public_communication_uri
      ) {
        throw new Error(
          "mintAbrV2: art34_3_c_disproportionate exemption requires public_communication_uri",
        );
      }
      if (
        input.exemption_ground !== "art34_3_c_disproportionate" &&
        input.public_communication_uri
      ) {
        throw new Error(
          "mintAbrV2: public_communication_uri only permitted on art34_3_c_disproportionate",
        );
      }
      break;
    case "breach.contained":
      if (!input.containment_at) {
        throw new Error("mintAbrV2: breach.contained requires containment_at");
      }
      if (!isSha256Hex(input.containment_summary_hash)) {
        throw new Error(
          "mintAbrV2: breach.contained requires containment_summary_hash as `sha256:<64-hex>`",
        );
      }
      break;
    case "breach.closed":
      if (!input.closed_at) {
        throw new Error("mintAbrV2: breach.closed requires closed_at");
      }
      break;
  }

  const baseBody = buildBody(input);
  const field_root = computeFieldRoot(baseBody);
  const bodyOut: AbrV2BodyOut = { ...baseBody, field_root };

  const envelopeKindOut: Kind | null =
    input.envelope_kind === undefined ? "decision" : input.envelope_kind;

  // FAMILY-CONSISTENCY §3 + ABR §E subject resolution.
  // - breach.subject_notified: subject = body.subject_batch_root (D10-ABR-4 binding).
  // - every other event_type:  subject = null (hard-pinned).
  const subjectOut: string | null =
    input.event_type === "breach.subject_notified" ? input.subject_batch_root : null;

  return abrFamily.mintV2({
    body: bodyOut,
    issuerPrivateKey: input.signingKey.privateKey,
    kid: input.signingKey.kid,
    issuerDid: input.issuer,
    subject: subjectOut,
    anchor: input.anchor,
    exp: input.exp ?? null,
    prev: input.prev ?? null,
    policy_uri: input.policy_uri,
    policy_hash: input.policy_hash,
    policy_version: input.policy_version,
    kind: envelopeKindOut,
    cause: input.cause ?? null,
    predicate: input.predicate ?? null,
    ...(input.statusList !== undefined ? { statusList: input.statusList } : {}),
    ...(input.suspensionList !== undefined ? { suspensionList: input.suspensionList } : {}),
    ...(input.tsa !== undefined ? { tsa: input.tsa, tsaFetcher: input.tsaFetcher } : {}),
  });
}
