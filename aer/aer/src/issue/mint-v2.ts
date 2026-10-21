/**
 * AER v=2 mint path — produces v=2 Envelopes for Anchored Evaluation Receipts.
 *
 * Single export surface: `mintAerV2(input)` with event_type-discriminated input.
 * AER is v=2 only (no v=1 legacy). Per-event-type convenience wrappers live
 * in `mint-single.ts`.
 *
 * Subject rules (FAMILY-CONSISTENCY §3 + AER spec §4):
 *   - conformity → `subject` MUST be null (AI-system-level; no individual subject)
 *   - transparency → `subject` MUST be `sha256:<hex>` (interaction/session anchor)
 *
 * `field_root` is computed over the body fields and embedded inside the body.
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
  AerBody,
  AerConformityBody,
  AerTransparencyBody,
  AerRiskClass,
  AerAssessmentRoute,
  AerAnnexIiiCategory,
  AerDisclosureScope,
  AerDisclosureType,
  AerWatermarkScheme,
  AerProfile,
} from "../types.ts";
import { aerFamily } from "../family.ts";

const AER_CLAIM_TYPE = aerFamily.meta.claim_types[0]!;

export type { StatusListConfig, SuspensionListConfig, TsaFetcher };
export { TsaMintError };

import type { SigningKey } from "@dekimuhq/anchors-envelope/issuer";
export type { SigningKey };

// Re-export enum types for consumer convenience
export type {
  AerBody,
  AerConformityBody,
  AerTransparencyBody,
  AerRiskClass,
  AerAssessmentRoute,
  AerAnnexIiiCategory,
  AerDisclosureScope,
  AerDisclosureType,
  AerWatermarkScheme,
  AerProfile,
};

// ── v=2 body shape (issuer side adds field_root) ──────────────────────────────

export type AerV2BodyOut = AerBody & { field_root: string };

// ── Common input fields ───────────────────────────────────────────────────────

interface MintAerV2Common {
  /** Issuer DID or short identifier. */
  issuer: string;
  /** Ed25519 signing key (32-byte seed). */
  signingKey: SigningKey;
  /** Anchor proof (caller supplies; log worker replaces post-mint). */
  anchor: AnchorProof;
  /** Optional: previous receipt ID for chain linkage. */
  prev?: string | null;
  /** Optional: expiry ISO 8601 UTC. */
  exp?: string | null;
  /** Optional: envelope-level policy URI. */
  policy_uri?: string | null;
  /** Optional: SHA-256 hash of the policy document. */
  policy_hash?: string | null;
  /** Optional: semantic version of the policy. */
  policy_version?: string | null;
  /** Optional: TSA configuration. If present, tsaFetcher must also be provided. */
  tsa?: TsaConfig;
  /** Optional: TSA fetcher (caller-provided; required if `tsa` is set). */
  tsaFetcher?: TsaFetcher;
  /** Optional: W3C Bitstring Status List 2021 pointer config. */
  statusList?: StatusListConfig;
  /**
   * Optional: Suspension List configuration. When provided, a W3C Bitstring
   * Status List 2021 Entry pointer with statusPurpose "suspension" is minted
   * and embedded BEFORE signing. Suspension is two-way (suspend/unsuspend),
   * unlike revocation which is permanent.
   */
  suspensionList?: SuspensionListConfig;
  /** v1.2 §4.1: receipt classification. */
  envelope_kind?: Kind | null;
  /** v1.2 §4.2: typed trigger (closed enum). Optional. */
  cause?: Cause | null;
}

// ── Conformity input ──────────────────────────────────────────────────────────

export interface MintAerConformityInput extends MintAerV2Common {
  event_type: "conformity";
  /** Regulatory profile (spec §5). Required on conformity. */
  profile: AerProfile;
  /** Commitment to the AI system identifier. */
  system_id_commit: string;
  /** Semantic version of the AI system at assessment time. */
  system_version: string;
  /** Commitment to the model identifier. */
  model_id_commit: string;
  /** AI Act risk class. */
  risk_class: AerRiskClass;
  /** Annex III categories (required when risk_class = "high"). */
  annex_iii_categories: AerAnnexIiiCategory[] | null;
  /** Conformity assessment route. */
  assessment_route: AerAssessmentRoute;
  /** Notified body identifier (required when route = thirdparty_notified_body). */
  notified_body_id: string | null;
  /** List of harmonized standards applied. */
  harmonized_standards: string[];
  /** SHA-256 hash of the technical documentation. */
  tech_doc_hash: string;
  /** Optional: ARR receipt hash for tech doc versioning. */
  tech_doc_arr_receipt_hash?: string | null;
  /** SHA-256 hash of the risk management system record. */
  risk_management_system_hash: string;
  /** SHA-256 hash of the data governance record. */
  data_governance_hash: string;
  /** SHA-256 hash of the fundamental rights impact assessment (required when route = fundamental_rights). */
  fundamental_rights_hash?: string | null;
  /** Optional: hash of training arrangement (ATR). */
  training_atr_arrangement_hash?: string | null;
  /** Optional: hash of training data binding (APuR). */
  training_apur_binding_hash?: string | null;
  /** ISO 8601 UTC: start of conformity validity. */
  valid_from: string;
  /** ISO 8601 UTC: end of conformity validity (null = open-ended). */
  valid_until?: string | null;
  /** Optional: SHA-256 hash of an AAR receipt attesting QTS posture. */
  qts_attestation_hash?: string | null;
}

// ── Transparency input ────────────────────────────────────────────────────────

export interface MintAerTransparencyInput extends MintAerV2Common {
  event_type: "transparency";
  /** Regulatory profile (spec §5). Required on transparency. */
  profile: AerProfile;
  /**
   * Subject HMAC commitment — REQUIRED on transparency (`sha256:<hex>`).
   * Anchors the individual interaction/session.
   */
  subject: string;
  /** Commitment to the AI system identifier. */
  system_id_commit: string;
  /** Optional: DID / kid of the APR for the system. */
  system_apr_kid?: string | null;
  /** SHA-256 hash of the backing conformity receipt. */
  conformity_receipt_hash: string;
  /** Commitment to the subject identity (may differ from envelope subject). */
  subject_commit: string;
  /** Disclosure scope: single interaction, session, or batch. */
  disclosure_scope: AerDisclosureScope;
  /** Type of disclosure (chatbot, synthetic media, etc.). */
  disclosure_type: AerDisclosureType;
  /** SHA-256 hash of the disclosure text shown to the user. */
  disclosure_text_hash: string;
  /** BCP 47 locale of the disclosure text. */
  disclosure_locale: string;
  /** ISO 8601 UTC: start of the interaction/session window. */
  interaction_window_start: string;
  /** ISO 8601 UTC: end of the interaction/session window. */
  interaction_window_end: string;
  /** Optional: APR hash for the artifact produced. */
  artifact_apr_hash?: string | null;
  /** Optional: ACR hash for human oversight approval. */
  oversight_acr_hash?: string | null;
  /** Watermarking scheme applied. */
  watermark_scheme: AerWatermarkScheme;
  /** Optional: commitment to a watermark sample (required when scheme != none). */
  watermark_sample_commit?: string | null;
  /** Optional: SHA-256 hash of an AAR receipt attesting QTS posture. */
  qts_attestation_hash?: string | null;
}

export type MintAerV2Input = MintAerConformityInput | MintAerTransparencyInput;

// ── Body builder ──────────────────────────────────────────────────────────────

function buildBody(input: MintAerV2Input): AerBody {
  switch (input.event_type) {
    case "conformity": {
      const body: AerConformityBody = {
        event_type: "conformity",
        profile: input.profile,
        system_id_commit: input.system_id_commit,
        system_version: input.system_version,
        model_id_commit: input.model_id_commit,
        risk_class: input.risk_class,
        annex_iii_categories: input.annex_iii_categories,
        assessment_route: input.assessment_route,
        notified_body_id: input.notified_body_id,
        harmonized_standards: input.harmonized_standards,
        tech_doc_hash: input.tech_doc_hash,
        tech_doc_arr_receipt_hash: input.tech_doc_arr_receipt_hash ?? null,
        risk_management_system_hash: input.risk_management_system_hash,
        data_governance_hash: input.data_governance_hash,
        fundamental_rights_hash: input.fundamental_rights_hash ?? null,
        training_atr_arrangement_hash: input.training_atr_arrangement_hash ?? null,
        training_apur_binding_hash: input.training_apur_binding_hash ?? null,
        valid_from: input.valid_from,
        valid_until: input.valid_until ?? null,
        qts_attestation_hash: input.qts_attestation_hash ?? null,
      };
      return body;
    }
    case "transparency": {
      const body: AerTransparencyBody = {
        event_type: "transparency",
        profile: input.profile,
        system_id_commit: input.system_id_commit,
        system_apr_kid: input.system_apr_kid ?? null,
        conformity_receipt_hash: input.conformity_receipt_hash,
        subject_commit: input.subject_commit,
        disclosure_scope: input.disclosure_scope,
        disclosure_type: input.disclosure_type,
        disclosure_text_hash: input.disclosure_text_hash,
        disclosure_locale: input.disclosure_locale,
        interaction_window_start: input.interaction_window_start,
        interaction_window_end: input.interaction_window_end,
        artifact_apr_hash: input.artifact_apr_hash ?? null,
        oversight_acr_hash: input.oversight_acr_hash ?? null,
        watermark_scheme: input.watermark_scheme,
        watermark_sample_commit: input.watermark_sample_commit ?? null,
        qts_attestation_hash: input.qts_attestation_hash ?? null,
      };
      return body;
    }
  }
}

// ── mintAerV2 ─────────────────────────────────────────────────────────────────

export async function mintAerV2(input: MintAerV2Input): Promise<Envelope> {
  if (!input.issuer) throw new Error("mintAerV2: issuer required");
  if (!input.signingKey?.kid) {
    throw new Error("mintAerV2: signingKey.kid required");
  }
  if (input.signingKey.privateKey.length !== 32) {
    throw new Error("mintAerV2: signingKey.privateKey must be 32 bytes");
  }
  if (!input.anchor) throw new Error("mintAerV2: anchor required");

  // Subject rules: conformity → null, transparency → sha256:<hex>
  if (input.event_type === "conformity") {
    // subject is always null for conformity — AI-system-level, no individual
  } else {
    // transparency: subject MUST be sha256:<hex>
    if (!isSha256Hex(input.subject)) {
      throw new Error(
        "mintAerV2: transparency subject must be `sha256:<64-hex>` (AER spec §4.2)",
      );
    }
  }

  if (input.tsa !== undefined && input.tsaFetcher === undefined) {
    throw new Error("mintAerV2: tsaFetcher is required when tsa config is provided");
  }

  const id = generateReceiptId();
  const iat = new Date().toISOString();
  const { privateKey, issKey } = keyObjectFromSeed(input.signingKey.privateKey);

  const baseBody = buildBody(input);
  const field_root = computeFieldRoot(baseBody);
  const bodyOut: AerV2BodyOut = { ...baseBody, field_root };

  const envelopeKindOut: Kind | null =
    input.envelope_kind === undefined ? "observation" : input.envelope_kind;

  const subjectOut: string | null =
    input.event_type === "transparency" ? input.subject : null;

  let preSign: Envelope = {
    v: 2,
    id,
    iat,
    iat_ms: Date.parse(iat),
    claim_type: AER_CLAIM_TYPE,
    iss: input.issuer,
    iss_key: issKey,
    subject: subjectOut as unknown as string,
    exp: input.exp ?? null,
    prev: input.prev ?? null,
    policy_uri: input.policy_uri ?? null,
    policy_hash: input.policy_hash ?? null,
    policy_version: input.policy_version ?? null,
    kind: envelopeKindOut,
    cause: input.cause ?? null,
    predicate: null,
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
