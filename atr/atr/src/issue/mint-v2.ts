/**
 * ATR v=2 mint path — produces v=2 Envelopes for Anchored Transfer Receipts.
 *
 * Single export surface: `mintAtrV2(input)` with event_type-discriminated input.
 * ATR is v=2 only (no v=1 legacy). Per-event-type convenience wrappers live
 * in `mint-single.ts`.
 *
 * Per FAMILY-CONSISTENCY §3 and ATR spec:
 *   - `transfer` event: `subject` MUST be `"sha256:<hex>"` (must-be-present)
 *   - `arrangement`, `tia`, `suspension` events: `subject` is auto-set to null
 *
 * Chain constraints:
 *   - `arrangement`: prev MUST be null (chain head)
 *   - `suspension`: prev MUST be present (references arrangement)
 *
 * `field_root` is computed over the body fields and embedded inside the body.
 *
 * Chip 5 — ATR family member.
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
  AtrBody,
  AtrArrangementBody,
  AtrTransferBody,
  AtrTiaBody,
  AtrSuspensionBody,
  AtrProfile,
  AtrAssessmentOutcome,
  AtrSuspensionTrigger,
  AtrSubjectCountBucket,
} from "../types.ts";
import { atrFamily } from "../family.ts";
import type { SigningKey } from "@dekimuhq/anchors-envelope/issuer";

const ATR_CLAIM_TYPE = atrFamily.meta.claim_types[0]!;

export type { StatusListConfig, SuspensionListConfig, TsaFetcher };
export { TsaMintError };
export type { SigningKey };

// Re-export types used in input interfaces so consumers don't need extra imports
export type {
  AtrProfile,
  AtrAssessmentOutcome,
  AtrSuspensionTrigger,
  AtrSubjectCountBucket,
};

// ── v=2 body shape (issuer side adds field_root) ──────────────────────────────

export type AtrV2BodyOut = AtrBody & { field_root: string };

// ── Input interfaces ──────────────────────────────────────────────────────────

interface MintAtrV2Common {
  /** Issuer DID or short identifier. */
  issuer: string;
  /** Ed25519 signing key (32-byte seed). */
  signingKey: SigningKey;
  /** ATR regulatory profile (spec §5). */
  profile: AtrProfile;
  /** Envelope-level policy URI. */
  policy_uri: string;
  /** SHA-256 hash of the policy document. */
  policy_hash: string;
  /** Semantic version of the policy. */
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
  /**
   * v1.2 §10: optional issuer countersignature public key (EUDI Wallet
   * forward-compat). Conditionally committed before signing — omitted when
   * absent so pre-countersig receipts stay byte-equal.
   */
  countersig_key?: `ed25519:${string}` | null;
}

export interface MintArrangementInput extends MintAtrV2Common {
  event_type: "arrangement";
  /** Blinded identifier for this transfer arrangement. */
  arrangement_id_commit: string;
  /** Blinded identifier for the data recipient. */
  recipient_commit: string;
  /** ISO 3166 alpha-2 destination country. */
  destination_country: string;
  /** Transfer mechanism version (spec §4.5). */
  mechanism_version: string;
  /** SHA-256 hash of the signed contract document. */
  contract_doc_hash: string;
  /** ISO 8601 UTC — date the arrangement enters into force. */
  in_force_from: string;
  /** ISO 8601 UTC — optional expiry of the arrangement. */
  in_force_until?: string | null;
  /** SHA-256 hash of any supplementary measures document. */
  supplementary_measures_hash: string;
  /** Optional: hash of a QTS attestation. */
  qts_attestation_hash?: string | null;
}

export interface MintTransferInput extends MintAtrV2Common {
  event_type: "transfer";
  /** Subject HMAC commitment — REQUIRED for transfer (`sha256:<hex>`). */
  subject: string;
  /** Hash of the parent arrangement receipt. */
  arrangement_hash: string;
  /** Hash of the TIA receipt, if applicable. */
  tia_hash?: string | null;
  /** ISO 3166 alpha-2 destination country. */
  destination_country: string;
  /** Blinded identifier for the data recipient. */
  recipient_commit: string;
  /** Personal data categories transferred. */
  data_categories: readonly string[];
  /** Bucketed count of data subjects. */
  subject_count_bucket: AtrSubjectCountBucket;
  /** ISO 8601 UTC — start of transfer window. */
  transfer_window_start: string;
  /** ISO 8601 UTC — end of transfer window. */
  transfer_window_end: string;
  /** Optional: hash of an APR artifact. */
  artifact_apr_hash?: string | null;
  /** Optional: hash of a consent receipt. */
  consent_receipt_hash?: string | null;
  /** Optional: hash of a purpose binding document. */
  purpose_binding_hash?: string | null;
  /** Optional: hash of a QTS attestation. */
  qts_attestation_hash?: string | null;
}

export interface MintTiaInput extends MintAtrV2Common {
  event_type: "tia";
  /** Hash of the parent arrangement receipt. */
  arrangement_hash: string;
  /** ISO 3166 alpha-2 destination country. */
  destination_country: string;
  /** SHA-256 hash of the TIA assessment document. */
  assessment_doc_hash: string;
  /** Surveillance law references assessed. */
  surveillance_law_refs: readonly string[];
  /** Outcome of the transfer impact assessment. */
  assessment_outcome: AtrAssessmentOutcome;
  /** SHA-256 hash of any supplementary measures document. */
  supplementary_measures_hash: string;
  /** ISO 8601 UTC — TIA validity start. */
  valid_from: string;
  /** ISO 8601 UTC — TIA validity end. */
  valid_until: string;
  /** Optional: hash of a QTS attestation. */
  qts_attestation_hash?: string | null;
}

export interface MintSuspensionInput extends MintAtrV2Common {
  event_type: "suspension";
  /** Reason for suspension. */
  trigger: AtrSuspensionTrigger;
  /** SHA-256 hash of the triggering reference document. */
  trigger_ref_hash: string;
  /** ISO 8601 UTC — when the suspension takes effect. */
  effective_at: string;
  /** Optional: hash of a QTS attestation. */
  qts_attestation_hash?: string | null;
}

export type MintAtrV2Input =
  | MintArrangementInput
  | MintTransferInput
  | MintTiaInput
  | MintSuspensionInput;

// ── Body builder ──────────────────────────────────────────────────────────────

function buildBody(input: MintAtrV2Input): AtrBody {
  switch (input.event_type) {
    case "arrangement": {
      const body: AtrArrangementBody = {
        event_type: "arrangement",
        arrangement_id_commit: input.arrangement_id_commit,
        recipient_commit: input.recipient_commit,
        destination_country: input.destination_country,
        mechanism_version: input.mechanism_version,
        contract_doc_hash: input.contract_doc_hash,
        in_force_from: input.in_force_from,
        in_force_until: input.in_force_until ?? null,
        supplementary_measures_hash: input.supplementary_measures_hash,
        qts_attestation_hash: input.qts_attestation_hash ?? null,
      };
      return body;
    }
    case "transfer": {
      const body: AtrTransferBody = {
        event_type: "transfer",
        arrangement_hash: input.arrangement_hash,
        tia_hash: input.tia_hash ?? null,
        destination_country: input.destination_country,
        recipient_commit: input.recipient_commit,
        data_categories: input.data_categories,
        subject_count_bucket: input.subject_count_bucket,
        transfer_window_start: input.transfer_window_start,
        transfer_window_end: input.transfer_window_end,
        artifact_apr_hash: input.artifact_apr_hash ?? null,
        consent_receipt_hash: input.consent_receipt_hash ?? null,
        purpose_binding_hash: input.purpose_binding_hash ?? null,
        qts_attestation_hash: input.qts_attestation_hash ?? null,
      };
      return body;
    }
    case "tia": {
      const body: AtrTiaBody = {
        event_type: "tia",
        arrangement_hash: input.arrangement_hash,
        destination_country: input.destination_country,
        assessment_doc_hash: input.assessment_doc_hash,
        surveillance_law_refs: input.surveillance_law_refs,
        assessment_outcome: input.assessment_outcome,
        supplementary_measures_hash: input.supplementary_measures_hash,
        valid_from: input.valid_from,
        valid_until: input.valid_until,
        qts_attestation_hash: input.qts_attestation_hash ?? null,
      };
      return body;
    }
    case "suspension": {
      const body: AtrSuspensionBody = {
        event_type: "suspension",
        trigger: input.trigger,
        trigger_ref_hash: input.trigger_ref_hash,
        effective_at: input.effective_at,
        qts_attestation_hash: input.qts_attestation_hash ?? null,
      };
      return body;
    }
  }
}

// ── mintAtrV2 ─────────────────────────────────────────────────────────────────

export async function mintAtrV2(input: MintAtrV2Input): Promise<Envelope> {
  if (!input.issuer) throw new Error("mintAtrV2: issuer required");
  if (!input.signingKey?.kid) {
    throw new Error("mintAtrV2: signingKey.kid required");
  }
  if (input.signingKey.privateKey.length !== 32) {
    throw new Error("mintAtrV2: signingKey.privateKey must be 32 bytes");
  }
  if (!input.anchor) throw new Error("mintAtrV2: anchor required");

  // Per FAMILY-CONSISTENCY §3:
  //   transfer: subject MUST be sha256:<hex> (must-be-present)
  //   arrangement / tia / suspension: subject is null (must-be-null)
  if (input.event_type === "transfer") {
    const transferInput = input as MintTransferInput;
    if (!isSha256Hex(transferInput.subject)) {
      throw new Error(
        "mintAtrV2: transfer subject must be `sha256:<64-hex>` (FAMILY-CONSISTENCY §3 — transfer must-be-present)",
      );
    }
  }

  // arrangement: prev MUST be null (chain head).
  if (input.event_type === "arrangement" && input.prev) {
    throw new Error("mintAtrV2: arrangement must have prev=null (chain head)");
  }

  // suspension: prev MUST be present.
  if (input.event_type === "suspension" && !input.prev) {
    throw new Error("mintAtrV2: suspension requires prev (references arrangement or tia)");
  }

  if (input.tsa !== undefined && input.tsaFetcher === undefined) {
    throw new Error("mintAtrV2: tsaFetcher is required when tsa config is provided");
  }

  const id = generateReceiptId();
  const iat = new Date().toISOString();
  const { privateKey, issKey } = keyObjectFromSeed(input.signingKey.privateKey);

  const baseBody = buildBody(input);
  const field_root = computeFieldRoot(baseBody);
  const bodyOut: AtrV2BodyOut = { ...baseBody, field_root };

  // Subject: transfer=caller-supplied sha256, others=null.
  // Envelope.subject is typed `string` (shared wire type); ATR legitimately
  // carries subject:null for arrangement/tia/suspension per FAMILY-CONSISTENCY
  // §3. Match the apur-issuer-kit precedent (`null as unknown as string`) until
  // the shared type is widened to `string | null` in the typecheck-debt cleanup.
  const subject: string =
    input.event_type === "transfer"
      ? (input as MintTransferInput).subject
      : (null as unknown as string);

  const envelopeKindOut: Kind | null =
    input.envelope_kind === undefined ? "decision" : input.envelope_kind;

  let preSign: Envelope = {
    v: 2,
    id,
    iat,
    iat_ms: Date.parse(iat),
    claim_type: ATR_CLAIM_TYPE,
    iss: input.issuer,
    iss_key: issKey,
    subject,
    exp: input.exp ?? null,
    prev: input.prev ?? null,
    policy_uri: input.policy_uri,
    policy_hash: input.policy_hash,
    policy_version: input.policy_version,
    kind: envelopeKindOut,
    cause: input.cause ?? null,
    predicate: null,
    tsa: null,
    credentialStatus: null,
    anchor: input.anchor,
    sig: "",
    countersig: null,
    ...(input.countersig_key !== undefined
      ? { countersig_key: input.countersig_key }
      : {}),
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
