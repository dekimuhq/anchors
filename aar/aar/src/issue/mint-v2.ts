/**
 * AAR v=2 mint path — produces v=2 Envelopes for Anchored Attestation Receipts.
 *
 * Single export surface: `mintAarV2(input)` with event_type-discriminated input.
 * AAR is v=2 only (no v=1 legacy). Per-event-type convenience wrappers live
 * in `mint-single.ts`.
 *
 * Per FAMILY-CONSISTENCY §3 and AAR spec: `subject` MUST be `"sha256:<hex>"`
 * on every event type (universal must-be-present rule).
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
  AarBody,
  AarIssuanceBody,
  AarRevocationBody,
  AarProfile,
  AarServiceType,
  AarSignatureFormat,
  AarRevocationReason,
} from "../types.ts";
import { aarFamily } from "../family.ts";

const AAR_CLAIM_TYPE = aarFamily.meta.claim_types[0]!;

export type { StatusListConfig, SuspensionListConfig, TsaFetcher };
export { TsaMintError };

import type { SigningKey } from "@dekimuhq/anchors-envelope/issuer";
export type { SigningKey };

// ── v=2 body shape (issuer side adds field_root) ──────────────────────────────

export type AarV2BodyOut = AarBody & { field_root: string };

// ── Input interfaces ──────────────────────────────────────────────────────────

interface MintAarV2Common {
  /** Issuer DID or short identifier. */
  issuer: string;
  /** Ed25519 signing key (32-byte seed). */
  signingKey: SigningKey;
  /** AAR regulatory profile (spec §5). */
  profile: AarProfile;
  /** Subject HMAC commitment — REQUIRED on every AAR event (`sha256:<hex>`). */
  subject: string;
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
}

export interface MintAarIssuanceInput extends MintAarV2Common {
  event_type: "issuance";
  service_type: AarServiceType;
  service_policy_oid: string;
  service_recipient_commit: string;
  artefact_hash: string | null;
  artefact_metadata_commit: string;
  signature_format?: AarSignatureFormat | null;
  qcert_serial_commit?: string | null;
  tsl_country: string;
  tsl_entry_hash: string;
  tsl_signed_tree_head_root: string;
  tsl_tree_size: number;
  tsl_inclusion_proof: string[];
  tsl_log_time: string;
  atr_transfer_hash?: string | null;
  /** Optional: SHA-256 hash of an AAR receipt attesting QTS posture. */
  qts_attestation_hash?: string | null;
}

export interface MintAarRevocationInput extends MintAarV2Common {
  event_type: "revocation";
  reason: AarRevocationReason;
  reason_ref_hash?: string | null;
  tsl_country: string;
  tsl_entry_hash: string;
  tsl_signed_tree_head_root: string;
  tsl_tree_size: number;
  tsl_inclusion_proof: string[];
  tsl_log_time: string;
  /** Optional: SHA-256 hash of an AAR receipt attesting QTS posture. */
  qts_attestation_hash?: string | null;
}

export type MintAarV2Input = MintAarIssuanceInput | MintAarRevocationInput;

// ── Body builder ──────────────────────────────────────────────────────────────

function buildBody(input: MintAarV2Input): AarBody {
  switch (input.event_type) {
    case "issuance": {
      const body: AarIssuanceBody = {
        event_type: "issuance",
        service_type: input.service_type,
        service_policy_oid: input.service_policy_oid,
        service_recipient_commit: input.service_recipient_commit,
        artefact_hash: input.artefact_hash,
        artefact_metadata_commit: input.artefact_metadata_commit,
        signature_format: input.signature_format ?? null,
        qcert_serial_commit: input.qcert_serial_commit ?? null,
        tsl_country: input.tsl_country,
        tsl_entry_hash: input.tsl_entry_hash,
        tsl_signed_tree_head_root: input.tsl_signed_tree_head_root,
        tsl_tree_size: input.tsl_tree_size,
        tsl_inclusion_proof: input.tsl_inclusion_proof,
        tsl_log_time: input.tsl_log_time,
        atr_transfer_hash: input.atr_transfer_hash ?? null,
        qts_attestation_hash: input.qts_attestation_hash ?? null,
      };
      return body;
    }
    case "revocation": {
      const body: AarRevocationBody = {
        event_type: "revocation",
        reason: input.reason,
        reason_ref_hash: input.reason_ref_hash ?? null,
        tsl_country: input.tsl_country,
        tsl_entry_hash: input.tsl_entry_hash,
        tsl_signed_tree_head_root: input.tsl_signed_tree_head_root,
        tsl_tree_size: input.tsl_tree_size,
        tsl_inclusion_proof: input.tsl_inclusion_proof,
        tsl_log_time: input.tsl_log_time,
        qts_attestation_hash: input.qts_attestation_hash ?? null,
      };
      return body;
    }
  }
}

// ── mintAarV2 ─────────────────────────────────────────────────────────────────

export async function mintAarV2(input: MintAarV2Input): Promise<Envelope> {
  if (!input.issuer) throw new Error("mintAarV2: issuer required");
  if (!input.signingKey?.kid) {
    throw new Error("mintAarV2: signingKey.kid required");
  }
  if (input.signingKey.privateKey.length !== 32) {
    throw new Error("mintAarV2: signingKey.privateKey must be 32 bytes");
  }
  if (!input.anchor) throw new Error("mintAarV2: anchor required");

  // AAR: subject MUST be sha256:<hex> on every event (universal must-be-present).
  if (!isSha256Hex(input.subject)) {
    throw new Error(
      "mintAarV2: subject must be `sha256:<64-hex>` (FAMILY-CONSISTENCY §3 — AAR must-be-present)",
    );
  }

  // issuance: prev MUST be null (chain head).
  if (input.event_type === "issuance" && input.prev) {
    throw new Error("mintAarV2: issuance must have prev=null (chain head)");
  }

  // revocation: prev MUST be set.
  if (input.event_type === "revocation" && !input.prev) {
    throw new Error("mintAarV2: revocation must have prev set (references issuance receipt)");
  }

  if (input.tsa !== undefined && input.tsaFetcher === undefined) {
    throw new Error("mintAarV2: tsaFetcher is required when tsa config is provided");
  }

  const id = generateReceiptId();
  const iat = new Date().toISOString();
  const { privateKey, issKey } = keyObjectFromSeed(input.signingKey.privateKey);

  const baseBody = buildBody(input);
  const field_root = computeFieldRoot(baseBody);
  const bodyOut: AarV2BodyOut = { ...baseBody, field_root };

  const envelopeKindOut: Kind | null =
    input.envelope_kind === undefined ? "decision" : input.envelope_kind;

  let preSign: Envelope = {
    v: 2,
    id,
    iat,
    iat_ms: Date.parse(iat),
    claim_type: AAR_CLAIM_TYPE,
    iss: input.issuer,
    iss_key: issKey,
    subject: input.subject,
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
