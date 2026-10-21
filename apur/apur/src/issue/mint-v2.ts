/**
 * APuR v=2 mint path — produces v=2 Envelopes for Anchored Purpose Receipts.
 *
 * Single export surface: `mintApurV2(input)` with event_type-discriminated input.
 * APuR is v=2 only (no v=1 legacy). Per-event-type convenience wrappers live
 * in `mint-single.ts`.
 *
 * Per FAMILY-CONSISTENCY §3 and APuR spec: `subject` MUST be `null`
 * (processing-activity-level — no per-subject chain).
 *
 * `field_root` is computed over the body fields and embedded inside the body.
 *
 * Chip 6, ar.purpose.v1.
 */

import {
  generateReceiptId,
  keyObjectFromSeed,
  computeFieldRoot,
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
  ApurBody,
  ApurBindingBody,
  ApurRepurposeBody,
  ApurUnbindingBody,
  ApurProfile,
  ApurCompatConclusion,
  ApurUnbindingReason,
} from "../types.ts";
import { apurFamily } from "../family.ts";

const APUR_CLAIM_TYPE = apurFamily.meta.claim_types[0]!;

export type { StatusListConfig, SuspensionListConfig, TsaFetcher };
export { TsaMintError };

import type { SigningKey } from "@dekimuhq/anchors-envelope/issuer";
export type { SigningKey };

// ── v=2 body shape (issuer side adds field_root) ──────────────────────────────

export type ApurV2BodyOut = ApurBody & { field_root: string };

// ── Input interfaces ──────────────────────────────────────────────────────────

interface MintApurV2Common {
  /** Issuer DID or short identifier. */
  issuer: string;
  /** Ed25519 signing key (32-byte seed). */
  signingKey: SigningKey;
  /** APuR regulatory profile (spec §5). */
  profile: ApurProfile;
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

export interface MintBindingInput extends MintApurV2Common {
  event_type: "binding";
  activity_id_commit: string;
  purpose_commit: string;
  purpose_class: string;
  lawful_basis: string;
  data_categories: string[];
  data_subjects_class: string;
  /** Body-level policy hash (separate from envelope policy_hash). */
  policy_hash_body: string;
  minimisation_hash: string;
  bound_at: string;
  // Optional cross-refs
  consent_receipt_hash?: string | null;
  retention_receipt_hash?: string | null;
  transfer_arrangement_hash?: string | null;
  /** Optional: SHA-256 hash of an AAR receipt attesting QTS posture. */
  qts_attestation_hash?: string | null;
  // Profile-conditional (hipaa.minimum_necessary §5.4):
  covered_entity_commit?: string;
  workforce_role_class?: string;
}

export interface MintRepurposeInput extends MintApurV2Common {
  event_type: "repurpose";
  new_purpose_commit: string;
  new_purpose_class: string;
  compat_link_hash: string;
  compat_context_hash: string;
  compat_subjects_reasonable_hash: string;
  compat_consequences_hash: string;
  compat_safeguards_hash: string;
  compat_conclusion: ApurCompatConclusion;
  minimisation_hash: string;
  tested_at: string;
  /** Optional: SHA-256 hash of an AAR receipt attesting QTS posture. */
  qts_attestation_hash?: string | null;
}

export interface MintUnbindingInput extends MintApurV2Common {
  event_type: "unbinding";
  reason: ApurUnbindingReason;
  downstream_arr_receipt_hash?: string | null;
  unbound_at: string;
  /** Optional: SHA-256 hash of an AAR receipt attesting QTS posture. */
  qts_attestation_hash?: string | null;
}

export type MintApurV2Input =
  | MintBindingInput
  | MintRepurposeInput
  | MintUnbindingInput;

// ── Body builder ──────────────────────────────────────────────────────────────

function buildBody(input: MintApurV2Input): ApurBody {
  switch (input.event_type) {
    case "binding": {
      const body: ApurBindingBody = {
        event_type: "binding",
        activity_id_commit: input.activity_id_commit,
        purpose_commit: input.purpose_commit,
        purpose_class: input.purpose_class,
        lawful_basis: input.lawful_basis,
        data_categories: input.data_categories,
        data_subjects_class: input.data_subjects_class,
        policy_hash: input.policy_hash_body,
        minimisation_hash: input.minimisation_hash,
        consent_receipt_hash: input.consent_receipt_hash ?? null,
        retention_receipt_hash: input.retention_receipt_hash ?? null,
        transfer_arrangement_hash: input.transfer_arrangement_hash ?? null,
        bound_at: input.bound_at,
        qts_attestation_hash: input.qts_attestation_hash ?? null,
        ...(input.covered_entity_commit !== undefined && {
          covered_entity_commit: input.covered_entity_commit,
        }),
        ...(input.workforce_role_class !== undefined && {
          workforce_role_class: input.workforce_role_class,
        }),
      };
      return body;
    }
    case "repurpose": {
      const body: ApurRepurposeBody = {
        event_type: "repurpose",
        new_purpose_commit: input.new_purpose_commit,
        new_purpose_class: input.new_purpose_class,
        compat_link_hash: input.compat_link_hash,
        compat_context_hash: input.compat_context_hash,
        compat_subjects_reasonable_hash: input.compat_subjects_reasonable_hash,
        compat_consequences_hash: input.compat_consequences_hash,
        compat_safeguards_hash: input.compat_safeguards_hash,
        compat_conclusion: input.compat_conclusion,
        minimisation_hash: input.minimisation_hash,
        tested_at: input.tested_at,
        qts_attestation_hash: input.qts_attestation_hash ?? null,
      };
      return body;
    }
    case "unbinding": {
      const body: ApurUnbindingBody = {
        event_type: "unbinding",
        reason: input.reason,
        downstream_arr_receipt_hash: input.downstream_arr_receipt_hash ?? null,
        unbound_at: input.unbound_at,
        qts_attestation_hash: input.qts_attestation_hash ?? null,
      };
      return body;
    }
  }
}

// ── mintApurV2 ────────────────────────────────────────────────────────────────

export async function mintApurV2(input: MintApurV2Input): Promise<Envelope> {
  if (!input.issuer) throw new Error("mintApurV2: issuer required");
  if (!input.signingKey?.kid) {
    throw new Error("mintApurV2: signingKey.kid required");
  }
  if (input.signingKey.privateKey.length !== 32) {
    throw new Error("mintApurV2: signingKey.privateKey must be 32 bytes");
  }
  if (!input.anchor) throw new Error("mintApurV2: anchor required");

  // binding: prev MUST be null (chain head).
  if (input.event_type === "binding" && input.prev) {
    throw new Error("mintApurV2: binding must have prev=null (chain head)");
  }

  // repurpose + unbinding: prev MUST be set (chain continuation).
  if (
    (input.event_type === "repurpose" || input.event_type === "unbinding") &&
    !input.prev
  ) {
    throw new Error(
      `mintApurV2: ${input.event_type} requires prev to be set (chain continuation)`,
    );
  }

  if (input.tsa !== undefined && input.tsaFetcher === undefined) {
    throw new Error("mintApurV2: tsaFetcher is required when tsa config is provided");
  }

  const id = generateReceiptId();
  const iat = new Date().toISOString();
  const { privateKey, issKey } = keyObjectFromSeed(input.signingKey.privateKey);

  const baseBody = buildBody(input);
  const field_root = computeFieldRoot(baseBody);
  const bodyOut: ApurV2BodyOut = { ...baseBody, field_root };

  const envelopeKindOut: Kind | null =
    input.envelope_kind === undefined ? "decision" : input.envelope_kind;

  let preSign: Envelope = {
    v: 2,
    id,
    iat,
    iat_ms: Date.parse(iat),
    claim_type: APUR_CLAIM_TYPE,
    iss: input.issuer,
    iss_key: issKey,
    subject: null as unknown as string,
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
