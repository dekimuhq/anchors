/**
 * ATokR v=2 mint path — produces v=2 Envelopes for Anchored Tokenization Receipts.
 *
 * Single export surface: `mintAtokrV2(input)` with event_type-discriminated input.
 * ATokR is v=2 only (no v=1 legacy). Per-event-type convenience wrappers live
 * in `mint-single.ts`.
 *
 * Per FAMILY-CONSISTENCY §3 and ATokR spec: `subject` MUST be `"sha256:<hex>"`
 * on every event type (universal must-be-present rule — no per-event split).
 *
 * `field_root` is computed over the body fields and embedded inside the body.
 *
 * Phase 2 — 14th family member (ATokR).
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
  AtokrBody,
  AtokrIssuedBody,
  AtokrRedeemedBody,
  AtokrRevokedBody,
  AtokrRotatedBody,
  AtokrFormatClass,
  AtokrProfile,
  AtokrScope,
  AtokrPciEnvironment,
  AtokrAttributeCategory,
  AtokrDataUseCategory,
} from "../types.ts";
import { atokrFamily } from "../family.ts";

const ATOKR_CLAIM_TYPE = atokrFamily.meta.claim_types[0]!;

export type { StatusListConfig, SuspensionListConfig, TsaFetcher };
export { TsaMintError };

import type { SigningKey } from "@dekimuhq/anchors-envelope/issuer";
export type { SigningKey };

// ── v=2 body shape (issuer side adds field_root) ──────────────────────────────

export type AtokrV2BodyOut = AtokrBody & { field_root: string };

// ── Input interfaces ──────────────────────────────────────────────────────────

interface MintAtokrV2Common {
  /** Issuer DID or short identifier. */
  issuer: string;
  /** Ed25519 signing key (32-byte seed). */
  signingKey: SigningKey;
  /** ATokR regulatory profile (spec §5). */
  profile: AtokrProfile;
  /** Subject HMAC commitment — REQUIRED on every ATokR event (`sha256:<hex>`). */
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

export interface MintTokenIssuedInput extends MintAtokrV2Common {
  event_type: "token.issued";
  token_id: string;
  format_class: AtokrFormatClass;
  scope: AtokrScope;
  // Profile-conditional
  separation_attestation?: boolean;
  pci_environment?: AtokrPciEnvironment;
  wallet_provider_did?: string;
  attribute_category?: AtokrAttributeCategory;
  data_use_category?: AtokrDataUseCategory;
  pseudonymisation_standard?: string;
  // Optional cross-refs
  asr_ref?: string | null;
  alr_ref?: string | null;
  apur_ref?: string | null;
  /** Optional: SHA-256 hash of an AAR receipt attesting QTS posture. */
  qts_attestation_hash?: string | null;
}

export interface MintTokenRedeemedInput extends MintAtokrV2Common {
  event_type: "token.redeemed";
  token_id: string;
  scope: AtokrScope;
  format_class?: AtokrFormatClass | null;
  redemption_audit_ref?: string | null;
  asr_ref?: string | null;
  apur_ref?: string | null;
  /** Optional: SHA-256 hash of an AAR receipt attesting QTS posture. */
  qts_attestation_hash?: string | null;
}

export interface MintTokenRevokedInput extends MintAtokrV2Common {
  event_type: "token.revoked";
  token_id: string;
  scope: AtokrScope;
  format_class?: AtokrFormatClass | null;
  asr_ref?: string | null;
  arr_ref?: string | null;
  apur_ref?: string | null;
  /** Optional: SHA-256 hash of an AAR receipt attesting QTS posture. */
  qts_attestation_hash?: string | null;
}

export interface MintTokenRotatedInput extends MintAtokrV2Common {
  event_type: "token.rotated";
  token_id: string;
  format_class: AtokrFormatClass;
  scope: AtokrScope;
  rotation_of: string;
  alr_ref?: string | null;
  apur_ref?: string | null;
  /** Optional: SHA-256 hash of an AAR receipt attesting QTS posture. */
  qts_attestation_hash?: string | null;
}

export type MintAtokrV2Input =
  | MintTokenIssuedInput
  | MintTokenRedeemedInput
  | MintTokenRevokedInput
  | MintTokenRotatedInput;

// ── Body builder ──────────────────────────────────────────────────────────────

function buildBody(input: MintAtokrV2Input): AtokrBody {
  switch (input.event_type) {
    case "token.issued": {
      const body: AtokrIssuedBody = {
        event_type: "token.issued",
        token_id: input.token_id,
        format_class: input.format_class,
        scope: input.scope,
        rotation_of: null,
        redemption_audit_ref: null,
        asr_ref: input.asr_ref ?? null,
        arr_ref: null,
        alr_ref: input.alr_ref ?? null,
        apur_ref: input.apur_ref ?? null,
        qts_attestation_hash: input.qts_attestation_hash ?? null,
        ...(input.separation_attestation !== undefined && {
          separation_attestation: input.separation_attestation,
        }),
        ...(input.pci_environment !== undefined && {
          pci_environment: input.pci_environment,
        }),
        ...(input.wallet_provider_did !== undefined && {
          wallet_provider_did: input.wallet_provider_did,
        }),
        ...(input.attribute_category !== undefined && {
          attribute_category: input.attribute_category,
        }),
        ...(input.data_use_category !== undefined && {
          data_use_category: input.data_use_category,
        }),
        ...(input.pseudonymisation_standard !== undefined && {
          pseudonymisation_standard: input.pseudonymisation_standard,
        }),
      };
      return body;
    }
    case "token.redeemed": {
      const body: AtokrRedeemedBody = {
        event_type: "token.redeemed",
        token_id: input.token_id,
        format_class: input.format_class ?? null,
        scope: input.scope,
        rotation_of: null,
        redemption_audit_ref: input.redemption_audit_ref ?? null,
        asr_ref: input.asr_ref ?? null,
        arr_ref: null,
        alr_ref: null,
        apur_ref: input.apur_ref ?? null,
        qts_attestation_hash: input.qts_attestation_hash ?? null,
      };
      return body;
    }
    case "token.revoked": {
      const body: AtokrRevokedBody = {
        event_type: "token.revoked",
        token_id: input.token_id,
        format_class: input.format_class ?? null,
        scope: input.scope,
        rotation_of: null,
        redemption_audit_ref: null,
        asr_ref: input.asr_ref ?? null,
        arr_ref: input.arr_ref ?? null,
        alr_ref: null,
        apur_ref: input.apur_ref ?? null,
        qts_attestation_hash: input.qts_attestation_hash ?? null,
      };
      return body;
    }
    case "token.rotated": {
      const body: AtokrRotatedBody = {
        event_type: "token.rotated",
        token_id: input.token_id,
        format_class: input.format_class,
        scope: input.scope,
        rotation_of: input.rotation_of,
        redemption_audit_ref: null,
        asr_ref: null,
        arr_ref: null,
        alr_ref: input.alr_ref ?? null,
        apur_ref: input.apur_ref ?? null,
        qts_attestation_hash: input.qts_attestation_hash ?? null,
      };
      return body;
    }
  }
}

// ── mintAtokrV2 ───────────────────────────────────────────────────────────────

export async function mintAtokrV2(input: MintAtokrV2Input): Promise<Envelope> {
  if (!input.issuer) throw new Error("mintAtokrV2: issuer required");
  if (!input.signingKey?.kid) {
    throw new Error("mintAtokrV2: signingKey.kid required");
  }
  if (input.signingKey.privateKey.length !== 32) {
    throw new Error("mintAtokrV2: signingKey.privateKey must be 32 bytes");
  }
  if (!input.anchor) throw new Error("mintAtokrV2: anchor required");

  // ATokR: subject MUST be sha256:<hex> on every event (universal must-be-present).
  if (!isSha256Hex(input.subject)) {
    throw new Error(
      "mintAtokrV2: subject must be `sha256:<64-hex>` (FAMILY-CONSISTENCY §3 — ATokR must-be-present)",
    );
  }

  // token.issued: prev MUST be null (chain head).
  if (input.event_type === "token.issued" && input.prev) {
    throw new Error("mintAtokrV2: token.issued must have prev=null (chain head)");
  }

  // token.rotated: rotation_of MUST be non-empty.
  if (input.event_type === "token.rotated" && !input.rotation_of) {
    throw new Error("mintAtokrV2: token.rotated requires rotation_of");
  }

  if (input.tsa !== undefined && input.tsaFetcher === undefined) {
    throw new Error("mintAtokrV2: tsaFetcher is required when tsa config is provided");
  }

  const id = generateReceiptId();
  const iat = new Date().toISOString();
  const { privateKey, issKey } = keyObjectFromSeed(input.signingKey.privateKey);

  const baseBody = buildBody(input);
  const field_root = computeFieldRoot(baseBody);
  const bodyOut: AtokrV2BodyOut = { ...baseBody, field_root };

  const envelopeKindOut: Kind | null =
    input.envelope_kind === undefined ? "decision" : input.envelope_kind;

  let preSign: Envelope = {
    v: 2,
    id,
    iat,
    iat_ms: Date.parse(iat),
    claim_type: ATOKR_CLAIM_TYPE,
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
