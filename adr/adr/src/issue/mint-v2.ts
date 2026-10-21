/**
 * ADR v=2 mint path — produces v=2 Envelopes for Anchored Delegation Receipts.
 *
 * Single export surface: `mintAdrV2(input)` with event-discriminated input.
 * ADR is v=2 only (no v=1 legacy). Per-event convenience wrappers live
 * in `mint-single.ts`.
 *
 * Per FAMILY-CONSISTENCY §3 and ADR spec: `subject` MUST be `"sha256:<hex>"`
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
  AdrBody,
  AdrGrantBody,
  AdrRevokeBody,
  AdrNarrowBody,
  AdrRenewBody,
  AdrSuspendBody,
  AdrResumeBody,
  AdrAgent,
  AdrScope,
  AdrProfile,
  AdrAuthorizingCredential,
} from "../types.ts";
import { adrFamily } from "../family.ts";

const ADR_CLAIM_TYPE = adrFamily.meta.claim_types[0]!;

export type { StatusListConfig, SuspensionListConfig, TsaFetcher };
export { TsaMintError };

import type { SigningKey } from "@dekimuhq/anchors-envelope/issuer";
export type { SigningKey };

// ── v=2 body shape (issuer side adds field_root) ──────────────────────────────

export type AdrV2BodyOut = AdrBody & { field_root: string };

// ── Input interfaces ──────────────────────────────────────────────────────────

interface MintAdrV2Common {
  /** Issuer DID or short identifier. */
  issuer: string;
  /** Ed25519 signing key (32-byte seed). */
  signingKey: SigningKey;
  /** ADR regulatory profile (spec §5). */
  profile: AdrProfile;
  /** Subject HMAC commitment — REQUIRED on every ADR event (`sha256:<hex>`). */
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

export interface MintGrantInput extends MintAdrV2Common {
  event: "grant";
  agent: AdrAgent;
  scope: AdrScope;
  delegable: boolean;
  expiry: number | null;
  rationale_uri: string;
  rationale_hash: string;
  /** Optional: SHA-256 hash of an AAR receipt attesting QTS posture. */
  qts_attestation_hash?: string | null;
  /**
   * Optional: reference (by id) to the external credential that authorized this
   * delegation — e.g. an AP2 mandate. Receipt-*of*, never is-a. Omit when the
   * delegation records no external authorization. See STANDARDS-BRIDGE §2d.
   */
  authorizing_credential?: AdrAuthorizingCredential | null;
}

export interface MintRevokeInput extends MintAdrV2Common {
  event: "revoke";
  reason_uri?: string;
  reason_hash?: string;
  /** Optional: SHA-256 hash of an AAR receipt attesting QTS posture. */
  qts_attestation_hash?: string | null;
}

export interface MintNarrowInput extends MintAdrV2Common {
  event: "narrow";
  scope: AdrScope;
  /** Optional: SHA-256 hash of an AAR receipt attesting QTS posture. */
  qts_attestation_hash?: string | null;
}

export interface MintRenewInput extends MintAdrV2Common {
  event: "renew";
  expiry: number;
  /** Optional: SHA-256 hash of an AAR receipt attesting QTS posture. */
  qts_attestation_hash?: string | null;
}

export interface MintSuspendInput extends MintAdrV2Common {
  event: "suspend";
  reason_uri?: string;
  reason_hash?: string;
  cascade?: boolean;
  /** Optional: SHA-256 hash of an AAR receipt attesting QTS posture. */
  qts_attestation_hash?: string | null;
}

export interface MintResumeInput extends MintAdrV2Common {
  event: "resume";
  /** Optional: SHA-256 hash of an AAR receipt attesting QTS posture. */
  qts_attestation_hash?: string | null;
}

export type MintAdrV2Input =
  | MintGrantInput
  | MintRevokeInput
  | MintNarrowInput
  | MintRenewInput
  | MintSuspendInput
  | MintResumeInput;

// ── Body builder ──────────────────────────────────────────────────────────────

function buildBody(input: MintAdrV2Input): AdrBody {
  switch (input.event) {
    case "grant": {
      const body: AdrGrantBody = {
        event: "grant",
        profile: input.profile,
        agent: input.agent,
        scope: input.scope,
        delegable: input.delegable,
        expiry: input.expiry,
        rationale_uri: input.rationale_uri,
        rationale_hash: input.rationale_hash,
        qts_attestation_hash: input.qts_attestation_hash ?? null,
        // Additive + optional: emit only when supplied so pre-existing grant
        // receipts stay byte-equal (key absent), matching the `reason_*` pattern.
        ...(input.authorizing_credential !== undefined && {
          authorizing_credential: input.authorizing_credential,
        }),
      };
      return body;
    }
    case "revoke": {
      const body: AdrRevokeBody = {
        event: "revoke",
        profile: input.profile,
        ...(input.reason_uri !== undefined && { reason_uri: input.reason_uri }),
        ...(input.reason_hash !== undefined && { reason_hash: input.reason_hash }),
        qts_attestation_hash: input.qts_attestation_hash ?? null,
      };
      return body;
    }
    case "narrow": {
      const body: AdrNarrowBody = {
        event: "narrow",
        profile: input.profile,
        scope: input.scope,
        qts_attestation_hash: input.qts_attestation_hash ?? null,
      };
      return body;
    }
    case "renew": {
      const body: AdrRenewBody = {
        event: "renew",
        profile: input.profile,
        expiry: input.expiry,
        qts_attestation_hash: input.qts_attestation_hash ?? null,
      };
      return body;
    }
    case "suspend": {
      const body: AdrSuspendBody = {
        event: "suspend",
        profile: input.profile,
        ...(input.reason_uri !== undefined && { reason_uri: input.reason_uri }),
        ...(input.reason_hash !== undefined && { reason_hash: input.reason_hash }),
        ...(input.cascade !== undefined && { cascade: input.cascade }),
        qts_attestation_hash: input.qts_attestation_hash ?? null,
      };
      return body;
    }
    case "resume": {
      const body: AdrResumeBody = {
        event: "resume",
        profile: input.profile,
        qts_attestation_hash: input.qts_attestation_hash ?? null,
      };
      return body;
    }
  }
}

// ── mintAdrV2 ─────────────────────────────────────────────────────────────────

export async function mintAdrV2(input: MintAdrV2Input): Promise<Envelope> {
  if (!input.issuer) throw new Error("mintAdrV2: issuer required");
  if (!input.signingKey?.kid) {
    throw new Error("mintAdrV2: signingKey.kid required");
  }
  if (input.signingKey.privateKey.length !== 32) {
    throw new Error("mintAdrV2: signingKey.privateKey must be 32 bytes");
  }
  if (!input.anchor) throw new Error("mintAdrV2: anchor required");

  // ADR: subject MUST be sha256:<hex> on every event (universal must-be-present).
  if (!isSha256Hex(input.subject)) {
    throw new Error(
      "mintAdrV2: subject must be `sha256:<64-hex>` (FAMILY-CONSISTENCY §3 — ADR must-be-present)",
    );
  }

  if (input.tsa !== undefined && input.tsaFetcher === undefined) {
    throw new Error("mintAdrV2: tsaFetcher is required when tsa config is provided");
  }

  const id = generateReceiptId();
  const iat = new Date().toISOString();
  const { privateKey, issKey } = keyObjectFromSeed(input.signingKey.privateKey);

  const baseBody = buildBody(input);
  const field_root = computeFieldRoot(baseBody);
  const bodyOut: AdrV2BodyOut = { ...baseBody, field_root };

  const envelopeKindOut: Kind | null =
    input.envelope_kind === undefined ? "decision" : input.envelope_kind;

  let preSign: Envelope = {
    v: 2,
    id,
    iat,
    iat_ms: Date.parse(iat),
    claim_type: ADR_CLAIM_TYPE,
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
