/**
 * ALR v=2 mint path — produces v=2 Envelopes for Anchored Lineage Receipts.
 *
 * Single export surface: `mintAlrV2(input)` with event_type-discriminated input.
 * ALR is v=2 only (no v=1 legacy) and has no batch claim_type — all minting
 * goes through this single function. Per-event-type convenience wrappers live
 * in `mint-single.ts`.
 *
 * Per FAMILY-CONSISTENCY §3 the envelope `subject` is ALWAYS `null` for ALR
 * (lineage is dataset-level). Callers cannot override.
 *
 * `field_root` is computed over the body fields and embedded inside the body
 * (`AlrV2BodyOut`). The alr-verifier types do not yet declare it; the verifier
 * ignores extra fields per its field-by-field check approach.
 *
 * Phase 1 §H of the 10-spec batch.
 */

import {
  computeFieldRoot,
  type Envelope,
  type AnchorProof,
  type Kind,
  type Cause,
  type JsonLogicAst,
} from "@dekimuhq/anchors-envelope";
import {
  TsaMintError,
  type TsaFetcher,
  type TsaConfig,
} from "@dekimuhq/anchors-envelope/tsa";
import {
  type StatusListConfig,
  type SuspensionListConfig,
} from "@dekimuhq/anchors-envelope/status";
import { alrFamily } from "../family.ts";
import type {
  AlrBody,
  AlrDerivedFromBody,
  AlrDisclosedBody,
  AlrForkedFromBody,
  AlrParentRef,
  AlrProfile,
  AlrSupersededByBody,
  AlrTransformClaim,
  AlrDisclosure,
} from "../types.ts";

// Phase A.2 — `claim_type` literal pulled from the family manifest instead of
// being re-declared here. ALR owns exactly one claim_type (`ar.lineage.v1`).
const ALR_CLAIM_TYPE = alrFamily.meta.claim_types[0] as "ar.lineage.v1";

export type { StatusListConfig, SuspensionListConfig, TsaFetcher };
export { TsaMintError };

import type { SigningKey } from "@dekimuhq/anchors-envelope/issuer";
export type { SigningKey };

// ── v=2 body shape (issuer side adds field_root) ──────────────────────────────

/**
 * Body emitted by the ALR v=2 mint surface. Identical to the verifier's
 * `AlrBody` discriminated union with a `field_root` commitment appended.
 * Verifier ignores extra fields today; future verifier hardening will
 * adopt this shape directly.
 */
export type AlrV2BodyOut = AlrBody & { field_root: string };

// ── Input interfaces ──────────────────────────────────────────────────────────

interface MintAlrV2Common {
  /** Issuer DID or short identifier. */
  issuer: string;
  /** Ed25519 signing key (32-byte seed). */
  signingKey: SigningKey;
  /** ALR regulatory profile (spec §5). */
  profile: AlrProfile;
  /** SHA-256 content address of the artifact this receipt is about. */
  artifact_hash: string;
  /** RFC 3339 issuer-claimed lineage event timestamp. */
  event_at: string;
  /** Optional: SHA-256 hash of an AAR receipt attesting QTS posture. */
  qts_attestation_hash?: string | null;
  /** Envelope-level policy URI (POLICY_BOUND on ar.lineage.v1). */
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
  /**
   * Optional: W3C Bitstring Status List 2021 pointer config. Attached BEFORE
   * signing per spec §5.5. ALR is the family's reference Status-List consumer
   * (FAMILY-CONSISTENCY §4).
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
   * v1.2 §4.1: receipt classification — observation vs decision. ALR receipts
   * default to `"decision"` (the issuer is asserting a lineage fact).
   * Pass `null` to opt out (v1.1-compat).
   */
  envelope_kind?: Kind | null;
  /**
   * v1.2 §4.2: typed trigger (closed enum). Optional. Plumbed verbatim
   * into the unsigned envelope (`null` when omitted).
   */
  cause?: Cause | null;
  /**
   * v1.2 §4.3: optional JSON Logic predicate. Operators MUST be inside the
   * v1.2 allowlist or the verifier rejects. Allowed on ar.lineage.v1 (no
   * claim_type forbids predicates in ALR).
   */
  predicate?: JsonLogicAst | null;
}

export interface MintAlrV2DerivedFromInput extends MintAlrV2Common {
  event_type: "derived_from";
  /** ≥1 parents; issuer-kit sorts canonically by `artifact_hash`. */
  parents: AlrParentRef[];
  /** Required, non-null. `summary` must be non-empty. */
  transform_claim: AlrTransformClaim;
}

export interface MintAlrV2ForkedFromInput extends MintAlrV2Common {
  event_type: "forked_from";
  /** Exactly 1 parent. */
  parents: [AlrParentRef];
  /** Optional. */
  transform_claim?: AlrTransformClaim | null;
}

export interface MintAlrV2SupersededByInput extends MintAlrV2Common {
  event_type: "superseded_by";
  /** The successor artifact reference. */
  successor: AlrParentRef;
  /** Required, non-null. `summary` must be non-empty. */
  transform_claim: AlrTransformClaim;
}

export interface MintAlrV2DisclosedInput extends MintAlrV2Common {
  event_type: "disclosed";
  /** Required disclosure record (all 4 sub-fields). */
  disclosure: AlrDisclosure;
}

export type MintAlrV2Input =
  | MintAlrV2DerivedFromInput
  | MintAlrV2ForkedFromInput
  | MintAlrV2SupersededByInput
  | MintAlrV2DisclosedInput;

// ── Internal helpers ──────────────────────────────────────────────────────────

function sortParents(parents: readonly AlrParentRef[]): AlrParentRef[] {
  return [...parents].sort((a, b) => {
    if (a.artifact_hash < b.artifact_hash) return -1;
    if (a.artifact_hash > b.artifact_hash) return 1;
    return 0;
  });
}

function buildBody(input: MintAlrV2Input): AlrBody {
  const base = {
    profile: input.profile,
    artifact_hash: input.artifact_hash,
    event_at: input.event_at,
    qts_attestation_hash: input.qts_attestation_hash ?? null,
  };
  switch (input.event_type) {
    case "derived_from": {
      const body: AlrDerivedFromBody = {
        ...base,
        event_type: "derived_from",
        parents: sortParents(input.parents),
        successor: null,
        transform_claim: input.transform_claim,
        disclosure: null,
      };
      return body;
    }
    case "forked_from": {
      const body: AlrForkedFromBody = {
        ...base,
        event_type: "forked_from",
        parents: input.parents,
        successor: null,
        transform_claim: input.transform_claim ?? null,
        disclosure: null,
      };
      return body;
    }
    case "superseded_by": {
      const body: AlrSupersededByBody = {
        ...base,
        event_type: "superseded_by",
        parents: [],
        successor: input.successor,
        transform_claim: input.transform_claim,
        disclosure: null,
      };
      return body;
    }
    case "disclosed": {
      const body: AlrDisclosedBody = {
        ...base,
        event_type: "disclosed",
        parents: [],
        successor: null,
        transform_claim: null,
        disclosure: input.disclosure,
      };
      return body;
    }
  }
}

// ── mintAlrV2 ─────────────────────────────────────────────────────────────────

export async function mintAlrV2(input: MintAlrV2Input): Promise<Envelope> {
  if (!input.issuer) throw new Error("mintAlrV2: issuer required");
  if (!input.signingKey?.kid) {
    throw new Error("mintAlrV2: signingKey.kid required");
  }
  if (!input.anchor) throw new Error("mintAlrV2: anchor required");
  if (!input.artifact_hash) throw new Error("mintAlrV2: artifact_hash required");

  switch (input.event_type) {
    case "derived_from":
      if (input.parents.length < 1) {
        throw new Error("mintAlrV2: derived_from requires ≥1 parent");
      }
      if (!input.transform_claim?.summary) {
        throw new Error("mintAlrV2: derived_from requires non-empty transform_claim.summary");
      }
      break;
    case "forked_from":
      if (input.parents.length !== 1) {
        throw new Error("mintAlrV2: forked_from requires exactly 1 parent");
      }
      break;
    case "superseded_by":
      if (!input.successor?.artifact_hash) {
        throw new Error("mintAlrV2: superseded_by requires successor.artifact_hash");
      }
      if (!input.transform_claim?.summary) {
        throw new Error("mintAlrV2: superseded_by requires non-empty transform_claim.summary");
      }
      break;
    case "disclosed":
      if (
        !input.disclosure?.recipient ||
        !input.disclosure?.recipient_role ||
        !input.disclosure?.scope_hash ||
        !input.disclosure?.basis
      ) {
        throw new Error("mintAlrV2: disclosed requires all 4 disclosure sub-fields");
      }
      break;
  }

  const baseBody = buildBody(input);
  const field_root = computeFieldRoot(baseBody);
  const bodyOut: AlrV2BodyOut = { ...baseBody, field_root };

  return alrFamily.mintV2({
    body: bodyOut,
    issuerPrivateKey: input.signingKey.privateKey,
    kid: input.signingKey.kid,
    issuerDid: input.issuer,
    subject: null,
    anchor: input.anchor,
    exp: input.exp ?? null,
    prev: input.prev ?? null,
    policy_uri: input.policy_uri,
    policy_hash: input.policy_hash,
    policy_version: input.policy_version,
    kind: input.envelope_kind === undefined ? "decision" : input.envelope_kind,
    cause: input.cause ?? null,
    predicate: input.predicate ?? null,
    ...(input.tsa !== undefined ? { tsa: input.tsa, tsaFetcher: input.tsaFetcher } : {}),
    ...(input.statusList !== undefined ? { statusList: input.statusList } : {}),
    ...(input.suspensionList !== undefined ? { suspensionList: input.suspensionList } : {}),
  });
}
