/**
 * ACR v=2 mint path — produces a v=2 Envelope with one of the three ACR
 * claim_type discriminators.
 *
 * The anchor field is supplied by the caller; post-mint the log worker can
 * replace it with a real inclusion proof (anchor is signed-out, so that
 * replacement does not invalidate the signature).
 *
 * Phase B Task 12c.
 */

import {
  type Envelope,
  type AnchorProof,
  type Kind,
  type Cause,
  type JsonLogicAst,
} from "@dekimuhq/anchors-envelope";
import { TsaMintError, type TsaFetcher, type TsaConfig } from "@dekimuhq/anchors-envelope/tsa";
import type { StatusListConfig } from "@dekimuhq/anchors-envelope/status";
import type { SuspensionListConfig } from "@dekimuhq/anchors-envelope/status";

export type { StatusListConfig, SuspensionListConfig };
import {
  acrFamily,
  commit,
  randomSalt,
  buildTree,
  type AcrProfile,
} from "../index.ts";

export type { TsaFetcher };

/** The three ACR claim_type discriminators. */
export type AcrV2Kind =
  | "ar.consent.v1"
  | "ar.withdrawal.v1"
  | "ar.modification.v1";

/** Per-field plaintext value with optional pre-existing salt. */
interface FieldInput {
  /** Plaintext value to commit (will be salted). */
  value: string;
  /** Optional pre-existing salt. If absent, a fresh one is generated. */
  salt?: string;
}

/** ACR-specific body that lives inside the v=2 envelope `body` field. */
export interface AcrV2Body {
  /** Regulation profile for this receipt. */
  profile: AcrProfile;
  /** Salted commitment to the data subject identifier. */
  sub_commit: string;
  /** Salted commitments to each purpose descriptor. */
  purposes: string[];
  /** Profile-specific lawful basis string. */
  lawful_basis: string;
  /** Salted commitment to the consented policy document hash. */
  policy_hash: string;
  /** RFC 3339 timestamp of consent grant claimed by issuer. */
  granted_at: string;
  /** Merkle root over all per-field commitments. */
  field_root: string;
  /** Cross-sibling QTS attestation hash — references an AAR receipt hash. */
  qts_attestation_hash: string | null;
}

export interface MintAcrV2Input {
  /** Issuer DID or short identifier. */
  issuer: string;
  /** Ed25519 keypair (from `./keys.ts`). */
  keypair: {
    kid: string;
    privateKey: Uint8Array;
  };
  /** Which ACR claim type to mint. */
  kind: AcrV2Kind;
  /** Envelope-level subject (whole-doc hash, e.g. `"sha256:<hex>"`). */
  subject: string;
  /** ACR profile for the consent context. */
  profile: AcrProfile;
  /** Per-field plaintext values + optional pre-existing salts. */
  fields: {
    sub_commit: FieldInput;
    purposes: FieldInput[];
    policy_hash: FieldInput;
  };
  /** Profile-specific lawful basis string. */
  lawful_basis: string;
  /** RFC 3339 timestamp of consent grant claimed by issuer. */
  granted_at: string;
  /** Anchor proof (caller supplies; log worker replaces post-mint). */
  anchor: AnchorProof;
  /** Optional: previous receipt ID for chain linkage. */
  prev?: string | null;
  /** Optional: expiry ISO 8601 UTC. */
  exp?: string | null;
  /** Optional: policy URI at envelope level. */
  policy_uri?: string | null;
  /** Optional: policy document hash at envelope level. */
  policy_hash?: string | null;
  /** Optional: policy semantic version at envelope level. */
  policy_version?: string | null;
  /** Optional: TSA configuration. If present, tsaFetcher must also be provided. */
  tsa?: TsaConfig;
  /** Optional: TSA fetcher (caller-provided; required if `tsa` is set). */
  tsaFetcher?: TsaFetcher;
  /**
   * Optional: Status List configuration. When provided, a W3C Bitstring Status
   * List 2021 Entry pointer is minted and embedded BEFORE signing (§5.5).
   * When omitted, `credentialStatus` stays `null`.
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
   * v1.2 §4.1: receipt classification — observation vs decision. ACR member
   * types are all `"decision"` per spec §6 — that is the default when omitted.
   * Callers may pass `null` explicitly to opt out (e.g. v1.1-compat issuance
   * under v1.2 transport).
   *
   * Named `envelope_kind` to avoid collision with the existing `kind` field
   * which carries the ACR claim_type discriminator (`ar.consent.v1`, …).
   */
  envelope_kind?: Kind | null;
  /**
   * v1.2 §4.2: typed trigger (closed enum). Optional. Plumbed verbatim
   * into the unsigned envelope (`null` when omitted).
   */
  cause?: Cause | null;
  /**
   * v1.2 §4.3: optional JSON Logic predicate committed to the receipt.
   * Recommended for consent receipts (spec §6 matrix). Operators MUST be
   * inside the v1.2 allowlist or the verifier will reject. Plumbed verbatim
   * (`null` when omitted); the issuer is responsible for ensuring the
   * predicate evaluates to `true` against the minted envelope.
   */
  predicate?: JsonLogicAst | null;
  /** Cross-sibling QTS attestation hash — references an AAR receipt hash. */
  qts_attestation_hash?: string | null;
}

// ── Per-field commit builder ──────────────────────────────────────────────────

function buildFieldCommits(fields: MintAcrV2Input["fields"]): {
  sub_commit: string;
  purposes: string[];
  policy_hash: string;
  field_root: string;
} {
  const subSalt = fields.sub_commit.salt ?? randomSalt();
  const sub_commit = commit(subSalt, fields.sub_commit.value);

  const purposeSalts = fields.purposes.map((p) => p.salt ?? randomSalt());
  const purposes = fields.purposes.map((p, i) =>
    commit(purposeSalts[i]!, p.value),
  );

  const polSalt = fields.policy_hash.salt ?? randomSalt();
  const policy_hash = commit(polSalt, fields.policy_hash.value);

  const leaves = [sub_commit, ...purposes, policy_hash];
  const { root: field_root } = buildTree(leaves);

  return { sub_commit, purposes, policy_hash, field_root };
}

// ── mintAcrV2 ─────────────────────────────────────────────────────────────────

export async function mintAcrV2(input: MintAcrV2Input): Promise<Envelope> {
  if (!input.issuer) throw new Error("mintAcrV2: issuer required");
  if (!input.subject) throw new Error("mintAcrV2: subject required");
  if (!input.kind) throw new Error("mintAcrV2: kind required");
  if (!input.keypair?.kid) throw new Error("mintAcrV2: keypair.kid required");
  if (!input.anchor) throw new Error("mintAcrV2: anchor required");
  if (!input.fields?.purposes?.length) {
    throw new Error("mintAcrV2: at least one purpose field is required");
  }

  const { sub_commit, purposes, policy_hash, field_root } =
    buildFieldCommits(input.fields);

  const acrBody: AcrV2Body = {
    profile: input.profile,
    sub_commit,
    purposes,
    lawful_basis: input.lawful_basis,
    policy_hash,
    granted_at: input.granted_at,
    field_root,
    qts_attestation_hash: input.qts_attestation_hash ?? null,
  };

  // v1.2 §6: ACR member types default to envelope_kind = "decision". Respect
  // explicit null for v1.1-compat issuance. Explicit "observation"/"decision"
  // pass through. Field name `envelope_kind` avoids collision with the
  // ACR claim_type discriminator (input.kind).
  const envelopeKindOut: Kind | null =
    input.envelope_kind === undefined ? "decision" : input.envelope_kind;

  return acrFamily.mintV2({
    body: acrBody,
    issuerPrivateKey: input.keypair.privateKey,
    kid: input.keypair.kid,
    issuerDid: input.issuer,
    subject: input.subject,
    claim_type: input.kind,
    anchor: input.anchor,
    exp: input.exp ?? null,
    prev: input.prev ?? null,
    policy_uri: input.policy_uri ?? null,
    policy_hash: input.policy_hash ?? null,
    policy_version: input.policy_version ?? null,
    kind: envelopeKindOut,
    cause: input.cause ?? null,
    predicate: input.predicate ?? null,
    ...(input.statusList !== undefined ? { statusList: input.statusList } : {}),
    ...(input.suspensionList !== undefined ? { suspensionList: input.suspensionList } : {}),
    ...(input.tsa !== undefined ? { tsa: input.tsa, tsaFetcher: input.tsaFetcher } : {}),
  });
}

// Re-export TsaMintError so consumers can catch it without importing tsa sub-path.
export { TsaMintError };
