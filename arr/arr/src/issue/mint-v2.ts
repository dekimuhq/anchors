/**
 * ARR v=2 mint path — produces v=2 Envelopes for Anchored Retention Receipts.
 *
 * Exports two functions:
 *   - mintArrV2Single — single-target receipts (5 non-batch claim types)
 *   - mintArrV2Batch  — batch receipts (ar.batch.v1)
 *
 * The anchor field is supplied by the caller; post-mint the log worker can
 * replace it with a real inclusion proof (anchor is signed-out, so that
 * replacement does not invalidate the signature).
 *
 * Phase B Task 12d.
 */

import { createHash } from "node:crypto";
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
import { buildTree } from "@dekimuhq/acr";
import { canonicalize } from "@dekimuhq/anchors-envelope";
import type {
  ArrProfile,
  ArrTargetKind,
  ArrTrigger,
  ArrStateSnapshot,
  ArrBatchEventKind,
  ArrProfileAttributes,
} from "../types.ts";
import { MAX_BATCH_TARGET_COUNT as MAX_BATCH } from "../types.ts";
import { arrFamily } from "../family.ts";

// Phase A.3 step 2 — `ar.batch.v1` literal pulled from the family manifest
// instead of being re-declared inline. Single-target mints use the
// `input.kind` parameter which is already typed against the manifest's
// owned claim_types.
const ARR_BATCH_CLAIM_TYPE = arrFamily.meta.claim_types[5] as "ar.batch.v1";
import type { BatchTarget } from "./mint-batch.ts";

export type { TsaFetcher };

// ── Claim type unions ─────────────────────────────────────────────────────────

/**
 * The 5 v=2 single-target ARR claim types (ar.hold.v1 is v=2-only — it does
 * not exist in the v=1 ArrSingleKind union which used arr.hold_extension.v1
 * and arr.hold_release.v1 instead).
 */
export type ArrV2SingleKind =
  | "ar.erasure.v1"
  | "ar.expiry.v1"
  | "ar.hold.v1"
  | "ar.anonymization.v1"
  | "ar.archive.v1";

import type { SigningKey } from "@dekimuhq/anchors-envelope/issuer";
export type { SigningKey };

// ── v=2 body shapes ───────────────────────────────────────────────────────────

/** Body carried inside a v=2 single-target ARR envelope. */
export interface ArrV2SingleBody {
  profile: ArrProfile;
  target_kind: ArrTargetKind;
  target_commit: string;
  salt_epoch: string;
  policy_hash: string;
  policy_uri: string;
  policy_version: string;
  trigger: ArrTrigger;
  trigger_receipt: string | null;
  event_at: string;
  granted_at: string;
  effective_until: string | null;
  state_snapshot: ArrStateSnapshot;
  field_root: string;
  /** SHA-256 hash of an AAR receipt attesting QTS posture. `null` when absent. */
  qts_attestation_hash: string | null;
  /**
   * Optional profile-specific attributes (additive; omitted when no regulated
   * retention profile applies). Read by the registered retention
   * `ProfileValidator`s. Rides outside `field_root`, like `qts_attestation_hash`.
   */
  profile_attributes?: ArrProfileAttributes;
}

/** Body carried inside a v=2 batch ARR envelope. */
export interface ArrV2BatchBody {
  profile: ArrProfile;
  batch_event_kind: ArrBatchEventKind;
  target_kind: ArrTargetKind;
  target_root: string;
  target_count: number;
  salt_epoch: string;
  policy_hash: string;
  policy_uri: string;
  policy_version: string;
  trigger: ArrTrigger;
  trigger_receipt: string | null;
  event_at: string;
  granted_at: string;
  effective_until: string | null;
  state_snapshot_root: string;
  field_root: string;
  /** SHA-256 hash of an AAR receipt attesting QTS posture. `null` when absent. */
  qts_attestation_hash: string | null;
  /** Optional profile-specific attributes (additive). See `ArrV2SingleBody`. */
  profile_attributes?: ArrProfileAttributes;
}

// ── Input interfaces ──────────────────────────────────────────────────────────

export interface MintArrV2SingleInput {
  /** Issuer DID or short identifier. */
  issuer: string;
  /** Ed25519 signing key (32-byte seed). */
  signingKey: SigningKey;
  /** Which single-target ARR claim type to mint. */
  kind: ArrV2SingleKind;
  /** Envelope-level subject — typically "sha256:<hex>" of the target identifier. */
  subject: string;
  /** ARR retention profile. */
  profile: ArrProfile;
  /** Kind of retention target. */
  target_kind: ArrTargetKind;
  /** Salted commitment to the target identifier. */
  target_commit: string;
  /** Salt epoch string. */
  salt_epoch: string;
  /** Policy document hash. */
  policy_hash: string;
  /** Policy document URI. */
  policy_uri: string;
  /** Semantic version of the policy. */
  policy_version: string;
  /** What triggered the retention event. */
  trigger: ArrTrigger;
  /** Receipt for subject request trigger (required when trigger === "subject_request"). */
  trigger_receipt: string | null;
  /** ISO 8601 UTC timestamp of the retention event. */
  event_at: string;
  /** ISO 8601 UTC timestamp of when the record was granted/processed. */
  granted_at: string;
  /** ISO 8601 UTC timestamp until which a hold or archive is effective. */
  effective_until?: string | null;
  /** State snapshot at time of event. */
  state_snapshot: ArrStateSnapshot;
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
   * v1.2 §4.1: receipt classification — observation vs decision. The 5
   * single-target ARR kinds are all `"decision"` per spec §6 — that is the
   * default when omitted. Callers may pass `null` explicitly to opt out
   * (e.g. v1.1-compat issuance under v1.2 transport).
   *
   * Named `envelope_kind` to avoid collision with the existing `kind` field
   * which carries the ARR claim_type discriminator (`ar.erasure.v1`, …).
   */
  envelope_kind?: Kind | null;
  /**
   * v1.2 §4.2: typed trigger (closed enum). Optional. Plumbed verbatim
   * into the unsigned envelope (`null` when omitted).
   */
  cause?: Cause | null;
  /**
   * v1.2 §4.3: optional JSON Logic predicate committed to the receipt.
   * Operators MUST be inside the v1.2 allowlist or the verifier rejects.
   * Plumbed verbatim (`null` when omitted); the issuer is responsible for
   * ensuring the predicate evaluates to `true` against the minted envelope.
   */
  predicate?: JsonLogicAst | null;
  /** Optional: SHA-256 hash of an AAR receipt attesting QTS posture. */
  qts_attestation_hash?: string | null;
  /**
   * Optional: profile-specific attributes for a regulated retention profile
   * (gdpr.art5e, hipaa.retention, kyc.retention, sox.retention,
   * mifid2.retention, aiact.art10). Carried verbatim in the body; read by the
   * matching registered `ProfileValidator` at verify time.
   */
  profile_attributes?: ArrProfileAttributes;
}

export interface MintArrV2BatchInput {
  /** Issuer DID or short identifier. */
  issuer: string;
  /** Ed25519 signing key (32-byte seed). */
  signingKey: SigningKey;
  /** Envelope-level subject — typically identifies the batch operation. */
  subject: string;
  /** ARR retention profile. */
  profile: ArrProfile;
  /** Sub-kind of the batch event. */
  batch_event_kind: ArrBatchEventKind;
  /** Kind of retention targets in this batch. */
  target_kind: ArrTargetKind;
  /** Salt epoch string. */
  salt_epoch: string;
  /** Policy document hash. */
  policy_hash: string;
  /** Policy document URI. */
  policy_uri: string;
  /** Semantic version of the policy. */
  policy_version: string;
  /** What triggered the batch event. */
  trigger: ArrTrigger;
  /** Receipt for subject request trigger. */
  trigger_receipt: string | null;
  /** ISO 8601 UTC timestamp of the batch event. */
  event_at: string;
  /** ISO 8601 UTC timestamp of when the batch was processed. */
  granted_at: string;
  /** ISO 8601 UTC — effective_until for holds/archives in the batch. */
  effective_until?: string | null;
  /** Per-target data (target_commit + state_snapshot). */
  targets: BatchTarget[];
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
   * Optional: Status List configuration. When provided, a W3C Bitstring Status
   * List 2021 Entry pointer is minted per-envelope BEFORE signing (§5.5).
   * Batch envelopes receive one shared pointer for the entire batch event.
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
   * v1.2 §4.2: typed trigger (closed enum). Optional. Plumbed verbatim
   * into the unsigned envelope (`null` when omitted).
   *
   * NOTE: ar.batch.v1 envelopes do not carry a `kind` (always null per spec
   * §6 — kind lives on member receipts) and MUST NOT carry a `predicate`
   * (L9 + §6 — predicates live on member receipts). Only `cause` is
   * meaningful on batch envelopes.
   */
  cause?: Cause | null;
  /** Optional: SHA-256 hash of an AAR receipt attesting QTS posture. */
  qts_attestation_hash?: string | null;
  /** Optional: profile-specific attributes (additive). See `MintArrV2SingleInput`. */
  profile_attributes?: ArrProfileAttributes;
}

// ── field_root helpers ────────────────────────────────────────────────────────

function computeSingleFieldRoot(
  input: MintArrV2SingleInput,
): string {
  const fields = {
    kind: input.kind,
    profile: input.profile,
    target_kind: input.target_kind,
    target_commit: input.target_commit,
    salt_epoch: input.salt_epoch,
    policy_hash: input.policy_hash,
    policy_uri: input.policy_uri,
    policy_version: input.policy_version,
    trigger: input.trigger,
    trigger_receipt: input.trigger_receipt,
    event_at: input.event_at,
    granted_at: input.granted_at,
    effective_until: input.effective_until ?? null,
  };
  const bytes = new TextEncoder().encode(canonicalize(fields));
  const prefixed = Buffer.concat([Buffer.from([0x00]), Buffer.from(bytes)]);
  return "sha256:" + createHash("sha256").update(prefixed).digest("hex");
}

function snapshotLeafHash(snap: ArrStateSnapshot): string {
  const bytes = new TextEncoder().encode(canonicalize(snap));
  return "sha256:" + createHash("sha256").update(bytes).digest("hex");
}

function computeBatchFieldRoot(
  input: MintArrV2BatchInput,
  target_root: string,
  state_snapshot_root: string,
): string {
  const fields = {
    kind: "ar.batch.v1",
    profile: input.profile,
    batch_event_kind: input.batch_event_kind,
    target_kind: input.target_kind,
    target_root,
    target_count: input.targets.length,
    salt_epoch: input.salt_epoch,
    policy_hash: input.policy_hash,
    policy_uri: input.policy_uri,
    policy_version: input.policy_version,
    trigger: input.trigger,
    trigger_receipt: input.trigger_receipt,
    event_at: input.event_at,
    granted_at: input.granted_at,
    effective_until: input.effective_until ?? null,
    state_snapshot_root,
  };
  const bytes = new TextEncoder().encode(canonicalize(fields));
  const prefixed = Buffer.concat([Buffer.from([0x00]), Buffer.from(bytes)]);
  return "sha256:" + createHash("sha256").update(prefixed).digest("hex");
}

// ── mintArrV2Single ───────────────────────────────────────────────────────────

export async function mintArrV2Single(
  input: MintArrV2SingleInput,
): Promise<Envelope> {
  if (!input.issuer) throw new Error("mintArrV2Single: issuer required");
  if (!input.subject) throw new Error("mintArrV2Single: subject required");
  if (!input.kind) throw new Error("mintArrV2Single: kind required");
  if (!input.signingKey?.kid) {
    throw new Error("mintArrV2Single: signingKey.kid required");
  }
  if (!input.anchor) throw new Error("mintArrV2Single: anchor required");
  if (input.trigger === "subject_request" && !input.trigger_receipt) {
    throw new Error("mintArrV2Single: trigger_receipt required for subject_request");
  }
  if (input.kind === "ar.archive.v1" && !input.effective_until) {
    throw new Error("mintArrV2Single: effective_until required for ar.archive.v1");
  }

  const field_root = computeSingleFieldRoot(input);

  const body: ArrV2SingleBody = {
    profile: input.profile,
    target_kind: input.target_kind,
    target_commit: input.target_commit,
    salt_epoch: input.salt_epoch,
    policy_hash: input.policy_hash,
    policy_uri: input.policy_uri,
    policy_version: input.policy_version,
    trigger: input.trigger,
    trigger_receipt: input.trigger_receipt,
    event_at: input.event_at,
    granted_at: input.granted_at,
    effective_until: input.effective_until ?? null,
    state_snapshot: input.state_snapshot,
    field_root,
    qts_attestation_hash: input.qts_attestation_hash ?? null,
    ...(input.profile_attributes !== undefined
      ? { profile_attributes: input.profile_attributes }
      : {}),
  };

  // v1.2 §6: ARR single-target kinds default to envelope_kind = "decision".
  // Respect explicit null for v1.1-compat issuance. Field name `envelope_kind`
  // avoids collision with the ARR claim_type discriminator (input.kind).
  const envelopeKindOut: Kind | null =
    input.envelope_kind === undefined ? "decision" : input.envelope_kind;

  return arrFamily.mintV2({
    body,
    issuerPrivateKey: input.signingKey.privateKey,
    kid: input.signingKey.kid,
    issuerDid: input.issuer,
    subject: input.subject,
    claim_type: input.kind,
    anchor: input.anchor,
    exp: input.exp ?? null,
    prev: input.prev ?? null,
    // Dual-carry per Phase C Task 14: envelope-level slots MUST be populated
    // because the 5 ARR single-target kinds are POLICY_BOUND (validatePolicyFields
    // rejects null/empty values on these claim types). The body copy is kept
    // unchanged for v=1 body-schema parity — body remains the source of truth
    // for ARR-specific semantics; the envelope copy is what the policy matrix
    // enforces.
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

// ── mintArrV2Batch ────────────────────────────────────────────────────────────

export async function mintArrV2Batch(
  input: MintArrV2BatchInput,
): Promise<Envelope> {
  if (!input.issuer) throw new Error("mintArrV2Batch: issuer required");
  if (!input.subject) throw new Error("mintArrV2Batch: subject required");
  if (!input.signingKey?.kid) {
    throw new Error("mintArrV2Batch: signingKey.kid required");
  }
  if (!input.anchor) throw new Error("mintArrV2Batch: anchor required");
  if (input.targets.length === 0) {
    throw new Error("mintArrV2Batch: target_count.zero");
  }
  if (input.targets.length > MAX_BATCH) {
    throw new Error("mintArrV2Batch: target_count.exceeds_max");
  }
  if (input.trigger === "subject_request" && !input.trigger_receipt) {
    throw new Error("mintArrV2Batch: trigger_receipt required for subject_request");
  }

  const target_root = buildTree(
    input.targets.map((t) => t.target_commit),
  ).root;
  const state_snapshot_root = buildTree(
    input.targets.map((t) => snapshotLeafHash(t.state_snapshot)),
  ).root;
  const field_root = computeBatchFieldRoot(
    input,
    target_root,
    state_snapshot_root,
  );

  const body: ArrV2BatchBody = {
    profile: input.profile,
    batch_event_kind: input.batch_event_kind,
    target_kind: input.target_kind,
    target_root,
    target_count: input.targets.length,
    salt_epoch: input.salt_epoch,
    policy_hash: input.policy_hash,
    policy_uri: input.policy_uri,
    policy_version: input.policy_version,
    trigger: input.trigger,
    trigger_receipt: input.trigger_receipt,
    event_at: input.event_at,
    granted_at: input.granted_at,
    effective_until: input.effective_until ?? null,
    state_snapshot_root,
    field_root,
    qts_attestation_hash: input.qts_attestation_hash ?? null,
    ...(input.profile_attributes !== undefined
      ? { profile_attributes: input.profile_attributes }
      : {}),
  };

  return arrFamily.mintV2({
    body,
    issuerPrivateKey: input.signingKey.privateKey,
    kid: input.signingKey.kid,
    issuerDid: input.issuer,
    subject: input.subject,
    claim_type: ARR_BATCH_CLAIM_TYPE,
    anchor: input.anchor,
    exp: input.exp ?? null,
    prev: input.prev ?? null,
    // ar.batch.v1 is excluded from the POLICY_BOUND set (Phase C Task 14
    // matrix): per-item policy lives inside the body per batch target, so
    // envelope-level slots stay null. Single-target ARR mints mirror policy
    // fields onto the envelope; batch does not.
    policy_uri: null,
    policy_hash: null,
    policy_version: null,
    // v1.2 §6: ar.batch.v1 carries kind=null (envelope of envelopes — kind
    // lives on members). predicate is forbidden (L9 + §6) — not passed to
    // factory so the field is absent from the signed envelope.
    kind: null,
    cause: input.cause ?? null,
    ...(input.statusList !== undefined ? { statusList: input.statusList } : {}),
    ...(input.suspensionList !== undefined ? { suspensionList: input.suspensionList } : {}),
    ...(input.tsa !== undefined ? { tsa: input.tsa, tsaFetcher: input.tsaFetcher } : {}),
  });
}

// Re-export TsaMintError so consumers can catch it without importing tsa sub-path.
export { TsaMintError };
