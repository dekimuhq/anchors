/**
 * Shared keypair / anchor / resolveKey / body-fixture helpers for
 * asr-issuer-kit tests. Per-family local helper (mirrors
 * abr/air/alr/anr-issuer-kit pattern).
 *
 * Mint goes through `mintAsrV2` (= `asrFamily.mintV2`); the input shape is
 * `FamilyMintV2Input` — body / issuerPrivateKey / issuerDid / subject /
 * anchor / policy_* / optional kind / cause / predicate / statusList.
 */

import { Buffer } from "node:buffer";
import { generateKeypair } from "@dekimuhq/anchors-envelope";
import type { AnchorProof, FamilyMintV2Input } from "@dekimuhq/anchors-envelope";
import type {
  AsrEscalatedBody,
  AsrExtendedBody,
  AsrFulfilledBody,
  AsrIdentityVerifiedBody,
  AsrPartiallyHonouredBody,
  AsrRecipientNotifiedBody,
  AsrRefusedBody,
  AsrRequestReceivedBody,
  AsrScopeClarifiedBody,
} from "../../src/index.ts";

/** Deterministic-per-run keypair shared across the suite. */
export const KP = generateKeypair("asr-issuer-kit-test-key");

const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/** DER-encoded SPKI form of `KP.publicKey` for `resolveKey` round-trips. */
export const PUB_DER = new Uint8Array(
  Buffer.concat([SPKI_PREFIX, Buffer.from(KP.publicKey)]),
);

/** sha256:<64-hex> commit form, parameterised on a single repeated character. */
export const sha256 = (c: string): string => `sha256:${c.repeat(64)}`;

/** Default subject commit used by fixtures below. */
export const SUBJECT = sha256("a");

/** Stable subject-rights-request id reused across the suite. */
export const REQ_ID = "f4b2d4c0-6e1c-4b9f-9b6d-1a2b3c4d5e6f";

/** Stable anchor proof. */
export const ANCHOR: AnchorProof = {
  log: "https://verify.dekimu.com/asr/v1",
  leaf_index: 0,
  inclusion_proof: [sha256("b")],
  tree_head_root: sha256("c"),
  tree_size: 1,
  log_time: "2026-05-19T00:00:00Z",
};

/** Async resolveKey returning the fixed PUB_DER. Verifier passes the full
 *  envelope; we ignore it because the suite uses a single key. */
export const resolveKey = async (
  _envelope: unknown,
): Promise<Uint8Array> => PUB_DER;

// ── Body fixtures (one per event_type) ───────────────────────────────────────

export const bodyRequestReceived = (
  o: Partial<AsrRequestReceivedBody> = {},
): AsrRequestReceivedBody => ({
  event_type: "request.received",
  subject_rights_request_id: REQ_ID,
  qts_attestation_hash: null,
  channel: "email",
  received_at: "2026-05-19T08:00:00Z",
  deadline_at: "2026-06-18T08:00:00Z",
  ...o,
});

export const bodyIdentityVerified = (
  o: Partial<AsrIdentityVerifiedBody> = {},
): AsrIdentityVerifiedBody => ({
  event_type: "request.identity_verified",
  subject_rights_request_id: REQ_ID,
  qts_attestation_hash: null,
  verification_method_hash: sha256("1"),
  ...o,
});

export const bodyScopeClarified = (
  o: Partial<AsrScopeClarifiedBody> = {},
): AsrScopeClarifiedBody => ({
  event_type: "request.scope_clarified",
  subject_rights_request_id: REQ_ID,
  qts_attestation_hash: null,
  scope_clarification_hash: sha256("2"),
  ...o,
});

export const bodyExtended = (
  o: Partial<AsrExtendedBody> = {},
): AsrExtendedBody => ({
  event_type: "request.extended",
  subject_rights_request_id: REQ_ID,
  qts_attestation_hash: null,
  extension_reason_hash: sha256("3"),
  extended_until_at: "2026-07-18T08:00:00Z",
  ...o,
});

export const bodyPartiallyHonoured = (
  o: Partial<AsrPartiallyHonouredBody> = {},
): AsrPartiallyHonouredBody => ({
  event_type: "request.partially_honoured",
  subject_rights_request_id: REQ_ID,
  qts_attestation_hash: null,
  fulfilled_partial_scope: ["art15"],
  fulfilled_artifact_hash: sha256("4"),
  fulfilment_uri: "https://example.test/artifact",
  refusal_ground: "art17_3_b_legal_obligation",
  refusal_justification_hash: sha256("5"),
  ...o,
});

export const bodyFulfilled = (
  o: Partial<AsrFulfilledBody> = {},
): AsrFulfilledBody => ({
  event_type: "request.fulfilled",
  subject_rights_request_id: REQ_ID,
  qts_attestation_hash: null,
  fulfilled_artifact_hash: sha256("6"),
  fulfilment_uri: "https://example.test/artifact",
  ...o,
});

export const bodyRefused = (
  o: Partial<AsrRefusedBody> = {},
): AsrRefusedBody => ({
  event_type: "request.refused",
  subject_rights_request_id: REQ_ID,
  qts_attestation_hash: null,
  refusal_ground: "art12_5_a_unfounded",
  refusal_justification_hash: sha256("7"),
  ...o,
});

export const bodyEscalated = (
  o: Partial<AsrEscalatedBody> = {},
): AsrEscalatedBody => ({
  event_type: "request.escalated",
  subject_rights_request_id: REQ_ID,
  qts_attestation_hash: null,
  escalation_dpa_reference: null,
  ...o,
});

export const bodyRecipientNotified = (
  o: Partial<AsrRecipientNotifiedBody> = {},
): AsrRecipientNotifiedBody => ({
  event_type: "request.recipient_notified",
  subject_rights_request_id: REQ_ID,
  qts_attestation_hash: null,
  recipient_set_alr_ids: ["alr_01HK0000000000000000000001"],
  recipient_notification_uri: "https://example.test/art19-notify",
  recipient_notification_hash: sha256("8"),
  ...o,
});

// ── Mint helpers ─────────────────────────────────────────────────────────────

export interface MintOverrides {
  readonly body?: unknown;
  readonly subject?: string | null;
  readonly issuerPrivateKey?: Uint8Array;
  readonly exp?: string | null;
  readonly prev?: string | null;
  readonly kind?: "observation" | "decision" | null;
  readonly cause?:
    | "manual"
    | "scheduled"
    | "event"
    | "api"
    | "regulatory_request"
    | "rectification"
    | "erasure_request"
    | "portability_request"
    | "objection"
    | "automated_decision_review"
    | "breach"
    | "review_cycle"
    | "material_change"
    | null;
  readonly predicate?: unknown;
  readonly policy_uri?: string | null;
  readonly policy_hash?: string | null;
  readonly policy_version?: string | null;
  readonly claim_type?: string;
  readonly statusList?: FamilyMintV2Input["statusList"];
}

/** Canonical mint input — every field set with stable values; spread to override. */
export function mintInput(over: MintOverrides = {}): FamilyMintV2Input {
  const base: FamilyMintV2Input = {
    body: over.body ?? bodyRequestReceived(),
    issuerPrivateKey: over.issuerPrivateKey ?? KP.privateKey,
    issuerDid: "did:web:test.example.com",
    subject: over.subject === undefined ? SUBJECT : over.subject,
    anchor: ANCHOR,
    policy_uri:
      over.policy_uri === undefined
        ? "https://example.test/policy.json"
        : over.policy_uri,
    policy_hash:
      over.policy_hash === undefined ? sha256("9") : over.policy_hash,
    policy_version:
      over.policy_version === undefined ? "2026-05-19" : over.policy_version,
    kind: over.kind === undefined ? "observation" : over.kind,
    cause: over.cause === undefined ? "manual" : over.cause,
  };
  const out: Record<string, unknown> = { ...base };
  if (over.exp !== undefined) out.exp = over.exp;
  if (over.prev !== undefined) out.prev = over.prev;
  if (over.predicate !== undefined) out.predicate = over.predicate;
  if (over.claim_type !== undefined) out.claim_type = over.claim_type;
  if (over.statusList !== undefined) out.statusList = over.statusList;
  return out as unknown as FamilyMintV2Input;
}
