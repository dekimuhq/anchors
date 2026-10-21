/**
 * Local test fixtures for ASR Phase 3 — shared by family.test.ts,
 * body-schema.test.ts, subject-presence.test.ts, and round-trip.test.ts.
 *
 * Per-family helper (matches ANR's choice, not a shared abstraction):
 * bodies diverge sharply across families and a premature shared helper
 * has bitten the workspace before.
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
} from "../../src/types.ts";

/** Deterministic-per-run keypair shared across the suite. */
export const KP = generateKeypair("asr-test-key");

/** DER-encoded SPKI form for `resolveKey` round-trips. */
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
export const PUB_DER = new Uint8Array(
  Buffer.concat([SPKI_PREFIX, Buffer.from(KP.publicKey)]),
);

/** sha256:<64-hex> commit form, parameterised on a single repeated character. */
export const sha256 = (c: string): string => `sha256:${c.repeat(64)}`;

/** Default subject commit used by every fixture below. */
export const SUBJECT = sha256("a");

/** Stable anchor proof. ASR uses `verify.dekimu.com/asr/v1`. */
export const ANCHOR: AnchorProof = {
  log: "https://verify.dekimu.com/asr/v1",
  leaf_index: 0,
  inclusion_proof: [sha256("b")],
  tree_head_root: sha256("c"),
  tree_size: 1,
  log_time: "2026-05-19T00:00:00Z",
};

/** Stable subject-rights-request id reused across the suite. */
export const REQ_ID = "f4b2d4c0-6e1c-4b9f-9b6d-1a2b3c4d5e6f";

// ── Body fixtures (one per event_type) ───────────────────────────────────────

export const bodyRequestReceived = (): AsrRequestReceivedBody => ({
  event_type: "request.received",
  subject_rights_request_id: REQ_ID,
  qts_attestation_hash: null,
  channel: "email",
  received_at: "2026-05-19T08:00:00Z",
  deadline_at: "2026-06-18T08:00:00Z",
});

export const bodyIdentityVerified = (): AsrIdentityVerifiedBody => ({
  event_type: "request.identity_verified",
  subject_rights_request_id: REQ_ID,
  qts_attestation_hash: null,
  verification_method_hash: sha256("1"),
});

export const bodyScopeClarified = (): AsrScopeClarifiedBody => ({
  event_type: "request.scope_clarified",
  subject_rights_request_id: REQ_ID,
  qts_attestation_hash: null,
  scope_clarification_hash: sha256("2"),
});

export const bodyExtended = (): AsrExtendedBody => ({
  event_type: "request.extended",
  subject_rights_request_id: REQ_ID,
  qts_attestation_hash: null,
  extension_reason_hash: sha256("3"),
  extended_until_at: "2026-07-18T08:00:00Z",
});

export const bodyPartiallyHonoured = (): AsrPartiallyHonouredBody => ({
  event_type: "request.partially_honoured",
  subject_rights_request_id: REQ_ID,
  qts_attestation_hash: null,
  fulfilled_partial_scope: ["art15"],
  fulfilled_artifact_hash: sha256("4"),
  fulfilment_uri: "https://example.test/artifact",
  refusal_ground: "art17_3_b_legal_obligation",
  refusal_justification_hash: sha256("5"),
});

export const bodyFulfilled = (): AsrFulfilledBody => ({
  event_type: "request.fulfilled",
  subject_rights_request_id: REQ_ID,
  qts_attestation_hash: null,
  fulfilled_artifact_hash: sha256("6"),
  fulfilment_uri: "https://example.test/artifact",
});

export const bodyRefused = (): AsrRefusedBody => ({
  event_type: "request.refused",
  subject_rights_request_id: REQ_ID,
  qts_attestation_hash: null,
  refusal_ground: "art12_5_a_unfounded",
  refusal_justification_hash: sha256("7"),
});

export const bodyEscalated = (): AsrEscalatedBody => ({
  event_type: "request.escalated",
  subject_rights_request_id: REQ_ID,
  qts_attestation_hash: null,
  escalation_dpa_reference: null,
});

export const bodyRecipientNotified = (): AsrRecipientNotifiedBody => ({
  event_type: "request.recipient_notified",
  subject_rights_request_id: REQ_ID,
  qts_attestation_hash: null,
  recipient_set_alr_ids: ["alr_01HK0000000000000000000001"],
  recipient_notification_uri: "https://example.test/art19-notify",
  recipient_notification_hash: sha256("8"),
});

// ── Mint helpers ─────────────────────────────────────────────────────────────

export interface MintOverrides {
  readonly body?: unknown;
  readonly subject?: string | null;
  readonly profile?: string;
  readonly issuerPrivateKey?: Uint8Array;
}

/**
 * Build a `FamilyMintV2Input` against the canonical fixtures. `profile` is
 * not part of `FamilyMintV2Input` itself — pass through `predicate` /
 * profile dispatch is handled by the factory pipeline; tests that need
 * profile dispatch call `verifyReceipt({ profile_id })` instead.
 */
export function mintInput(over: MintOverrides = {}): FamilyMintV2Input {
  return {
    body: over.body ?? bodyRequestReceived(),
    issuerPrivateKey: over.issuerPrivateKey ?? KP.privateKey,
    issuerDid: "did:web:test.example.com",
    subject: over.subject === undefined ? SUBJECT : over.subject,
    anchor: ANCHOR,
    policy_uri: "https://example.test/policy.json",
    policy_hash: sha256("9"),
    policy_version: "2026-05-19",
    kind: "observation",
    cause: "manual",
  };
}
