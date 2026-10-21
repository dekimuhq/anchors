import { createHash, type KeyObject } from "node:crypto";
import { canonicalize } from "@dekimuhq/anchors-envelope";
import type {
  ARRReceipt,
  ArrSingleKind,
  ArrProfile,
  ArrTargetKind,
  ArrTrigger,
  ArrStateSnapshot,
} from "../types.ts";
import { signCanonical } from "./keys.ts";

export interface MintSingleInput {
  iss: string;
  iss_key: string;
  privateKey: KeyObject;
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
  effective_until?: string | null;
  state_snapshot: ArrStateSnapshot;
  prev: string | null;
  extraFields?: Record<string, unknown>;
}

function commonChecks(input: MintSingleInput, kind: ArrSingleKind) {
  if (input.trigger === "subject_request" && !input.trigger_receipt) {
    throw new Error("trigger_receipt.required");
  }
  if ((kind === "arr.hold_extension.v1" || kind === "ar.archive.v1") && !input.effective_until) {
    throw new Error("effective_until.required");
  }
}

function computeFieldRoot(input: MintSingleInput, kind: ArrSingleKind): string {
  const fields = {
    kind,
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
    ...(input.extraFields ?? {}),
  };
  const bytes = new TextEncoder().encode(canonicalize(fields));
  const prefixed = Buffer.concat([Buffer.from([0x00]), Buffer.from(bytes)]);
  return "sha256:" + createHash("sha256").update(prefixed).digest("hex");
}

function buildAndSign(input: MintSingleInput, kind: ArrSingleKind): ARRReceipt {
  commonChecks(input, kind);
  const receipt: ARRReceipt = {
    kind,
    profile: input.profile,
    iss: input.iss,
    iss_key: input.iss_key,
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
    prev: input.prev,
    field_root: computeFieldRoot(input, kind),
    anchor: null,
    sig: null,
    // qts_attestation_hash is a required ARRReceipt field (string | null). These
    // legacy single minters predate QTS attestation; default null. Not part of
    // computeFieldRoot, so this does not affect field_root. `extraFields` may
    // override it.
    qts_attestation_hash: null,
    ...(input.extraFields ?? {}),
  };
  receipt.sig = signCanonical(receipt, input.privateKey);
  return receipt;
}

export const mintErasure = (i: MintSingleInput) => buildAndSign(i, "ar.erasure.v1");
export const mintExpiry = (i: MintSingleInput) => buildAndSign(i, "ar.expiry.v1");
export const mintHoldExtension = (i: MintSingleInput) => buildAndSign(i, "arr.hold_extension.v1");
export const mintHoldRelease = (i: MintSingleInput) => buildAndSign(i, "arr.hold_release.v1");
export const mintAnonymization = (i: MintSingleInput) => buildAndSign(i, "ar.anonymization.v1");
export const mintPseudonymization = (i: MintSingleInput) => buildAndSign(i, "arr.pseudonymization.v1");
export const mintArchive = (i: MintSingleInput) => buildAndSign(i, "ar.archive.v1");
