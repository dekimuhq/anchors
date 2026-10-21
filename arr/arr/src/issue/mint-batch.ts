import { createHash, type KeyObject } from "node:crypto";
import { canonicalize } from "@dekimuhq/anchors-envelope";
import { buildTree } from "@dekimuhq/acr";
import {
  MAX_BATCH_TARGET_COUNT,
  type ARRBatchReceipt,
  type ArrBatchEventKind,
  type ArrProfile,
  type ArrStateSnapshot,
  type ArrTargetKind,
  type ArrTrigger,
} from "../types.ts";
import { signCanonical } from "./keys.ts";

export interface BatchTarget {
  target_commit: string;
  state_snapshot: ArrStateSnapshot;
}

export interface MintBatchInput {
  iss: string;
  iss_key: string;
  privateKey: KeyObject;
  profile: ArrProfile;
  batch_event_kind: ArrBatchEventKind;
  target_kind: ArrTargetKind;
  salt_epoch: string;
  policy_hash: string;
  policy_uri: string;
  policy_version: string;
  trigger: ArrTrigger;
  trigger_receipt: string | null;
  event_at: string;
  granted_at: string;
  effective_until?: string | null;
  targets: BatchTarget[];
  extraFields?: Record<string, unknown>;
}

// buildTree applies the RFC 6962 leaf-prefix 0x00 internally; pass raw sha256(canonical(snapshot)).
function snapshotLeafHash(snap: ArrStateSnapshot): string {
  const bytes = new TextEncoder().encode(canonicalize(snap));
  return "sha256:" + createHash("sha256").update(bytes).digest("hex");
}

function computeFieldRoot(input: MintBatchInput, target_root: string, state_snapshot_root: string): string {
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
    ...(input.extraFields ?? {}),
  };
  const bytes = new TextEncoder().encode(canonicalize(fields));
  const prefixed = Buffer.concat([Buffer.from([0x00]), Buffer.from(bytes)]);
  return "sha256:" + createHash("sha256").update(prefixed).digest("hex");
}

export function mintBatch(input: MintBatchInput): ARRBatchReceipt {
  if (input.targets.length === 0) throw new Error("target_count.zero");
  if (input.targets.length > MAX_BATCH_TARGET_COUNT) throw new Error("target_count.exceeds_max");
  if (input.trigger === "subject_request" && !input.trigger_receipt) {
    throw new Error("trigger_receipt.required");
  }

  const target_root = buildTree(input.targets.map((t) => t.target_commit)).root;
  const state_snapshot_root = buildTree(input.targets.map((t) => snapshotLeafHash(t.state_snapshot))).root;
  const field_root = computeFieldRoot(input, target_root, state_snapshot_root);

  const receipt: ARRBatchReceipt = {
    kind: "ar.batch.v1",
    profile: input.profile,
    iss: input.iss,
    iss_key: input.iss_key,
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
    anchor: null,
    sig: null,
    // qts_attestation_hash is a required ARRBatchReceipt field (string | null).
    // Legacy batch minter predates QTS attestation; default null. Not part of
    // computeFieldRoot, so this does not affect field_root. `extraFields` may
    // override it.
    qts_attestation_hash: null,
    ...(input.extraFields ?? {}),
  };
  receipt.sig = signCanonical(receipt, input.privateKey);
  return receipt;
}
