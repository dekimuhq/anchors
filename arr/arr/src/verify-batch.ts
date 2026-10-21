import { verify as nodeVerify, createPublicKey } from "node:crypto";
import { canonicalize, base64UrlDecode, buildTree } from "./crypto-reexports.ts";
import type {
  ARRBatchReceipt,
  ArrBatchEventKind,
  ArrSingleKind,
} from "./types.ts";
import { MAX_BATCH_TARGET_COUNT } from "./types.ts";

export interface VerifyBatchOptions {
  anchorInclusionTime: string;
  strictSelfConsistency?: boolean;
  disclosedTargets?: string[];
}

export interface BatchVerifyResult {
  valid: boolean;
  errors: string[];
}

const ALLOWED_BATCH_KINDS: ReadonlySet<ArrSingleKind> = new Set([
  "ar.erasure.v1",
  "ar.expiry.v1",
  "arr.hold_extension.v1",
  "arr.hold_release.v1",
  "ar.anonymization.v1",
  "arr.pseudonymization.v1",
  "ar.archive.v1",
]);

const ED25519_SPKI_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

function importEd25519PublicKey(issKey: string) {
  if (!issKey.startsWith("ed25519:")) throw new Error("iss_key.format");
  const raw = base64UrlDecode(issKey.slice("ed25519:".length));
  if (raw.length !== 32) throw new Error("iss_key.length");
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]),
    format: "der",
    type: "spki",
  });
}

export function verifyBatchReceipt(
  receipt: ARRBatchReceipt,
  opts: VerifyBatchOptions,
): BatchVerifyResult {
  const errors: string[] = [];

  if (receipt.kind !== "ar.batch.v1") errors.push("kind.invalid");
  if (!ALLOWED_BATCH_KINDS.has(receipt.batch_event_kind as ArrBatchEventKind)) {
    errors.push("batch_event_kind.invalid");
  }
  if (receipt.target_count <= 0) errors.push("target_count.zero");
  if (receipt.target_count > MAX_BATCH_TARGET_COUNT) {
    errors.push("target_count.exceeds_max");
  }

  const anchorMs = Date.parse(opts.anchorInclusionTime);
  const eventMs = Date.parse(receipt.event_at);
  const grantedMs = Date.parse(receipt.granted_at);
  if (eventMs > anchorMs) errors.push("event_at.after.anchor");
  if (grantedMs > anchorMs) errors.push("granted_at.after.anchor");
  if (opts.strictSelfConsistency && eventMs > grantedMs) {
    errors.push("event_at.after.granted_at");
  }

  if (opts.disclosedTargets) {
    if (opts.disclosedTargets.length !== receipt.target_count) {
      errors.push("disclosed_targets.count_mismatch");
    } else {
      const computed = buildTree(opts.disclosedTargets).root;
      if (computed !== receipt.target_root) {
        errors.push("disclosed_targets.root_mismatch");
      }
    }
  }

  if (!receipt.sig) {
    errors.push("sig.missing");
    return { valid: errors.length === 0, errors };
  }

  try {
    const pub = importEd25519PublicKey(receipt.iss_key);
    const sigRaw = base64UrlDecode(receipt.sig.replace(/^ed25519:/, ""));
    const unsigned: ARRBatchReceipt = { ...receipt, anchor: null, sig: null };
    const msg = new TextEncoder().encode(canonicalize(unsigned));
    if (!nodeVerify(null, msg, pub, Buffer.from(sigRaw))) errors.push("sig.invalid");
  } catch {
    errors.push("sig.import_error");
  }

  return { valid: errors.length === 0, errors };
}
