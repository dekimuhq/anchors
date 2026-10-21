import { verify as nodeVerify, createPublicKey } from "node:crypto";
import { canonicalize, base64UrlDecode } from "./crypto-reexports.ts";
import type { ARRReceipt } from "./types.ts";

export interface VerifySingleOptions {
  anchorInclusionTime: string;
  strictSelfConsistency?: boolean;
}

export interface VerifyResult {
  valid: boolean;
  errors: string[];
}

const ED25519_SPKI_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

function importEd25519PublicKey(issKey: string) {
  if (!issKey.startsWith("ed25519:")) throw new Error("iss_key.format");
  const raw = base64UrlDecode(issKey.slice("ed25519:".length));
  if (raw.length !== 32) throw new Error("iss_key.length");
  const der = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

export function verifySingleReceipt(
  receipt: ARRReceipt,
  opts: VerifySingleOptions,
): VerifyResult {
  const errors: string[] = [];

  if (receipt.trigger === "subject_request" && !receipt.trigger_receipt) {
    errors.push("trigger_receipt.required");
  }

  const anchorMs = Date.parse(opts.anchorInclusionTime);
  const eventMs = Date.parse(receipt.event_at);
  const grantedMs = Date.parse(receipt.granted_at);
  if (Number.isNaN(anchorMs)) errors.push("anchor.time.invalid");
  if (Number.isNaN(eventMs)) errors.push("event_at.invalid");
  if (Number.isNaN(grantedMs)) errors.push("granted_at.invalid");
  if (eventMs > anchorMs) errors.push("event_at.after.anchor");
  if (grantedMs > anchorMs) errors.push("granted_at.after.anchor");
  if (opts.strictSelfConsistency && eventMs > grantedMs) {
    errors.push("event_at.after.granted_at");
  }

  if (!receipt.sig) {
    errors.push("sig.missing");
    return { valid: errors.length === 0, errors };
  }

  try {
    const pub = importEd25519PublicKey(receipt.iss_key);
    const sigRaw = base64UrlDecode(receipt.sig.replace(/^ed25519:/, ""));
    const unsigned: ARRReceipt = { ...receipt, anchor: null, sig: null };
    const msg = new TextEncoder().encode(canonicalize(unsigned));
    const ok = nodeVerify(null, msg, pub, Buffer.from(sigRaw));
    if (!ok) errors.push("sig.invalid");
  } catch {
    errors.push("sig.import_error");
  }

  return { valid: errors.length === 0, errors };
}
