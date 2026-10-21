import * as crypto from "node:crypto";
import { canonicalize, base64UrlDecode } from "./canonicalize.ts";
import type { ACRReceipt } from "./types.ts";

const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/**
 * Verify the issuer's Ed25519 signature on a receipt.
 *
 * Signature scope: the canonical JSON of the receipt with `anchor`, `sig`,
 * and `countersig` all set to `null` (regardless of their actual values).
 * This means a receipt is valid whether or not it has been anchored or
 * countersigned — those are independent attestations.
 */
export function verifyReceiptSignature(receipt: ACRReceipt): boolean {
  try {
    if (!receipt.sig?.startsWith("ed25519:")) return false;
    if (!receipt.iss_key.startsWith("ed25519:")) return false;

    const signed = { ...receipt, anchor: null, sig: null, countersig: null };
    const bytes = new TextEncoder().encode(canonicalize(signed));

    const sigBytes = base64UrlDecode(receipt.sig.slice("ed25519:".length));
    const pkBytes = base64UrlDecode(receipt.iss_key.slice("ed25519:".length));
    if (pkBytes.length !== 32) return false;
    if (sigBytes.length !== 64) return false;

    const spki = Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(pkBytes)]);
    const pkKey = crypto.createPublicKey({ key: spki, format: "der", type: "spki" });

    return crypto.verify(null, bytes, pkKey, Buffer.from(sigBytes));
  } catch {
    return false;
  }
}
