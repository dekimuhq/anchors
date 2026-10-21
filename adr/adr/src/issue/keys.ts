import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { base64UrlEncode } from "@dekimuhq/anchors-envelope";

/** Generate a KeyObject Ed25519 keypair (used by continuity attestations). */
export function generateIssuerKey(): { publicKey: KeyObject; privateKey: KeyObject } {
  return generateKeyPairSync("ed25519");
}

/** Encode a KeyObject public key as `ed25519:<base64url>`. */
export function encodePublicKey(publicKey: KeyObject): string {
  const spki = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const raw = spki.subarray(spki.length - 32);
  return `ed25519:${base64UrlEncode(raw)}`;
}
