/**
 * Ed25519 signing helpers for `@dekimuhq/air/issue`.
 *
 * Mirrors the family pattern (apr/acr/arr/alr/anr/abr-issuer-kit): generate a
 * Node keypair, encode the public key as `ed25519:<base64url>`, sign a
 * canonicalised payload with the private key. The `signCanonical` helper is
 * used by the family-shared continuity attestation re-exported from
 * `@dekimuhq/anchors-envelope/continuity`; v=2 envelope signing goes through
 * `signEnvelope` from `@dekimuhq/anchors-envelope` (see `mint-v2.ts`).
 */

import {
  generateKeyPairSync,
  sign as nodeSign,
  createPrivateKey,
  type KeyObject,
} from "node:crypto";
import { canonicalize, base64UrlEncode } from "@dekimuhq/anchors-envelope";

export function generateIssuerKey(): { publicKey: KeyObject; privateKey: KeyObject } {
  return generateKeyPairSync("ed25519");
}

export function encodePublicKey(publicKey: KeyObject): string {
  const spki = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const raw = spki.subarray(spki.length - 32);
  return `ed25519:${base64UrlEncode(raw)}`;
}

export function signCanonical(payload: unknown, privateKey: KeyObject): string {
  const msg = new TextEncoder().encode(canonicalize(payload));
  const sig = nodeSign(null, msg, privateKey);
  return `ed25519:${base64UrlEncode(sig)}`;
}

export function loadPrivateKey(pkcs8Pem: string): KeyObject {
  return createPrivateKey({ key: pkcs8Pem, format: "pem", type: "pkcs8" });
}
