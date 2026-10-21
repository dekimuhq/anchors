/**
 * Ed25519 signing key helpers for `@dekimuhq/quality` (`./issue`).
 *
 * Generates a keypair from `node:crypto` and exports:
 *   - `signingKey.privateKey` — 32-byte Ed25519 seed (used by `keyObjectFromSeed`)
 *   - `publicKeyDer` — SPKI DER (used to verify receipts in tests)
 *
 * The `QualitySigningKey` interface satisfies the `SigningKey` type from
 * `@dekimuhq/anchors-envelope/issuer`.
 */

import { generateKeyPairSync } from "node:crypto";

export interface QualitySigningKey {
  kid: string;
  privateKey: Uint8Array;
}

export interface QualityKeyPair {
  signingKey: QualitySigningKey;
  publicKeyDer: Uint8Array;
}

export function generateQualityKeypair(kid: string): QualityKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pkcs8 = privateKey.export({ type: "pkcs8", format: "der" });
  const seed = new Uint8Array(pkcs8.subarray(pkcs8.length - 32));
  const pubDer = publicKey.export({ type: "spki", format: "der" });
  return {
    signingKey: { kid, privateKey: seed },
    publicKeyDer: new Uint8Array(pubDer),
  };
}
