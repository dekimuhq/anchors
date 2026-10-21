/**
 * Ed25519 signing key helpers for `@dekimuhq/apur/issue`.
 *
 * Generates a keypair from `node:crypto` and exports:
 *   - `signingKey.privateKey` — 32-byte Ed25519 seed (used by `keyObjectFromSeed`)
 *   - `publicKeyDer` — SPKI DER (used to verify receipts in tests)
 *
 * The `ApurSigningKey` interface satisfies the `SigningKey` type from
 * `@dekimuhq/anchors-envelope/issuer`.
 */

import { generateKeyPairSync } from "node:crypto";

export interface ApurSigningKey {
  kid: string;
  privateKey: Uint8Array;
}

export interface ApurKeyPair {
  signingKey: ApurSigningKey;
  publicKeyDer: Uint8Array;
}

export function generateApurKeypair(kid: string): ApurKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pkcs8 = privateKey.export({ type: "pkcs8", format: "der" });
  const seed = new Uint8Array(pkcs8.subarray(pkcs8.length - 32));
  const pubDer = publicKey.export({ type: "spki", format: "der" });
  return {
    signingKey: { kid, privateKey: seed },
    publicKeyDer: new Uint8Array(pubDer),
  };
}
