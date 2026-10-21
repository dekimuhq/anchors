/**
 * Ed25519 signing key helpers for `@dekimuhq/aar/issue`.
 *
 * Generates a keypair from `node:crypto` and exports:
 *   - `signingKey.privateKey` — 32-byte Ed25519 seed (used by `keyObjectFromSeed`)
 *   - `publicKeyDer` — SPKI DER (used to verify receipts in tests)
 *
 * The `AarSigningKey` interface satisfies the `SigningKey` type from
 * `@dekimuhq/anchors-envelope/issuer`.
 */

import { generateKeyPairSync } from "node:crypto";

export interface AarSigningKey {
  kid: string;
  privateKey: Uint8Array;
}

export interface AarKeyPair {
  signingKey: AarSigningKey;
  publicKeyDer: Uint8Array;
}

export function generateAarKeypair(kid: string): AarKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pkcs8 = privateKey.export({ type: "pkcs8", format: "der" });
  const seed = new Uint8Array(pkcs8.subarray(pkcs8.length - 32));
  const pubDer = publicKey.export({ type: "spki", format: "der" });
  return {
    signingKey: { kid, privateKey: seed },
    publicKeyDer: new Uint8Array(pubDer),
  };
}
