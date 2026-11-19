/** Ed25519 signing-key helper for `@dekimuhq/screening/issue`. */
import { generateKeyPairSync } from "node:crypto";

export interface ScreeningSigningKey { kid: string; privateKey: Uint8Array; }
export interface ScreeningKeyPair { signingKey: ScreeningSigningKey; publicKeyDer: Uint8Array; }

export function generateScreeningKeypair(kid: string): ScreeningKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pkcs8 = privateKey.export({ type: "pkcs8", format: "der" });
  const seed = new Uint8Array(pkcs8.subarray(pkcs8.length - 32));
  return { signingKey: { kid, privateKey: seed }, publicKeyDer: new Uint8Array(publicKey.export({ type: "spki", format: "der" })) };
}
