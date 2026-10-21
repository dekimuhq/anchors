// @dekimuhq/<member>-issuer-kit — keypair generation
//
// Ed25519 via node:crypto. Returns base64url-encoded public/private keys
// matching the iss_key wire format ("ed25519:<base64url>").

import { generateKeyPairSync } from "node:crypto";

export interface Keypair {
  publicKey: string;
  privateKey: string;
  iss_key: string;
}

export async function generateKeypair(): Promise<Keypair> {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");

  const pubRaw = publicKey.export({ format: "der", type: "spki" });
  const privRaw = privateKey.export({ format: "der", type: "pkcs8" });

  const pubB64u = Buffer.from(pubRaw).toString("base64url");
  const privB64u = Buffer.from(privRaw).toString("base64url");

  return {
    publicKey: pubB64u,
    privateKey: privB64u,
    iss_key: `ed25519:${pubB64u}`,
  };
}
