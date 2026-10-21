import { sign, verify, createPrivateKey, createPublicKey } from "node:crypto";

/**
 * Extract the raw 32-byte Ed25519 public key from a PEM. Accepts either a public-key PEM
 * or a private-key PEM (the public key is derived). The raw key is the trailing 32 bytes of
 * the fixed-length SPKI DER encoding — needed for the C2SP key-hash (which hashes the bare key).
 */
export function ed25519RawPublicKey(keyPem: string): Buffer {
  const der = createPublicKey(keyPem).export({ type: "spki", format: "der" });
  if (der.length < 32) throw new Error("ed25519RawPublicKey: not an Ed25519 SPKI key");
  return Buffer.from(der.subarray(der.length - 32));
}

/** Sign arbitrary bytes with an Ed25519 PEM private key. Returns base64url. */
export function signBytes(data: Uint8Array, privateKeyPem: string): string {
  const key = createPrivateKey(privateKeyPem);
  return sign(null, Buffer.from(data), key).toString("base64url");
}

/** Verify a base64url Ed25519 signature over bytes against a PEM public key. Never throws. */
export function verifyBytes(sigB64url: string, data: Uint8Array, publicKeyPem: string): boolean {
  try {
    const key = createPublicKey(publicKeyPem);
    return verify(null, Buffer.from(data), key, Buffer.from(sigB64url, "base64url"));
  } catch {
    return false;
  }
}
