/**
 * Ed25519 verify wrapper backed by Node 22's built-in crypto. The verifier
 * library has zero runtime npm deps; the only platform requirement is a
 * runtime that exposes Node-compatible `crypto.verify` for Ed25519 (Node 18+,
 * Bun, Deno).
 */

import * as crypto from "node:crypto";

const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function rawPubToKeyObject(rawPub: Uint8Array): crypto.KeyObject {
  if (rawPub.length !== 32) {
    throw new Error("ed25519: public key must be 32 bytes");
  }
  const der = Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(rawPub)]);
  return crypto.createPublicKey({ key: der, format: "der", type: "spki" });
}

export function ed25519Verify(
  rawPub: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (signature.length !== 64) return false;
  let key: crypto.KeyObject;
  try {
    key = rawPubToKeyObject(rawPub);
  } catch {
    return false;
  }
  try {
    return crypto.verify(null, message, key, signature);
  } catch {
    return false;
  }
}
