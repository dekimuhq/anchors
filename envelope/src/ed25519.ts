/**
 * Ed25519 issuer-key helpers + canonical sign/verify — hoisted from per-family
 * `keys.ts` files so issuer-kits no longer duplicate. Consumed by every
 * `<family>-issuer-kit` and by `FamilyManifest.mintV2` (Task 1.6).
 */

import * as crypto from "node:crypto";
import { base64UrlEncode, base64UrlDecode } from "./base64url.ts";
import { canonicalize } from "./canonicalize.ts";

const PKCS8_ED25519_PREFIX = Buffer.from(
  "302e020100300506032b657004220420",
  "hex",
);

const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export interface Keypair {
  kid: string;
  privateKey: Uint8Array; // 32-byte Ed25519 seed
  publicKey: Uint8Array;  // 32-byte Ed25519 public key
}

/** Generate a fresh Ed25519 keypair for the given `kid`. */
export function generateKeypair(kid: string): Keypair {
  if (!kid) throw new Error("generateKeypair: kid required");
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const skRaw = (privateKey.export({ format: "der", type: "pkcs8" }) as Buffer)
    .subarray(-32);
  const pkRaw = (publicKey.export({ format: "der", type: "spki" }) as Buffer)
    .subarray(-32);
  return {
    kid,
    privateKey: new Uint8Array(skRaw),
    publicKey: new Uint8Array(pkRaw),
  };
}

/** Derive the 32-byte public key from a 32-byte private seed. */
export function publicKeyFromSeed(seed: Uint8Array): Uint8Array {
  if (seed.length !== 32) {
    throw new Error("publicKeyFromSeed: seed must be 32 bytes");
  }
  const der = Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seed)]);
  const sk = crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  const pkRaw = (crypto
    .createPublicKey(sk)
    .export({ format: "der", type: "spki" }) as Buffer).subarray(-32);
  return new Uint8Array(pkRaw);
}

/** Encode raw bytes (e.g. a 32-byte seed or pubkey) as base64url, no padding. */
export function encodeRaw(bytes: Uint8Array): string {
  return base64UrlEncode(bytes);
}

/** Decode a base64url-encoded raw key. Asserts 32 bytes. */
export function decodeRaw32(s: string): Uint8Array {
  const out = base64UrlDecode(s);
  if (out.length !== 32) {
    throw new Error(`decodeRaw32: expected 32 bytes, got ${out.length}`);
  }
  return out;
}

/**
 * Sign a canonical-JCS representation of `body` with the 32-byte Ed25519 seed.
 * Returns a 64-byte raw Ed25519 signature. Throws on non-32-byte seed.
 */
export function signCanonical(body: unknown, privateKeySeed: Uint8Array): Uint8Array {
  if (privateKeySeed.length !== 32) {
    throw new Error("signCanonical: privateKey seed must be 32 bytes");
  }
  const der = Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(privateKeySeed)]);
  const sk = crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  const canonical = canonicalize(body);
  const sig = crypto.sign(null, Buffer.from(canonical, "utf8"), sk);
  return new Uint8Array(sig);
}

/**
 * Verify a 64-byte Ed25519 signature against `body` (canonicalized via JCS)
 * using the 32-byte public key. Returns `true` iff the signature matches.
 * Returns `false` (never throws) for malformed inputs.
 */
export function verifyCanonical(
  body: unknown,
  signature: Uint8Array,
  publicKeyBytes: Uint8Array,
): boolean {
  try {
    if (publicKeyBytes.length !== 32) return false;
    if (signature.length !== 64) return false;
    const der = Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(publicKeyBytes)]);
    const pk = crypto.createPublicKey({ key: der, format: "der", type: "spki" });
    const canonical = canonicalize(body);
    return crypto.verify(null, Buffer.from(canonical, "utf8"), pk, Buffer.from(signature));
  } catch {
    return false;
  }
}
