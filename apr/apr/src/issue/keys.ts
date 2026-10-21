/**
 * Key helpers for issuers — generate, encode, derive public.
 * Mirrors what `verify.dekimu.com` and `apr-verifier` consume.
 */

import * as crypto from "node:crypto";
import type { KeyObject } from "node:crypto";
import { base64UrlEncode, base64UrlDecode } from "../base64url.ts";

const PKCS8_ED25519_PREFIX = Buffer.from(
  "302e020100300506032b657004220420",
  "hex",
);

export interface Keypair {
  kid: string;
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

/** Generate a KeyObject Ed25519 keypair (used by continuity attestations). */
export function generateIssuerKey(): { publicKey: KeyObject; privateKey: KeyObject } {
  return crypto.generateKeyPairSync("ed25519");
}

/** Encode a KeyObject public key as `ed25519:<base64url>`. */
export function encodePublicKey(publicKey: KeyObject): string {
  const spki = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const raw = spki.subarray(spki.length - 32);
  return `ed25519:${base64UrlEncode(raw)}`;
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
  if (seed.length !== 32) throw new Error("publicKeyFromSeed: seed must be 32 bytes");
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
