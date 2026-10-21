/**
 * Shared issuer-kit helpers — lifted from 8 per-family mint-v2.ts files.
 *
 * P0 abstraction (2026-05-21): these helpers were byte-identical across
 * every issuer-kit and also duplicated privately in `family-mint-pipeline.ts`.
 * Now a single source of truth.
 */

import * as nodeCrypto from "node:crypto";
import { createHash } from "node:crypto";
import { base64UrlEncode } from "./base64url.ts";
import { canonicalize } from "./canonicalize.ts";
import {
  encodeMlDsaIssKey,
  privateKeyFromSecret,
  type MlDsaSecretKey,
} from "./ml-dsa.ts";

// ── PKCS8 Ed25519 seed import ───────────────────────────────────────────────

const PKCS8_ED25519_PREFIX = Buffer.from(
  "302e020100300506032b657004220420",
  "hex",
);

/**
 * Derive a `KeyObject` + `iss_key` fingerprint from a 32-byte Ed25519 seed.
 *
 * Returns the Node.js private key object (for signing) and the `ed25519:<b64url>`
 * fingerprint string (for the envelope `iss_key` field). Identical to the
 * per-family `keyObjectFromSeed` helpers that shipped since APR.
 */
export function keyObjectFromSeed(seed: Uint8Array): {
  privateKey: nodeCrypto.KeyObject;
  issKey: `ed25519:${string}`;
} {
  const der = Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seed)]);
  const privateKey = nodeCrypto.createPrivateKey({
    key: der,
    format: "der",
    type: "pkcs8",
  });
  const pkRaw = (
    nodeCrypto
      .createPublicKey(privateKey)
      .export({ format: "der", type: "spki" }) as Buffer
  ).subarray(-32);
  const issKey: `ed25519:${string}` = `ed25519:${base64UrlEncode(
    new Uint8Array(pkRaw),
  )}`;
  return { privateKey, issKey };
}

// ── ML-DSA-65 secret import (v1.3 PQC issuer-kit minting) ────────────────────

/**
 * Derive a `KeyObject` + `iss_key` fingerprint from a persisted ML-DSA-65
 * secret (seed + raw public key). The PQC counterpart to `keyObjectFromSeed`.
 *
 * Returns the private key object (for signing) and the `ml-dsa-65:<b64url>`
 * fingerprint. The caller is responsible for also setting `sig_alg:
 * "ml-dsa-65"` on the envelope (signed-in §L3) — `buildMintV2` does this.
 */
export function keyObjectFromMlDsaSecret(secret: MlDsaSecretKey): {
  privateKey: nodeCrypto.KeyObject;
  issKey: `ml-dsa-65:${string}`;
} {
  return {
    privateKey: privateKeyFromSecret(secret),
    issKey: encodeMlDsaIssKey(secret.publicKeyRaw),
  };
}

// ── ULID receipt ID ─────────────────────────────────────────────────────────

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/**
 * Generate a new ULID (Universally Unique Lexicographically Sortable
 * Identifier) in Crockford Base32. Used as the `id` field on every v=2
 * envelope.
 */
export function generateReceiptId(): string {
  const now = Date.now();
  let timeStr = "";
  let t = now;
  for (let i = 0; i < 10; i++) {
    timeStr = CROCKFORD[t % 32]! + timeStr;
    t = Math.floor(t / 32);
  }
  const randBytes = nodeCrypto.randomBytes(10);
  let randStr = "";
  for (let i = 0; i < 10; i++) {
    randStr += CROCKFORD[randBytes[i]! % 32]!;
  }
  while (randStr.length < 16) {
    randStr += "0";
  }
  return timeStr + randStr;
}

// ── field_root computation ──────────────────────────────────────────────────

/**
 * Compute `field_root` over a body object: SHA-256 of RFC 6962 leaf-prefix
 * (0x00) concatenated with RFC 8785 canonical JSON of the body.
 *
 * Returns `"sha256:<hex64>"`. Used by ANR/ABR/AIR/ALR issuer-kits that
 * compute `field_root` from the complete body. ARR has a variant that
 * computes over a subset of fields — not covered by this helper.
 */
export function computeFieldRoot(body: unknown): string {
  const bytes = new TextEncoder().encode(canonicalize(body));
  const prefixed = Buffer.concat([Buffer.from([0x00]), Buffer.from(bytes)]);
  return "sha256:" + createHash("sha256").update(prefixed).digest("hex");
}

// ── SHA-256 hex validator ───────────────────────────────────────────────────

const SHA256_RE = /^sha256:[0-9a-f]{64}$/;

/**
 * Check if a string matches the `sha256:<hex64>` format used for commit
 * values, field roots, and artifact hashes across the anchors family.
 */
export function isSha256Hex(s: unknown): s is string {
  return typeof s === "string" && SHA256_RE.test(s);
}
