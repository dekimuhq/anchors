/**
 * Deterministic v=1 ACR consent receipt fixture for v=1 regression tests.
 *
 * Exports: { receipt, publicKey }
 *   receipt   — signed ACRReceipt (kind "ar.consent.v1", sig: "ed25519:<b64>")
 *   publicKey — Uint8Array (raw 32-byte Ed25519 public key), informational only
 *               (ACR v=1 verifyReceipt self-resolves the key from iss_key)
 */

import * as crypto from "node:crypto";
import { canonicalize, base64UrlEncode } from "@dekimuhq/acr";
import type { ACRReceipt } from "@dekimuhq/acr";

const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");

const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
// Last 32 bytes of the SPKI DER are the raw public key.
const pkRaw = pkDer.subarray(-32);
const pkB64 = base64UrlEncode(new Uint8Array(pkRaw));

// Build unsigned receipt (sig: null — zeroed during signing per ACR spec).
const base: Omit<ACRReceipt, "sig"> & { sig: null } = {
  kind: "ar.consent.v1",
  profile: "gdpr.art7",
  iss: "did:web:bank-v1-regression.example",
  iss_key: `ed25519:${pkB64}`,
  sub_commit: "sha256:" + "a".repeat(64),
  purposes: ["sha256:" + "b".repeat(64)],
  lawful_basis: "6(1)(a)",
  policy_hash: "sha256:" + "c".repeat(64),
  granted_at: "2026-05-17T00:00:00Z",
  prev: null,
  field_root: "sha256:" + "d".repeat(64),
  qts_attestation_hash: null,
  anchor: null,
  sig: null,
  countersig: null,
};

const canonicalBytes = new TextEncoder().encode(canonicalize(base));

const skPkcs8Raw = (
  privateKey.export({ format: "der", type: "pkcs8" }) as Buffer
).subarray(-32);
const skPkcs8 = Buffer.concat([
  Buffer.from("302e020100300506032b657004220420", "hex"),
  skPkcs8Raw,
]);
const skKey = crypto.createPrivateKey({ key: skPkcs8, format: "der", type: "pkcs8" });
const sigBytes = crypto.sign(null, canonicalBytes, skKey);
const sigB64 = base64UrlEncode(new Uint8Array(sigBytes));

const receipt: ACRReceipt = { ...base, sig: `ed25519:${sigB64}` };

export default {
  receipt,
  publicKey: new Uint8Array(pkRaw),
};
