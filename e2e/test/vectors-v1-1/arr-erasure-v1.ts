/**
 * Deterministic v=1 ARR erasure receipt fixture for v=1 regression tests.
 *
 * Exports: { receipt, publicKey, anchorInclusionTime }
 *   receipt            — signed ARRReceipt (kind "ar.erasure.v1")
 *   publicKey          — Uint8Array (raw 32-byte Ed25519 public key), informational
 *   anchorInclusionTime — ISO 8601 string after all event_at / granted_at timestamps
 */

import * as crypto from "node:crypto";
import { canonicalize, base64UrlEncode } from "@dekimuhq/arr";
import type { ARRReceipt } from "@dekimuhq/arr";

const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");

const spki = publicKey.export({ format: "der", type: "spki" }) as Buffer;
// Last 32 bytes of the SPKI DER are the raw public key.
const rawPub = spki.subarray(spki.length - 32);
const pubB64 = base64UrlEncode(new Uint8Array(rawPub));

// Build the unsigned receipt (sig: null, anchor: null — zeroed during signing).
const unsigned: ARRReceipt = {
  kind: "ar.erasure.v1",
  profile: "gdpr.art17",
  iss: "did:web:processor-v1-regression.example",
  iss_key: `ed25519:${pubB64}`,
  target_kind: "subject",
  target_commit: "sha256:" + "ab".repeat(32),
  salt_epoch: "2026Q2",
  policy_hash: "sha256:" + "cd".repeat(32),
  policy_uri: "https://processor-v1-regression.example/p/v1",
  policy_version: "1.0.0",
  trigger: "subject_request",
  trigger_receipt: "sha256:" + "ef".repeat(32),
  event_at: "2026-05-17T08:00:00Z",
  granted_at: "2026-05-17T08:02:00Z",
  effective_until: null,
  state_snapshot: {
    retention_status: "erased",
    current_policy_hash: "sha256:" + "cd".repeat(32),
    hold_active: false,
    hold_reason_commit: null,
    anonymized: false,
    archived: false,
  },
  prev: null,
  field_root: "sha256:" + "11".repeat(32),
  qts_attestation_hash: null,
  anchor: null,
  sig: null,
};

const msg = new TextEncoder().encode(canonicalize(unsigned));

const skPkcs8Raw = (
  privateKey.export({ format: "der", type: "pkcs8" }) as Buffer
).subarray(-32);
const skPkcs8 = Buffer.concat([
  Buffer.from("302e020100300506032b657004220420", "hex"),
  skPkcs8Raw,
]);
const skKey = crypto.createPrivateKey({ key: skPkcs8, format: "der", type: "pkcs8" });
const sigBytes = crypto.sign(null, msg, skKey);

const receipt: ARRReceipt = {
  ...unsigned,
  sig: `ed25519:${base64UrlEncode(new Uint8Array(sigBytes))}`,
};

// Fixed anchor time AFTER both event_at and granted_at so time-bound checks pass.
const anchorInclusionTime = "2026-05-17T08:10:00Z";

export default {
  receipt,
  publicKey: new Uint8Array(rawPub),
  anchorInclusionTime,
};
