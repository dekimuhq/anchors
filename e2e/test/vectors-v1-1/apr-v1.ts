/**
 * Deterministic v=1 APR provenance claim fixture for v=1 regression tests.
 *
 * Exports: { receipt, publicKey }
 *   receipt   — signed APRClaim (v=1, kind "ar.provenance.v1")
 *   publicKey — Uint8Array (raw 32-byte Ed25519 public key) for the resolver
 */

import * as crypto from "node:crypto";
import { canonicalize, base64UrlEncode } from "@dekimuhq/anchors-envelope";
import type { APRClaim } from "@dekimuhq/apr";

const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");

const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
// Last 32 bytes of the SPKI DER are the raw public key.
const pkRaw = pkDer.subarray(-32);

// Build unsigned claim — sig field omitted so canonicalize produces the
// bytes that verifyClaim will reconstruct via `const { sig, ...unsigned } = claim`.
const unsigned: Omit<APRClaim, "sig"> = {
  v: 1,
  id: "01HXX0000000000000000APRV1T",
  kind: "ar.provenance.v1",
  issuer: "did:web:test-issuer.example",
  subject: "sha256:" + "a".repeat(64),
  iat: 1_747_440_000, // 2025-05-17T00:00:00Z (fixed for determinism)
  kid: "apr-v1-regression-kid",
  body: {
    artifact: {
      type: "miniterms.document",
      id: "art-v1-regression-001",
      hash: "0".repeat(64),
      hashAlgorithm: "sha256",
    },
    agent: { kind: "template" },
    authorization: { principalId: "principal-v1-regression" },
    startedAt: 1_747_440_000,
    completedAt: 1_747_440_001,
    disclosure: "public_minimal",
    qts_attestation_hash: null,
  },
};

const canonicalBytes = new TextEncoder().encode(canonicalize(unsigned));

// APR v=1 sig is raw base64url — no "ed25519:" prefix (confirmed by verify-claim.ts).
const skPkcs8Raw = (
  privateKey.export({ format: "der", type: "pkcs8" }) as Buffer
).subarray(-32);
const skPkcs8 = Buffer.concat([
  Buffer.from("302e020100300506032b657004220420", "hex"),
  skPkcs8Raw,
]);
const skKey = crypto.createPrivateKey({ key: skPkcs8, format: "der", type: "pkcs8" });
const sigBytes = crypto.sign(null, canonicalBytes, skKey);
const sig = base64UrlEncode(new Uint8Array(sigBytes));

const receipt: APRClaim = { ...unsigned, sig };

export default {
  receipt,
  publicKey: new Uint8Array(pkRaw),
};
