/**
 * OPTIONAL wrapper Data-Integrity proof (design doc Q2, layer 2).
 *
 * Two trust layers, kept honest:
 *   1. ROOT OF TRUST = the embedded envelope `sig` — verified by the family's
 *      existing verifier on `extractEnvelope(vc)`. The binding never touches it.
 *   2. WRAPPER PROOF (this file) = an OPTIONAL `DataIntegrityProof` over the VC
 *      wrapper, signed by the SAME issuer key. It proves wrapper INTEGRITY under
 *      whatever key the verifier supplies — it is NOT, by itself, an issuer-
 *      authenticity check: the `verificationMethod` and `vc.issuer` are both
 *      writable by whoever builds the credential. Issuer authenticity comes ONLY
 *      from layer 1 (the envelope `sig` verified against a key resolved from the
 *      trust anchor). Use `verifyCredential` for the correct combined check.
 *
 * The envelope `sig` is NEVER reused as the VC `proof`: it covers the envelope
 * canonical bytes, not the wrapper fields, so reusing it would falsely assert the
 * wrapper is signed.
 *
 * Profile: the signature covers the RFC 8785 (JCS) canonical form of the
 * credential with its `proof` member removed (`signCanonical` canonicalises
 * internally). Cryptosuite `eddsa-jcs-2022` for ed25519; `proofValue` is base64url
 * (matching the envelope's signature encoding, not multibase). A PQC suite is
 * documented but unregistered until wired — mirrors the envelope `sig_alg` posture.
 */

import {
  base64UrlEncode,
  base64UrlDecode,
  signCanonical,
  verifyCanonical,
  type Keypair,
} from "@dekimuhq/anchors-envelope";
import type { AnchoredReceiptCredential, DataIntegrityProof } from "./types.ts";

/** eddsa-jcs-2022 — the only registered wrapper cryptosuite in v1. */
export const WRAPPER_CRYPTOSUITE = "eddsa-jcs-2022" as const;

export interface AttachProofOpts {
  /** DID URL of the verification method, e.g. `did:web:issuer.example#key-1`. */
  verificationMethod: string;
  /** ISO 8601 UTC proof creation time. Defaults to the credential `validFrom`. */
  created?: string;
}

export type VerifyProofResult =
  | { ok: true }
  | { ok: false; reason: "no_proof" | "unsupported_cryptosuite" | "bad_signature" };

/**
 * The credential with its `proof` member removed — the exact bytes the DI proof
 * covers. Symmetric across attach (no proof yet) and verify (proof stripped), so
 * the canonical form matches.
 */
function unsignedDocument(
  vc: AnchoredReceiptCredential,
): Omit<AnchoredReceiptCredential, "proof"> {
  const { proof: _omit, ...rest } = vc;
  return rest;
}

/**
 * Attach an `eddsa-jcs-2022` Data-Integrity proof over the wrapper, signed by the
 * issuer key. Returns a new credential — does not mutate the input.
 */
export function attachWrapperProof(
  vc: AnchoredReceiptCredential,
  key: Keypair,
  opts: AttachProofOpts,
): AnchoredReceiptCredential {
  const sig = signCanonical(unsignedDocument(vc), key.privateKey);
  const proof: DataIntegrityProof = {
    type: "DataIntegrityProof",
    cryptosuite: WRAPPER_CRYPTOSUITE,
    created: opts.created ?? vc.validFrom,
    verificationMethod: opts.verificationMethod,
    proofPurpose: "assertionMethod",
    proofValue: base64UrlEncode(sig),
  };
  return { ...vc, proof };
}

/**
 * Verify the wrapper DI proof against a raw 32-byte ed25519 public key. Returns a
 * tagged result, never throws.
 *
 * This proves ONLY that `publicKey` signed the wrapper bytes — it is NOT an
 * issuer-authenticity check on its own (the caller must supply a key resolved
 * from the trust anchor, e.g. via `resolveWrapperKey` / `verifyCredential`). A
 * `no_proof` credential is NOT valid; the embedded envelope remains the root of
 * trust regardless (`extractEnvelope` + the family verifier). Rejects any
 * cryptosuite other than the single registered `eddsa-jcs-2022` (v1) so a forged
 * proof cannot claim an algorithm this verifier does not actually evaluate.
 */
export function verifyWrapperProof(
  vc: AnchoredReceiptCredential,
  publicKey: Uint8Array,
): VerifyProofResult {
  if (!vc.proof) return { ok: false, reason: "no_proof" };
  if (vc.proof.cryptosuite !== WRAPPER_CRYPTOSUITE) {
    return { ok: false, reason: "unsupported_cryptosuite" };
  }
  const sig = base64UrlDecode(vc.proof.proofValue);
  return verifyCanonical(unsignedDocument(vc), sig, publicKey)
    ? { ok: true }
    : { ok: false, reason: "bad_signature" };
}
