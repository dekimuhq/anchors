/**
 * Status List Credential signature verify — W3C VC Ed25519Signature2020 over
 * RFC 8785 canonical simplified form. Phase D Task 18.
 *
 * Returns `true` iff:
 *   - `credential` is a non-null object with a well-formed `proof` block,
 *   - `proof.type === "Ed25519Signature2020"`,
 *   - `proof.verificationMethod === rootKey.kid`,
 *   - `proof.proofValue` base64url-decodes to exactly 64 bytes,
 *   - `rootKey.publicKeyDer` base64url-decodes to a valid SPKI Ed25519 key,
 *   - and Ed25519 verify succeeds over the RFC 8785-canonicalised credential
 *     MINUS the `proof` block.
 *
 * All failure modes (malformed proof block, undecodable inputs, key
 * construction errors, signature mismatch) return `false`. Never throws.
 */

import { verify as edVerify, createPublicKey } from "node:crypto";
import { canonicalize } from "../canonicalize.ts";
import { base64UrlDecode } from "../base64url.ts";
import type {
  StatusListCredential,
  RootKeyMaterial,
} from "./types.ts";

export async function verifyStatusListCredentialSignature(
  credential: unknown,
  rootKey: RootKeyMaterial,
): Promise<boolean> {
  if (typeof credential !== "object" || credential === null) return false;
  const c = credential as StatusListCredential;
  if (!c.proof || c.proof.type !== "Ed25519Signature2020") return false;
  if (c.proof.verificationMethod !== rootKey.kid) return false;

  const { proof: _proof, ...unsigned } = c;
  const canonical = canonicalize(unsigned);

  let sigBytes: Uint8Array;
  try {
    sigBytes = base64UrlDecode(c.proof.proofValue);
  } catch {
    return false;
  }
  if (sigBytes.length !== 64) return false;

  let pubKey;
  try {
    pubKey = createPublicKey({
      key: Buffer.from(base64UrlDecode(rootKey.publicKeyDer)),
      format: "der",
      type: "spki",
    });
  } catch {
    return false;
  }

  try {
    return edVerify(
      null,
      Buffer.from(canonical, "utf8"),
      pubKey,
      Buffer.from(sigBytes),
    );
  } catch {
    return false;
  }
}
