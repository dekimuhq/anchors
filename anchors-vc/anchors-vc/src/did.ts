/**
 * DID helpers for the wrapper proof (design doc Q5).
 *
 * Scope: `did:web` primary — resolved via the shared `@dekimuhq/did-web-resolver`
 * (no new resolver, per the acceptance criteria). `did:key`-equivalent tolerated
 * as a fallback because the envelope `iss_key` is a self-describing raw key
 * (`<sig_alg>:<base64url-raw-key>`). All other DID methods are out of v1.
 *
 * Key-format note: envelope verifiers take SPKI DER, but the WRAPPER proof
 * (`verifyWrapperProof` → `verifyCanonical`) takes the RAW ed25519 key. The
 * shared resolver returns SPKI DER (44 B) for ed25519, so `resolveWrapperKey`
 * strips it to the raw 32 B the wrapper verifier expects.
 */

import {
  resolveDidWebKey,
  type ResolveDidWebKeyOptions,
} from "@dekimuhq/did-web-resolver";
import { base64UrlDecode, isSupportedSigAlg, type SigAlg } from "@dekimuhq/anchors-envelope";
import { AnchorsVcError } from "./unwrap.ts";

/** SPKI DER length for an ed25519 public key: 12-byte prefix + 32-byte key. */
const ED25519_SPKI_DER_LEN = 44;
const ED25519_SPKI_PREFIX_LEN = 12;

/** Split a self-describing `<sig_alg>:<base64url-raw-key>` ref into its parts. */
function splitIssKey(issKey: string): { alg: string; raw: string } {
  const idx = issKey.indexOf(":");
  if (idx <= 0 || idx === issKey.length - 1) {
    throw new AnchorsVcError(`malformed iss_key: ${issKey}`);
  }
  return { alg: issKey.slice(0, idx), raw: issKey.slice(idx + 1) };
}

/**
 * Decode the self-describing issuer key ref into its algorithm + RAW key bytes.
 * For ed25519 this is the 32-byte raw key that `verifyWrapperProof` expects — the
 * `did:key`-equivalent fallback source.
 */
export function publicKeyFromIssKey(issKey: string): { alg: SigAlg; key: Uint8Array } {
  const { alg, raw } = splitIssKey(issKey);
  if (!isSupportedSigAlg(alg)) {
    throw new AnchorsVcError(`unsupported sig_alg in iss_key: ${alg}`);
  }
  const key = base64UrlDecode(raw);
  if (key.length === 0) throw new AnchorsVcError(`empty key in iss_key: ${issKey}`);
  return { alg: alg as SigAlg, key };
}

/**
 * Build a `verificationMethod` DID URL for `attachWrapperProof`. Derives a stable
 * fragment from the algorithm + key material so distinct keys get distinct method
 * ids under the same issuer DID.
 */
export function verificationMethodFor(iss: string, issKey: string): string {
  const { alg, raw } = splitIssKey(issKey);
  return `${iss}#${alg}-${raw}`;
}

/**
 * Resolve the issuer public key for wrapper-proof verification, returning RAW key
 * bytes (ed25519: 32-byte raw). `did:web` reuses the shared resolver; any other
 * `iss` falls back to the self-describing `iss_key` (did:key-equivalent). The
 * caller feeds the result straight to `verifyWrapperProof`.
 */
export async function resolveWrapperKey(
  iss: string,
  issKey: string,
  opts: Omit<ResolveDidWebKeyOptions, "iss" | "iss_key"> = {},
): Promise<Uint8Array> {
  // The v1 wrapper suite (eddsa-jcs-2022) is ed25519-only. Fail loudly on any
  // other issuer-key algorithm rather than returning a key that would produce a
  // generic `bad_signature` downstream.
  const { alg } = publicKeyFromIssKey(issKey);
  if (alg !== "ed25519") {
    throw new AnchorsVcError(
      `wrapper proof requires an ed25519 issuer key; got ${alg}`,
    );
  }
  if (iss.startsWith("did:web:")) {
    const served = await resolveDidWebKey({ iss, iss_key: issKey, ...opts });
    // Strip SPKI framing to the raw key the wrapper verifier expects.
    return served.length === ED25519_SPKI_DER_LEN
      ? served.subarray(ED25519_SPKI_PREFIX_LEN)
      : served;
  }
  return publicKeyFromIssKey(issKey).key;
}
