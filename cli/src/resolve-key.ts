/**
 * Offline issuer-key resolvers for the verifier CLI.
 *
 * `FamilyVerifyOptions.resolveKey` must return the issuer's DER-encoded
 * (SubjectPublicKeyInfo) Ed25519 public key, or `null` for "issuer unknown".
 * For OFFLINE / third-party verification there is no Dekimu key store to call —
 * the key the receipt was signed with travels inside the envelope as the
 * `iss_key` fingerprint (`ed25519:<base64url-raw>`). Two postures:
 *
 *   - `selfCertifyingResolveKey` — trust the embedded key. Proves the receipt
 *     is internally consistent and signed by the key it CLAIMS, but NOT that
 *     the key belongs to anyone in particular. Honest label: "self-certifying".
 *   - `makeTrustedKeysResolveKey(set)` — only resolve when the embedded
 *     `iss_key` is in a caller-supplied allowlist of trusted fingerprints.
 *     Anything else returns `null` -> `signature_valid: false`.
 *
 * ML-DSA-65 (`ml-dsa-65:` prefix, v1.3 PQC) is also decoded (rollout R2). Its
 * public key has no SPKI DER framing in `node:crypto` — the verifier consumes
 * the 1952-byte RAW key directly (see `verifyMlDsaPreSig`). So per the
 * `SigVerifier` byte-encoding contract, `keyBytesFromFingerprint` returns SPKI
 * DER for ed25519 and the raw 1952-byte key for ml-dsa-65; each envelope
 * `SIG_VERIFIERS` entry interprets the bytes its own scheme expects. The
 * envelope's `sig_alg`↔`iss_key`-prefix binding (§L8) guarantees the byte form
 * matches the algorithm that will verify the signature.
 */

import { base64UrlDecode, MLDSA65_PUBKEY_BYTES } from "@dekimuhq/anchors-envelope";

/** Standard Ed25519 SubjectPublicKeyInfo prefix (12 bytes), DER. */
const SPKI_ED25519_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

const ED25519_FINGERPRINT = /^ed25519:(.+)$/;
const ML_DSA_65_FINGERPRINT = /^ml-dsa-65:(.+)$/;

/** Read `envelope.iss_key` as a string, or `null`. */
function readIssKey(envelope: unknown): string | null {
  if (typeof envelope !== "object" || envelope === null) return null;
  const raw = (envelope as { iss_key?: unknown }).iss_key;
  return typeof raw === "string" && raw.length > 0 ? raw : null;
}

/**
 * Decode an `ed25519:<base64url>` fingerprint into a DER SPKI public key.
 * Returns `null` for any non-ed25519 algorithm, malformed base64, or a
 * raw key that is not exactly 32 bytes.
 */
export function derFromFingerprint(issKey: string): Uint8Array | null {
  const match = ED25519_FINGERPRINT.exec(issKey);
  if (match === null || match[1] === undefined) return null;
  let raw: Uint8Array;
  try {
    raw = base64UrlDecode(match[1]);
  } catch {
    return null;
  }
  if (raw.length !== 32) return null;
  const der = new Uint8Array(SPKI_ED25519_PREFIX.length + raw.length);
  der.set(SPKI_ED25519_PREFIX, 0);
  der.set(raw, SPKI_ED25519_PREFIX.length);
  return der;
}

/**
 * Decode an `ml-dsa-65:<base64url>` fingerprint into the 1952-byte raw public
 * key (FIPS 204). Returns `null` for any non-ml-dsa-65 algorithm, malformed
 * base64, or a key that is not exactly `MLDSA65_PUBKEY_BYTES`.
 */
export function rawFromMlDsaFingerprint(issKey: string): Uint8Array | null {
  const match = issKey.match(ML_DSA_65_FINGERPRINT);
  if (match === null || match[1] === undefined) return null;
  let raw: Uint8Array;
  try {
    raw = base64UrlDecode(match[1]);
  } catch {
    return null;
  }
  if (raw.length !== MLDSA65_PUBKEY_BYTES) return null;
  return raw;
}

/**
 * Decode an `<alg>:<base64url>` `iss_key` fingerprint into the public-key bytes
 * the matching envelope `SigVerifier` expects: SPKI DER for `ed25519:`, the raw
 * 1952-byte key for `ml-dsa-65:`. Returns `null` for any unregistered algorithm
 * or malformed key.
 */
export function keyBytesFromFingerprint(issKey: string): Uint8Array | null {
  if (issKey.startsWith("ml-dsa-65:")) return rawFromMlDsaFingerprint(issKey);
  return derFromFingerprint(issKey);
}

/**
 * Self-certifying resolver: decode whatever `iss_key` the envelope carries
 * (ed25519 or ml-dsa-65). Returns `null` when the key is absent, an
 * unregistered algorithm, or malformed.
 */
export function selfCertifyingResolveKey(envelope: unknown): Uint8Array | null {
  const issKey = readIssKey(envelope);
  return issKey === null ? null : keyBytesFromFingerprint(issKey);
}

/**
 * Allowlist resolver: resolve the embedded `iss_key` ONLY when its fingerprint
 * is in `trustedFingerprints` (e.g. `["ed25519:AbC..."]`). Any receipt signed
 * by a key outside the set returns `null` -> the family verifier reports
 * `signature_valid: false`.
 */
export function makeTrustedKeysResolveKey(
  trustedFingerprints: ReadonlySet<string>
): (envelope: unknown) => Uint8Array | null {
  return (envelope) => {
    const issKey = readIssKey(envelope);
    if (issKey === null || !trustedFingerprints.has(issKey)) return null;
    return keyBytesFromFingerprint(issKey);
  };
}
