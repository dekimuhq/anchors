/**
 * ML-DSA-65 (FIPS 204, NIST category 3) issuer-key helpers + canonical
 * sign/verify — the first post-quantum scheme registered in the v1.3 `sig_alg`
 * agility hook (envelope.ts `SIG_VERIFIERS`). Parallel to `ed25519.ts`.
 *
 * Provider: `node:crypto` on Node ≥24.6 (OpenSSL 3.5 ML-DSA binding, nodejs/node
 * #59259). This preserves the family's "no third-party crypto — node:crypto
 * only" invariant; the Node-floor bump to 24.6 is the cost. Decision:
 * an internal design record (not published)
 *
 * Two deliberate departures from the Ed25519 path, both grounded in the live
 * binding (probed on Node v24.16.0 / OpenSSL 3.5.6):
 *
 *   1. No raw key export. `node:crypto` exposes ML-DSA public keys only as SPKI
 *      DER (1974 B) or JWK (`kty:"AKP"`, `pub` = the 1952 B raw key, base64url).
 *      The wire `iss_key` carries the raw 1952 B public key (`ml-dsa-65:<b64url>`),
 *      symmetric with `ed25519:<b64url-raw-32>`; this module reconstructs the
 *      `KeyObject` from those raw bytes via a JWK import.
 *
 *   2. Randomized (hedged) signatures. ML-DSA defaults to hedged mode and the
 *      Node 24.16 binding does not surface a deterministic toggle (every
 *      `deterministic`/`hedged` option is silently ignored). This is sound for
 *      the envelope: `sig` is signed-OUT of the Merkle leaf (`preSigCanonical`
 *      zeroes it), so a randomized signature yields the same leaf hash, anchor,
 *      and inclusion proof; verification never re-signs; and re-mint already
 *      varies the ULID `id`. Spec M-1 relaxed accordingly (decision doc §M-1).
 */

import * as crypto from "node:crypto";
import { base64UrlEncode, base64UrlDecode } from "./base64url.ts";
import { canonicalize } from "./canonicalize.ts";

/** FIPS 204 ML-DSA-65 raw public-key length, in bytes. */
export const MLDSA65_PUBKEY_BYTES = 1952;
/** FIPS 204 ML-DSA-65 signature length, in bytes. */
export const MLDSA65_SIG_BYTES = 3309;
/** FIPS 204 ML-DSA private-key SEED length (ξ), in bytes — the persistable secret. */
export const MLDSA65_SEED_BYTES = 32;

/** Prefix for the portable `serializeMlDsaSecret` string form. */
const MLDSA65_SECRET_PREFIX = "ml-dsa-65-sk:";

const JWK_ALG = "ML-DSA-65";
/** JWK `kty` for the algorithm-key-pair family (PQC keys), per the JOSE PQC draft. */
const JWK_KTY = "AKP";

const MLDSA65_KEY_TYPE = "ml-dsa-65";

export interface MlDsaKeypair {
  kid: string;
  /** ML-DSA-65 private key, held as a node:crypto KeyObject (no portable raw form). */
  privateKey: crypto.KeyObject;
  /** 1952-byte raw ML-DSA-65 public key — the bytes carried in `iss_key`. */
  publicKeyRaw: Uint8Array;
  /**
   * 32-byte FIPS 204 seed (ξ) — the persistable secret. Pair it with
   * `publicKeyRaw` to reconstruct `privateKey` later (node:crypto cannot derive
   * the public key from the seed alone — see `MlDsaSecretKey`).
   */
  seed: Uint8Array;
}

/**
 * The serialisable form of an ML-DSA-65 signing secret.
 *
 * Unlike Ed25519 — where the 32-byte seed alone reconstructs the keypair — the
 * Node 24.16 / OpenSSL 3.5 ML-DSA binding refuses to import a private key from
 * the seed without the matching public key (probed: a seed-only JWK import
 * throws `ERR_INVALID_ARG_TYPE`). So a persisted ML-DSA secret MUST carry both
 * the 32-byte seed and the 1952-byte raw public key. This is the unit issuers
 * store (in a key vault / env) and reload to mint PQC receipts.
 */
export interface MlDsaSecretKey {
  /** 32-byte FIPS 204 seed (ξ). */
  seed: Uint8Array;
  /** 1952-byte raw public key — required to reconstruct the private `KeyObject`. */
  publicKeyRaw: Uint8Array;
}

/** Generate a fresh ML-DSA-65 keypair for the given `kid`. */
export function generateMlDsaKeypair(kid: string): MlDsaKeypair {
  if (!kid) throw new Error("generateMlDsaKeypair: kid required");
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ml-dsa-65");
  return {
    kid,
    privateKey,
    publicKeyRaw: rawPublicKey(publicKey),
    seed: seedFromPrivateKey(privateKey),
  };
}

// ── Seed serialization (issuer-kit ml-dsa minting) ───────────────────────────

/** Extract the 32-byte FIPS 204 seed (ξ) from an ML-DSA-65 private `KeyObject`. */
export function seedFromPrivateKey(privateKey: crypto.KeyObject): Uint8Array {
  if (privateKey.asymmetricKeyType !== MLDSA65_KEY_TYPE) {
    throw new Error("seedFromPrivateKey: privateKey is not ml-dsa-65");
  }
  const jwk = privateKey.export({ format: "jwk" }) as { priv?: string };
  if (!jwk.priv) throw new Error("seedFromPrivateKey: no seed in private JWK");
  return base64UrlDecode(jwk.priv);
}

/** Capture the persistable secret (seed + raw public key) from a live keypair. */
export function toMlDsaSecret(kp: MlDsaKeypair): MlDsaSecretKey {
  return { seed: kp.seed, publicKeyRaw: kp.publicKeyRaw };
}

/**
 * Reconstruct an ML-DSA-65 private `KeyObject` from a persisted secret.
 *
 * node:crypto needs BOTH the seed and the raw public key (seed-only import
 * throws) — hence `MlDsaSecretKey` carries both.
 *
 * Because the public key is caller-supplied (node cannot derive it from the
 * seed during import), a mismatched seed+pub would otherwise import cleanly and
 * mint a receipt whose `iss_key` (from the pub) does NOT match the actual
 * signing key (from the seed) — a dead-on-arrival receipt that only fails far
 * downstream at verify. We close that by re-deriving the public key from the
 * imported seed and asserting it equals `secret.publicKeyRaw` — failing LOUDLY
 * at reconstruction (mint/load time) instead. (The Ed25519 path can't hit this
 * class because `keyObjectFromSeed` derives the pub from the seed and never
 * trusts a supplied one.)
 */
export function privateKeyFromSecret(secret: MlDsaSecretKey): crypto.KeyObject {
  if (secret.seed.length !== MLDSA65_SEED_BYTES) {
    throw new Error(
      `privateKeyFromSecret: seed must be ${MLDSA65_SEED_BYTES} bytes, got ${secret.seed.length}`,
    );
  }
  if (secret.publicKeyRaw.length !== MLDSA65_PUBKEY_BYTES) {
    throw new Error(
      `privateKeyFromSecret: publicKeyRaw must be ${MLDSA65_PUBKEY_BYTES} bytes, got ${secret.publicKeyRaw.length}`,
    );
  }
  // Newer Node 24.x releases (seen on 24.22) validate the JWK seed↔pub binding
  // inside createPrivateKey and throw "Invalid JWK AKP key"; older ones accept
  // the mismatch and leave it to the explicit check below. Normalise both paths
  // to the same loud error so callers see one failure mode on every Node ≥24.6.
  let privateKey: crypto.KeyObject;
  try {
    privateKey = crypto.createPrivateKey({
      key: {
        kty: JWK_KTY,
        alg: JWK_ALG,
        priv: base64UrlEncode(secret.seed),
        pub: base64UrlEncode(secret.publicKeyRaw),
      },
      format: "jwk",
    });
  } catch (cause) {
    throw new Error(
      "privateKeyFromSecret: seed does not correspond to publicKeyRaw (mismatched/corrupt secret)",
      { cause },
    );
  }
  // Seed↔pub binding: createPublicKey recomputes the pub from the seed (not the
  // supplied bytes), so a mismatch surfaces here.
  const derived = rawPublicKey(crypto.createPublicKey(privateKey));
  if (!timingSafeEqualBytes(derived, secret.publicKeyRaw)) {
    throw new Error(
      "privateKeyFromSecret: seed does not correspond to publicKeyRaw (mismatched/corrupt secret)",
    );
  }
  return privateKey;
}

/** Constant-time-ish byte compare for the seed↔pub binding check. */
function timingSafeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/**
 * Encode a secret as a single portable string for env / vault storage:
 * `ml-dsa-65-sk:<b64url-seed>.<b64url-pub>`. Inverse of `deserializeMlDsaSecret`.
 */
export function serializeMlDsaSecret(secret: MlDsaSecretKey): string {
  if (secret.seed.length !== MLDSA65_SEED_BYTES) {
    throw new Error(`serializeMlDsaSecret: seed must be ${MLDSA65_SEED_BYTES} bytes`);
  }
  if (secret.publicKeyRaw.length !== MLDSA65_PUBKEY_BYTES) {
    throw new Error(`serializeMlDsaSecret: publicKeyRaw must be ${MLDSA65_PUBKEY_BYTES} bytes`);
  }
  return `${MLDSA65_SECRET_PREFIX}${base64UrlEncode(secret.seed)}.${base64UrlEncode(secret.publicKeyRaw)}`;
}

/** Parse the `ml-dsa-65-sk:<seed>.<pub>` portable form. Throws on any malformation. */
export function deserializeMlDsaSecret(s: string): MlDsaSecretKey {
  if (!s.startsWith(MLDSA65_SECRET_PREFIX)) {
    throw new Error(`deserializeMlDsaSecret: missing '${MLDSA65_SECRET_PREFIX}' prefix`);
  }
  const parts = s.slice(MLDSA65_SECRET_PREFIX.length).split(".");
  if (parts.length !== 2) {
    throw new Error("deserializeMlDsaSecret: expected '<seed>.<pub>' after prefix");
  }
  const secret: MlDsaSecretKey = {
    seed: base64UrlDecode(parts[0]!),
    publicKeyRaw: base64UrlDecode(parts[1]!),
  };
  if (secret.seed.length !== MLDSA65_SEED_BYTES) {
    throw new Error(
      `deserializeMlDsaSecret: seed must be ${MLDSA65_SEED_BYTES} bytes, got ${secret.seed.length}`,
    );
  }
  if (secret.publicKeyRaw.length !== MLDSA65_PUBKEY_BYTES) {
    throw new Error(
      `deserializeMlDsaSecret: publicKeyRaw must be ${MLDSA65_PUBKEY_BYTES} bytes, got ${secret.publicKeyRaw.length}`,
    );
  }
  return secret;
}

/** Extract the 1952-byte raw public key from an ML-DSA-65 public `KeyObject`. */
export function rawPublicKey(publicKey: crypto.KeyObject): Uint8Array {
  const jwk = publicKey.export({ format: "jwk" }) as { pub?: string };
  if (!jwk.pub) throw new Error("rawPublicKey: not an ML-DSA public key");
  return base64UrlDecode(jwk.pub);
}

/** Reconstruct an ML-DSA-65 public `KeyObject` from the 1952-byte raw key. */
export function publicKeyFromRaw(publicKeyRaw: Uint8Array): crypto.KeyObject {
  if (publicKeyRaw.length !== MLDSA65_PUBKEY_BYTES) {
    throw new Error(
      `publicKeyFromRaw: expected ${MLDSA65_PUBKEY_BYTES} bytes, got ${publicKeyRaw.length}`,
    );
  }
  return crypto.createPublicKey({
    key: { kty: JWK_KTY, alg: JWK_ALG, pub: base64UrlEncode(publicKeyRaw) },
    format: "jwk",
  });
}

/** Encode a raw public key as the `ml-dsa-65:<base64url>` wire fingerprint. */
export function encodeMlDsaIssKey(publicKeyRaw: Uint8Array): `ml-dsa-65:${string}` {
  return `ml-dsa-65:${base64UrlEncode(publicKeyRaw)}`;
}

/**
 * Sign the canonical-JCS representation of `body` with an ML-DSA-65 private key.
 * Returns a 3309-byte signature. Randomized (hedged) — see module header.
 */
export function signMlDsaCanonical(
  body: unknown,
  privateKey: crypto.KeyObject,
): Uint8Array {
  if (privateKey.asymmetricKeyType !== MLDSA65_KEY_TYPE) {
    throw new Error("signMlDsaCanonical: privateKey is not ml-dsa-65");
  }
  const sig = crypto.sign(null, Buffer.from(canonicalize(body), "utf8"), privateKey);
  return new Uint8Array(sig);
}

/**
 * Verify an ML-DSA-65 signature against `body` (canonicalized via JCS) using the
 * 1952-byte raw public key. Returns `true` iff the signature matches. Returns
 * `false` (never throws) for malformed inputs.
 */
export function verifyMlDsaCanonical(
  body: unknown,
  signature: Uint8Array,
  publicKeyRaw: Uint8Array,
): boolean {
  return verifyMlDsaPreSig(
    Buffer.from(canonicalize(body), "utf8"),
    signature,
    publicKeyRaw,
  );
}

/**
 * `SigVerifier`-shaped ML-DSA-65 check over already-canonical pre-signature
 * bytes. Registered in `envelope.ts` `SIG_VERIFIERS`. Never throws.
 *
 * @param publicKeyRaw the 1952-byte raw public key (decoded from the
 *        `ml-dsa-65:` portion of `iss_key`).
 */
export function verifyMlDsaPreSig(
  canonical: Buffer,
  signature: Uint8Array,
  publicKeyRaw: Uint8Array,
): boolean {
  try {
    if (signature.length !== MLDSA65_SIG_BYTES) return false;
    if (publicKeyRaw.length !== MLDSA65_PUBKEY_BYTES) return false;
    const pk = publicKeyFromRaw(publicKeyRaw);
    return crypto.verify(null, canonical, pk, Buffer.from(signature));
  } catch {
    return false;
  }
}
