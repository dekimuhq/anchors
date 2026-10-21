/**
 * Canonicalize / sign / verify entry points for the shared Anchored Receipt envelope.
 *
 * canonicalize + signEnvelope: implemented in Phase A Task 3.
 * verifyEnvelopeSignature + isKnownClaimType + rejectUnknownFields: Phase A Task 4.
 */

import {
  sign as edSign,
  verify as edVerify,
  createPublicKey,
  type KeyObject,
} from "node:crypto";

import { canonicalize as jcs } from "./canonicalize.ts";
import { base64UrlDecode, base64UrlEncode } from "./base64url.ts";
import type { Envelope, IssuerKeyRef, SigAlg } from "./envelope-types.ts";
import { CLAIM_TYPES } from "./envelope-types.ts";
import { verifyMlDsaPreSig, MLDSA65_PUBKEY_BYTES } from "./ml-dsa.ts";

// Signed-out fields split into two lists by a hard correctness rule (v1.3 §C-1):
//
//   ZEROED   — mandatory, always-present fields. Set to `null`. Zeroing is
//              idempotent for these because every receipt carries them, so the
//              canonical bytes are unchanged whether or not the field held a
//              value at sign time.
//   EXCLUDED — OPTIONAL signed-out fields. Deleted (not zeroed). Setting an
//              absent optional field to `null` would INJECT a key into the
//              canonical form of every receipt that never carried it, changing
//              the signed bytes and breaking byte-equality for the existing
//              receipt corpus. `delete` on an absent key is a genuine no-op, so
//              old receipts canonicalize identically; receipts that do carry the
//              field (e.g. an `incl` block attached post-mint by the log) drop
//              it before signing/verifying, so its presence never perturbs the
//              signature. `incl` is the v1.4 transparency block — added after
//              minting, therefore signed-out, therefore EXCLUDED not ZEROED.
//
// credentialStatus / suspensionStatus are SIGNED-IN (mutating after sign
// invalidates the sig) and appear in neither list.
const SIGNED_OUT_ZEROED = ["anchor", "sig", "countersig", "tsa"] as const;
// `incl`: v1.4 transparency block (added post-mint). `sig2`: v1.3 §L7 hybrid
// second signature (added at mint, but signed-out so BOTH `sig` and `sig2`
// cover the IDENTICAL pre-signature bytes — you cannot sign over your own
// signature). EXCLUDED (deleted, not zeroed) so a receipt that never carried
// the field canonicalizes byte-identically to the pre-R3 corpus.
const SIGNED_OUT_EXCLUDED = ["incl", "sig2"] as const;

/**
 * Return the canonical JSON string of `e` in pre-signature form:
 *   - the 4 mandatory signed-out fields (`anchor`/`sig`/`countersig`/`tsa`)
 *     zeroed to `null`,
 *   - the optional signed-out fields (`incl`, `sig2`) deleted if present.
 *
 * `credentialStatus`/`suspensionStatus` and the v1.3 `sig_alg`/`sig2_alg`/
 * `sig2_key`/`sig_min_alg` discriminators are SIGNED-IN — present and unchanged
 * in the pre-signature form. Mutating them after signing invalidates the sig.
 * Both `sig` (zeroed) and `sig2` (excluded) therefore cover identical bytes.
 *
 * Uses RFC 8785-lite JCS (sorted UTF-16 keys, no whitespace, NFC strings).
 */
export function preSigCanonical(e: Envelope): string {
  const c: Record<string, unknown> = {
    ...(e as unknown as Record<string, unknown>),
  };
  for (const f of SIGNED_OUT_ZEROED) c[f] = null;
  for (const f of SIGNED_OUT_EXCLUDED) delete c[f];
  return jcs(c);
}

/**
 * Return the UTF-8 byte encoding of `preSigCanonical(e)`.
 *
 * This is the exact byte sequence handed to the Ed25519 signer and verifier.
 */
export function canonicalizeEnvelope(e: Envelope): Uint8Array {
  return new TextEncoder().encode(preSigCanonical(e));
}

/**
 * Sign the envelope with the provided private key.
 * Returns a new Envelope with `sig` set to the base64url-encoded signature.
 *
 * The signature covers `preSigCanonical(e)` UTF-8 bytes.
 *
 * Algorithm-agnostic: `crypto.sign(null, …)` dispatches on the `KeyObject`, so
 * this signs Ed25519 (v1.2 default, deterministic — same envelope+key → byte-
 * equal output) or ML-DSA-65 (v1.3, randomized/hedged — see ml-dsa.ts M-1).
 * The caller MUST set `sig_alg` on `e` to match the key's algorithm before
 * calling (Ed25519 omits it; ML-DSA-65 sets `sig_alg: "ml-dsa-65"`) — `sig_alg`
 * is signed-in (§L3), so it is covered by the signature produced here.
 */
export async function signEnvelope(
  e: Envelope,
  privateKey: KeyObject,
): Promise<Envelope> {
  const sigBytes = edSign(
    null,
    Buffer.from(preSigCanonical(e), "utf8"),
    privateKey,
  );
  return { ...e, sig: base64UrlEncode(new Uint8Array(sigBytes)) };
}

/**
 * v1.3 §L7 hybrid dual-sign: produce the SECOND signature `sig2` over the SAME
 * `preSigCanonical(e)` bytes as `sig`. Returns a new Envelope with `sig2` set.
 *
 * The caller MUST have already set the signed-in `sig2_alg` and `sig2_key`
 * fields to match `sig2PrivateKey`'s algorithm BEFORE the primary `signEnvelope`
 * call — those discriminators are covered by `sig` (and by `sig2`). `sig` is
 * zeroed and `sig2` is excluded in `preSigCanonical`, so signing order between
 * `signEnvelope` and `signEnvelopeSig2` does not matter: both sign identical
 * bytes. Algorithm-agnostic (`crypto.sign(null, …)` dispatches on the KeyObject).
 */
export async function signEnvelopeSig2(
  e: Envelope,
  sig2PrivateKey: KeyObject,
): Promise<Envelope> {
  const sigBytes = edSign(
    null,
    Buffer.from(preSigCanonical(e), "utf8"),
    sig2PrivateKey,
  );
  return { ...e, sig2: base64UrlEncode(new Uint8Array(sigBytes)) };
}

// ── Verify (Phase A Task 4 · v1.3 sig_alg dispatch) ──────────────────────────

/**
 * A signature verifier for one `SigAlg`. Receives the pre-signature canonical
 * bytes, the decoded signature, and the public key in this scheme's own byte
 * encoding (ed25519: SPKI DER; ml-dsa-65: the 1952-byte raw key). Returns `true`
 * iff the signature is valid. MUST NOT throw — callers treat any throw as a
 * verification failure.
 *
 * `resolveKey` (family-verify-pipeline) is responsible for producing the byte
 * form the scheme named by `sig_alg` expects.
 */
type SigVerifier = (
  canonical: Buffer,
  sig: Uint8Array,
  publicKey: Uint8Array,
) => boolean;

/** Ed25519 over SPKI public key — the only registered scheme in Phase 1. */
function verifyEd25519(
  canonical: Buffer,
  sig: Uint8Array,
  publicKeyDer: Uint8Array,
): boolean {
  if (sig.length !== 64) return false;
  const pubKey = createPublicKey({
    key: Buffer.from(publicKeyDer),
    format: "der",
    type: "spki",
  });
  return edVerify(null, canonical, pubKey, sig);
}

/**
 * v1.3 §L8 verifier dispatch registry, keyed by `SigAlg`. The wire format
 * carries `sig_alg`; a verifier routes on it via `alg = sig_alg ?? "ed25519"`.
 * Adding a scheme here is a pure additive change — no wire-format edit.
 *
 * `ml-dsa-65` (FIPS 204) registered 2026-06-04 via native `node:crypto` on
 * Node ≥24.6 (ml-dsa.ts), preserving the no-third-party-crypto invariant.
 */
const SIG_VERIFIERS: Record<SigAlg, SigVerifier> = {
  ed25519: verifyEd25519,
  "ml-dsa-65": verifyMlDsaPreSig,
};

/**
 * Resolve the verifier for `alg` via an OWN-property lookup. `Object.hasOwn`
 * (not the `in` operator, not bare `SIG_VERIFIERS[alg]`) is mandatory here: a
 * forged receipt whose `sig_alg` is an inherited `Object.prototype` member name
 * (`"toString"`, `"valueOf"`, `"constructor"`, `"__proto__"`, …) would otherwise
 * resolve to a prototype method — truthy, callable, and returning a truthy
 * non-boolean — which a naive `if (!verify)` gate would treat as a registered
 * verifier and a naive `return verify(...)` would treat as a valid signature.
 * That is a full signature-verification bypass with no key material. Own-property
 * lookup admits ONLY the explicitly registered schemes.
 */
function resolveVerifier(alg: string): SigVerifier | undefined {
  return Object.hasOwn(SIG_VERIFIERS, alg)
    ? SIG_VERIFIERS[alg as SigAlg]
    : undefined;
}

/**
 * Return `true` if the envelope's signature algorithm is one this verifier can
 * evaluate. `undefined` ≡ `"ed25519"` (§L2). A `sig_alg` outside the registry
 * (e.g. a forward receipt from a newer issuer advertising a PQC scheme) is
 * unsupported — callers MUST refuse with `unsupported_sig_alg`, never guess.
 *
 * Uses an OWN-property check (see `resolveVerifier`) so a prototype-member name
 * cannot masquerade as a supported algorithm.
 */
export function isSupportedSigAlg(sigAlg: string | undefined): boolean {
  return Object.hasOwn(SIG_VERIFIERS, sigAlg ?? "ed25519");
}

/**
 * Verify the issuer signature on an envelope against a DER-encoded public key,
 * dispatching on `sig_alg` (§L8). Absent `sig_alg` ≡ `"ed25519"`.
 *
 * Returns `true` only when `sig` is present, the algorithm is registered, and
 * the signature is cryptographically valid. All failure cases — unsupported
 * algorithm, malformed keys, malformed signatures, or empty `sig` — return
 * `false`. Never throws. (For the distinct `unsupported_sig_alg` failure reason,
 * the verify pipeline gates on `isSupportedSigAlg` before reaching here.)
 *
 * The signature covers `preSigCanonical(e)` UTF-8 bytes.
 */
export function verifyEnvelopeSignature(
  e: Envelope,
  publicKeyDer: Uint8Array,
): boolean {
  try {
    if (!e.sig) return false;

    const alg = e.sig_alg ?? "ed25519";

    // §L8 binding (sig_alg_key_prefix_mismatch): the `iss_key` algorithm prefix
    // MUST equal `sig_alg`. Without this, an issuer could advertise a key under
    // one algorithm while the verifier validates the signature under another —
    // an algorithm-substitution / agility-downgrade primitive once more than one
    // scheme is registered. `iss_key` is `<alg>:<base64url>`; reject a mismatch.
    if (e.iss_key) {
      const prefix = e.iss_key.slice(0, e.iss_key.indexOf(":"));
      if (prefix !== alg) return false;
    }

    const verify = resolveVerifier(alg);
    if (!verify) return false;

    const sigBytes = base64UrlDecode(e.sig);
    const canonical = Buffer.from(preSigCanonical(e), "utf8");

    // Coerce to a strict boolean — a verifier must never report success via a
    // truthy non-boolean (defense-in-depth alongside the own-property lookup).
    return verify(canonical, sigBytes, publicKeyDer) === true;
  } catch {
    return false;
  }
}

// ── v1.3 R3 — hybrid second signature + downgrade posture ────────────────────

/** Standard Ed25519 SubjectPublicKeyInfo prefix (12 bytes), DER. */
const SPKI_ED25519_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

/**
 * Decode a self-describing `<alg>:<base64url-raw-key>` fingerprint into the
 * public-key bytes the matching `SIG_VERIFIERS` entry expects: SPKI DER for
 * `ed25519:`, the raw 1952-byte key for `ml-dsa-65:`. Returns `null` for any
 * unregistered algorithm prefix, malformed base64, or a wrong-length key.
 *
 * This is the SELF-CERTIFYING decode — it trusts the key embedded in the
 * fingerprint. It proves the receipt is internally consistent (signed by the
 * key it CLAIMS), not that the key belongs to a particular issuer; pair it with
 * a trust layer for the latter. Used to resolve `sig2_key` for hybrid receipts
 * when the caller supplies no dedicated `sig2` key resolver (§L7). Mirrors the
 * CLI's `keyBytesFromFingerprint` — kept here so envelope-core can verify a
 * hybrid receipt without depending on the CLI package.
 */
export function keyBytesFromKeyRef(
  ref: IssuerKeyRef | string | null | undefined,
): Uint8Array | null {
  if (typeof ref !== "string" || ref.length === 0) return null;
  const idx = ref.indexOf(":");
  if (idx <= 0) return null;
  const alg = ref.slice(0, idx);
  const b64 = ref.slice(idx + 1);
  if (b64.length === 0) return null;
  let raw: Uint8Array;
  try {
    raw = base64UrlDecode(b64);
  } catch {
    return null;
  }
  if (alg === "ed25519") {
    if (raw.length !== 32) return null;
    const der = new Uint8Array(SPKI_ED25519_PREFIX.length + 32);
    der.set(SPKI_ED25519_PREFIX, 0);
    der.set(raw, SPKI_ED25519_PREFIX.length);
    return der;
  }
  if (alg === "ml-dsa-65") {
    if (raw.length !== MLDSA65_PUBKEY_BYTES) return null;
    return raw;
  }
  return null;
}

/**
 * PQC-migration ordering for the `sig_min_alg` posture (§C-2). Higher rank =
 * quantum-stronger. A valid signature whose alg rank is ≥ `rank(sig_min_alg)`
 * satisfies the receipt's minimum-signature posture. Classical `ed25519` is the
 * floor; every registered PQC scheme ranks above it.
 *
 * Keyed by `SigAlg` so adding a scheme to `SIG_ALGS` forces a rank here (the
 * `Record<SigAlg, …>` makes a missing entry a compile error).
 */
export const SIG_ALG_RANK: Record<SigAlg, number> = {
  ed25519: 0,
  "ml-dsa-65": 1,
};

/**
 * Verify the hybrid SECOND signature `sig2` against its own key, dispatching on
 * `sig2_alg` (§L7). Parallel to `verifyEnvelopeSignature` for the `sig2` slot.
 *
 * Returns `true` only when `sig2` is present, `sig2_alg`/`sig2_key` are present,
 * the `sig2_key` prefix matches `sig2_alg` (§L6 binding for the second slot),
 * the algorithm is registered, and the signature is cryptographically valid over
 * `preSigCanonical(e)` — the same bytes `sig` covers. Never throws.
 */
export function verifyEnvelopeSig2(
  e: Envelope,
  sig2PublicKey: Uint8Array,
): boolean {
  try {
    if (!e.sig2) return false;
    const alg = e.sig2_alg;
    if (!alg) return false;
    if (!e.sig2_key) return false;

    // §L6 binding for the sig2 slot: the sig2_key algorithm prefix MUST equal
    // sig2_alg, or an attacker could advertise a key under one algorithm while
    // the verifier validates the signature under another. Both are signed-in.
    const prefix = e.sig2_key.slice(0, e.sig2_key.indexOf(":"));
    if (prefix !== alg) return false;

    const verify = resolveVerifier(alg);
    if (!verify) return false;

    const sigBytes = base64UrlDecode(e.sig2);
    const canonical = Buffer.from(preSigCanonical(e), "utf8");
    return verify(canonical, sigBytes, sig2PublicKey) === true;
  } catch {
    return false;
  }
}

/** Structured outcome of {@link verifyEnvelopeHybrid}. */
export interface HybridVerifyResult {
  /** Overall verdict: primary `sig` valid AND the `sig_min_alg` posture met. */
  readonly ok: boolean;
  /** Whether the primary `sig` verified. */
  readonly primaryOk: boolean;
  /** Whether the hybrid `sig2` verified (false when absent or unverifiable). */
  readonly sig2Ok: boolean;
  /**
   * The algorithms whose signatures actually verified, in slot order (primary
   * first, then `sig2` if it verified). When the primary `sig` failed, the
   * primary algorithm is absent (a still-valid `sig2` algorithm may be listed,
   * but `ok` is `false` — consumers MUST gate on `ok` before trusting this).
   * Exposed so an out-of-band policy layer (e.g. the issuer PQC-migration mandate,
   * spec §5 / Open Q #3) can read the highest-rank VALID algorithm without
   * re-verifying — the only signal that survives a forged self-described posture.
   */
  readonly validAlgs: readonly SigAlg[];
  /**
   * Failure reason, or `null` when `ok`. One of:
   *   - `signature_invalid` — primary `sig` failed (no path validates neither).
   *   - `unsupported_sig_alg:<alg>` — `sig_min_alg` names an algorithm this
   *     verifier cannot evaluate, so the posture cannot be proven (fail-closed).
   *   - `sig_min_alg_unsatisfied:<alg>` — a posture is required but no valid
   *     signature reaches it (e.g. the PQC half was stripped).
   */
  readonly reason: string | null;
}

/**
 * v1.3 §L7 + §C-2 hybrid verification with downgrade-posture enforcement.
 *
 * Verifies the primary `sig` against `primaryKey` and, when `sig2` is present,
 * the second signature against `sig2Key`, then enforces the signed-in
 * `sig_min_alg` posture: the receipt is rejected unless a VALID signature whose
 * algorithm rank ≥ `rank(sig_min_alg)` is present.
 *
 * The primary `sig` is ALWAYS required (the spec's "no path validates neither" —
 * old verifiers ignore `sig2` but still require `sig`). Pass `sig2Key = null`
 * (or omit) to skip the `sig2` check; if `sig_min_alg` then demands an algorithm
 * only `sig2` could provide, the posture fails closed — which is correct.
 *
 * HARD LIMIT: this enforces per-receipt posture only. Against a CRQC adversary
 * who has broken the classical key, a forged classical-only receipt with
 * `sig_min_alg` absent is still syntactically valid — the complete defense is
 * issuer-level PQC-migration trust state (spec §5 / Open Q #3), enforced in the
 * verify pipeline via the injected `verifyIssuerPqc` seam (R3 Phase 2) reading
 * `validAlgs` from this result. This function stays per-receipt by design.
 */
export function verifyEnvelopeHybrid(
  e: Envelope,
  primaryKey: Uint8Array,
  sig2Key?: Uint8Array | null,
): HybridVerifyResult {
  const primaryAlg: SigAlg = e.sig_alg ?? "ed25519";
  const primaryOk = verifyEnvelopeSignature(e, primaryKey);

  // Collect the algorithms whose signatures actually verified.
  const validAlgs: SigAlg[] = primaryOk ? [primaryAlg] : [];

  let sig2Ok = false;
  if (e.sig2 && e.sig2_alg && e.sig2_key && sig2Key) {
    // Only attempt schemes this verifier supports; an unsupported sig2_alg is
    // simply not counted toward the posture (handled below if sig_min_alg needs it).
    if (isSupportedSigAlg(e.sig2_alg)) {
      sig2Ok = verifyEnvelopeSig2(e, sig2Key);
      if (sig2Ok) validAlgs.push(e.sig2_alg);
    }
  }

  if (!primaryOk) {
    return { ok: false, primaryOk, sig2Ok, validAlgs, reason: "signature_invalid" };
  }

  const min = e.sig_min_alg;
  if (min !== undefined && min !== null) {
    // A receipt that requires an algorithm we cannot evaluate must fail closed —
    // we cannot prove its posture, so we refuse rather than silently pass.
    if (!isSupportedSigAlg(min)) {
      return {
        ok: false,
        primaryOk,
        sig2Ok,
        validAlgs,
        reason: `unsupported_sig_alg:${String(min)}`,
      };
    }
    const minRank = SIG_ALG_RANK[min];
    const satisfied = validAlgs.some((a) => SIG_ALG_RANK[a] >= minRank);
    if (!satisfied) {
      return {
        ok: false,
        primaryOk,
        sig2Ok,
        validAlgs,
        reason: `sig_min_alg_unsatisfied:${min}`,
      };
    }
  }

  return { ok: true, primaryOk, sig2Ok, validAlgs, reason: null };
}

// ── isKnownClaimType (Phase A Task 4) ────────────────────────────────────────

/**
 * Derived from `CLAIM_TYPES` — single source of truth.
 * Adding a new literal to CLAIM_TYPES is sufficient; no second list to update.
 */
const KNOWN_CLAIM_TYPES = new Set<string>(CLAIM_TYPES);

/**
 * Return `true` if `s` is one of the active ClaimType discriminators
 * (`CLAIM_TYPES` in envelope-types.ts is the single source of truth).
 * Parked members and unknown strings return `false`.
 */
export function isKnownClaimType(s: string): boolean {
  return KNOWN_CLAIM_TYPES.has(s);
}

// ── rejectUnknownFields (Phase A Task 4) ─────────────────────────────────────

/**
 * Exhaustive list of the 30 top-level Envelope fields (v1.2 + countersig_key delta + v1.4 incl + v1.3 sig_alg + v1.3 R3 hybrid).
 * Derived from the Envelope interface — update both together. A new field
 * missing from this set fails `rejectUnknownFields` before any signature check.
 *
 * v1.2 additions: `iat_ms`, `kind`, `cause`, `predicate`.
 * countersig_key delta (2026-05-21): `countersig_key`.
 * v1.4 transparency log (2026-05-31): `incl`.
 * v1.3 sig_alg agility hook (2026-06-01): `sig_alg`.
 * v1.3 R3 hybrid dual-sign: `sig2`, `sig2_alg`, `sig2_key`, `sig_min_alg`.
 */
const ALLOWED_TOP_LEVEL = new Set<string>([
  "v",
  "id",
  "claim_type",
  "iss",
  "iss_key",
  "subject",
  "iat",
  "iat_ms",
  "exp",
  "prev",
  "body",
  "policy_uri",
  "policy_hash",
  "policy_version",
  "kind",
  "cause",
  "predicate",
  "tsa",
  "credentialStatus",
  "suspensionStatus",
  "anchor",
  "sig",
  "countersig",
  "countersig_key",
  "incl",
  "sig_alg",
  "sig2",
  "sig2_alg",
  "sig2_key",
  "sig_min_alg",
]);

/**
 * Return `"unknown_field:<name>"` if any top-level key in `e` is not in the
 * allowed 30-field set; return `null` if all keys are known.
 *
 * Returns on the FIRST stray key found (V8 insertion order — deterministic
 * for the same input object).
 */
export function rejectUnknownFields(e: Record<string, unknown>): string | null {
  for (const k of Object.keys(e)) {
    if (!ALLOWED_TOP_LEVEL.has(k)) return `unknown_field:${k}`;
  }
  return null;
}
