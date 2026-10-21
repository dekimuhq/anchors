/**
 * family-mint-pipeline.ts — generic mint orchestrator for FamilyManifest.
 *
 * Builds a `mintV2(input) => Promise<Envelope>` function from a predicate
 * bundle extracted from a `FamilyManifest`. The 9-step pipeline mirrors the
 * hand-rolled `mint-v2.ts` that every shipped issuer-kit currently duplicates,
 * providing a symmetric counterpart to `family-verify-pipeline.ts` (Task 1.5).
 *
 * Pipeline order:
 *
 *   1. Private-key length gate (non-32-byte seed → throw immediately)
 *   2. Body schema validation (fail fast — before any crypto work)
 *   3. Subject presence pre-check (enforce family rule at mint time)
 *   4. claim_type selection:
 *        single owned → auto-selected
 *        multi-owned + input.claim_type provided → validate ownership
 *        multi-owned + input.claim_type absent → throw
 *   5. Build unsigned Envelope shape (ULID id, ISO iat, derived iss_key)
 *   6. Optional credentialStatus attach (BEFORE signing — signed-in field)
 *   7. Sign (signEnvelope via the Ed25519 private seed)
 *   8. Optional TSA attach (AFTER signing — signed-out field)
 *   9. Return signed (+ optionally timestamped) Envelope
 *
 * NOTE: field_root is a body-level concern computed inside each issuer-kit's
 * body-builder, not at the envelope layer. The orchestrator receives the final
 * `body` as-is and never computes field_root itself (Phase 4 per-family
 * migration may hoist this when bodies are structurally known here).
 *
 * NOTE: tsa_mandate is a verifier-side rule. The mint pipeline does NOT enforce
 * it — a receipt minted without TSA will fail the verifier's mandate check, but
 * that is deliberate (issuers can mint off-network and attach TSA later).
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/envelope
 * Phase A.2 Task 1.6.
 */

import {
  signEnvelope,
  signEnvelopeSig2,
  SIG_ALG_RANK,
} from "./envelope.ts";
import {
  generateReceiptId,
  keyObjectFromSeed,
  keyObjectFromMlDsaSecret,
} from "./mint-helpers.ts";
import {
  MLDSA65_SEED_BYTES,
  MLDSA65_PUBKEY_BYTES,
  type MlDsaSecretKey,
} from "./ml-dsa.ts";
import { attachTsaBlock } from "./tsa/attach.ts";
import type { TsaFetcher } from "./tsa/attach.ts";
import type { TsaConfig } from "./tsa/types.ts";
import { attachCredentialStatus } from "./status/attach.ts";
import type { StatusListConfig } from "./status/attach.ts";
import { attachSuspensionStatus } from "./status/suspension-attach.ts";
import type { SuspensionListConfig } from "./status/suspension-attach.ts";
import type { Envelope, AnchorProof, Kind, Cause, SigAlg } from "./envelope-types.ts";
import type { JsonLogicAst } from "./jsonlogic-types.ts";
import type {
  FamilyMeta,
  BodyValidateResult,
  SubjectPresenceResult,
} from "./define-family.ts";
import type { ClaimType } from "./envelope-types.ts";

// ── Public types ─────────────────────────────────────────────────────────────

/**
 * Input to `mintV2()` bound on a `FamilyManifest`.
 *
 * Required fields cover the minimum needed to produce a valid, signed v=2
 * envelope. Optional fields map to the optional envelope sections documented
 * in the v1.2 spec.
 */
export interface FamilyMintV2Input {
  /**
   * Pre-validated body. The orchestrator will re-validate it against the
   * family's `body_schema` before doing any crypto work, so passing an
   * already-validated body is fine — the check is a lightweight gate.
   */
  readonly body: unknown;

  /**
   * 32-byte Ed25519 private key seed. Must be exactly 32 bytes.
   * Use `generateKeypair()` from `ed25519.ts` to produce a valid seed.
   *
   * Provide EXACTLY ONE of `issuerPrivateKey` (Ed25519, the default) or
   * `mlDsaKey` (ML-DSA-65, v1.3 PQC). Omit this field when minting with
   * `mlDsaKey`.
   */
  readonly issuerPrivateKey?: Uint8Array;

  /**
   * v1.3 (§L2) post-quantum signing key — ML-DSA-65 (FIPS 204). When provided,
   * the receipt is signed with ML-DSA-65 instead of Ed25519:
   *   - `sig_alg: "ml-dsa-65"` is set on the envelope (signed-in §L3),
   *   - `iss_key` carries the `ml-dsa-65:<raw-pub>` fingerprint,
   *   - `issuerPrivateKey` MUST be omitted (providing both throws).
   *
   * node:crypto cannot reconstruct an ML-DSA private key from the seed alone,
   * so the secret carries both the 32-byte seed and the 1952-byte raw public
   * key (`MlDsaSecretKey`). Requires Node ≥24.6 (OpenSSL 3.5 ML-DSA binding).
   */
  readonly mlDsaKey?: MlDsaSecretKey;

  /**
   * v1.3 §L7 hybrid dual-sign — an OPTIONAL SECOND signing key. When provided,
   * the receipt carries `sig2` / `sig2_alg` / `sig2_key` alongside the primary
   * `sig`, both over the same bytes. The typical transition pairing is an
   * Ed25519 primary (`issuerPrivateKey`) + an ML-DSA-65 `sig2` (`mlDsa`).
   *
   * Provide EXACTLY ONE of `ed25519` (32-byte seed) | `mlDsa` (MlDsaSecretKey),
   * and its algorithm MUST DIFFER from the primary key's (a same-algorithm pair
   * carries no quantum benefit and throws). Set `sigMinAlg` to commit the
   * downgrade posture (e.g. `"ml-dsa-65"`) so a stripped PQC half is detectable.
   */
  readonly sig2?: {
    readonly ed25519?: Uint8Array;
    readonly mlDsa?: MlDsaSecretKey;
  };

  /**
   * v1.3 §C-2 signed-in downgrade posture. When set, the verifier rejects the
   * receipt unless a valid signature whose algorithm rank ≥ this is present.
   * Mint enforces that some provided key satisfies it (else the receipt would
   * fail its own posture). Omit for a classical-acceptable receipt.
   */
  readonly sigMinAlg?: SigAlg | null;

  /**
   * Issuer DID or short identifier, e.g. "did:web:invoiceup.app" or "invoiceup".
   * Placed in `iss` on the envelope.
   */
  readonly issuerDid: string;

  /**
   * Key identifier, placed in `iss_key` prefix. Optional; defaults to
   * `"default"`. In typical use, the issuer-kit derives iss_key from the
   * public key fingerprint — passing kid here is for label tracking only.
   *
   * Recon note: per-family issuer-kits (apr, alr) pass kid only for their
   * internal SigningKey shape. The orchestrator derives `iss_key` from the
   * public key bytes — the `kid` field is not embedded on the wire.
   */
  readonly kid?: string;

  /**
   * Envelope-level subject. `null` for families with `subject_presence:
   * "must-be-null"` (e.g. ALR). Required non-empty string for families with
   * `subject_presence: "must-be-present"` (e.g. APR).
   *
   * The orchestrator enforces the family rule at mint time (Step 3).
   */
  readonly subject: string | null;

  /**
   * Claim-type discriminator. Required when the family owns >1 claim_types
   * (e.g. ARR owns 8 discriminators). For single-claim families (APR, ALR,
   * ACR, ANR) the field is optional — the single owned claim_type is selected
   * automatically. Passing a claim_type that is not owned by the family throws.
   */
  readonly claim_type?: string;

  /**
   * Anchor proof supplied by the caller. Post-mint, the log worker can replace
   * this with a real inclusion proof — `anchor` is a signed-out field and does
   * not affect the signature.
   */
  readonly anchor: AnchorProof;

  /** Optional: expiry timestamp ISO 8601 UTC, or null. */
  readonly exp?: string | null;

  /** Optional: previous receipt ID for chain linkage, or null. */
  readonly prev?: string | null;

  /** Optional: URI to the applicable policy document. */
  readonly policy_uri?: string | null;

  /** Optional: SHA-256 hash of the policy document. */
  readonly policy_hash?: string | null;

  /** Optional: semantic version of the policy document. */
  readonly policy_version?: string | null;

  /**
   * v1.2 §4.1 receipt classification. Families that forbid kind (e.g. APR per
   * spec §6 + L9) validate this externally — the orchestrator passes it
   * through verbatim.
   */
  readonly kind?: Kind | null;

  /**
   * v1.2 §4.2 typed trigger. Passed verbatim into the unsigned envelope;
   * null when omitted.
   */
  readonly cause?: Cause | null;

  /**
   * v1.2 §4.3 JSON Logic predicate. Families that forbid predicates
   * (e.g. APR per L9) validate this externally — the orchestrator passes it
   * through verbatim. Absent when omitted.
   */
  readonly predicate?: JsonLogicAst | null;

  /**
   * Public key fingerprint of the expected countersigner — `ed25519:<base64url>`.
   * Signed-in: committed by the issuer at mint time. When absent, the receipt
   * carries no countersigner identity and countersig verification is format-only.
   */
  readonly countersig_key?: `ed25519:${string}` | null;

  /**
   * RFC 3161 TSA configuration. When present, `tsaFetcher` must also be
   * provided. TSA attach happens AFTER signing (Step 8).
   */
  readonly tsa?: TsaConfig;

  /**
   * TSA transport. Caller-provided async function that sends a DER
   * TimeStampReq to the configured TSA URL and returns the raw
   * DER TimeStampResp. Required when `tsa` is provided.
   */
  readonly tsaFetcher?: TsaFetcher;

  /**
   * W3C Bitstring Status List 2021 configuration. When present, a
   * `credentialStatus` pointer is minted and attached BEFORE signing (Step 6)
   * so it is covered by the envelope signature.
   *
   * Pass only when `meta.status_list_slot !== null` for the family.
   */
  readonly statusList?: StatusListConfig;

  /**
   * W3C Bitstring Status List 2021 suspension configuration. When present, a
   * `suspensionStatus` pointer is minted and attached BEFORE signing so it is
   * covered by the envelope signature. Suspension is two-way (suspend/unsuspend),
   * unlike revocation which is permanent.
   */
  readonly suspensionList?: SuspensionListConfig;
}

// ── Predicate bundle ─────────────────────────────────────────────────────────

/**
 * The subset of `FamilyManifest` predicates that `buildMintV2` needs.
 * Intentionally parallel to `FamilyVerifyPredicates` so both builders can
 * share the same bundle from `defineFamily()`.
 */
export interface FamilyMintPredicates<BodyType = unknown> {
  meta: FamilyMeta;
  validateBody: (body: unknown) => BodyValidateResult<BodyType>;
  checkSubjectPresence: (subject: string | null | undefined, body?: unknown) => SubjectPresenceResult;
  isOwnedClaimType: (claim_type: string) => boolean;
}

// ── Builder ──────────────────────────────────────────────────────────────────

/**
 * Build a `mintV2` function from a predicate bundle.
 *
 * The returned function is async and throws on any hard validation failure
 * (bad key length, body schema reject, subject presence violation,
 * claim_type mismatch, TSA config inconsistency).
 *
 * Usage:
 *   const mint = buildMintV2(manifest);
 *   const envelope = await mint({ body, issuerPrivateKey, issuerDid, subject, anchor });
 */
export function buildMintV2<BodyType>(
  predicates: FamilyMintPredicates<BodyType>,
): (input: FamilyMintV2Input) => Promise<Envelope> {
  const { meta, validateBody, checkSubjectPresence, isOwnedClaimType } = predicates;

  return async (input: FamilyMintV2Input): Promise<Envelope> => {
    // ── Step 1: signing-key gate (alg-aware, no crypto yet) ──────────────────
    // Exactly one of issuerPrivateKey (Ed25519) | mlDsaKey (ML-DSA-65, v1.3).
    const usePqc = input.mlDsaKey !== undefined;
    if (usePqc) {
      if (input.issuerPrivateKey !== undefined) {
        throw new Error(
          `mintV2 (${meta.acronym}): provide exactly one of issuerPrivateKey (ed25519) or mlDsaKey (ml-dsa-65), not both`,
        );
      }
      if (
        input.mlDsaKey!.seed?.length !== MLDSA65_SEED_BYTES ||
        input.mlDsaKey!.publicKeyRaw?.length !== MLDSA65_PUBKEY_BYTES
      ) {
        throw new Error(
          `mintV2 (${meta.acronym}): mlDsaKey requires a ${MLDSA65_SEED_BYTES}-byte seed and ${MLDSA65_PUBKEY_BYTES}-byte publicKeyRaw`,
        );
      }
    } else if (!input.issuerPrivateKey || input.issuerPrivateKey.length !== 32) {
      throw new Error(
        `mintV2 (${meta.acronym}): issuerPrivateKey must be a 32-byte Ed25519 seed`,
      );
    }

    // ── Step 1b: hybrid sig2 gate (v1.3 §L7) ─────────────────────────────────
    const primaryAlg: SigAlg = usePqc ? "ml-dsa-65" : "ed25519";
    let secondaryAlg: SigAlg | undefined;
    if (input.sig2 !== undefined) {
      const hasEd = input.sig2.ed25519 !== undefined;
      const hasMl = input.sig2.mlDsa !== undefined;
      if (hasEd === hasMl) {
        throw new Error(
          `mintV2 (${meta.acronym}): sig2 requires exactly one of ed25519 (32-byte seed) or mlDsa (MlDsaSecretKey)`,
        );
      }
      secondaryAlg = hasMl ? "ml-dsa-65" : "ed25519";
      if (secondaryAlg === primaryAlg) {
        throw new Error(
          `mintV2 (${meta.acronym}): sig2 algorithm must differ from the primary (${primaryAlg}) — a same-algorithm hybrid pair carries no quantum benefit`,
        );
      }
      if (hasEd && input.sig2.ed25519!.length !== 32) {
        throw new Error(
          `mintV2 (${meta.acronym}): sig2.ed25519 must be a 32-byte Ed25519 seed`,
        );
      }
      if (
        hasMl &&
        (input.sig2.mlDsa!.seed?.length !== MLDSA65_SEED_BYTES ||
          input.sig2.mlDsa!.publicKeyRaw?.length !== MLDSA65_PUBKEY_BYTES)
      ) {
        throw new Error(
          `mintV2 (${meta.acronym}): sig2.mlDsa requires a ${MLDSA65_SEED_BYTES}-byte seed and ${MLDSA65_PUBKEY_BYTES}-byte publicKeyRaw`,
        );
      }
    }

    // sig_min_alg satisfiability — never mint a receipt that fails its own
    // posture (the verifier would reject what we just signed).
    if (input.sigMinAlg !== undefined && input.sigMinAlg !== null) {
      const minRank = SIG_ALG_RANK[input.sigMinAlg];
      const available: SigAlg[] = [primaryAlg];
      if (secondaryAlg !== undefined) available.push(secondaryAlg);
      if (!available.some((a) => SIG_ALG_RANK[a] >= minRank)) {
        throw new Error(
          `mintV2 (${meta.acronym}): sigMinAlg "${input.sigMinAlg}" cannot be satisfied — no provided signing key (${available.join(", ")}) reaches it`,
        );
      }
    }

    // ── Step 2: body schema validation (fail fast) ────────────────────────────
    const bodyR = validateBody(input.body);
    if (!bodyR.ok) {
      throw new Error(
        `mintV2 (${meta.acronym}): body invalid — ${bodyR.reason}`,
      );
    }

    // ── Step 3: subject presence pre-check ────────────────────────────────────
    const subjR = checkSubjectPresence(input.subject, input.body);
    if (!subjR.ok) {
      throw new Error(
        `mintV2 (${meta.acronym}): subject presence violation — ${subjR.reason}`,
      );
    }

    // ── Step 4: claim_type selection ──────────────────────────────────────────
    let resolvedClaimType: ClaimType;
    if (meta.claim_types.length === 1) {
      // Single-owned: auto-select; ignore input.claim_type (Phase 4 families
      // may want to verify it matches — for now, accept any or absent).
      resolvedClaimType = meta.claim_types[0]!;
    } else {
      // Multi-owned: input.claim_type required.
      if (!input.claim_type) {
        throw new Error(
          `mintV2 (${meta.acronym}): claim_type required — family owns ${meta.claim_types.length} discriminators: ${meta.claim_types.join(", ")}`,
        );
      }
      if (!isOwnedClaimType(input.claim_type)) {
        throw new Error(
          `mintV2 (${meta.acronym}): claim_type "${input.claim_type}" is not owned by this family`,
        );
      }
      resolvedClaimType = input.claim_type as ClaimType;
    }

    // ── Step 5: build unsigned envelope ──────────────────────────────────────
    const id = generateReceiptId();
    const iat = new Date().toISOString();
    // Resolve the signing KeyObject + iss_key fingerprint for the chosen alg.
    // signEnvelope (Step 7) is alg-agnostic — crypto.sign(null, …) dispatches on
    // the KeyObject — so the only alg-specific work is the key/iss_key/sig_alg.
    const { privateKey, issKey } = usePqc
      ? keyObjectFromMlDsaSecret(input.mlDsaKey!)
      : keyObjectFromSeed(input.issuerPrivateKey!);

    // Resolve the optional hybrid second signing key + its sig2_key fingerprint.
    const secondary =
      input.sig2 === undefined
        ? undefined
        : input.sig2.mlDsa !== undefined
          ? keyObjectFromMlDsaSecret(input.sig2.mlDsa)
          : keyObjectFromSeed(input.sig2.ed25519!);

    // TSA config coherence guard (before any crypto work).
    if (input.tsa !== undefined && input.tsaFetcher === undefined) {
      throw new Error(
        `mintV2 (${meta.acronym}): tsaFetcher required when tsa config is provided`,
      );
    }

    let unsigned: Envelope = {
      v: 2,
      id,
      iat,
      // v1.2 §4.4: numeric mirror of `iat`. MUST equal Date.parse(iat) exactly.
      iat_ms: Date.parse(iat),
      claim_type: resolvedClaimType,
      iss: input.issuerDid,
      iss_key: issKey,
      // v1.3 §L2/§L3: sig_alg is SIGNED-IN. Set it only for ml-dsa-65; an
      // Ed25519 receipt omits it (absent ≡ ed25519) to stay byte-equal to v1.2.
      ...(usePqc ? { sig_alg: "ml-dsa-65" as const } : {}),
      // v1.3 §L7: hybrid second-signature discriminators are SIGNED-IN — set
      // BEFORE signing so both `sig` and `sig2` cover them. `sig2` itself is
      // signed-out and added after signing (Step 7b). `sig_min_alg` (§C-2) is
      // signed-in too.
      ...(secondary !== undefined
        ? { sig2_alg: secondaryAlg!, sig2_key: secondary.issKey }
        : {}),
      ...(input.sigMinAlg !== undefined && input.sigMinAlg !== null
        ? { sig_min_alg: input.sigMinAlg }
        : {}),
      // ALR (and any other must-be-null family) uses null at runtime; the
      // Envelope type declares `subject: string`, so we cast through unknown.
      subject: input.subject as unknown as string,
      exp: input.exp ?? null,
      prev: input.prev ?? null,
      policy_uri: input.policy_uri ?? null,
      policy_hash: input.policy_hash ?? null,
      policy_version: input.policy_version ?? null,
      // v1.2 fields — passed verbatim; families enforce their own constraints.
      ...(input.kind !== undefined ? { kind: input.kind } : { kind: null }),
      cause: input.cause ?? null,
      ...(input.predicate !== undefined ? { predicate: input.predicate } : {}),
      tsa: null,
      credentialStatus: null,
      anchor: input.anchor,
      sig: "",
      countersig: null,
      ...(input.countersig_key !== undefined ? { countersig_key: input.countersig_key } : {}),
      body: input.body,
    };

    // ── Step 6: optional credentialStatus attach (BEFORE signing) ─────────────
    // credentialStatus is a signed-in field — must be set before signEnvelope.
    if (input.statusList !== undefined) {
      // Only families with status_list_slot !== null should attach.
      // The caller is responsible for not passing statusList for APR-like
      // families; the verifier will reject credentialStatus_unexpected.
      unsigned = await attachCredentialStatus(unsigned, input.statusList);
    }

    // ── Step 6.5: optional suspensionStatus attach (BEFORE signing) ──────────
    // suspensionStatus is a signed-in field — must be set before signEnvelope.
    // Suspension is two-way (suspend/unsuspend), unlike revocation (permanent).
    if (input.suspensionList !== undefined) {
      unsigned = await attachSuspensionStatus(unsigned, input.suspensionList);
    }

    // ── Step 7: sign (primary) ────────────────────────────────────────────────
    let signed = await signEnvelope(unsigned, privateKey);

    // ── Step 7b: optional hybrid second signature (v1.3 §L7) ──────────────────
    // sig2 covers the SAME preSigCanonical bytes as sig (sig zeroed, sig2
    // excluded), so signing order is irrelevant.
    if (secondary !== undefined) {
      signed = await signEnvelopeSig2(signed, secondary.privateKey);
    }

    // ── Step 8: optional TSA attach (AFTER signing) ────────────────────────────
    if (input.tsa !== undefined) {
      // tsaFetcher is guaranteed non-undefined by the guard in Step 5.
      return attachTsaBlock(signed, input.tsa, input.tsaFetcher!);
    }

    // ── Step 9: return signed envelope ────────────────────────────────────────
    return signed;
  };
}
