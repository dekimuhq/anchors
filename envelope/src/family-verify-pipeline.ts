/**
 * family-verify-pipeline.ts — generic verify orchestrator for FamilyManifest.
 *
 * Builds a `verifyReceipt(receipt, opts) => Promise<FamilyVerifyResult>` function
 * from a predicate bundle extracted from a `FamilyManifest`. The 13-step pipeline
 * mirrors the hand-rolled `envelope-v2.ts` that every shipped family currently
 * duplicates, with two orchestrator-only additions (body schema + subject presence)
 * inserted at the natural points after signature verification.
 *
 * Pipeline order (matches APR `envelope-v2.ts` for byte-equal migration in Phase 4):
 *
 *   1. Unknown field rejection                       — rejectUnknownFields
 *   2. Global claim_type ownership                   — isKnownClaimType
 *   3. Family claim_type ownership                   — manifest.isOwnedClaimType
 *   4. Status-list slot gate                         — manifest.meta.status_list_slot
 *      (null → credentialStatus MUST be absent; non-null → credentialStatus OK)
 *   5. Key resolution + signature verification       — opts.resolveKey + verifyEnvelopeSignature
 *   6. Trusted-log allowlist (opt-in)                — opts.trustedLogs
 *   7. v1.2 iat_ms + predicate                      — checkIatMs + checkPredicate
 *   8. Policy field matrix                           — validatePolicyFields
 *   9. Body schema                                   — manifest.validateBody
 *  10. Subject presence                              — manifest.checkSubjectPresence
 *  11. Status-list reconciliation (advisory)         — verifyCredentialStatus
 *  12. TSA dispatch (advisory; MANDATORY level → hard fail)
 *  13. Profile dispatch (advisory; result surfaced in profile_state)
 *
 * Advisory steps (11–13) never poison `signature_valid` on their own, EXCEPT:
 *   - TSA with tsaMandateLevel "mandatory" + tsa_absent → signature_valid: false
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/envelope
 * Phase A.2 Task 1.5.
 */

import {
  verifyEnvelopeHybrid,
  keyBytesFromKeyRef,
  isKnownClaimType,
  rejectUnknownFields,
  isSupportedSigAlg,
  SIG_ALG_RANK,
} from "./envelope.ts";
import { base64UrlDecode } from "./base64url.ts";
import {
  validatePolicyFields,
  fetchAndCheckPolicy,
} from "./policy.ts";
import {
  checkIatMs,
  checkPredicate,
} from "./predicate-verify.ts";
import type { Envelope, SigAlg } from "./envelope-types.ts";
import {
  verifyTsa,
  computeTsaImprint,
  loadTrustAnchors,
  defaultTrustAnchorPath,
} from "./tsa/index.ts";
import type { TrustAnchor, TsaReason, TsaState } from "./tsa/index.ts";
import { verifyCredentialStatus } from "./status/reconcile.ts";
import type { StatusCheck, RootKeyMaterial, StatusCacheConfig } from "./status/index.ts";
import { dispatchProfiles } from "./profile/dispatch.ts";
import type { ProfileStateEntry } from "./profile/types.ts";
import type {
  FamilyMeta,
  BodyValidateResult,
  SubjectPresenceResult,
  TsaMandateLevel,
  ComposeCallback,
} from "./define-family.ts";
import type { ProfileValidator } from "./profile/types.ts";
import type {
  IssuerTrustOutcome,
  IssuerTrustResult,
  TrustedIssuerRecord,
  VerifyIssuerTrust,
  VerifyIssuerPqc,
} from "./issuer-trust.ts";

// ── Public types ─────────────────────────────────────────────────────────────

/**
 * Options for `verifyReceipt()` bound on a `FamilyManifest`.
 *
 * `resolveKey` is required. All other fields are opt-in to enable the
 * corresponding advisory or audit step.
 */
export interface FamilyVerifyOptions {
  /**
   * Resolves the issuer's DER-encoded Ed25519 public key (SubjectPublicKeyInfo
   * format) for the given envelope. Typically reads `envelope.iss_key` (the
   * `ed25519:<base64>` fingerprint) and looks up a trusted key store.
   *
   * Return `null` or `undefined` → "issuer unknown" → `signature_valid: false`.
   * A thrown exception is caught and surfaces as
   * `{ signature_valid: false, reason: "resolve_key_threw:<msg>" }`.
   */
  resolveKey: (envelope: unknown) => Promise<Uint8Array | null | undefined> | Uint8Array | null | undefined;

  /**
   * v1.3 §L7 — OPTIONAL resolver for the hybrid second-signature key (`sig2`),
   * symmetric to `resolveKey` but for `sig2_key`. Returns the public-key bytes
   * the `sig2_alg` scheme expects (SPKI DER for ed25519, raw 1952-byte for
   * ml-dsa-65). When omitted, the pipeline SELF-CERTIFIES the `sig2_key`
   * embedded in the receipt (decodes the fingerprint directly) — the honest
   * default, since the per-receipt downgrade defense (§C-2) only needs a VALID
   * PQC signature over the bytes, not a trusted second key (issuer identity is
   * established by the primary `sig`). Supply this only to bind `sig2` to a
   * trusted key store as well. A thrown exception is caught and the `sig2` check
   * is treated as failed (the `sig_min_alg` posture then decides the verdict).
   */
  resolveSig2Key?: (envelope: unknown) => Promise<Uint8Array | null | undefined> | Uint8Array | null | undefined;

  /**
   * Optional exact-match set of trusted anchor-log URLs. When set, any receipt
   * whose `anchor.log` is not in the set (or is missing) returns
   * `{ signature_valid: false, reason: "untrusted_log" }`.
   */
  trustedLogs?: ReadonlySet<string>;

  /** Trust anchors for TSA verification. Default: bundled FreeTSA anchor. */
  tsaAnchors?: TrustAnchor[];
  /** Drift tolerance for TSA genTime vs reference time. Default 300 seconds. */
  tsaDriftToleranceSec?: number;
  /** Reference time for drift comparison. Default: new Date(). */
  tsaReferenceTime?: Date;

  /** Profile ID to dispatch after envelope+body validation. */
  profile?: string;

  /**
   * Opt-in: fetch the policy document at `policy_uri` and verify its SHA-256
   * matches `policy_hash`. Off by default.
   */
  fetchPolicy?: boolean;

  /** Root key for Status List Credential signature verification. */
  statusListRootKey?: RootKeyMaterial;
  /** Status-list cache and freshness configuration. */
  statusCacheConfig?: StatusCacheConfig;
  /** Chain-successor resolver (ACR/ARR — return true if a successor exists). */
  chainResolver?: (id: string) => Promise<boolean>;

  /**
   * Optional issuer-trust dispatch. When defined, the pipeline calls it
   * between Step 5 (key resolution) and Step 6 (trusted-log allowlist).
   * Maps the 5-outcome `IssuerTrustResult` onto `signature_valid` + the
   * `trust_outcome` / `trust_reason` / `trusted_issuer_record` result fields.
   *
   *   - `valid_trusted` / `valid_untrusted` → continue pipeline
   *   - `valid_revoked` → hard fail with reason `issuer_revoked`
   *   - `invalid_key_doc` → hard fail with reason `did_web_invalid_key_doc:<r>`
   *   - `invalid_signature` → hard fail with reason `did_web_invalid_signature:<r>`
   *
   * Default implementation lives in `@dekimuhq/did-web-resolver`'s
   * `makeVerifyIssuerTrust({ trustedIssuers, ... })` factory. Custom
   * implementations are welcome — the surface is type-only structural.
   *
   * When undefined, `trust_outcome` / `trust_reason` / `trusted_issuer_record`
   * remain unset and the rest of the pipeline behaves byte-equal to the pre-0.8.0
   * pipeline. Backward-compatible.
   */
  verifyIssuerTrust?: VerifyIssuerTrust;

  /**
   * Optional issuer PQC-migration enforcement (v1.3 R3 Phase 2 — the
   * inert→enforced flip of the issuer-level HNDL defense). Invoked only when
   * `verifyIssuerTrust` resolved to a matched record (i.e. a closed-allowlist
   * issuer); the pipeline passes the matched record, the highest-rank VALID
   * signature algorithm (from `HybridVerifyResult.validAlgs` — never the
   * receipt's self-described `sig_alg`), and the envelope. A `{ ok: false }`
   * verdict hard-fails the receipt (`signature_valid:false`, reason surfaced,
   * e.g. `issuer_pqc_mandatory:ml-dsa-65`); a thrown error becomes
   * `verify_issuer_pqc_threw:<msg>`.
   *
   * Default composition: `makeVerifyIssuerPqc({ resolveEffectiveTime })` from
   * `@dekimuhq/anchors-trusted-issuers`, which binds the pure `satisfiesIssuerPqc`
   * policy to a caller-supplied quantum-trustworthy effective-time (no source ⇒
   * `now`, i.e. fail-toward-rejection per the policy's security contract).
   * Injected (not imported) because envelope must not depend on trusted-issuers.
   *
   * When undefined, no PQC enforcement runs — the inert pre-Phase-2 behavior.
   */
  verifyIssuerPqc?: VerifyIssuerPqc;

  /**
   * Optional cross-family resolvers. Consumed by family `compose` callbacks
   * that walk into a sibling family (e.g. ASR art17 fulfilment → ARR erasure
   * receipt, ASR request.recipient_notified → ALR `disclosed` events). Each
   * resolver MUST return either the resolved receipt envelope (a plain
   * object — the compose callback duck-types the fields it inspects) or
   * `null` to indicate "not found". A thrown exception is caught by the
   * pipeline and surfaces as `compose_threw:<msg>`.
   *
   * When undefined, the consuming compose callback MUST skip the related
   * cross-walk silently — callers that don't wire resolvers MUST keep
   * passing verification (matches the optional-resolver discipline of
   * `chainResolver`, `statusListRootKey`, `fetchPolicy`, etc.).
   *
   * Type is `unknown` because each family verifier owns its own envelope
   * type. Compose callbacks duck-type the fields they actually need
   * (`claim_type`, `subject`, `body.target_kind`, etc.).
   */
  resolveArr?: (id: string) => Promise<unknown> | unknown;
  resolveAlr?: (id: string) => Promise<unknown> | unknown;
  resolveAtr?: (id: string) => Promise<unknown> | unknown;
  resolveApur?: (id: string) => Promise<unknown> | unknown;

  /**
   * Optional "find the complete set of disclosed-ALR receipt ids for this
   * subject" resolver. Consumed by family compose callbacks that need to
   * detect *informational* incompleteness against an authoritative universe
   * (e.g. ASR art19 `request.recipient_notified` cross-checks the body's
   * `recipient_set_alr_ids` against the controller's complete `disclosed`
   * ALR ledger for the subject).
   *
   * When undefined, the consuming compose callback MUST skip the
   * completeness check silently — callers without an authoritative ledger
   * MUST keep passing verification. When defined and the body's set is a
   * strict subset of the resolved complete set, the compose callback
   * SHOULD emit an informational warning (e.g. `art19_recipient_set_incomplete`)
   * via `ComposeResult.warnings`. A thrown exception is caught by the
   * pipeline and surfaces as `compose_threw:<msg>`.
   */
  findDisclosedAlrsForSubject?: (subject: string) => Promise<readonly string[]> | readonly string[];

  /**
   * Optional "fetch receipt by envelope id" resolver. Consumed by family
   * compose callbacks that walk the envelope-`prev` chain to surface
   * chain-walk warnings against an authoritative corpus.
   *
   * Currently consumed by `@dekimuhq/air-verifier` (`composeAir` walks the
   * DPIA lifecycle chain to detect `dpia_review_overdue`, `dpo_commit_drift`,
   * `dpia_post_hoc_warning`, `art36_consultation_overdue`,
   * `voluntary_high_risk_no_consultation`, `re_dpia_predecessor_missing`).
   * Generic surface — `@dekimuhq/anr-verifier` and `@dekimuhq/abr-verifier`
   * plan to adopt the same hook for their cross-event compose passes
   * (Phase 4C / Phase 4D).
   *
   * Return shape: the resolved receipt envelope as a plain object — compose
   * callbacks duck-type the fields they inspect (`id`, `iat`, `iss`, `prev`,
   * `body.event_type`, …). Return `null` or `undefined` to indicate the id
   * is not present in the caller's corpus; the consuming compose callback
   * decides whether absence is informational (`re_dpia_predecessor_missing`)
   * or silent.
   *
   * When undefined, the consuming compose callback MUST skip chain-walk
   * warnings silently — callers without an authoritative chain ledger MUST
   * keep passing verification. Matches the optional-resolver discipline of
   * `resolveArr` / `findDisclosedAlrsForSubject` / `chainResolver`. A thrown
   * exception is caught by the pipeline as `compose_threw:<msg>`.
   *
   * Type is `unknown` because each family's envelope body shape differs.
   * The pipeline does not validate the returned object — that is the
   * compose callback's responsibility.
   */
  resolveReceiptById?: (id: string) => Promise<unknown> | unknown;
}

/**
 * Result of a `verifyReceipt()` call. Mirrors `EnvelopeVerifyResult` in
 * shipped family verifiers so Phase 4 migration can assert byte-equal output.
 */
export interface FamilyVerifyResult {
  /** Always `2` for the v=2 pipeline. */
  envelope_version: 2;
  /** `true` iff all hard checks passed. */
  signature_valid: boolean;
  /** Machine-readable failure reason when `signature_valid: false`. */
  reason?: string;
  /** The receipt's `claim_type`, surfaced for callers that dispatch on it. */
  claim_type?: string;

  // ── TSA fields ──
  /**
   * Full TSA state: `"tsa_absent"` when no block, a `TsaReason` when one was
   * present and verified, or a mandate state (`"tsa_required"` /
   * `"tsa_recommended"`) assigned by a per-family TSA-mandate post-step.
   */
  tsa_state?: TsaState;
  /** Whether the TSA anchor is listed on a trust list (e.g. eIDAS EUTL). */
  tsa_listed?: boolean;
  /** Human-readable anchor name, if a trust anchor was matched. */
  tsa_anchor_name?: string;
  /** ISO 8601 UTC genTime from the TSR, if available. */
  tsa_genTime?: string;
  /** TSA policy OID, if the TST was successfully parsed. */
  tsa_policy_oid?: string;

  // ── Policy fields ──
  policy_uri?: string | null;
  policy_hash?: string | null;
  policy_version?: string | null;
  policy_fetched_match?: "not_attempted" | true | false;

  // ── Status-list fields ──
  status_state?: StatusCheck["state"];
  status_list_id?: string | null;
  warnings?: string[];
  status_fresh_until?: number;
  status_cached_age_sec?: number;

  // ── Profile fields ──
  /** Advisory profile-validator results (never poisons signature_valid). */
  profile_state?: ProfileStateEntry[];

  // ── Issuer-trust fields ──
  /**
   * Issuer-trust outcome from `opts.verifyIssuerTrust`. Undefined when
   * `verifyIssuerTrust` was not supplied. See `IssuerTrustOutcome` for the
   * 5-way discriminator semantics.
   */
  trust_outcome?: IssuerTrustOutcome;
  /**
   * Structured reason string from the trust dispatch. For `valid_*` outcomes
   * this summarises the trust state; for `invalid_*` outcomes this mirrors
   * the underlying resolver error code.
   */
  trust_reason?: string;
  /**
   * Allowlist record matched by the trust dispatch. Null on
   * `valid_untrusted` and on the `invalid_*` outcomes. Non-null on
   * `valid_trusted` and `valid_revoked` (revoked record carries `revoked_at`).
   */
  trusted_issuer_record?: TrustedIssuerRecord | null;
}

// ── Predicate bundle ─────────────────────────────────────────────────────────

/**
 * The subset of `FamilyManifest` predicates that `buildVerifyReceipt` needs.
 * Avoids a circular reference back to `FamilyManifest.verifyReceipt`.
 */
export interface FamilyVerifyPredicates<BodyType = unknown> {
  meta: FamilyMeta;
  validateBody: (body: unknown) => BodyValidateResult<BodyType>;
  isOwnedClaimType: (claim_type: string) => boolean;
  checkSubjectPresence: (subject: string | null | undefined, body?: unknown) => SubjectPresenceResult;
  tsaMandateLevel: (profile_id: string) => TsaMandateLevel;
  profileValidators: readonly ProfileValidator[];
  profileIds: readonly string[];
  hasProfile: (profile_id: string) => boolean;
  /**
   * Optional cross-family composition callback. When present, the orchestrator
   * invokes it as the final pipeline step after profile dispatch. Throw-safe:
   * exceptions are caught and surfaced as `compose_threw:<msg>`.
   */
  compose?: ComposeCallback;
}

// ── Internal status helper ───────────────────────────────────────────────────

function applyStatusCheck(out: FamilyVerifyResult, s: StatusCheck): void {
  out.status_state = s.state;
  switch (s.state) {
    case "not_attempted":
    case "no_status_pointer":
    case "list_signature_invalid":
    case "invalid_pointer":
    case "unreachable":
    case "list_mismatch":
      return;
    case "active":
      out.status_fresh_until = s.fresh_until;
      out.status_list_id = s.status_list_id;
      return;
    case "active_stale":
      out.status_fresh_until = s.fresh_until;
      out.status_list_id = s.status_list_id;
      out.status_cached_age_sec = s.cached_age_sec;
      appendWarnings(out, s.warnings);
      return;
    case "revoked":
      out.status_fresh_until = s.fresh_until;
      out.status_list_id = s.status_list_id;
      if (s.warnings) appendWarnings(out, s.warnings);
      return;
    case "revoked_stale":
      out.status_fresh_until = s.fresh_until;
      out.status_list_id = s.status_list_id;
      out.status_cached_age_sec = s.cached_age_sec;
      appendWarnings(out, s.warnings);
      return;
    case "revoked_by_chain":
      out.status_list_id = s.status_list_id;
      if (s.cached_age_sec !== undefined) out.status_cached_age_sec = s.cached_age_sec;
      if (s.warnings) appendWarnings(out, s.warnings);
      return;
  }
}

function appendWarnings(out: FamilyVerifyResult, ws: readonly string[]): void {
  if (!out.warnings) out.warnings = [];
  for (const w of ws) out.warnings.push(w);
}

// ── Builder ──────────────────────────────────────────────────────────────────

/**
 * Build a `verifyReceipt` function from a predicate bundle.
 *
 * The returned function is async and never throws — all exceptions from
 * `resolveKey` and profile validators are caught and surfaced in the result.
 *
 * Usage:
 *   const verify = buildVerifyReceipt(manifest);
 *   const result = await verify(unknownReceipt, { resolveKey });
 */
export function buildVerifyReceipt<BodyType>(
  predicates: FamilyVerifyPredicates<BodyType>,
): (receipt: unknown, opts: FamilyVerifyOptions) => Promise<FamilyVerifyResult> {
  const {
    meta,
    validateBody,
    isOwnedClaimType,
    checkSubjectPresence,
    tsaMandateLevel,
    profileValidators,
    hasProfile,
    compose,
  } = predicates;

  return async (receipt: unknown, opts: FamilyVerifyOptions): Promise<FamilyVerifyResult> => {
    // ── Step 1: unknown-field rejection ───────────────────────────────────────
    if (typeof receipt !== "object" || receipt === null) {
      return { envelope_version: 2, signature_valid: false, reason: "not_an_object" };
    }
    const fieldErr = rejectUnknownFields(receipt as Record<string, unknown>);
    if (fieldErr) {
      return { envelope_version: 2, signature_valid: false, reason: fieldErr };
    }

    const e = receipt as unknown as Envelope;

    // ── Step 2: global claim_type ownership ──────────────────────────────────
    if (!isKnownClaimType(e.claim_type)) {
      return {
        envelope_version: 2,
        signature_valid: false,
        reason: "schema_invalid:claim_type",
      };
    }

    // ── Step 3: family claim_type ownership ──────────────────────────────────
    if (!isOwnedClaimType(e.claim_type)) {
      return {
        envelope_version: 2,
        signature_valid: false,
        reason: "wrong_protocol",
        claim_type: e.claim_type,
      };
    }

    // ── Step 4: status-list slot gate ─────────────────────────────────────────
    // null slot → family does not consume Status List 2021 → credentialStatus MUST be absent.
    // non-null slot → family consumes Status List 2021 → credentialStatus is allowed.
    if (meta.status_list_slot === null) {
      if (e.credentialStatus !== null && e.credentialStatus !== undefined) {
        return {
          envelope_version: 2,
          signature_valid: false,
          reason: "credentialStatus_unexpected",
          claim_type: e.claim_type,
        };
      }
    }

    // ── Step 4.5: signature-algorithm support gate (v1.3 §L8) ─────────────────
    // `sig_alg` is signed-in; an algorithm this verifier cannot evaluate (e.g. a
    // forward receipt from a newer issuer advertising a PQC scheme) is refused
    // explicitly, never attempted as ed25519 and never silently passed.
    if (!isSupportedSigAlg(e.sig_alg)) {
      return {
        envelope_version: 2,
        signature_valid: false,
        reason: `unsupported_sig_alg:${String(e.sig_alg)}`,
        claim_type: e.claim_type,
      };
    }

    // ── Step 5: key resolution + signature verification ───────────────────────
    let pub: Uint8Array | null | undefined;
    try {
      const resolved = opts.resolveKey(e);
      pub = resolved instanceof Promise ? await resolved : resolved;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        envelope_version: 2,
        signature_valid: false,
        reason: `resolve_key_threw:${msg}`,
        claim_type: e.claim_type,
      };
    }

    if (pub === null || pub === undefined) {
      return {
        envelope_version: 2,
        signature_valid: false,
        reason: "no_key_resolver",
        claim_type: e.claim_type,
      };
    }

    // ── Hybrid second-signature key resolution (v1.3 §L7) ─────────────────────
    // Only when the receipt carries a `sig2`. Self-certify the embedded
    // `sig2_key` unless the caller bound a dedicated `resolveSig2Key`. A null/
    // undefined/throwing resolution leaves sig2 unverified — verifyEnvelopeHybrid
    // then lets the `sig_min_alg` posture decide (fail-closed if it required PQC).
    let sig2Pub: Uint8Array | null | undefined;
    if (e.sig2) {
      if (opts.resolveSig2Key !== undefined) {
        try {
          const r = opts.resolveSig2Key(e);
          sig2Pub = r instanceof Promise ? await r : r;
        } catch {
          sig2Pub = null;
        }
      } else {
        sig2Pub = keyBytesFromKeyRef(e.sig2_key);
      }
    }

    // ── Hybrid verify + sig_min_alg posture enforcement (v1.3 §C-2) ───────────
    const hybrid = verifyEnvelopeHybrid(e, pub, sig2Pub);
    const out: FamilyVerifyResult = {
      envelope_version: 2,
      signature_valid: hybrid.ok,
      claim_type: e.claim_type,
    };

    if (!hybrid.ok) {
      out.reason = hybrid.reason ?? "signature_invalid";
      return out;
    }

    // ── Step 5.5: issuer-trust dispatch (opt-in) ──────────────────────────────
    if (opts.verifyIssuerTrust !== undefined) {
      let trustR: IssuerTrustResult;
      try {
        trustR = await opts.verifyIssuerTrust(e);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        out.signature_valid = false;
        out.reason = `verify_issuer_trust_threw:${msg}`;
        return out;
      }

      out.trust_outcome = trustR.outcome;
      out.trust_reason = trustR.reason;
      out.trusted_issuer_record = trustR.matched_record;

      switch (trustR.outcome) {
        case "valid_trusted":
        case "valid_untrusted":
          // Continue pipeline. `signature_valid` already true from Step 5.
          break;
        case "valid_revoked":
          out.signature_valid = false;
          out.reason = "issuer_revoked";
          return out;
        case "invalid_key_doc":
          out.signature_valid = false;
          out.reason = `did_web_invalid_key_doc:${trustR.reason}`;
          return out;
        case "invalid_signature":
          out.signature_valid = false;
          out.reason = `did_web_invalid_signature:${trustR.reason}`;
          return out;
      }

      // ── Step 5.6: issuer PQC-migration enforcement (v1.3 R3 Phase 2) ─────────
      // Only the valid_trusted / valid_untrusted paths reach here (the others
      // returned above). Enforce ONLY when a record was matched (a closed-
      // allowlist issuer): an untrusted/unknown issuer carries no mandate. The
      // policy is injected (envelope must not depend on trusted-issuers); the
      // pipeline supplies the highest-rank VALID algorithm — read from the
      // VERIFIED signatures, never the receipt's self-described `sig_alg`, which
      // is forgeable post-CRQC. `validAlgs` is non-empty here (hybrid.ok ⟹
      // primaryOk), but the guard keeps it fail-safe if that ever changes.
      if (opts.verifyIssuerPqc !== undefined && trustR.matched_record !== null) {
        let receiptSigAlg: SigAlg | undefined;
        for (const a of hybrid.validAlgs) {
          if (receiptSigAlg === undefined || SIG_ALG_RANK[a] > SIG_ALG_RANK[receiptSigAlg]) {
            receiptSigAlg = a;
          }
        }
        if (receiptSigAlg !== undefined) {
          let pqc: { ok: true } | { ok: false; reason: string };
          try {
            pqc = await opts.verifyIssuerPqc({
              record: trustR.matched_record,
              receiptSigAlg,
              envelope: e,
            });
          } catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            out.signature_valid = false;
            out.reason = `verify_issuer_pqc_threw:${msg}`;
            return out;
          }
          if (!pqc.ok) {
            out.signature_valid = false;
            out.reason = pqc.reason;
            return out;
          }
        }
      }
    } else if (opts.verifyIssuerPqc !== undefined) {
      // ── Step 5.6 misconfig guard (fail-closed) ──────────────────────────────
      // `verifyIssuerPqc` enforces against an issuer's `pqc_mandatory`, which is
      // sourced from the `verifyIssuerTrust` dispatch (`matched_record`). Supplying
      // the PQC hook WITHOUT a trust dispatch would silently enforce NOTHING — the
      // worst failure mode for an HNDL defense: a migrated issuer's classical-only
      // forgery sails through while the verifier believes enforcement is on. Fail
      // closed + loud so the misconfiguration cannot masquerade as enforcement.
      // (Found by doubt-driven adversarial review.)
      out.signature_valid = false;
      out.reason = "issuer_pqc_requires_trust_dispatch";
      return out;
    }

    // ── Step 6: trusted-log allowlist ─────────────────────────────────────────
    if (opts.trustedLogs) {
      const logUrl = e.anchor?.log;
      if (logUrl === undefined || !opts.trustedLogs.has(logUrl)) {
        out.signature_valid = false;
        out.reason = "untrusted_log";
        return out;
      }
    }

    // ── Step 7: v1.2 iat_ms + predicate ──────────────────────────────────────
    const iatR = checkIatMs(e);
    if (!iatR.ok) {
      out.signature_valid = false;
      out.reason = iatR.reason;
      return out;
    }
    const predR = checkPredicate(e);
    if (!predR.ok) {
      out.signature_valid = false;
      out.reason = predR.reason;
      return out;
    }

    // ── Step 8: policy field matrix ───────────────────────────────────────────
    const policyR = validatePolicyFields(e);
    if (!policyR.ok) {
      out.signature_valid = false;
      out.reason = policyR.reason!;
      return out;
    }
    out.policy_uri = e.policy_uri;
    out.policy_hash = e.policy_hash;
    out.policy_version = e.policy_version;
    out.policy_fetched_match = "not_attempted";

    if (opts.fetchPolicy && e.policy_uri && e.policy_hash) {
      out.policy_fetched_match = await fetchAndCheckPolicy(e.policy_uri, e.policy_hash);
    }

    // ── Step 9: body schema ───────────────────────────────────────────────────
    const bodyR = validateBody(e.body);
    if (!bodyR.ok) {
      out.signature_valid = false;
      out.reason = `body_invalid:${bodyR.reason}`;
      return out;
    }

    // ── Step 10: subject presence ─────────────────────────────────────────────
    const subjR = checkSubjectPresence(e.subject, e.body);
    if (!subjR.ok) {
      out.signature_valid = false;
      out.reason = subjR.reason;
      return out;
    }

    // ── Step 11: status-list reconciliation (advisory) ────────────────────────
    if (opts.statusListRootKey) {
      const statusBaseOpts: {
        rootKey: RootKeyMaterial;
        cacheConfig?: StatusCacheConfig;
        chainSuccessorExists?: (id: string) => Promise<boolean>;
      } = { rootKey: opts.statusListRootKey };
      if (opts.statusCacheConfig !== undefined) {
        statusBaseOpts.cacheConfig = opts.statusCacheConfig;
      }
      if (opts.chainResolver !== undefined) {
        statusBaseOpts.chainSuccessorExists = opts.chainResolver;
      }
      const statusR = await verifyCredentialStatus(e, statusBaseOpts);
      applyStatusCheck(out, statusR);
    } else {
      out.status_state = "not_attempted";
    }

    // ── Step 12: TSA dispatch (advisory; MANDATORY → hard fail on tsa_absent) ─
    if (e.tsa) {
      const tsr = base64UrlDecode(e.tsa.tsr);
      const imprint = computeTsaImprint(e);
      const anchors = opts.tsaAnchors ?? loadTrustAnchors([defaultTrustAnchorPath()]);
      const driftSec = opts.tsaDriftToleranceSec ?? 300;
      const refTime = opts.tsaReferenceTime ?? new Date();
      const tsaResult = verifyTsa(tsr, imprint, {
        anchors,
        driftToleranceSec: driftSec,
        referenceTime: refTime,
      });
      out.tsa_state = tsaResult.reason;
      out.tsa_listed = tsaResult.listed;
      if (tsaResult.anchorName !== undefined) out.tsa_anchor_name = tsaResult.anchorName;
      if (tsaResult.genTime !== undefined) out.tsa_genTime = tsaResult.genTime;
      if (tsaResult.policy_oid !== undefined) out.tsa_policy_oid = tsaResult.policy_oid;
    } else {
      out.tsa_state = "tsa_absent";
      out.tsa_listed = false;

      // TSA mandate enforcement: MANDATORY + tsa_absent → hard fail.
      if (opts.profile) {
        const mandate = tsaMandateLevel(opts.profile);
        if (mandate === "mandatory") {
          out.signature_valid = false;
          out.reason = "tsa_required";
          return out;
        }
      }
    }

    // ── Step 13: profile dispatch (advisory) ──────────────────────────────────
    if (opts.profile) {
      if (!hasProfile(opts.profile)) {
        out.signature_valid = false;
        out.reason = "unknown_profile";
        return out;
      }

      // Find the single validator for this profile.
      const profileIdx = predicates.profileIds.indexOf(opts.profile);
      const validator = profileValidators[profileIdx];
      if (validator !== undefined) {
        const ctx: import("./profile/types.ts").ProfileValidatorCtx = {};
        if (out.tsa_state !== undefined) ctx.tsa_state = out.tsa_state;
        if (out.tsa_listed !== undefined) ctx.tsa_listed = out.tsa_listed;
        if (out.tsa_policy_oid !== undefined) ctx.tsa_policy_oid = out.tsa_policy_oid;
        const entries = dispatchProfiles(e, e.body, ctx, [validator]);
        out.profile_state = entries;
      }
    }

    // ── Step 14: composition walk (if family declares one) ────────────────────
    if (compose !== undefined) {
      try {
        const composeInput = {
          envelope: {
            id: e.id,
            claim_type: e.claim_type,
            body: e.body,
            subject: e.subject as string | null,
            iat: e.iat,
            iss: e.iss,
            prev: e.prev as string | null,
          },
          opts,
        };
        const composeR = await compose(composeInput);
        if (composeR.warnings !== undefined && composeR.warnings.length > 0) {
          appendWarnings(out, composeR.warnings);
        }
        if (!composeR.ok) {
          out.signature_valid = false;
          out.reason = composeR.reason;
          return out;
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        out.signature_valid = false;
        out.reason = `compose_threw:${msg}`;
        return out;
      }
    }

    return out;
  };
}
