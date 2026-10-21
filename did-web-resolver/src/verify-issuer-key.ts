import { resolveDidWebKey } from "./resolve.ts";
import { DidWebResolveError, type DidWebResolveErrorCode } from "./errors.ts";
import type { KeyCache } from "./cache.ts";
import type { TrustedIssuerRecord, TrustedIssuersSource } from "./trust-source.ts";

/**
 * Trust outcome from `verifyIssuerKey`.
 *
 * - `valid_trusted` — DID resolves to a key valid in this window, AND issuer
 *   is on the allowlist with `revoked_at: null`.
 * - `valid_untrusted` — DID resolves to a key valid in this window, but issuer
 *   is NOT on the allowlist. Verifier may surface a warning; caller chooses
 *   whether to accept. `valid_untrusted` is also the outcome when no
 *   `trustedIssuers` source is supplied (open trust).
 * - `valid_revoked` — DID resolves to a key valid in this window, but issuer
 *   is on the allowlist with a non-null `revoked_at` ≤ now. Caller MUST treat
 *   this as a hard-fail (family verifiers map it to `issuer_revoked`).
 * - `invalid_key_doc` — Resolver-level failure relating to the key doc itself:
 *   fetch_failed, non_200, json_parse, key_doc_invalid, invalid_public_key_encoding,
 *   iss_key_fingerprint_mismatch, invalid_did, unsupported_did_method, negative_cached.
 * - `invalid_signature` — Resolver-level failure relating to the key match or
 *   rotation window: no_matching_key, key_not_yet_valid, key_no_longer_valid.
 *   Named "invalid_signature" per plan §1.1 because downstream signature
 *   verification cannot proceed.
 */
export type IssuerTrustOutcome =
  | "valid_trusted"
  | "valid_untrusted"
  | "valid_revoked"
  | "invalid_key_doc"
  | "invalid_signature";

export interface IssuerTrustResultValid {
  outcome: "valid_trusted" | "valid_untrusted" | "valid_revoked";
  iss: string;
  iss_key: string;
  /** SPKI DER bytes of the resolved key. */
  spki: Uint8Array;
  /**
   * The matched allowlist record, or null if no `trustedIssuers` source was
   * supplied OR the issuer was not on the allowlist. Distinguishes
   * `valid_untrusted` (record=null) from `valid_trusted`/`valid_revoked`
   * (record set).
   */
  matched_record: TrustedIssuerRecord | null;
  /** Structured reason string. For `valid_*` outcomes, summarises the trust state. */
  reason: string;
}

export interface IssuerTrustResultInvalid {
  outcome: "invalid_key_doc" | "invalid_signature";
  iss: string;
  iss_key: string;
  spki: null;
  matched_record: null;
  /** Mirrors `DidWebResolveError.code` for the underlying failure. */
  reason: DidWebResolveErrorCode | "iss_scheme_unsupported";
}

export type IssuerTrustResult = IssuerTrustResultValid | IssuerTrustResultInvalid;

export interface VerifyIssuerKeyResolveEvent {
  iss: string;
  iss_key: string;
  outcome: IssuerTrustOutcome;
  durationMs: number;
  cacheHit: boolean;
}

export interface VerifyIssuerKeyOptions {
  iss: string;
  iss_key: string;
  /**
   * Trust-tier source. When undefined, every successfully resolved issuer
   * returns `valid_untrusted` (open trust). Family verifiers integrating this
   * function are expected to pass a `TrustedIssuersSource` from
   * `@dekimuhq/anchors-trusted-issuers` or a hand-rolled equivalent.
   */
  trustedIssuers?: TrustedIssuersSource;
  fetcher?: typeof fetch;
  cache?: KeyCache;
  now?: () => Date;
  /**
   * Observability hook. Receives one event per call with the outcome,
   * duration, and cache-hit flag. Forwarded to caller telemetry — this is
   * the single hook for "how often are we hitting the network during a
   * verify pass?".
   */
  onResolve?: (event: VerifyIssuerKeyResolveEvent) => void;
}

const KEY_DOC_CODES = new Set<DidWebResolveErrorCode>([
  "unsupported_did_method",
  "invalid_did",
  "fetch_failed",
  "non_200",
  "json_parse",
  "key_doc_invalid",
  "invalid_public_key_encoding",
  "iss_key_fingerprint_mismatch",
  "negative_cached",
]);

const SIGNATURE_CODES = new Set<DidWebResolveErrorCode>([
  "no_matching_key",
  "key_not_yet_valid",
  "key_no_longer_valid",
]);

/**
 * Resolve `iss` to its SPKI DER bytes via did:web AND dispatch trust-tier
 * policy against an optional `TrustedIssuersSource`.
 *
 * Returns a structured `IssuerTrustResult`. Never throws on documented
 * resolver failure paths — they map to `invalid_key_doc` / `invalid_signature`
 * outcomes. Throws only on programming errors (e.g. malformed options object).
 *
 * Family verifiers' integration pattern (plan §1.4):
 *
 *   const trust = await verifyIssuerKey({ iss, iss_key, trustedIssuers, ... });
 *   if (trust.outcome === "invalid_key_doc" || trust.outcome === "invalid_signature")
 *     return { ok: false, code: trust.reason };
 *   if (trust.outcome === "valid_revoked")
 *     return { ok: false, code: "issuer_revoked" };
 *   verifyAgainstResolvedKey(env, sig, trust.spki);
 */
export async function verifyIssuerKey(opts: VerifyIssuerKeyOptions): Promise<IssuerTrustResult> {
  const startedAt = Date.now();
  const now = opts.now ?? (() => new Date());

  if (!opts.iss.startsWith("did:web:")) {
    const result: IssuerTrustResultInvalid = {
      outcome: "invalid_key_doc",
      iss: opts.iss,
      iss_key: opts.iss_key,
      spki: null,
      matched_record: null,
      reason: "iss_scheme_unsupported",
    };
    opts.onResolve?.({
      iss: opts.iss,
      iss_key: opts.iss_key,
      outcome: result.outcome,
      durationMs: Date.now() - startedAt,
      cacheHit: false,
    });
    return result;
  }

  const cacheKey = `${opts.iss}#${opts.iss_key}`;
  const cacheHit = opts.cache?.get(cacheKey) !== undefined;

  let spki: Uint8Array;
  try {
    spki = await resolveDidWebKey({
      iss: opts.iss,
      iss_key: opts.iss_key,
      ...(opts.fetcher !== undefined ? { fetcher: opts.fetcher } : {}),
      ...(opts.cache !== undefined ? { cache: opts.cache } : {}),
      now,
    });
  } catch (err) {
    if (!(err instanceof DidWebResolveError)) throw err;
    const code = err.code;
    const outcome: "invalid_key_doc" | "invalid_signature" = SIGNATURE_CODES.has(code)
      ? "invalid_signature"
      : KEY_DOC_CODES.has(code)
        ? "invalid_key_doc"
        : "invalid_key_doc";
    const result: IssuerTrustResultInvalid = {
      outcome,
      iss: opts.iss,
      iss_key: opts.iss_key,
      spki: null,
      matched_record: null,
      reason: code,
    };
    opts.onResolve?.({
      iss: opts.iss,
      iss_key: opts.iss_key,
      outcome,
      durationMs: Date.now() - startedAt,
      cacheHit,
    });
    return result;
  }

  const record = opts.trustedIssuers?.lookup(opts.iss, now()) ?? null;
  let trustOutcome: "valid_trusted" | "valid_untrusted" | "valid_revoked";
  let reason: string;

  if (record === null) {
    trustOutcome = "valid_untrusted";
    reason = opts.trustedIssuers === undefined
      ? "no_trusted_issuers_source_supplied"
      : "issuer_not_on_allowlist";
  } else if (record.revoked_at !== null && new Date(record.revoked_at) <= now()) {
    trustOutcome = "valid_revoked";
    reason = `revoked_at:${record.revoked_at}`;
  } else {
    trustOutcome = "valid_trusted";
    reason = `trusted_since:${record.added_at}`;
  }

  const result: IssuerTrustResultValid = {
    outcome: trustOutcome,
    iss: opts.iss,
    iss_key: opts.iss_key,
    spki,
    matched_record: record,
    reason,
  };
  opts.onResolve?.({
    iss: opts.iss,
    iss_key: opts.iss_key,
    outcome: trustOutcome,
    durationMs: Date.now() - startedAt,
    cacheHit,
  });
  return result;
}
