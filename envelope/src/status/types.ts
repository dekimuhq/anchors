/**
 * CredentialStatus — W3C Bitstring Status List 2021 Entry (real shape, Phase A Task 2).
 *
 * Fields: id, type ("StatusList2021Entry"), statusPurpose ("revocation"),
 *         statusListIndex (decimal string), statusListCredential (URL).
 *
 * Re-exported from the envelope-types canonical location — single source of truth.
 *
 * Phase D Task 16 adds Status List fetcher + cache types alongside the pointer shape:
 *   - StatusListEntry      — cached VC body + freshness metadata
 *   - StatusCacheStorage   — pluggable cache backend (in-memory default)
 *   - StatusCacheConfig    — caller-facing configuration knobs
 *   - StatusFetchResult    — discriminated result returned by the fetcher
 */

export type { CredentialStatus } from "../envelope-types.ts";

/**
 * Cached Status List 2021 Credential entry.
 *
 * `fetched_at` and `fresh_until` are unix-ms timestamps. `body` is the raw VC JSON
 * (parsed from the wire), kept opaque so the bit-decoder can re-validate shape.
 * `etag` is preserved across refreshes to support 304 conditional revalidation.
 */
export interface StatusListEntry {
  fetched_at: number;
  fresh_until: number;
  body: unknown;
  etag?: string;
}

/**
 * Pluggable status-list cache backend.
 *
 * The default `InMemoryStatusCache` implements this with a bounded LRU map;
 * production callers may swap in a Redis-backed or filesystem-backed
 * implementation without touching the fetcher.
 */
export interface StatusCacheStorage {
  get(url: string): Promise<StatusListEntry | undefined>;
  set(url: string, entry: StatusListEntry): Promise<void>;
}

/**
 * Caller-facing configuration for status-list freshness behaviour.
 *
 * `freshTtlSec` (recommended baseline 3600) bounds how long a cached entry is
 * considered authoritative without a refetch. `staleTtlSec` (recommended
 * baseline 86400) bounds the grace window during which an expired entry is
 * still acceptable when the upstream is unreachable. `maxEntries` (default
 * 256, used by InMemoryStatusCache when no `storage` is provided) sizes the
 * in-memory LRU.
 *
 * Defaults are NOT applied at the type level — the consuming verifier
 * (`verifyCredentialStatus`) supplies defaults when the config or its fields
 * are absent. Direct `fetchStatusListCredential` callers MUST supply all
 * three required fields (`freshTtlSec`, `staleTtlSec`, plus a `storage` or
 * `maxEntries` for the in-memory backend).
 */
export interface StatusCacheConfig {
  freshTtlSec: number;
  staleTtlSec: number;
  storage?: StatusCacheStorage;
  maxEntries?: number;
}

/**
 * Discriminated result returned by `fetchStatusListCredential`.
 *
 * - `fresh`        — entry is within `freshTtlSec` (cache hit, no HTTP) OR was
 *                    just refetched (HTTP 200 or 304 with cached body).
 * - `stale`        — refetch failed but cache is still within
 *                    `fresh_until + staleTtlSec`; caller MAY use the body but
 *                    SHOULD surface `cached_age_sec`.
 * - `unreachable`  — refetch failed and cache is absent or beyond stale TTL;
 *                    caller MUST treat the status check as unavailable.
 */
export type StatusFetchResult =
  | { state: "fresh"; entry: StatusListEntry }
  | { state: "stale"; entry: StatusListEntry; cached_age_sec: number }
  | { state: "unreachable"; reason: string };

/**
 * W3C Verifiable Credential — Bitstring Status List 2021.
 *
 * Phase D Task 18: shape consumed by `verifyStatusListCredentialSignature`.
 * Signed with Ed25519Signature2020 over the RFC 8785-canonical credential
 * minus the `proof` block. `proofValue` is the base64url-encoded 64-byte
 * Ed25519 signature.
 */
export interface StatusListCredential {
  "@context": string[];
  id: string;
  type: string[];
  issuer: string;
  validFrom: string;
  credentialSubject: {
    id: string;
    type: "StatusList2021";
    statusPurpose: string;
    encodedList: string;
  };
  proof: {
    type: "Ed25519Signature2020";
    created: string;
    verificationMethod: string;
    proofPurpose: "assertionMethod";
    proofValue: string;
  };
}

/**
 * Root key material for the `did:web:verify.dekimu.com` signer (or any peer).
 *
 * `kid` matches the credential's `proof.verificationMethod` (e.g.
 * `did:web:verify.dekimu.com#root`); `publicKeyDer` is the base64url-encoded
 * SPKI DER of the Ed25519 public key.
 */
export interface RootKeyMaterial {
  kid: string;
  publicKeyDer: string;
}

/**
 * Discriminated reconciliation result returned by `verifyCredentialStatus`
 * (Phase D Task 19). Each state surfaces only the fields meaningful for that
 * branch. Callers map this onto their result objects without re-classifying.
 *
 *  - not_attempted       caller did not supply `statusListRootKey`.
 *  - no_status_pointer   envelope has no `credentialStatus` (`null`).
 *  - invalid_pointer     `validateCredentialStatusPointer` rejected the pointer.
 *  - unreachable         fetcher returned `unreachable` (no usable cache).
 *  - list_signature_invalid    list's own Ed25519Signature2020 didn't verify.
 *  - list_mismatch       statusPurpose mismatch / encodedList missing /
 *                        bitstring decode failed / index out of range.
 *  - active              bit=0 on a fresh list, no chain successor.
 *  - active_stale        bit=0 on a stale (cached past freshTtl) list.
 *  - revoked             bit=1 on a fresh list (chain_inconsistency warning if
 *                        no successor exists in the local chain).
 *  - revoked_stale       bit=1 on a stale (cached past freshTtl) list.
 *  - revoked_by_chain    bit=0 BUT chain says a successor exists (list lags).
 */
export type StatusCheck =
  | { state: "not_attempted" }
  | { state: "no_status_pointer" }
  | { state: "invalid_pointer"; reason: string }
  | { state: "unreachable"; reason: string }
  | { state: "list_signature_invalid" }
  | { state: "list_mismatch"; reason: string }
  | { state: "active"; fresh_until: number; status_list_id: string }
  | {
      state: "active_stale";
      fresh_until: number;
      status_list_id: string;
      cached_age_sec: number;
      warnings: ["status_stale"];
    }
  | {
      state: "revoked";
      fresh_until: number;
      status_list_id: string;
      warnings?: ["status_chain_inconsistency"];
    }
  | {
      // First-element invariant enforced structurally: `warnings[0]` is always
      // `"status_stale"`. Additional entries (e.g. `"status_chain_inconsistency"`
      // when the chain doesn't show a successor on a stale-list revoked bit)
      // may follow.
      state: "revoked_stale";
      fresh_until: number;
      status_list_id: string;
      cached_age_sec: number;
      warnings: readonly ["status_stale", ...string[]];
    }
  | {
      state: "revoked_by_chain";
      status_list_id: string;
      warnings?: ["status_stale"];
      cached_age_sec?: number;
    };
