/**
 * verifyCredentialStatus — W3C Status List 2021 reconciliation.
 *
 * Phase D Task 19. Resolves the full status of an envelope's credentialStatus
 * pointer against a fetched + signature-verified Status List Credential, with
 * optional chain-successor reconciliation.
 *
 * Design invariants:
 *   - Advisory-only: this function NEVER poisons `signature_valid` on the
 *     calling verifier. All states are informational except `credentialStatus`
 *     presence on APR (that guard lives in apr-verifier/src/envelope-v2.ts).
 *   - When called with no `rootKey`, returns `{ state: "not_attempted" }` and
 *     skips all I/O. Callers may surface this as a missing-config note.
 *   - v=1 paths are never passed here; callers are responsible for dispatch.
 *
 * Chain reconciliation:
 *   If `chainSuccessorExists(envelope.id)` is true AND the bit is 0, the list
 *   is behind the chain → `revoked_by_chain` (optionally with `status_stale`
 *   warning if the list entry was also stale).
 *   If the bit is 1 AND `chainSuccessorExists` returns false (default), the
 *   list says revoked but no chain successor is known → `revoked` with
 *   `status_chain_inconsistency` warning.
 */

import { validateCredentialStatusPointer } from "./pointer.ts";
import { fetchStatusListCredential } from "./fetch.ts";
import { verifyStatusListCredentialSignature } from "./verify.ts";
import { decodeEncodedList, readBitAt } from "./decode.ts";
import { InMemoryStatusCache } from "./cache.ts";
import type { Envelope } from "../envelope-types.ts";
import type {
  StatusCheck,
  StatusCacheConfig,
  RootKeyMaterial,
  StatusListCredential,
} from "./types.ts";

export interface ReconcileOpts {
  /**
   * Root key for verifying the Status List Credential signature. Required for
   * a real check. If absent (undefined), returns `{ state: "not_attempted" }`.
   */
  rootKey?: RootKeyMaterial;
  /** Cache / freshness config. Defaults: freshTtlSec=3600, staleTtlSec=86400. */
  cacheConfig?: StatusCacheConfig;
  /**
   * Caller-supplied chain-successor resolver. Return `true` if a successor
   * receipt (withdrawal / modification) exists for the given envelope ID.
   * Defaults to `async () => false` (chain check skipped / no-op).
   *
   * For ACR callers: wire this to whatever ledger/store tracks chain linkage.
   * The verifier exposes the hook; the implementation is caller-owned.
   */
  chainSuccessorExists?: (id: string) => Promise<boolean>;
  /** Injected fetch — for tests only. Production callers omit this. */
  _testFetch?: typeof fetch;
}

/** Default StatusCacheConfig when caller omits cacheConfig. */
const DEFAULT_CACHE_CONFIG: StatusCacheConfig = {
  freshTtlSec: 3600,
  staleTtlSec: 86400,
  maxEntries: 256,
};

export async function verifyCredentialStatus(
  envelope: Envelope,
  opts: ReconcileOpts,
): Promise<StatusCheck> {
  if (!envelope.credentialStatus) {
    return { state: "no_status_pointer" };
  }

  if (!opts.rootKey) {
    return { state: "not_attempted" };
  }

  // T15 — validate the pointer shape before any I/O.
  const ptr = validateCredentialStatusPointer(envelope.credentialStatus);
  if (!ptr.ok) {
    return { state: "invalid_pointer", reason: ptr.reason ?? "invalid_pointer" };
  }

  const statusListId = envelope.credentialStatus.statusListCredential;
  const cacheConfig = opts.cacheConfig ?? DEFAULT_CACHE_CONFIG;
  const storage =
    cacheConfig.storage ?? new InMemoryStatusCache(cacheConfig.maxEntries ?? 256);
  const chainSuccessorExists = opts.chainSuccessorExists ?? (async () => false);

  const fetchBase = {
    cache: storage,
    freshTtlSec: cacheConfig.freshTtlSec,
    staleTtlSec: cacheConfig.staleTtlSec,
  };
  const fetched = await fetchStatusListCredential(
    statusListId,
    opts._testFetch !== undefined
      ? { ...fetchBase, _testFetch: opts._testFetch }
      : fetchBase,
  );

  if (fetched.state === "unreachable") {
    return { state: "unreachable", reason: fetched.reason };
  }

  const entry = fetched.entry;
  const isStale = fetched.state === "stale";
  const cachedAgeSec = isStale ? fetched.cached_age_sec : undefined;

  const sigOk = await verifyStatusListCredentialSignature(entry.body, opts.rootKey);
  if (!sigOk) {
    return { state: "list_signature_invalid" };
  }

  // Narrow the credential body for statusPurpose + encodedList.
  const body = entry.body as StatusListCredential;
  if (
    !body?.credentialSubject?.statusPurpose ||
    body.credentialSubject.statusPurpose !== envelope.credentialStatus.statusPurpose
  ) {
    return { state: "list_mismatch", reason: "statusPurpose_mismatch" };
  }

  let bits: Uint8Array;
  let bit: 0 | 1;
  try {
    bits = decodeEncodedList(body.credentialSubject.encodedList);
    const idx = parseInt(envelope.credentialStatus.statusListIndex, 10);
    // Guard against indices that overflow safe-integer or exceed the bitstring.
    // `readBitAt` internally does `index >>> 3` (ToUint32 modulo 2^32), so a
    // statusListIndex > 2^32 would silently alias to a small index and return
    // the wrong bit. Pointer-schema regex `/^\d+$/` doesn't bound numerically.
    if (!Number.isSafeInteger(idx) || idx >= bits.length * 8) {
      return { state: "list_mismatch", reason: "statusListIndex_out_of_range" };
    }
    bit = readBitAt(bits, idx);
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    return { state: "list_mismatch", reason };
  }

  // Chain reconciliation.
  const chainSuccessor = await chainSuccessorExists(envelope.id);

  if (chainSuccessor && bit === 0) {
    // Chain says revoked; list hasn't caught up yet.
    if (isStale && cachedAgeSec !== undefined) {
      return {
        state: "revoked_by_chain",
        status_list_id: statusListId,
        warnings: ["status_stale"],
        cached_age_sec: cachedAgeSec,
      };
    }
    return { state: "revoked_by_chain", status_list_id: statusListId };
  }

  if (!chainSuccessor && bit === 1) {
    // List says revoked; no known chain successor — surface inconsistency warning.
    // If the cache is also stale, both signals matter: an auditor should see
    // `status_stale` (cache past freshTtl, retryable) AND
    // `status_chain_inconsistency` (chain doesn't show the successor that the
    // list implies). `cached_age_sec` is preserved so the staleness is
    // quantifiable.
    if (isStale && cachedAgeSec !== undefined) {
      return {
        state: "revoked_stale",
        fresh_until: entry.fresh_until,
        status_list_id: statusListId,
        cached_age_sec: cachedAgeSec,
        warnings: ["status_stale", "status_chain_inconsistency"],
      };
    }
    return {
      state: "revoked",
      fresh_until: entry.fresh_until,
      status_list_id: statusListId,
      warnings: ["status_chain_inconsistency"],
    };
  }

  if (bit === 1) {
    if (isStale && cachedAgeSec !== undefined) {
      return {
        state: "revoked_stale",
        fresh_until: entry.fresh_until,
        status_list_id: statusListId,
        cached_age_sec: cachedAgeSec,
        warnings: ["status_stale"],
      };
    }
    return { state: "revoked", fresh_until: entry.fresh_until, status_list_id: statusListId };
  }

  // bit === 0, no chain successor.
  if (isStale && cachedAgeSec !== undefined) {
    return {
      state: "active_stale",
      fresh_until: entry.fresh_until,
      status_list_id: statusListId,
      cached_age_sec: cachedAgeSec,
      warnings: ["status_stale"],
    };
  }
  return { state: "active", fresh_until: entry.fresh_until, status_list_id: statusListId };
}
