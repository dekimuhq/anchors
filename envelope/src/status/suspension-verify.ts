/**
 * verifySuspensionStatus — W3C Status List 2021 suspension check.
 *
 * Wave 3. Same fetch → decode → bit-read pipeline as verifyCredentialStatus
 * but reads from envelope.suspensionStatus and returns SuspensionCheck states.
 *
 * No chain reconciliation for suspension — suspension is direct (no chain-
 * successor concept for temporary invalidation).
 */

import { validateSuspensionStatusPointer } from "./suspension-pointer.ts";
import { fetchStatusListCredential } from "./fetch.ts";
import { verifyStatusListCredentialSignature } from "./verify.ts";
import { decodeEncodedList, readBitAt } from "./decode.ts";
import { InMemoryStatusCache } from "./cache.ts";
import type { Envelope } from "../envelope-types.ts";
import type {
  StatusCacheConfig,
  RootKeyMaterial,
  StatusListCredential,
} from "./types.ts";
import type { SuspensionCheck } from "./suspension-types.ts";

export interface SuspensionVerifyOpts {
  rootKey?: RootKeyMaterial;
  cacheConfig?: StatusCacheConfig;
  _testFetch?: typeof fetch;
}

const DEFAULT_CACHE_CONFIG: StatusCacheConfig = {
  freshTtlSec: 3600,
  staleTtlSec: 86400,
  maxEntries: 256,
};

export async function verifySuspensionStatus(
  envelope: Envelope,
  opts: SuspensionVerifyOpts,
): Promise<SuspensionCheck> {
  if (!envelope.suspensionStatus) {
    return { state: "no_suspension_pointer" };
  }

  if (!opts.rootKey) {
    return { state: "not_attempted" };
  }

  const ptr = validateSuspensionStatusPointer(envelope.suspensionStatus);
  if (!ptr.ok) {
    return { state: "invalid_pointer", reason: ptr.reason ?? "invalid_pointer" };
  }

  const statusListId = envelope.suspensionStatus.statusListCredential;
  const cacheConfig = opts.cacheConfig ?? DEFAULT_CACHE_CONFIG;
  const storage =
    cacheConfig.storage ?? new InMemoryStatusCache(cacheConfig.maxEntries ?? 256);

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

  const body = entry.body as StatusListCredential;
  if (
    !body?.credentialSubject?.statusPurpose ||
    body.credentialSubject.statusPurpose !== "suspension"
  ) {
    return { state: "list_mismatch", reason: "statusPurpose_mismatch" };
  }

  let bits: Uint8Array;
  let bit: 0 | 1;
  try {
    bits = decodeEncodedList(body.credentialSubject.encodedList);
    const idx = parseInt(envelope.suspensionStatus.statusListIndex, 10);
    if (!Number.isSafeInteger(idx) || idx >= bits.length * 8) {
      return { state: "list_mismatch", reason: "statusListIndex_out_of_range" };
    }
    bit = readBitAt(bits, idx);
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    return { state: "list_mismatch", reason };
  }

  if (bit === 1) {
    if (isStale && cachedAgeSec !== undefined) {
      return {
        state: "suspended_stale",
        fresh_until: entry.fresh_until,
        status_list_id: statusListId,
        cached_age_sec: cachedAgeSec,
        warnings: ["status_stale"],
      };
    }
    return { state: "suspended", fresh_until: entry.fresh_until, status_list_id: statusListId };
  }

  if (isStale && cachedAgeSec !== undefined) {
    return {
      state: "not_suspended_stale",
      fresh_until: entry.fresh_until,
      status_list_id: statusListId,
      cached_age_sec: cachedAgeSec,
      warnings: ["status_stale"],
    };
  }
  return { state: "not_suspended", fresh_until: entry.fresh_until, status_list_id: statusListId };
}
