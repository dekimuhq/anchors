/**
 * Status-list binding + freshness checks (security audit finding F3).
 *
 * A valid list signature proves only "the root key signed SOME list". It does
 * not prove the list is the one the pointer named, nor that it is the newest
 * one: a validly-signed list for a different URL (substitution) or an older
 * genuine snapshot of the same list (rollback — e.g. from before a revocation)
 * would otherwise be accepted as the answer.
 *
 * `checkListBinding` runs AFTER the signature verifies and returns a
 * `list_mismatch` reason, or `null` when the list may be used.
 *
 * ## What the rollback defence actually requires (PUBLISHER CONTRACT)
 *
 * The signed body has no sequence number; `validFrom` is the only signed
 * ordering signal. A list publisher MUST therefore sign `validFrom` = the
 * SIGNING time of each re-sign, strictly increasing per re-sign (never the
 * start of a time bucket). Only then does:
 *   - `validFrom < high-water`  detect replay of an older snapshot, and
 *   - `maxListAgeSec`           measure freshness rather than bucket age.
 * If a publisher re-signs with a constant `validFrom`, replay of a
 * pre-revocation snapshot is indistinguishable from the genuine list EXCEPT for
 * one signal we can still use: for `revocation` lists (`monotoneRevocation`),
 * revocation is permanent, so at an EQUAL `validFrom` a list that clears a bit
 * the cache already knows is set is rejected as `list_rollback`. That catches
 * replay only after this cache has seen the post-revocation list; it cannot
 * help a verifier that never saw it. Suspension lists legitimately clear bits,
 * so they get no such rule.
 */

import { decodeEncodedList } from "./decode.ts";
import type { StatusCacheStorage, StatusListEntry } from "./types.ts";

/** Caller-supplied freshness bounds. All optional; absent = no bound. */
export interface ListFreshnessBounds {
  /**
   * Reject a list whose `validFrom` is earlier than this instant. Meaningful
   * only if the publisher signs `validFrom` = signing time (see the publisher
   * contract above); a bucket-start `validFrom` makes this a bucket-age bound.
   */
  minListValidFrom?: string | Date;
  /**
   * Reject a list whose `validFrom` is more than this many seconds old.
   * Measures FRESHNESS only if the publisher signs `validFrom` = signing time;
   * against a publisher that signs a bucket start it measures bucket age and
   * would reject genuine late-bucket lists — leave unset for such publishers.
   */
  maxListAgeSec?: number;
}

const ISO_WITH_ZONE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:\d{2})$/;

function parseValidFrom(v: unknown): number | undefined {
  if (typeof v !== "string" || !ISO_WITH_ZONE.test(v)) return undefined;
  const ms = Date.parse(v);
  return Number.isNaN(ms) ? undefined : ms;
}

export async function checkListBinding(args: {
  body: { id?: unknown; validFrom?: unknown };
  url: string;
  storage: StatusCacheStorage;
  /** Cache entry as it was BEFORE this fetch (carries the verified high-water mark). */
  prev: StatusListEntry | undefined;
  entry: StatusListEntry;
  bounds: ListFreshnessBounds;
  /** Revocation lists only: a set bit may never clear at an equal `validFrom`. */
  monotoneRevocation?: boolean;
}): Promise<string | null> {
  const { body, url, storage, prev, entry, bounds } = args;
  const hw = prev?.verified_valid_from;

  const reject = async (reason: string): Promise<string> => {
    // Do not let a rejected list overwrite the remembered high-water mark.
    await restorePrev(storage, url, prev);
    return reason;
  };

  // Binding: the signed list must be the list the pointer named.
  if (body.id !== url) return reject("list_id_mismatch");

  const validFrom = parseValidFrom(body.validFrom);
  const boundMs =
    bounds.minListValidFrom === undefined
      ? undefined
      : bounds.minListValidFrom instanceof Date
        ? bounds.minListValidFrom.getTime()
        : Date.parse(bounds.minListValidFrom);
  const bounded =
    bounds.minListValidFrom !== undefined || bounds.maxListAgeSec !== undefined;

  if (validFrom === undefined) {
    // Freshness cannot be established. Fail closed when a bound or history exists.
    if (bounded || hw !== undefined) return reject("list_validFrom_invalid");
    return null;
  }
  if (boundMs !== undefined && (Number.isNaN(boundMs) || validFrom < boundMs)) {
    return reject("list_too_old");
  }
  if (
    bounds.maxListAgeSec !== undefined &&
    Date.now() - validFrom > bounds.maxListAgeSec * 1000
  ) {
    return reject("list_too_old");
  }
  if (hw !== undefined && validFrom < hw) return reject("list_rollback");

  const encoded = (body as { credentialSubject?: { encodedList?: unknown } })
    .credentialSubject?.encodedList;
  if (
    args.monotoneRevocation === true &&
    hw !== undefined &&
    validFrom === hw &&
    prev?.verified_encoded_list !== undefined &&
    typeof encoded === "string" &&
    clearsKnownRevokedBit(prev.verified_encoded_list, encoded)
  ) {
    return reject("list_rollback");
  }

  // Accepted: advance the verified high-water mark (monotonic).
  const next: StatusListEntry = {
    ...entry,
    verified_valid_from: hw === undefined ? validFrom : Math.max(hw, validFrom),
  };
  if (typeof encoded === "string") next.verified_encoded_list = encoded;
  else delete next.verified_encoded_list;
  await storage.set(url, next);
  return null;
}

/**
 * Put the pre-fetch cache entry back. `fetchStatusListCredential` writes the
 * fetched body to the cache BEFORE its signature is checked, so any rejection
 * after the fetch must restore `prev` or an unverified/garbage/old body would
 * replace the entry that carries the verified high-water mark.
 */
export async function restorePrev(
  storage: StatusCacheStorage,
  url: string,
  prev: StatusListEntry | undefined,
): Promise<void> {
  if (prev !== undefined) await storage.set(url, prev);
}

/** True when `next` clears (or truncates away) any bit that `known` has set. */
function clearsKnownRevokedBit(known: string, next: string): boolean {
  let a: Uint8Array;
  let b: Uint8Array;
  try {
    a = decodeEncodedList(known);
    b = decodeEncodedList(next);
  } catch {
    return false; // a malformed new list is rejected by the caller's decode step
  }
  for (let i = 0; i < a.length; i++) {
    if (((a[i] ?? 0) & ~(b[i] ?? 0) & 0xff) !== 0) return true;
  }
  return false;
}
