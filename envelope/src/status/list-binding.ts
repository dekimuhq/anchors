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
 */

import type { StatusCacheStorage, StatusListEntry } from "./types.ts";

/** Caller-supplied freshness bounds. All optional; absent = no bound. */
export interface ListFreshnessBounds {
  /** Reject a list whose `validFrom` is earlier than this instant. */
  minListValidFrom?: string | Date;
  /** Reject a list whose `validFrom` is more than this many seconds old. */
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
}): Promise<string | null> {
  const { body, url, storage, prev, entry, bounds } = args;
  const hw = prev?.verified_valid_from;

  const reject = async (reason: string): Promise<string> => {
    // Do not let a rejected list overwrite the remembered high-water mark.
    if (prev !== undefined && hw !== undefined) await storage.set(url, prev);
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

  // Accepted: advance the verified high-water mark (monotonic).
  await storage.set(url, {
    ...entry,
    verified_valid_from: hw === undefined ? validFrom : Math.max(hw, validFrom),
  });
  return null;
}
