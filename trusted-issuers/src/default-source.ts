/**
 * `makeDefaultTrustedIssuersSource` — production-ready `TrustedIssuersSource`
 * that fetches + verifies an `ar.trusted_issuers.v1` document over HTTP, caches
 * the parsed result in-process, and refreshes in the background after a TTL.
 *
 * Behavior (per Phase B master plan §2.4 + Phase B4 plan):
 *   - Lazy: no fetch on construction. First `lookup()` triggers a background
 *     `refresh()` and returns null immediately. Callers that need a synchronous
 *     warm start should `await source.refresh()` before their first lookup.
 *   - Synchronous `lookup`: `TrustedIssuersSource.lookup` is sync (consumed by
 *     `verifyIssuerKey`); the default source therefore CANNOT block on a fetch
 *     inside `lookup`. Cold-start failure modes surface via `onRefresh`.
 *   - TTL: default 5 min, matching `did-web-resolver`. When `now() - lastAt
 *     > ttlMs` on a subsequent `lookup()`, kicks off a background refresh and
 *     serves the previous (stale-but-verified) result immediately. Background
 *     refresh failures keep serving the last good list.
 *   - `valid_until` past: refresh attempt fires; `onRefresh` receives
 *     `outcome: "stale"`. Records are still served — caller decides fail-closed
 *     policy (master plan §2.4 + Q1).
 *   - Concurrency: only one in-flight refresh at a time. Concurrent triggers
 *     share the same promise.
 *   - `cache.ttlMs: 0` disables caching — every lookup kicks off a background
 *     refresh. (Still serves last good list; lookup remains synchronous.)
 */

import type {
  TrustedIssuerRecord,
  TrustedIssuersSource,
} from "@dekimuhq/did-web-resolver";
import { fetchTrustedIssuers, TrustedIssuersFetchError, TrustedIssuersSchemaError } from "./fetch.ts";
import { TrustedIssuersSourceFromList } from "./source.ts";
import { verifyTrustedIssuersList } from "./verify.ts";

const DEFAULT_TTL_MS = 5 * 60 * 1000;

export type RefreshOutcome =
  | "ok"
  | "stale"
  | "fetch_failed"
  | "schema_invalid"
  | "signature_invalid"
  | "publisher_key_mismatch"
  | "unsupported_publisher_key_alg"
  | "window_invalid"
  | "resolver_failed"
  | "bootstrap_required_but_absent";

export interface RefreshEvent {
  ok: boolean;
  durationMs: number;
  outcome: RefreshOutcome;
}

export interface MakeDefaultTrustedIssuersSourceOptions {
  url: string;
  resolver: (iss: string, iss_key: string) => Promise<Uint8Array>;
  bootstrap?: { publisher_key: string; spki_der: Uint8Array };
  fetcher?: (url: string, init?: { signal?: AbortSignal }) => Promise<Response>;
  cache?: { ttlMs?: number };
  now?: () => Date;
  onRefresh?: (event: RefreshEvent) => void;
}

export interface DefaultTrustedIssuersSource extends TrustedIssuersSource {
  /** Explicit re-fetch + re-verify. Bypasses TTL. Resolves when complete. */
  refresh(): Promise<void>;
  /** Last refresh state, or null if no refresh has completed yet. */
  lastRefresh(): { at: Date; outcome: RefreshOutcome } | null;
}

export function makeDefaultTrustedIssuersSource(
  opts: MakeDefaultTrustedIssuersSourceOptions,
): DefaultTrustedIssuersSource {
  const now = opts.now ?? (() => new Date());
  const ttlMs = opts.cache?.ttlMs ?? DEFAULT_TTL_MS;

  let inner: TrustedIssuersSource | null = null;
  let lastRefreshAt: Date | null = null;
  let lastOutcome: RefreshOutcome | null = null;
  let inFlight: Promise<void> | null = null;
  let everTriggered = false;

  async function doRefresh(): Promise<void> {
    const startMs = now().getTime();
    let outcome: RefreshOutcome;
    let ok = false;
    try {
      const doc = await fetchTrustedIssuers({
        url: opts.url,
        ...(opts.fetcher !== undefined && { fetcher: opts.fetcher }),
      });
      const result = await verifyTrustedIssuersList({
        doc,
        resolver: opts.resolver,
        ...(opts.bootstrap !== undefined && { bootstrap: opts.bootstrap }),
        now,
      });
      if (result.ok) {
        inner = TrustedIssuersSourceFromList(result.doc);
        outcome = "ok";
        ok = true;
      } else if (result.outcome === "window_invalid") {
        outcome = "stale";
      } else {
        outcome = result.outcome;
      }
    } catch (err) {
      if (err instanceof TrustedIssuersFetchError) {
        outcome = "fetch_failed";
      } else if (err instanceof TrustedIssuersSchemaError) {
        outcome = "schema_invalid";
      } else {
        outcome = "fetch_failed";
      }
    }
    const endMs = now().getTime();
    lastRefreshAt = new Date(endMs);
    lastOutcome = outcome;
    opts.onRefresh?.({ ok, durationMs: endMs - startMs, outcome });
  }

  function refresh(): Promise<void> {
    if (inFlight) return inFlight;
    inFlight = doRefresh().finally(() => {
      inFlight = null;
    });
    return inFlight;
  }

  function shouldRefresh(): boolean {
    if (lastRefreshAt === null) return true;
    if (ttlMs === 0) return true;
    return now().getTime() - lastRefreshAt.getTime() > ttlMs;
  }

  return {
    lookup(iss: string, lookupNow: Date): TrustedIssuerRecord | null {
      const needsRefresh = !everTriggered || shouldRefresh();
      if (needsRefresh) {
        everTriggered = true;
        void refresh();
      }
      if (inner === null) return null;
      return inner.lookup(iss, lookupNow);
    },
    refresh,
    lastRefresh(): { at: Date; outcome: RefreshOutcome } | null {
      if (lastRefreshAt === null || lastOutcome === null) return null;
      return { at: lastRefreshAt, outcome: lastOutcome };
    },
  };
}
