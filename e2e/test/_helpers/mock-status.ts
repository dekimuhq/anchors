/**
 * Verifier-option helpers for the v1.2 deferred conformance vectors.
 *
 * Translates the `verify_opts` block on a vector JSON into a concrete set of
 * options for `verifyArr` (and the equivalent ACR/APR verifiers), plus a
 * teardown that restores any patched globals.
 *
 * Capabilities:
 *   - Status List cache seeding (fresh or stale-aged).
 *   - Optional global `fetch` mock that fails every call (for stale/unreachable).
 *   - Chain-successor resolver injection.
 *   - Trust-anchor override (synthesises a FreeTSA-like anchor with a custom
 *     `valid_until` — used to produce `tsa_anchor_expired`).
 *   - `tsaReferenceTime` parsing.
 *
 * NEVER imports verifier internals — it only constructs the public options
 * shape (`EnvelopeVerifyOptions` from `@dekimuhq/arr-verifier`).
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  InMemoryStatusCache,
  type StatusCacheConfig,
  type StatusListEntry,
  type RootKeyMaterial,
} from "@dekimuhq/anchors-envelope/status";
import type { TrustAnchor } from "@dekimuhq/anchors-envelope/tsa";

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Wire-format `verify_opts` block carried inside a vector JSON. All fields
 * optional — absence means "use verifier defaults".
 */
export interface VerifyOptsWire {
  /** ISO 8601 reference time passed as `tsaReferenceTime` to the verifier. */
  tsaReferenceTime?: string;
  /** Drift tolerance in seconds (default: verifier's 300). */
  tsaDriftToleranceSec?: number;
  /** Named trust-anchor override (currently "freetsa-expired-2020" only). */
  trustAnchorOverride?: string;
  /** Public key material for the Status List 2021 Credential signer. */
  statusListRootKey?: RootKeyMaterial;
  /** Cache freshness configuration. Defaults to freshTtl=3600 / staleTtl=86400. */
  statusCacheConfig?: { freshTtlSec: number; staleTtlSec: number };
  /** Seed the in-memory cache before verifier runs. */
  statusCacheSeed?: {
    url: string;
    /** true → entry within freshTtl (fetched_at = now); false → past freshTtl. */
    fresh: boolean;
    /** When fresh=false, how many seconds in the past to set `fetched_at`. */
    ageSec?: number;
    credential: unknown;
  };
  /** Truthy → chainResolver returns true for every envelope id. */
  chainSuccessorExists?: boolean;
  /** "fail" → patch globalThis.fetch to reject every call for this vector. */
  statusFetchMode?: "fail";
}

/**
 * Concrete options object built from a `VerifyOptsWire`. Sliced into a shape
 * directly assignable to `verifyArr(..., opts)`.
 */
export interface BuiltVerifyOpts {
  tsaReferenceTime?: Date;
  tsaDriftToleranceSec?: number;
  tsaAnchors?: TrustAnchor[];
  statusListRootKey?: RootKeyMaterial;
  statusCacheConfig?: StatusCacheConfig;
  chainResolver?: (id: string) => Promise<boolean>;
}

export interface PreparedVerify {
  opts: BuiltVerifyOpts;
  /** Call when the test finishes (success or failure) to restore globals. */
  teardown: () => void;
}

const FREETSA_ANCHOR_PATH = join(__dirname, "..", "..", "..", "data", "freetsa-trust-anchor.json");

interface AnchorCatalogShape {
  anchors: TrustAnchor[];
}

function loadAnchorCatalogRaw(): AnchorCatalogShape {
  return JSON.parse(readFileSync(FREETSA_ANCHOR_PATH, "utf8")) as AnchorCatalogShape;
}

/**
 * Resolve a named trust-anchor override into a concrete `TrustAnchor[]`.
 *
 *   "freetsa-expired-2020"
 *      Loads the bundled FreeTSA root anchor but rewrites `valid_until` to
 *      "2020-01-01T00:00:00Z" so the verifier matches the cert (step 2) and
 *      then trips `tsa_anchor_expired` at step 3.
 */
function resolveTrustAnchorOverride(name: string): TrustAnchor[] {
  switch (name) {
    case "freetsa-expired-2020": {
      const catalog = loadAnchorCatalogRaw();
      return catalog.anchors.map((a) => ({
        ...a,
        valid_until: "2020-01-01T00:00:00Z",
      }));
    }
    default:
      throw new Error(`mock-status: unknown trustAnchorOverride "${name}"`);
  }
}

/**
 * Build a verifier options bag + teardown from a vector's `verify_opts`.
 *
 * Side-effect: when `statusFetchMode: "fail"` is set, patches `globalThis.fetch`
 * to reject for the duration of the test. The returned teardown restores the
 * original. Node's test runner runs tests serially within a file, so the patch
 * window is contained.
 */
export function prepareVerify(wire: VerifyOptsWire | undefined): PreparedVerify {
  const opts: BuiltVerifyOpts = {};
  const restores: Array<() => void> = [];

  if (!wire) {
    return { opts, teardown: () => undefined };
  }

  if (wire.tsaReferenceTime) {
    opts.tsaReferenceTime = new Date(wire.tsaReferenceTime);
  }
  if (wire.tsaDriftToleranceSec !== undefined) {
    opts.tsaDriftToleranceSec = wire.tsaDriftToleranceSec;
  }
  if (wire.trustAnchorOverride) {
    opts.tsaAnchors = resolveTrustAnchorOverride(wire.trustAnchorOverride);
  }
  if (wire.statusListRootKey) {
    opts.statusListRootKey = wire.statusListRootKey;
  }

  // Build statusCacheConfig with optional pre-seed.
  if (wire.statusListRootKey) {
    const freshTtlSec = wire.statusCacheConfig?.freshTtlSec ?? 3600;
    const staleTtlSec = wire.statusCacheConfig?.staleTtlSec ?? 86400;
    const storage = new InMemoryStatusCache(8);

    if (wire.statusCacheSeed) {
      const now = Date.now();
      const seed = wire.statusCacheSeed;
      const entry: StatusListEntry = seed.fresh
        ? {
            fetched_at: now,
            fresh_until: now + freshTtlSec * 1000,
            body: seed.credential,
          }
        : (() => {
            const ageMs = (seed.ageSec ?? freshTtlSec + 1) * 1000;
            const fetchedAt = now - ageMs;
            return {
              fetched_at: fetchedAt,
              fresh_until: fetchedAt + freshTtlSec * 1000,
              body: seed.credential,
            };
          })();
      // Fire-and-forget — InMemoryStatusCache.set is synchronous under the hood.
      void storage.set(seed.url, entry);
    }

    opts.statusCacheConfig = { freshTtlSec, staleTtlSec, storage };
  }

  if (wire.chainSuccessorExists) {
    opts.chainResolver = async () => true;
  }

  if (wire.statusFetchMode === "fail") {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async () => {
      throw new Error("mock-status: fetch disabled for this test");
    }) as typeof fetch;
    restores.push(() => {
      globalThis.fetch = originalFetch;
    });
  }

  return {
    opts,
    teardown: () => {
      for (const r of restores) r();
    },
  };
}
