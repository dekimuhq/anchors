/**
 * make-verify-issuer-trust.ts — factory producing a `VerifyIssuerTrust`
 * callback ready to drop into `@dekimuhq/anchors-envelope`'s
 * `FamilyVerifyOptions.verifyIssuerTrust` (and the matching field on each
 * legacy `EnvelopeVerifyOptions` in apr/acr/arr/alr).
 *
 * Wraps `verifyIssuerKey` with a uniform signature that accepts the parsed
 * envelope and extracts `iss` + `iss_key` from it. All trust-source / cache /
 * fetcher / observability options pass through verbatim.
 *
 * Spec: an internal design record (not published) (Phase 3)
 * Plan: an internal design record (not published) §1.4
 */

import { verifyIssuerKey } from "./verify-issuer-key.ts";
import type { VerifyIssuerKeyOptions, VerifyIssuerKeyResolveEvent } from "./verify-issuer-key.ts";
import type { IssuerTrustResult } from "./verify-issuer-key.ts";
import type { TrustedIssuersSource } from "./trust-source.ts";
import type { KeyCache } from "./cache.ts";

export interface MakeVerifyIssuerTrustOptions {
  /**
   * Optional allowlist source. When absent, every successfully resolved issuer
   * returns `valid_untrusted` (open trust). Family verifiers operating in a
   * closed-allowlist policy MUST supply this from
   * `@dekimuhq/anchors-trusted-issuers` (Phase B) or a hand-rolled equivalent.
   */
  trustedIssuers?: TrustedIssuersSource;
  fetcher?: typeof fetch;
  cache?: KeyCache;
  now?: () => Date;
  /** Observability hook — forwarded to verifyIssuerKey for every dispatch. */
  onResolve?: (event: VerifyIssuerKeyResolveEvent) => void;
}

/**
 * Produce a `VerifyIssuerTrust` callback bound to the supplied options.
 *
 * Usage with the shared envelope pipeline:
 *
 *   import { makeVerifyIssuerTrust } from "@dekimuhq/did-web-resolver";
 *
 *   const verifyIssuerTrust = makeVerifyIssuerTrust({
 *     trustedIssuers: source,
 *     cache: new InMemoryKeyCache({ maxEntries: 256, ttlMs: 5 * 60_000 }),
 *   });
 *
 *   const r = await asrFamily.verifyReceipt(receipt, {
 *     resolveKey: (env) => resolveDidWebKey({ iss: env.iss, iss_key: env.iss_key }),
 *     verifyIssuerTrust,
 *   });
 *
 * Usage with the legacy verifiers (apr/acr/arr/alr 0.5.0/0.2.0):
 *
 *   const r = await verifyReceipt(receipt, {
 *     resolveKey: (iss_key) => resolveDidWebKey({ iss, iss_key }),
 *     verifyIssuerTrust: makeVerifyIssuerTrust({ trustedIssuers }),
 *   });
 */
export function makeVerifyIssuerTrust(
  opts: MakeVerifyIssuerTrustOptions,
): (envelope: unknown) => Promise<IssuerTrustResult> {
  return async (envelope: unknown): Promise<IssuerTrustResult> => {
    // Extract iss + iss_key defensively. Non-object input or missing fields
    // produce empty strings, which `verifyIssuerKey` then rejects with
    // `iss_scheme_unsupported` — the factory does not introduce a parallel
    // error taxonomy. Callers wanting strict envelope-shape validation should
    // gate before invoking the verifier (Step 1 unknown-field rejection in
    // family-verify-pipeline.ts already does this for the shared pipeline).
    let iss = "";
    let iss_key = "";
    if (typeof envelope === "object" && envelope !== null) {
      const e = envelope as Record<string, unknown>;
      if (typeof e["iss"] === "string") iss = e["iss"] as string;
      if (typeof e["iss_key"] === "string") iss_key = e["iss_key"] as string;
    }

    const verifyOpts: VerifyIssuerKeyOptions = { iss, iss_key };
    if (opts.trustedIssuers !== undefined) verifyOpts.trustedIssuers = opts.trustedIssuers;
    if (opts.fetcher !== undefined) verifyOpts.fetcher = opts.fetcher;
    if (opts.cache !== undefined) verifyOpts.cache = opts.cache;
    if (opts.now !== undefined) verifyOpts.now = opts.now;
    if (opts.onResolve !== undefined) verifyOpts.onResolve = opts.onResolve;
    return verifyIssuerKey(verifyOpts);
  };
}
