/**
 * `TrustedIssuersSourceFromList` — concrete `TrustedIssuersSource`
 * implementation backed by a verified `ar.trusted_issuers.v1` document.
 *
 * Per master plan §2.4: callers verify the list first
 * (`verifyTrustedIssuersList`), then pass the verified doc here. This builder
 * does NOT enforce `valid_until` — once a list is verified, every record in it
 * is authoritative until the consumer re-fetches. Staleness/freshness is the
 * consumer's responsibility (the daily allowlist-monitor cron in Phase B5).
 *
 * Revocation semantics (per `did-web-resolver/src/trust-source.ts`): records
 * with `revoked_at` set are returned (NOT filtered out) so the caller can
 * distinguish "never on allowlist" (null) from "previously on allowlist, now
 * revoked" (record with `revoked_at` set). `verifyIssuerKey` maps the latter
 * to `valid_revoked`.
 */

import type {
  TrustedIssuerRecord,
  TrustedIssuersSource,
} from "@dekimuhq/did-web-resolver";
import type { TrustedIssuerListV1 } from "./types.ts";

export function TrustedIssuersSourceFromList(
  list: TrustedIssuerListV1,
): TrustedIssuersSource {
  const index = new Map<string, TrustedIssuerRecord>(
    list.issuers.map((r) => [r.iss, r]),
  );
  return {
    lookup(iss: string, _now: Date): TrustedIssuerRecord | null {
      return index.get(iss) ?? null;
    },
  };
}
