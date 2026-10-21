/**
 * composeAbr — Phase 4C Task 3 compose-warnings callback.
 *
 * Wires the ABR family's `compose` slot in `abrFamily` (see family.ts).
 * Invoked by the envelope's `buildVerifyReceipt` pipeline as the final
 * step (after profile dispatch) when verifying a receipt. Returns
 * `{ ok: true, warnings: [...] }` with zero or more informational warning
 * codes; warnings flow onto `FamilyVerifyResult.warnings` without poisoning
 * `signature_valid`. See `@dekimuhq/anchors-envelope/define-family.ts`
 * `ComposeResult` for the channel shape and `@dekimuhq/air`'s `compose.ts`
 * (commit `fdcd950` / `441ba5f`) for the family-precedent pattern.
 *
 * ── Single-receipt warning (clock_skew_warning) ─────────────────────────
 *
 * Fires on `breach.detected` only. Computable from the envelope-body pair
 * alone — no resolver needed.
 *
 *   - `clock_skew_warning` — spec §3.1 row 1 + spec line 57. Surfaces when
 *     `|envelope.iat - body.detected_at| > 5 minutes`. The strict spec
 *     interpretation cross-checks the TSA's `genTime` (cryptographic
 *     clock-start) against the controller-asserted `body.detected_at`.
 *     The compose surface does not currently receive the parsed TSA
 *     genTime — `ComposeInput.envelope` exposes only the receipt fields
 *     plumbed via `family-verify-pipeline.ts` Step 14. Compose therefore
 *     uses `envelope.iat` as the clock anchor, which is correct in
 *     practice because `breach.detected` MUST carry a TSA (D10-ABR-2
 *     MANDATORY) and conforming issuers mint `iat` aligned to TSA
 *     genTime within standard drift tolerance (300s default per
 *     `tsaDriftToleranceSec`). The warning is informational either way;
 *     a future envelope MINOR bump may plumb the parsed TSA genTime if a
 *     consumer needs sub-iat precision.
 *
 * ── Chain-walk warning (notification_overdue) ───────────────────────────
 *
 * Fires on `breach.dpa_notified` only. Surfaced when the caller supplies
 * `opts.resolveReceiptById` (envelope 0.11.0+). Walks the envelope-`prev`
 * chain backward from the receipt under verification to find:
 *
 *   1. The chain head — a `breach.detected` event. If absent (dangling
 *      `prev` reference, missing from resolver corpus, chain head is a
 *      different event), the warning silently skips.
 *   2. Any `breach.dpa_delayed` between the head and the notification.
 *      Per spec line 232 + line 363, a prior `breach.dpa_delayed` justifies
 *      late notification and suppresses the warning.
 *
 *   - `notification_overdue` — spec §4.3 + §4.4 + D10-ABR-6 + spec line 58.
 *     Surfaces when:
 *       - `body.profile === "breach.gdpr.art33"` AND elapsed (notified.iat
 *         − detected.iat) > 72h, OR
 *       - `body.profile === "breach.nis2.art23"` AND
 *         `body.notification_phase === "early_warning"` AND elapsed > 24h, OR
 *       - `body.profile === "breach.nis2.art23"` AND
 *         `body.notification_phase === "full_notification"` AND elapsed > 72h, OR
 *       - `body.profile === "breach.nis2.art23"` AND
 *         `body.notification_phase === "final_report"` AND elapsed > 30 days.
 *     Suppressed by any prior `breach.dpa_delayed` in the chain.
 *
 *     Per D10-ABR-6 the strict reference is the TSA `genTime` of
 *     `breach.detected`, not `iat`. Same constraint as `clock_skew_warning`
 *     above — compose uses `iat` of the resolved detected hop as the
 *     practical reference (`breach.detected` MUST carry TSA, so iat ~
 *     TSA.genTime within drift tolerance).
 *
 *     Other profiles (`breach.gdpr.art34`, `breach.dora.art19`,
 *     `breach.us_state.attorney_general`) have no compose-side deadline —
 *     Art. 34 has no hard window ("undue delay"); DORA Art. 19's 4h
 *     initial / 72h intermediate / 1mo final phasing is mapped through
 *     `notification_phase` on a future spec amendment; US-AG deadlines are
 *     per-state and require an external lookup. Compose silently skips
 *     `notification_overdue` for these profiles. The profile validators
 *     in `@dekimuhq/abr-profiles` still apply their own profile-specific
 *     gates.
 *
 * ── Walk semantics ──────────────────────────────────────────────────────
 *
 * The walker follows `prev` from the envelope under verification backward,
 * capping at `ABR_DEFAULT_DEPTH_LIMIT` hops. The resolver is called once
 * per hop until either:
 *
 *   1. The walker reaches the chain head — `breach.detected` event.
 *   2. The resolver returns `null` / `undefined` for a `prev` that is
 *      non-null (dangling reference — chain walk aborts; warning skips).
 *   3. The depth limit is hit (`ABR_DEFAULT_DEPTH_LIMIT` hops).
 *   4. The resolver throws — caught by the envelope pipeline and surfaced
 *      as `compose_threw:<msg>`.
 *   5. A cycle is detected via the visited-set.
 *
 * When `opts.resolveReceiptById` is undefined, chain-walk warnings skip
 * silently. Single-receipt warnings (clock_skew_warning) still fire.
 */

import type { ComposeCallback } from "@dekimuhq/anchors-envelope";
import { ABR_DEFAULT_DEPTH_LIMIT } from "./types.ts";
import type { AbrBody } from "./types.ts";

const MS_PER_MINUTE = 60_000;
const MS_PER_HOUR = 60 * MS_PER_MINUTE;
const MS_PER_DAY = 24 * MS_PER_HOUR;

/** Clock-skew tolerance for `breach.detected` (spec §3.1 row 1). */
const ABR_CLOCK_SKEW_TOLERANCE_MS = 5 * MS_PER_MINUTE;

/**
 * Profile + phase keyed deadline table (ms). Other profiles (Art. 34, DORA,
 * US-AG) intentionally have no entry — compose skips `notification_overdue`
 * for them.
 */
function deadlineForDpaNotified(body: AbrBody): number | null {
  if (body.event_type !== "breach.dpa_notified") return null;
  if (body.profile === "breach.gdpr.art33") return 72 * MS_PER_HOUR;
  if (body.profile === "breach.nis2.art23") {
    switch (body.notification_phase) {
      case "early_warning":
        return 24 * MS_PER_HOUR;
      case "full_notification":
        return 72 * MS_PER_HOUR;
      case "final_report":
        return 30 * MS_PER_DAY;
      default:
        return null;
    }
  }
  return null;
}

/** Parse an ISO 8601 timestamp into ms since epoch. Returns null on malformed input. */
function parseTimestamp(value: unknown): number | null {
  if (typeof value !== "string" || value.length === 0) return null;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : null;
}

/**
 * Minimal projection of an unknown resolved-envelope onto the fields the
 * walker reads. Returns `null` if the projection fails. Mirrors the
 * `projectChainReceipt` pattern in `air/air-verifier/src/compose.ts`.
 */
interface ProjectedHop {
  id: string;
  iat: string;
  prev: string | null;
  body: AbrBody;
}

function projectHop(resolved: unknown): ProjectedHop | null {
  if (resolved === null || typeof resolved !== "object") return null;
  const e = resolved as Record<string, unknown>;
  if (typeof e.id !== "string") return null;
  if (typeof e.iat !== "string") return null;
  if (e.prev !== null && typeof e.prev !== "string") return null;
  if (e.body === null || typeof e.body !== "object") return null;
  const body = e.body as Record<string, unknown>;
  if (typeof body.event_type !== "string") return null;
  return {
    id: e.id,
    iat: e.iat,
    prev: e.prev as string | null,
    body: e.body as AbrBody,
  };
}

/**
 * compose-warnings callback for ABR. See module docstring for the exhaustive
 * warning surface.
 *
 * Pure-relative-to-resolvers / total — never throws. The factory pipeline
 * wraps any throw in `compose_threw:<msg>` per `ComposeResult` contract.
 */
export const composeAbr: ComposeCallback = async (input) => {
  const warnings: string[] = [];

  const body = input.envelope.body as AbrBody | undefined;
  if (!body || typeof body !== "object") {
    return { ok: true };
  }

  // ── Single-receipt: clock_skew_warning on breach.detected ─────────────
  if (body.event_type === "breach.detected") {
    const detectedAt = (body as { detected_at?: unknown }).detected_at;
    const iatMs = parseTimestamp(input.envelope.iat);
    const detectedMs = parseTimestamp(detectedAt);
    if (iatMs !== null && detectedMs !== null) {
      if (Math.abs(iatMs - detectedMs) > ABR_CLOCK_SKEW_TOLERANCE_MS) {
        warnings.push("clock_skew_warning");
      }
    }
  }

  // ── Chain-walk: notification_overdue on breach.dpa_notified ───────────
  //
  // Skipped silently when no resolver is supplied or the receipt is not a
  // `breach.dpa_notified` event. Callers that don't wire a chain corpus
  // MUST still pass verification.
  const resolve = input.opts.resolveReceiptById;
  if (resolve === undefined || body.event_type !== "breach.dpa_notified") {
    return warnings.length > 0 ? { ok: true, warnings } : { ok: true };
  }

  const deadlineMs = deadlineForDpaNotified(body);
  if (deadlineMs === null) {
    return warnings.length > 0 ? { ok: true, warnings } : { ok: true };
  }

  // Walk backward from current envelope to find the chain head
  // (breach.detected) and observe whether any breach.dpa_delayed sits in
  // between (suppression rule per spec line 232 + line 363).
  let cursor: string | null = input.envelope.prev;
  const seen = new Set<string>([input.envelope.id]);
  let hopsTaken = 1;
  let detectedHop: ProjectedHop | null = null;
  let hasDelay = false;

  while (cursor !== null && hopsTaken < ABR_DEFAULT_DEPTH_LIMIT) {
    if (seen.has(cursor)) break;
    const resolved = await resolve(cursor);
    if (resolved === null || resolved === undefined) break;
    const hop = projectHop(resolved);
    if (hop === null) break;
    seen.add(hop.id);
    if (hop.body.event_type === "breach.dpa_delayed") {
      hasDelay = true;
    }
    if (hop.body.event_type === "breach.detected") {
      detectedHop = hop;
      break;
    }
    cursor = hop.prev;
    hopsTaken += 1;
  }

  if (detectedHop !== null && !hasDelay) {
    const detectedIatMs = parseTimestamp(detectedHop.iat);
    const notifiedIatMs = parseTimestamp(input.envelope.iat);
    if (detectedIatMs !== null && notifiedIatMs !== null) {
      const elapsed = notifiedIatMs - detectedIatMs;
      if (elapsed > deadlineMs) {
        warnings.push("notification_overdue");
      }
    }
  }

  return warnings.length > 0 ? { ok: true, warnings } : { ok: true };
};
