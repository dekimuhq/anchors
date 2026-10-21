/**
 * composeAir — Phase 4B / Phase 4B-2 compose-warnings callback.
 *
 * Wires the AIR family's `compose` slot in `airFamily` (see family.ts).
 * Invoked by the envelope's `buildVerifyReceipt` pipeline as the final
 * step (after profile dispatch) when verifying a receipt. Returns
 * `{ ok: true, warnings: [...] }` with zero or more informational warning
 * codes; warnings flow onto `FamilyVerifyResult.warnings` without poisoning
 * `signature_valid`. See `@dekimuhq/anchors-envelope/define-family.ts`
 * `ComposeResult` for the channel shape and `@dekimuhq/asr`'s `compose.ts`
 * (commit 68ba5f7) for the family-precedent pattern.
 *
 * ── Single-receipt warnings (Phase 4B-1) ─────────────────────────────────
 *
 * Computable from the envelope-body pair plus the envelope-level `iat`:
 *
 *   - `art35_3a_aer_link_missing` — spec §5.1 + §8.1. On
 *     `dpia.completed` of profile `impact.art35_3_a_automated_decisions`,
 *     `body.aer_receipt_ids` SHOULD be a non-empty array. Empty or null
 *     surfaces this warning. Not HARD-invalid because pre-deployment DPIAs
 *     legitimately have no AER receipts yet.
 *
 *   - `art35_3b_alr_link_missing` — spec §5.2 + §8.3. On
 *     `dpia.completed` of profile
 *     `impact.art35_3_b_large_scale_special_categories`,
 *     `body.alr_receipt_ids` SHOULD be a non-empty array (special-category
 *     data flows benefit from explicit lineage anchoring). Empty or null
 *     surfaces this warning.
 *
 *   - `review_window_long` — spec §5.1 / §5.2 / §5.3 / §5.4. On
 *     `dpia.completed` of any strict-window profile (the four Art. 35(3-4)
 *     profiles), `body.review_due_at - envelope.iat > 12 months` surfaces
 *     this warning. The 12-month review SHOULD honour Art. 35(11).
 *
 *   - `review_window_long_voluntary` — spec §5.5. On `dpia.completed` of
 *     profile `impact.voluntary`, `body.review_due_at - envelope.iat > 36
 *     months` surfaces this warning. Voluntary DPIAs SHOULD honour a
 *     looser 36-month window.
 *
 * ── ADM cross-family composition (§8.1) ──────────────────────────────
 *
 * When `body.aer_receipt_ids` IS non-empty on `impact.art35_3_a_automated_decisions`
 * AND `opts.resolveReceiptById` is supplied, the callback resolves each
 * referenced AER receipt and validates it is an AER conformity receipt
 * (`claim_type: ar.evaluation.v1`, `body.event_type: conformity`).
 * Three advisory warnings:
 *
 *   - `art35_3a_aer_unresolvable` — a referenced AER receipt ID could
 *     not be resolved (resolver returned null/undefined).
 *
 *   - `art35_3a_aer_not_conformity` — the resolved envelope is not an
 *     AER conformity receipt (wrong claim_type or event_type).
 *
 *   - `art35_3a_aer_expired` — the AER conformity receipt's
 *     `body.valid_until` has elapsed before the AIR receipt's `iat`.
 *     The algorithmic-evaluation evidence the DPIA relies on has
 *     expired by the time the DPIA was completed.
 *
 * When `opts.resolveReceiptById` is absent, the ADM check is skipped
 * silently (only the `art35_3a_aer_link_missing` presence check fires).
 *
 * ── Chain-walk warnings (Phase 4B-2) ─────────────────────────────────────
 *
 * Surfaced when the caller supplies `opts.resolveReceiptById` (envelope
 * 0.11.0+). The callback walks the envelope-`prev` chain from the
 * receipt under verification back to the chain head, builds an
 * `AirChainIndex`, then runs `walkAirChain` and collects its `warnings`
 * array (the `hard_invalid_reasons` array is intentionally ignored —
 * chain conformance hard-fail stays the responsibility of callers that
 * invoke `walkAirChain` directly; compose only surfaces *informational*
 * diagnostics, never poisons `signature_valid`):
 *
 *   - `dpia_review_overdue` — §6.2 rule 6. Most recent `dpia.completed`
 *     has `review_due_at < now` and no `dpia.reviewed` followed it.
 *
 *   - `art36_consultation_overdue` — spec §4.8. Art. 36
 *     `prior_consultation_resolved.iat > prior_consultation_initiated.iat
 *     + 14 weeks` (8 + 6 max).
 *
 *   - `dpo_commit_drift` — spec §4.3. Two or more `dpia.dpo_advised`
 *     events in the chain carry different `dpo_did_or_email_commit`.
 *
 *   - `dpia_post_hoc_warning` — D10-AIR. A `dpia.completed` landed
 *     strictly later than the chain head's `processing_start_at`.
 *
 *   - `re_dpia_predecessor_missing` — §6.2 rule 7. Chain head is a
 *     re-DPIA (`prev !== null`) but the referenced predecessor is absent
 *     from the resolver's corpus.
 *
 *   - `voluntary_high_risk_no_consultation` — spec §5.5. New in Phase
 *     4B-2. Surfaces only when the verifier is invoked with
 *     `opts.profile === "impact.voluntary"` AND the most recent
 *     unsuperseded `dpia.completed` carried
 *     `residual_risk_level === "high"` AND no
 *     `dpia.prior_consultation_initiated` followed it. The
 *     `processing_authorised` path is still hard-invalidated by §6.2 rule
 *     5 via `art36_prior_consultation_skipped` — this warning fires
 *     earlier, advising the issuer before the chain reaches that
 *     terminal.
 *
 * When `opts.resolveReceiptById` is undefined, every chain-walk warning
 * is silently skipped (matches the optional-resolver discipline of
 * `resolveArr` / `findDisclosedAlrsForSubject`). Single-receipt warnings
 * are unaffected.
 *
 * ── Walk semantics ──────────────────────────────────────────────────────
 *
 * The walker follows `prev` from the envelope under verification
 * backward, capping at `AIR_DEFAULT_DEPTH_LIMIT` hops. The resolver is
 * called once per hop until either:
 *
 *   1. The walker reaches the chain head (`event_type ===
 *      "dpia.threshold_triggered"` or `prev === null`).
 *   2. The resolver returns `null` / `undefined` for a `prev` that is
 *      non-null (dangling reference — chain walk aborts; no chain-walk
 *      warnings fire; the receipt under verification is still surfaced
 *      to `walkAirChain` so single-hop rules still consider its body).
 *   3. The depth limit is hit (`AIR_DEFAULT_DEPTH_LIMIT` hops).
 *   4. The resolver throws — caught by the envelope pipeline and
 *      surfaced as `compose_threw:<msg>`.
 *
 * The receipt under verification is always the *first* element of the
 * collected hops array; the index built from it lists every receipt the
 * walker observed, keyed by `id`.
 *
 * ── Duplicate-with-profile-validator concern ────────────────────────────
 *
 * Single-receipt warnings #1 / #2 / #3 / #4 are ALSO emitted by
 * `@dekimuhq/air-profiles`'s per-profile validators
 * (`validateImpactArt35_3_a`, `validateImpactArt35_3_b`,
 * `validateImpactVoluntary`). However those warnings get dropped by the
 * envelope's `dispatchProfiles` because `ProfileStateEntry` has no
 * `warnings` field. The compose channel is the canonical surface for
 * top-level warning emission.
 */

import type { ComposeCallback } from "@dekimuhq/anchors-envelope";
import {
  buildAirChainIndex,
  walkAirChain,
  type AirChainReceipt,
} from "./chain.ts";
import { AIR_DEFAULT_DEPTH_LIMIT } from "./types.ts";
import type { AirBody } from "./types.ts";

const MS_PER_DAY = 86_400_000;
const DAYS_PER_MONTH = 30;
const AIR_MONTH_MS = MS_PER_DAY * DAYS_PER_MONTH;

/**
 * 12-month review-window threshold for the four Art. 35(3-4) profiles
 * (strict). Matches `AIR_REVIEW_WINDOW_MONTHS_STRICT` in
 * `@dekimuhq/air-profiles/types.ts` — duplicated here so the verifier does
 * not take a runtime dependency on profiles for compose.
 */
const AIR_REVIEW_WINDOW_STRICT_MS = 12 * AIR_MONTH_MS;

/**
 * 36-month review-window threshold for the `impact.voluntary` profile.
 * Matches `AIR_REVIEW_WINDOW_MONTHS_VOLUNTARY` in
 * `@dekimuhq/air-profiles/types.ts`.
 */
const AIR_REVIEW_WINDOW_VOLUNTARY_MS = 36 * AIR_MONTH_MS;

/** Profile IDs that follow the strict 12-month review-window threshold. */
const STRICT_REVIEW_WINDOW_PROFILES: ReadonlySet<string> = new Set([
  "impact.art35_3_a_automated_decisions",
  "impact.art35_3_b_large_scale_special_categories",
  "impact.art35_3_c_public_monitoring",
  "impact.art35_4_dpa_list",
]);

const VOLUNTARY_PROFILE_ID = "impact.voluntary" as const;

/** Parse an ISO 8601 timestamp into ms since epoch. Returns null on malformed input. */
function parseTimestamp(value: unknown): number | null {
  if (typeof value !== "string" || value.length === 0) return null;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : null;
}

/** True iff the value is a non-empty array of strings (defensive duck-type). */
function isNonEmptyStringArray(value: unknown): value is readonly string[] {
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    value.every((v) => typeof v === "string")
  );
}

/**
 * Project an arbitrary resolved-envelope object onto the minimal
 * `AirChainReceipt` shape expected by `walkAirChain`. Returns `null` when
 * the projection fails (missing/mistyped field) — callers treat this as
 * "dangling reference" and abort the walk gracefully.
 *
 * `body` is duck-typed: any object with a `string` `air_receipt_id` and
 * a `string` `event_type` passes through. Stricter body validation is the
 * responsibility of `verifyAirBody` upstream; the walker treats `body` as
 * a typed projection target rather than a canonical schema check.
 */
function projectChainReceipt(resolved: unknown): AirChainReceipt | null {
  if (resolved === null || typeof resolved !== "object") return null;
  const e = resolved as Record<string, unknown>;
  if (typeof e.id !== "string") return null;
  if (typeof e.iss !== "string") return null;
  if (typeof e.iat !== "string") return null;
  if (e.prev !== null && typeof e.prev !== "string") return null;
  if (e.body === null || typeof e.body !== "object") return null;
  const body = e.body as Record<string, unknown>;
  if (typeof body.air_receipt_id !== "string") return null;
  if (typeof body.event_type !== "string") return null;
  return {
    id: e.id,
    iss: e.iss,
    iat: e.iat,
    prev: e.prev as string | null,
    body: e.body as AirBody,
  };
}

/**
 * Project an arbitrary resolved-envelope object onto the minimal AER
 * conformity shape needed by the ADM composition check. Returns `null`
 * when the projection fails — the resolved receipt is either not an AER
 * envelope or not a conformity event.
 *
 * Validates:
 * - `claim_type === "ar.evaluation.v1"` (AER family)
 * - `body.event_type === "conformity"` (not transparency)
 *
 * Returns the `valid_from` and `valid_until` fields from the body for
 * the expiry check.
 */
function projectAerReceipt(
  resolved: unknown,
): { valid_from: string; valid_until: string | null } | null {
  if (resolved === null || typeof resolved !== "object") return null;
  const e = resolved as Record<string, unknown>;
  if (e.claim_type !== "ar.evaluation.v1") return null;
  if (e.body === null || typeof e.body !== "object") return null;
  const body = e.body as Record<string, unknown>;
  if (body.event_type !== "conformity") return null;
  if (typeof body.valid_from !== "string") return null;
  return {
    valid_from: body.valid_from,
    valid_until: typeof body.valid_until === "string" ? body.valid_until : null,
  };
}

/**
 * compose-warnings callback for AIR. See module docstring for the
 * exhaustive warning surface.
 *
 * Pure-relative-to-resolvers / total — never throws. The factory pipeline
 * wraps any throw in `compose_threw:<msg>` per `ComposeResult` contract.
 */
export const composeAir: ComposeCallback = async (input) => {
  const warnings: string[] = [];

  const body = input.envelope.body as AirBody | undefined;
  if (!body || typeof body !== "object") {
    return { ok: true };
  }

  // ── Single-receipt warnings (Phase 4B-1) ────────────────────────────────
  //
  // Fire only on `dpia.completed` and only when `opts.profile` is supplied.
  // Profile is caller-side metadata for AIR — neither AirBody nor the
  // shared Envelope type carry a `profile` field. Callers pass
  // `opts.profile`; the envelope-v2 wrapper forwards it to factoryOpts;
  // the factory exposes it via input.opts.profile to this compose callback.
  const profile = input.opts.profile;

  if (body.event_type === "dpia.completed" && profile !== undefined) {
    // `dpia.completed` body fields used below; declared via duck-type to
    // avoid coupling compose.ts to the AirCompletedBody narrowed type.
    const completed = body as {
      aer_receipt_ids?: unknown;
      alr_receipt_ids?: unknown;
      review_due_at?: unknown;
    };

    // §5.1 + §8.1 — AER link missing on art35_3_a + dpia.completed.
    if (profile === "impact.art35_3_a_automated_decisions") {
      if (!isNonEmptyStringArray(completed.aer_receipt_ids)) {
        warnings.push("art35_3a_aer_link_missing");
      } else {
        // §8.1 ADM composition — cross-family AER verification.
        // When aer_receipt_ids is present and a resolver is available,
        // resolve each referenced AER receipt and validate it is actually
        // an AER conformity receipt (claim_type: ar.evaluation.v1,
        // event_type: conformity). Warnings are informational only.
        const resolve = input.opts.resolveReceiptById;
        if (resolve !== undefined) {
          const iatMs = parseTimestamp(input.envelope.iat);
          for (const aerId of completed.aer_receipt_ids) {
            const resolved = await resolve(aerId);
            if (resolved === null || resolved === undefined) {
              warnings.push("art35_3a_aer_unresolvable");
              continue;
            }
            const aerEnvelope = projectAerReceipt(resolved);
            if (aerEnvelope === null) {
              warnings.push("art35_3a_aer_not_conformity");
              continue;
            }
            // Check validity window: conformity receipt's valid_until
            // should not have elapsed before the AIR receipt's iat.
            if (iatMs !== null && typeof aerEnvelope.valid_until === "string") {
              const validUntilMs = parseTimestamp(aerEnvelope.valid_until);
              if (validUntilMs !== null && validUntilMs < iatMs) {
                warnings.push("art35_3a_aer_expired");
              }
            }
          }
        }
      }
    }

    // §5.2 + §8.3 — ALR link missing on art35_3_b + dpia.completed.
    if (profile === "impact.art35_3_b_large_scale_special_categories") {
      if (!isNonEmptyStringArray(completed.alr_receipt_ids)) {
        warnings.push("art35_3b_alr_link_missing");
      }
    }

    // §5.1-§5.4 + §5.5 — review-window check against envelope.iat.
    const iatMs = parseTimestamp(input.envelope.iat);
    const reviewMs = parseTimestamp(completed.review_due_at);
    if (iatMs !== null && reviewMs !== null) {
      const windowMs = reviewMs - iatMs;
      if (STRICT_REVIEW_WINDOW_PROFILES.has(profile)) {
        if (windowMs > AIR_REVIEW_WINDOW_STRICT_MS) {
          warnings.push("review_window_long");
        }
      } else if (profile === VOLUNTARY_PROFILE_ID) {
        if (windowMs > AIR_REVIEW_WINDOW_VOLUNTARY_MS) {
          warnings.push("review_window_long_voluntary");
        }
      }
    }
  }

  // ── Chain-walk warnings (Phase 4B-2) ───────────────────────────────────
  //
  // Skipped silently when no resolver is supplied. Callers that don't wire
  // a chain corpus MUST still pass verification — chain-walk diagnostics
  // are advisory only.
  const resolve = input.opts.resolveReceiptById;
  if (resolve === undefined) {
    return warnings.length > 0 ? { ok: true, warnings } : { ok: true };
  }

  // Project the receipt under verification onto the chain receipt shape.
  // If projection fails (unexpected body shape, missing fields), skip
  // chain-walk entirely — the single-hop verifier upstream will already
  // have caught structural problems.
  const startReceipt = projectChainReceipt({
    id: input.envelope.id,
    iss: input.envelope.iss,
    iat: input.envelope.iat,
    prev: input.envelope.prev,
    body: input.envelope.body,
  });
  if (startReceipt === null) {
    return warnings.length > 0 ? { ok: true, warnings } : { ok: true };
  }

  const collected: AirChainReceipt[] = [startReceipt];
  const seen = new Set<string>([startReceipt.id]);
  let cursor: string | null = startReceipt.prev;
  let hopsTaken = 1;

  while (cursor !== null && hopsTaken < AIR_DEFAULT_DEPTH_LIMIT) {
    if (seen.has(cursor)) {
      // Cycle in the corpus — walker (called below) will also detect this
      // via its visited-set; stop fetching here either way.
      break;
    }
    const resolved = await resolve(cursor);
    if (resolved === null || resolved === undefined) {
      // Dangling reference — keep what we have so the head check still runs
      // on the partial chain. `re_dpia_predecessor_missing` is handled
      // separately by the walker reading the index directly.
      break;
    }
    const projected = projectChainReceipt(resolved);
    if (projected === null) {
      // Resolver returned a shape that doesn't conform — same handling as
      // dangling.
      break;
    }
    collected.push(projected);
    seen.add(projected.id);
    if (projected.body.event_type === "dpia.threshold_triggered") {
      // Reached the chain head — fetch ONE MORE hop for the re-DPIA rule,
      // because `walkAirChain` reads `head.prev` from the index to validate
      // re-DPIA inheritance (`re_dpia_invalid_predecessor` HARD-invalid,
      // `re_dpia_predecessor_missing` warning). The hard-fail is dropped
      // by compose; the warning is the one we care about surfacing.
      if (projected.prev !== null && !seen.has(projected.prev)) {
        const pred = await resolve(projected.prev);
        if (pred !== null && pred !== undefined) {
          const predProjected = projectChainReceipt(pred);
          if (predProjected !== null) {
            collected.push(predProjected);
            seen.add(predProjected.id);
          }
        }
      }
      break;
    }
    cursor = projected.prev;
    hopsTaken += 1;
  }

  // Build the index from collected hops and walk it. The walker re-traverses
  // and applies cross-event rules; we surface only its warnings (hard-fail
  // reasons stay the responsibility of direct `walkAirChain` callers per
  // module docstring).
  //
  // Pass `opts.tsaReferenceTime` as `now` when supplied — keeps replay /
  // historical-corpus runs deterministic. Pass `opts.profile` so the
  // §5.5 voluntary-high-risk evaluator can fire.
  const index = buildAirChainIndex(collected);
  const walkOpts: {
    depthLimit?: number;
    now?: Date;
    profile?: string;
  } = {};
  if (input.opts.tsaReferenceTime !== undefined) {
    walkOpts.now = input.opts.tsaReferenceTime;
  }
  if (profile !== undefined) {
    walkOpts.profile = profile;
  }
  const walk = walkAirChain(startReceipt.id, index, walkOpts);

  for (const w of walk.warnings) {
    warnings.push(w);
  }

  return warnings.length > 0 ? { ok: true, warnings } : { ok: true };
};
