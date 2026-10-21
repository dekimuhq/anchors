/**
 * composeAnr — Phase 4D compose-warnings callback.
 *
 * Wires the ANR family's `compose` slot in `anrFamily` (see family.ts).
 * Invoked by the envelope's `buildVerifyReceipt` pipeline as the final
 * step (after profile dispatch) when verifying a receipt. Returns
 * `{ ok: true, warnings: [...] }` with zero or more informational warning
 * codes; warnings flow onto `FamilyVerifyResult.warnings` without poisoning
 * `signature_valid`. See `@dekimuhq/anchors-envelope/define-family.ts`
 * `ComposeResult` for the channel shape; reverses the prior "compose
 * DELIBERATELY OMITTED" posture per
 * an internal design record (not published) (D-anchors-8).
 *
 * The existing `composition.ts` module is UNTOUCHED — it is an offline,
 * corpus-wide ACR↔ANR roll-up tool for auditor tooling. `compose.ts` answers
 * a different question: what informational signals does *this single receipt*
 * warrant at verify-time. The two abstractions are kept distinct per the
 * decision doc's §3 two-abstraction split.
 *
 * ── Single-receipt warning (lang_jurisdiction_mismatch) ──────────────────
 *
 * Spec §9 open question 4 — "Notice content language vs jurisdiction
 * mismatch." DPOs and auditors need the signal when a controller serves a
 * DE-language notice (`lang_tag = "de-DE"`) to a subject in a different
 * jurisdiction (`jurisdiction = "GB"`).
 *
 *   - `lang_jurisdiction_mismatch` — fires when the BCP 47 region subtag
 *     of `body.lang_tag` is a 2-letter ISO 3166-1 alpha-2 code and does
 *     NOT match `body.jurisdiction` (case-insensitive). Skips silently
 *     when:
 *       - the event is `notice.translated` (spec §4.5 omits `jurisdiction`
 *         on translations — `body.jurisdiction` is `null` and no
 *         comparison is possible);
 *       - `lang_tag` carries no region subtag (e.g. `de`, `pt`);
 *       - the region subtag is a UN M.49 numeric code (e.g. `419`) — not
 *         directly comparable to an ISO country code;
 *       - `body.jurisdiction` is the region-level reservation `"EU"` —
 *         no single-country mapping, deliberate region-level posture;
 *       - `body.jurisdiction` is anything other than a 2-letter alpha-2
 *         code (defensive — body validator already enforces shape).
 *
 *     This is a weak-signal warning by design: a German-language notice
 *     in a UK jurisdiction may be appropriate when the subject is a
 *     German-speaking expatriate. The signal alerts the DPO to verify.
 *
 * ── Chain-walk warning (base_unresolvable) ───────────────────────────────
 *
 * Spec §6.2 walk-rule 3 — `notice.translated` carries `base_anr_id`
 * referencing the base-language receipt. The compose surface uses the
 * caller-supplied `opts.resolveReceiptById` (envelope 0.11.0+) to look up
 * the base receipt by id.
 *
 *   - `base_unresolvable` — fires on `notice.translated` events only.
 *     When the caller supplies `opts.resolveReceiptById` AND the resolver
 *     returns `null`/`undefined` for `body.base_anr_id`, the warning
 *     surfaces. Informational only — base notices may be erased
 *     independently from translations per Art. 17 erasure (the closure
 *     family ALR + ASR handle the erasure surface). Skipped silently
 *     when:
 *       - the event is not `notice.translated`;
 *       - `opts.resolveReceiptById` is undefined (cannot determine —
 *         matches the AIR/ABR optional-resolver discipline);
 *       - `body.base_anr_id` is not a string (defensive — body validator
 *         already enforces shape).
 *
 * ── Out-of-scope warnings (re-homed by D-anchors-8) ──────────────────────
 *
 * Two spec-defined ANR warnings were re-homed by the decision doc and are
 * NOT surfaced here:
 *
 *   - `notice_staleness_warning` (spec §4.1 line 197) — fires from the
 *     ACR side when a `consent.collect@*` receipt's `body.anr_id`
 *     resolves to a stale `notice.presented`. ANR cannot see ACR receipts
 *     at its own verify-time. Re-homed to ACR Phase 4 (B.1.a).
 *
 *   - `subject_erased` (spec §6.4) — needs a `resolveReceiptsBySubject`
 *     primitive on `defineFamily()` that does not yet exist. Re-homed to
 *     a future cross-family compose surface (B.1.b).
 */

import type { ComposeCallback } from "@dekimuhq/anchors-envelope";
import type { AnrBody } from "./types.ts";

/**
 * Extract the BCP 47 region subtag from a language tag.
 *
 * Returns the uppercased 2-letter alpha-2 region subtag when present
 * (e.g. `"en-GB"` → `"GB"`, `"de-DE-1996"` → `"DE"`). Returns `null` when:
 *
 *   - the input is not a string;
 *   - there is no region subtag (e.g. `"de"`, `"zh-Hans"`);
 *   - the region subtag is a UN M.49 numeric code (3 digits, e.g.
 *     `"es-419"`) — not comparable to an ISO 3166-1 alpha-2 code.
 *
 * BCP 47 syntax: `language[-script][-region][-variant...]`. The region
 * subtag, when present, is the first subtag after the language that is
 * either 2 alpha characters or 3 digits. Scripts are 4 alpha characters
 * and precede the region. Extended language subtags are 3 alpha and
 * precede the script.
 */
function extractRegionSubtag(langTag: unknown): string | null {
  if (typeof langTag !== "string") return null;
  const parts = langTag.split("-");
  // First part is the language subtag (2-3 alpha, sometimes longer for
  // grandfathered tags). Walk subsequent parts looking for a 2-alpha
  // region subtag, skipping 3-alpha extlang and 4-alpha script subtags.
  for (let i = 1; i < parts.length; i += 1) {
    const part = parts[i];
    if (part === undefined) continue;
    if (/^[A-Za-z]{2}$/.test(part)) {
      return part.toUpperCase();
    }
    if (/^[0-9]{3}$/.test(part)) {
      // UN M.49 numeric region — not alpha-2 comparable. Stop walking;
      // the region slot is occupied by a non-comparable code.
      return null;
    }
    // Skip 3-alpha extlang and 4-alpha script subtags; continue walking.
  }
  return null;
}

/**
 * compose-warnings callback for ANR. See module docstring for the
 * exhaustive warning surface.
 *
 * Pure-relative-to-resolvers / total — never throws under normal input.
 * The factory pipeline wraps any throw in `compose_threw:<msg>` per the
 * `ComposeResult` contract.
 */
export const composeAnr: ComposeCallback = async (input) => {
  const warnings: string[] = [];

  const body = input.envelope.body as AnrBody | undefined;
  if (!body || typeof body !== "object") {
    return { ok: true };
  }

  // ── W1: lang_jurisdiction_mismatch (single-receipt) ──────────────────
  //
  // Excludes `notice.translated` per spec §4.5 (jurisdiction is null on
  // translations). Defensive on body.jurisdiction shape.
  if (body.event_type !== "notice.translated") {
    const jurisdiction = (body as { jurisdiction?: unknown }).jurisdiction;
    if (
      typeof jurisdiction === "string" &&
      /^[A-Za-z]{2}$/.test(jurisdiction) &&
      jurisdiction.toUpperCase() !== "EU"
    ) {
      const region = extractRegionSubtag(
        (body as { lang_tag?: unknown }).lang_tag,
      );
      if (region !== null && region !== jurisdiction.toUpperCase()) {
        warnings.push("lang_jurisdiction_mismatch");
      }
    }
  }

  // ── W2: base_unresolvable (chain-walk via resolveReceiptById) ────────
  //
  // Fires on `notice.translated` only. Skipped when no resolver supplied
  // (matches AIR/ABR optional-resolver discipline).
  const resolve = input.opts.resolveReceiptById;
  if (body.event_type === "notice.translated" && resolve !== undefined) {
    const baseId = (body as { base_anr_id?: unknown }).base_anr_id;
    if (typeof baseId === "string") {
      const resolved = await resolve(baseId);
      if (resolved === null || resolved === undefined) {
        warnings.push("base_unresolvable");
      }
    }
  }

  return warnings.length > 0 ? { ok: true, warnings } : { ok: true };
};
