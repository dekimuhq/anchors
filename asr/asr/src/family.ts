/**
 * ASR family manifest — first true factory-from-day-1 consumer.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/asr
 * Plan: an internal design record (not published) §Phase 3
 *
 * Greenfield through `defineFamily()` — no hand-rolled `envelope-v2.ts`,
 * no `keys.ts`. The factory orchestrator owns mint + verify; this manifest
 * supplies the family-specific predicates.
 *
 * Wiring choices for Phase 3:
 *
 *   - `subject_presence: "must-be-present"` + `subject_presence_check`
 *     (D10-ASR-5 — uniform sha256:<hex> form across all 9 events). The
 *     callback enforces the format; the base rule is overridden but kept
 *     declarative for documentation. See `subject-presence.ts`.
 *
 *   - `body_schema: AsrBodySchema` — per-event MANDATORY fields per spec §4.
 *     Profile-specific extras (Art. 18 `restriction_reason_code`, Art. 20
 *     `portability_format`, Art. 21 `objection_scope` / `balancing_test_hash`,
 *     Art. 17 `arr_receipt_id` MANDATORY link) live in the per-profile
 *     validators in `@dekimuhq/asr-profiles` (Phase 3 Step 7, deferred).
 *
 *   - `profiles` — 6 v1 profile IDs registered to real validators from
 *     `@dekimuhq/asr-profiles` (Phase 3 Step 7). Profile-specific MANDATORY
 *     fields (Art. 17 `arr_receipt_id`, Art. 18 `restriction_reason_code`,
 *     Art. 20 `portability_format` / `portability_format_detail`, Art. 21
 *     `objection_scope` / `balancing_test_hash`) are enforced at dispatch.
 *     Cross-family resolution (Art. 17 ARR link, Art. 19 ALR cascade, Art. 20
 *     ATR pair, Art. 21 APuR back-reference) is deferred to Phase 3 §G.
 *
 *   - `tsa_mandate` — OMITTED. Per FAMILY-CONSISTENCY §2 the ASR mandate
 *     matrix is EVENT-keyed (`request.received` RECOMMENDED, others OPTIONAL),
 *     not PROFILE-keyed. The factory's profile-keyed `tsa_mandate` only
 *     enforces MANDATORY; ASR has none, so leaving the field unset is
 *     semantically equivalent. Event-keyed mandate semantics arrive via the
 *     same Phase 4 Task 4.5a callback shape that resolves ABR's event-keyed
 *     matrix (Phase 1 quirk #7).
 *
 *   - `continuity: true` — ASR supports `ar.continuity.v1` attestations
 *     (issuer-kit re-exports the continuity helpers; matches §8.1).
 *
 *   - `compose: composeAsr` (Phase 3 §G) — cross-family composition. Wires
 *     four cross-walks via the v0.9.0 envelope compose surface:
 *       * Art. 17 ARR (MANDATORY, HARD-invalid): claim_type ∈
 *         {ar.erasure.v1, ar.anonymization.v1}, ARR `body.target_kind ===
 *         "subject"` + `body.target_commit === ASR.subject`, ARR `iat`
 *         within ±14 days of ASR `iat`. Fires only on
 *         `subject_rights.art17.erasure_request` + `request.fulfilled`.
 *       * Art. 19 ALR cascade (HARD-invalid shape): each referenced ALR
 *         is `ar.lineage.v1` with `body.event_type === "disclosed"` and
 *         subject parity. Fires on art16/art17/art18 +
 *         `request.recipient_notified`. Spec §4.9's
 *         "art19_recipient_set_incomplete" warning is OUT OF SCOPE here
 *         (binary compose-result shape; deferred to Phase 4).
 *       * Art. 20 ATR (OPTIONAL): when `body.atr_receipt_id` is set,
 *         claim_type = `ar.transfer.v1` + subject parity. Absence is fine.
 *       * Art. 21 APuR (OPTIONAL): when `body.apur_receipt_id` is set,
 *         claim_type = `ar.purpose.v1`, body.event_type = `unbinding`,
 *         subject parity.
 *     Each cross-walk is skipped silently when its resolver
 *     (`opts.resolveArr` / `opts.resolveAlr` / `opts.resolveAtr` /
 *     `opts.resolveApur`) is not wired. Callers without resolvers wired
 *     keep passing verification byte-equal.
 */

import {
  defineFamily,
  type FamilyManifest,
  type ProfileValidator,
} from "@dekimuhq/anchors-envelope";
import {
  validateArt15AccessProfile,
  validateArt16RectificationProfile,
  validateArt17ErasureRequestProfile,
  validateArt18RestrictionProfile,
  validateArt20PortabilityProfile,
  validateArt21ObjectionProfile,
} from "@dekimuhq/asr-profiles";
import { AsrBodySchema } from "./body-schema.ts";
import { composeAsr } from "./compose.ts";
import { checkAsrSubjectPresence } from "./subject-presence.ts";
import { ASR_PROFILES, type AsrBody, type AsrProfile } from "./types.ts";

/**
 * Phase 3 Step 7 — wires the 6 v1 profile validators from
 * `@dekimuhq/asr-profiles` into the family manifest. Replaces the prior
 * placeholder factory (`() => ({ ok: true })`) that shipped with Steps 1–6.
 *
 * Profile semantics per ASR spec §5:
 *   - art15.access — forbids art17 + art20 cross-link fields on fulfilled.
 *   - art16.rectification — same forbids; before-after hash convention is
 *     issuer-side.
 *   - art17.erasure_request — MANDATORY `body.arr_receipt_id` on fulfilled
 *     (D10-ASR-3). Stale-link / subject-parity / claim_type cross-checks
 *     deferred to Phase 3 §G `compose`.
 *   - art18.restriction — MANDATORY `body.restriction_reason_code` ∈ closed
 *     enum.
 *   - art20.portability — MANDATORY `body.portability_format` ∈ closed enum;
 *     `other` requires `body.portability_format_detail`.
 *   - art21.objection — MANDATORY `body.objection_scope` ∈ closed enum;
 *     `art21_1_general_legitimate_interest` requires `body.balancing_test_hash`.
 */
const profileRegistry: Readonly<Record<AsrProfile, ProfileValidator>> = {
  "subject_rights.art15.access": validateArt15AccessProfile,
  "subject_rights.art16.rectification": validateArt16RectificationProfile,
  "subject_rights.art17.erasure_request": validateArt17ErasureRequestProfile,
  "subject_rights.art18.restriction": validateArt18RestrictionProfile,
  "subject_rights.art20.portability": validateArt20PortabilityProfile,
  "subject_rights.art21.objection": validateArt21ObjectionProfile,
};

/**
 * Frozen ASR family manifest. Chip 12, status_list_slot 6, claim_type
 * `ar.subject_rights.v1`. 6 v1 profiles, free TSA upgrade path,
 * continuity enabled, compose registered (composeAsr).
 */
export const asrFamily: FamilyManifest<AsrBody> = defineFamily<AsrBody>({
  acronym: "ASR",
  name: "Anchored Subject-Rights Receipts",
  claim_types: ["ar.subject_rights.v1"],
  spec_path:
    "https://github.com/dekimuhq/anchors-spec/tree/main/asr",

  chip: 12,
  status_list_slot: 6,
  subject_presence: "must-be-present",
  subject_presence_check: checkAsrSubjectPresence,
  tsa_upgrade_path: "free",

  body_schema: AsrBodySchema,

  profiles: profileRegistry,

  continuity: true,

  compose: composeAsr,
});

export { ASR_PROFILES };
