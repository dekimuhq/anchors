/**
 * ANR family manifest — Phase 2 adoption of `defineFamily()`.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/anr
 * Plan: an internal design record (not published)
 *
 * ANR is the first family member after the Phase 1 factory extension to bind
 * subject-presence + TSA mandate + continuity through the manifest surface.
 * Wiring choices (per Phase 2 plan + faithful-wrap migration decision):
 *
 *   - `subject_presence_check` — per-event split (FAMILY-CONSISTENCY.md §3,
 *     spec §3.1 + §4.3). `notice.acknowledged` MUST carry `"sha256:<hex>"`;
 *     other events MAY carry `"sha256:<hex>"` OR `null`. Reasons are
 *     pre-mapped to the envelope-level codes existing callers depend on
 *     (`subject_missing`, `subject_invalid_form`) so the factory pipeline
 *     emits the same reason strings as the hand-rolled `applyAnrSubjectPresence`.
 *   - `tsa_mandate` — profile-keyed matrix per FAMILY-CONSISTENCY.md §2.
 *     `notice.aiact.art50_transparency` is MANDATORY (AI Act Art. 50 stricter
 *     than baseline GDPR). All other v1 profiles are RECOMMENDED. The factory
 *     pipeline only enforces MANDATORY; the hand-rolled `applyAnrTsaMandate`
 *     post-processor in `envelope-v2.ts` restores RECOMMENDED downgrade
 *     semantics on top of factory output.
 *   - `body_schema` — pass-through adapter. ANR body shape validation lives
 *     in `verifyAnrBody` (`verify-single.ts`) and is invoked separately by
 *     callers that hold a body in hand. See `body-validator.ts` for the
 *     rationale.
 *   - `continuity: true` — ANR emits `ar.continuity.v1` attestations via
 *     `mintContinuity`/`verifyContinuity` (continuity unification commit
 *     `dae0df4`). Pre-bound on the manifest, the `anr-issuer-kit` continuity
 *     module becomes a thin wrapper.
 *   - `compose` — wired to `composeAnr` (see compose.ts) per
 *     an internal design record (not published)
 *     (D-anchors-8). Phase 4D surfaces two informational warnings:
 *     `lang_jurisdiction_mismatch` (single-receipt — BCP 47 region subtag
 *     of `body.lang_tag` differs from `body.jurisdiction`; excludes
 *     `notice.translated` per spec §4.5) and `base_unresolvable`
 *     (chain-walk — on `notice.translated`, `body.base_anr_id` does not
 *     resolve via the caller-supplied `opts.resolveReceiptById`). The
 *     existing `composition.ts` module is UNTOUCHED — it remains the
 *     offline ACR↔ANR corpus roll-up tool for auditor tooling. The two
 *     abstractions answer different questions (corpus-wide vs. per-receipt)
 *     and coexist with no friction; see the decision doc §3 two-abstraction
 *     split. When `opts.resolveReceiptById` is undefined, the chain-walk
 *     warning silently skips; the single-receipt warning still fires.
 */

import {
  defineFamily,
  type FamilyManifest,
  type SubjectPresenceCheck,
} from "@dekimuhq/anchors-envelope";
import {
  validateArt13CollectedDirectProfile,
  validateArt14CollectedIndirectProfile,
  validateArt26JointControllerEssenceProfile,
  validateLayeredTransparencyProfile,
  validateAiactArt50TransparencyProfile,
} from "@dekimuhq/anr-profiles";
import { anrBodyValidator } from "./body-validator.ts";
import { composeAnr } from "./compose.ts";
import { checkAnrSubjectPresence } from "./subject-presence.ts";
import type { AnrBody } from "./types.ts";

/**
 * Subject-presence callback wired into the manifest. Translates the internal
 * `subject_must_be_present` / `subject_must_be_sha256` reason codes (used by
 * `checkAnrSubjectPresence` and the hand-rolled wrapper) into the
 * envelope-level codes that have always appeared on `EnvelopeVerifyResult.reason`:
 *
 *   - `subject_must_be_present`  → `subject_missing`
 *   - `subject_must_be_sha256`   → `subject_invalid_form`
 *
 * This mapping preserves byte-equal output across the Phase 2 migration.
 */
const subjectPresenceCheck: SubjectPresenceCheck = ({ subject, body }) => {
  const r = checkAnrSubjectPresence({ subject, body });
  if (r.ok) return { ok: true };
  const reason =
    r.reason === "subject_must_be_present"
      ? "subject_missing"
      : "subject_invalid_form";
  return { ok: false, reason };
};

/**
 * Frozen ANR family manifest. Chip 10, status_list_slot 4, claim_type
 * `ar.notice.v1`. Wired with the per-event subject-presence callback, the
 * profile-keyed TSA mandate matrix, all five v1 profile validators, and
 * continuity helpers from `@dekimuhq/anchors-envelope`.
 */
export const anrFamily: FamilyManifest<AnrBody> = defineFamily<AnrBody>({
  acronym: "ANR",
  name: "Anchored Notice Receipts",
  claim_types: ["ar.notice.v1"],
  spec_path:
    "https://github.com/dekimuhq/anchors-spec/tree/main/anr",

  chip: 10,
  status_list_slot: 4,
  subject_presence: "either",
  subject_presence_check: subjectPresenceCheck,
  tsa_upgrade_path: "free",

  body_schema: anrBodyValidator,

  profiles: {
    "notice.art13.collected_direct": validateArt13CollectedDirectProfile,
    "notice.art14.collected_indirect": validateArt14CollectedIndirectProfile,
    "notice.art26.joint_controller_essence":
      validateArt26JointControllerEssenceProfile,
    "notice.layered_transparency": validateLayeredTransparencyProfile,
    "notice.aiact.art50_transparency": validateAiactArt50TransparencyProfile,
  },

  tsa_mandate: {
    "notice.aiact.art50_transparency": "mandatory",
    "notice.art13.collected_direct": "recommended",
    "notice.art14.collected_indirect": "recommended",
    "notice.art26.joint_controller_essence": "recommended",
    "notice.layered_transparency": "recommended",
  },

  continuity: true,
  compose: composeAnr,
});
