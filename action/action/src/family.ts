/**
 * AActR family manifest — defineFamily() wiring.
 *
 * Chip 15, ar.action.v1. Anchored Action Receipts.
 *
 * Wiring choices (spec §2):
 *   - `subject_presence: "must-be-null"` — workspace/activity-level; the
 *     action's target is a body commit, not the envelope subject. No per-event
 *     split, so no `subject_presence_check` callback is needed (the universal
 *     rule covers it; `checkActionSubjectPresence` is exported for direct tests).
 *   - `status_list_slot: null` — an action is a non-revocable event (APR-style
 *     non-consumer of Status List 2021).
 *   - `tsa_upgrade_path: "free"`, all profiles OPTIONAL — no regulatory clock
 *     starts on an autonomous action; trusted timestamp is opt-in.
 *   - no `continuity`, no `compose` — v1 is single-receipt, no chain.
 */

import { defineFamily, type FamilyManifest } from "@dekimuhq/anchors-envelope";
import {
  validateHubAutomationProfile,
  validateAiactArt12Profile,
} from "@dekimuhq/action-profiles";
import { actionBodyValidator } from "./body-validator.ts";
import type { AActRBody } from "./types.ts";

export const actionFamily: FamilyManifest<AActRBody> = defineFamily<AActRBody>({
  acronym: "AActR",
  name: "Anchored Action Receipts",
  claim_types: ["ar.action.v1"],
  spec_path:
    "https://github.com/dekimuhq/anchors-spec/tree/main/action",

  chip: 15,
  status_list_slot: null,
  subject_presence: "must-be-null",
  tsa_upgrade_path: "free",

  body_schema: actionBodyValidator,

  profiles: {
    "hub.automation": validateHubAutomationProfile,
    "aiact.art12": validateAiactArt12Profile,
  },

  tsa_mandate: {},

  continuity: false,
});
