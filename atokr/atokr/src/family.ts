/**
 * ATokR family manifest — `defineFamily()` wiring.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/atokr
 *
 * ATokR is the 14th family member (chip 14, status_list_slot 13,
 * ar.tokenization.v1). Wiring choices:
 *
 *   - `subject_presence: "must-be-present"` — ATokR has the simplest rule:
 *     every event MUST carry `subject = "sha256:<hex>"`. No per-event split.
 *     The `subject_presence_check` callback maps internal reason codes to the
 *     envelope-level codes (`subject_missing`, `subject_invalid_form`).
 *
 *   - `tsa_mandate: {}` — all profiles are OPTIONAL per spec §5. No MANDATORY
 *     or RECOMMENDED entries at v1.
 *
 *   - `tsa_upgrade_path: "free"` — callers may opt into TSA timestamping at no
 *     additional policy cost (matches the family-wide default).
 *
 *   - `continuity: true` — ATokR emits continuity attestations via
 *     `mintContinuity`/`verifyContinuity`; token chains are the primary ATokR
 *     use case.
 *
 *   - `compose` — wired to `composeAtokr` (stub, Task 6 implements chain-walk
 *     warnings: `token_chain_broken`, `single_use_redeemed_again`,
 *     `rotation_target_already_rotated`).
 *
 *   - `body_schema` — delegates to `atokrBodyValidator` (wraps `verifyAtokrBody`
 *     from `verify-single.ts`). Structural validation continues to live there;
 *     the manifest validator is a pass-through adapter.
 */

import {
  defineFamily,
  type FamilyManifest,
  type SubjectPresenceCheck,
} from "@dekimuhq/anchors-envelope";
import {
  validateGdprArt32Profile,
  validateGdprArt4_5Profile,
  validatePciDssV4Profile,
  validateEudiWalletArfProfile,
  validateSectorHealthProfile,
} from "@dekimuhq/atokr-profiles";
import { atokrBodyValidator } from "./body-validator.ts";
import { composeAtokr } from "./compose.ts";
import { checkAtokrSubjectPresence } from "./subject-presence.ts";
import type { AtokrBody } from "./types.ts";

/**
 * Subject-presence callback wired into the manifest. Translates the internal
 * `subject_must_be_present` / `subject_must_be_sha256` reason codes into the
 * envelope-level codes:
 *
 *   - `subject_must_be_present`  → `subject_missing`
 *   - `subject_must_be_sha256`   → `subject_invalid_form`
 */
const subjectPresenceCheck: SubjectPresenceCheck = ({ subject }) => {
  const r = checkAtokrSubjectPresence({ subject });
  if (r.ok) return { ok: true };
  const reason =
    r.reason === "subject_must_be_present"
      ? "subject_missing"
      : "subject_invalid_form";
  return { ok: false, reason };
};

/**
 * Frozen ATokR family manifest. Chip 14, status_list_slot 13, claim_type
 * `ar.tokenization.v1`. Universal must-be-present subject rule (no per-event
 * split). All 5 v1 profiles registered; TSA mandate empty (all OPTIONAL).
 * Continuity enabled. Compose slot wired (stub — full impl in Task 6).
 */
export const atokrFamily: FamilyManifest<AtokrBody> = defineFamily<AtokrBody>({
  acronym: "ATokR",
  name: "Anchored Tokenization Receipts",
  claim_types: ["ar.tokenization.v1"],
  spec_path:
    "https://github.com/dekimuhq/anchors-spec/tree/main/atokr",

  chip: 14,
  status_list_slot: 13,
  subject_presence: "must-be-present",
  subject_presence_check: subjectPresenceCheck,
  tsa_upgrade_path: "free",

  body_schema: atokrBodyValidator,

  profiles: {
    "tokenization.gdpr.art32": validateGdprArt32Profile,
    "tokenization.gdpr.art4_5": validateGdprArt4_5Profile,
    "tokenization.pci.dss_v4": validatePciDssV4Profile,
    "tokenization.eudi.wallet_arf": validateEudiWalletArfProfile,
    "tokenization.sector.health": validateSectorHealthProfile,
  },

  tsa_mandate: {},

  continuity: true,
  compose: composeAtokr,
});
