/**
 * ADR family manifest — `defineFamily()` wiring.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/adr
 *
 * ADR is the 9th family member (chip 4, status_list_slot 8,
 * ar.delegation.v1). Wiring choices:
 *
 *   - `subject_presence: "must-be-present"` — every ADR event MUST carry
 *     `subject = "sha256:<hex>"`. The `subject_presence_check` callback maps
 *     internal reason codes to envelope-level codes (`subject_missing`,
 *     `subject_invalid_form`).
 *
 *   - `tsa_mandate: {}` — all profiles are OPTIONAL per spec. No MANDATORY
 *     or RECOMMENDED entries at v1.
 *
 *   - `tsa_upgrade_path: "free"` — callers may opt into TSA timestamping at
 *     no additional policy cost (family-wide default).
 *
 *   - `continuity: true` — ADR emits continuity attestations via
 *     `mintContinuity`/`verifyContinuity`; delegation chains are the primary
 *     ADR use case.
 *
 *   - `compose` — wired to `composeAdr` (no-op stub — ADR chain and tree
 *     walking is handled by `walkAdrChain` and `walkDelegationTree` directly).
 *
 *   - `body_schema` — delegates to `AdrBodySchema` from `body-schema.ts`.
 *     Per-event field validation lives there; profile-specific extensions
 *     are enforced by the per-profile validators in `@dekimuhq/adr-profiles`.
 */

import {
  defineFamily,
  type FamilyManifest,
  type SubjectPresenceCheck,
} from "@dekimuhq/anchors-envelope";
import {
  validateAiactArt26DeployerProfile,
  validateAiactArt14OversightProfile,
  validateAgentopsScopedDelegationProfile,
  validateGdprArt28ProcessorProfile,
  validateGdprDsrAuthorisedAgentProfile,
  validateCorporateOfficerProfile,
} from "@dekimuhq/adr-profiles";
import { AdrBodySchema } from "./body-schema.ts";
import { composeAdr } from "./compose.ts";
import { checkAdrSubjectPresence } from "./subject-presence.ts";
import { ADR_PROFILES, type AdrBody } from "./types.ts";

/**
 * Subject-presence callback wired into the manifest. Translates the internal
 * `subject_must_be_present` / `subject_must_be_sha256` reason codes into the
 * envelope-level codes:
 *
 *   - `subject_must_be_present`  → `subject_missing`
 *   - `subject_must_be_sha256`   → `subject_invalid_form`
 */
const subjectPresenceCheck: SubjectPresenceCheck = ({ subject }) => {
  const r = checkAdrSubjectPresence({ subject });
  if (r.ok) return { ok: true };
  const reason =
    r.reason === "subject_must_be_present"
      ? "subject_missing"
      : "subject_invalid_form";
  return { ok: false, reason };
};

/**
 * Frozen ADR family manifest. Chip 4, status_list_slot 8, claim_type
 * `ar.delegation.v1`. Universal must-be-present subject rule (no per-event
 * split). All 6 v1 profiles registered; TSA mandate empty (all OPTIONAL).
 * Continuity enabled. Compose slot wired (no-op — chain/tree walking is
 * direct in ADR).
 */
export const adrFamily: FamilyManifest<AdrBody> = defineFamily<AdrBody>({
  acronym: "ADR",
  name: "Anchored Delegation Receipts",
  claim_types: ["ar.delegation.v1"],
  spec_path:
    "https://github.com/dekimuhq/anchors-spec/tree/main/adr",

  chip: 4,
  status_list_slot: 8,
  subject_presence: "must-be-present",
  subject_presence_check: subjectPresenceCheck,
  tsa_upgrade_path: "free",

  body_schema: AdrBodySchema,

  profiles: {
    "aiact.art26.deployer": validateAiactArt26DeployerProfile,
    "aiact.art14.oversight": validateAiactArt14OversightProfile,
    "agentops.scoped-delegation": validateAgentopsScopedDelegationProfile,
    "gdpr.art28.processor": validateGdprArt28ProcessorProfile,
    "gdpr.dsr.authorised-agent": validateGdprDsrAuthorisedAgentProfile,
    "corporate.officer": validateCorporateOfficerProfile,
  },

  tsa_mandate: {},

  continuity: true,
  compose: composeAdr,
});

export { ADR_PROFILES };
