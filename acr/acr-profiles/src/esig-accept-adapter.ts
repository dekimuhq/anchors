/**
 * Universal-signature adapter for the esig.accept@qes profile validator.
 *
 * Wraps `validateEsigAcceptQes` (which uses profile-specific shapes) into
 * the family-wide `ProfileValidator` shape so it can be dispatched from
 * any verifier via the `profileValidators` option.
 *
 * Phase E Task E.2.
 */

import type { ProfileValidator } from "@dekimuhq/anchors-envelope";
import type { TsaReason } from "@dekimuhq/anchors-envelope/tsa";
import {
  validateEsigAcceptQes,
  type EsigAcceptQesReceipt,
} from "./esig-accept.ts";

export const ESIG_ACCEPT_QES_PROFILE_ID = "acr.esig.accept@qes" as const;

export const validateEsigAcceptQesProfile: ProfileValidator = (_envelope, body, ctx) => {
  const receipt = body as EsigAcceptQesReceipt;
  const result = validateEsigAcceptQes(receipt, {
    tsa_state: (ctx.tsa_state ?? "tsa_absent") as TsaReason,
    tsa_listed: ctx.tsa_listed ?? false,
    ...(ctx.tsa_policy_oid !== undefined ? { tsa_policy_oid: ctx.tsa_policy_oid } : {}),
  });
  return {
    profile_id: ESIG_ACCEPT_QES_PROFILE_ID,
    ok: result.ok,
    ...(result.reason ? { reason: result.reason } : {}),
  };
};
