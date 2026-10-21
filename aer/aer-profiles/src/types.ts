/**
 * Shared types for AER v1 profile validators (spec §5).
 */

import type { AerProfile } from "./body.ts";

export interface ProfileValidationResult {
  errors: string[];
}

export interface AerProfileCtx {
  tsa_state?: string;
  tsa_listed?: boolean;
  tsa_policy_oid?: string;
}

export type { AerProfile };
