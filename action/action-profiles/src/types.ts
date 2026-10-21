/**
 * Shared types for AActR v1 profile validators (spec §5).
 */

import type { AActRProfile } from "./body.ts";

export interface ProfileValidationResult {
  errors: string[];
}

export type { AActRProfile };
