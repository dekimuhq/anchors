/** Shared types for AGR v1 (Anchored Guard Verdicts). */
import type { GuardDecision, GuardSeverity, GuardCategory } from "@dekimuhq/guard-detect";

export type AGRProfile = "guard.input";

export interface GuardMatch {
  id: string;
  category: GuardCategory;
  severity: GuardSeverity;
}
export interface GuardDetector {
  engine: "deterministic";
  name: string;
  version: string;
}
export type { GuardDecision };
