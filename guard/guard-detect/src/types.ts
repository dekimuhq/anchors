import type { GuardCategory, GuardSeverity, GuardDecision } from "./categories.ts";
export interface GuardMatch { id: string; category: GuardCategory; severity: GuardSeverity; }
export interface GuardScreenResult {
  decision: GuardDecision;
  matched_rules: GuardMatch[];
  ruleset_id: string;
  ruleset_version: string;
  ruleset_hash: string;
}
