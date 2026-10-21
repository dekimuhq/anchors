import { RULES, RULESET_ID, RULESET_VERSION, DECISION_POLICY } from "./rules.ts";
import { RULESET_HASH } from "./ruleset-hash.ts";
import type { GuardScreenResult, GuardMatch } from "./types.ts";
import type { GuardDecision, GuardSeverity } from "./categories.ts";

const SEVERITY_RANK: Record<GuardSeverity, number> = { info: 0, warn: 1, critical: 2 };
const DECISION_RANK: Record<GuardDecision, number> = { pass: 0, flagged: 1, blocked: 2 };

export function screen(content: string): GuardScreenResult {
  const matched_rules: GuardMatch[] = [];
  for (const rule of RULES) {
    const re = new RegExp(rule.pattern, rule.flags ?? "i");
    if (re.test(content)) matched_rules.push({ id: rule.id, category: rule.category, severity: rule.severity });
  }
  let decision: GuardDecision = "pass";
  for (const m of matched_rules) {
    const d = DECISION_POLICY[m.severity];
    if (DECISION_RANK[d] > DECISION_RANK[decision]) decision = d;
  }
  matched_rules.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return { decision, matched_rules, ruleset_id: RULESET_ID, ruleset_version: RULESET_VERSION, ruleset_hash: RULESET_HASH };
}
