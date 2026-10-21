import { createHash } from "node:crypto";
import { RULES, RULESET_ID, RULESET_VERSION, DECISION_POLICY } from "./rules.ts";

export function computeRulesetHash(): string {
  const sorted = [...RULES].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
    .map((r) => ({ id: r.id, category: r.category, severity: r.severity, pattern: r.pattern, flags: r.flags ?? "i" }));
  const canonical = JSON.stringify({
    ruleset_id: RULESET_ID,
    ruleset_version: RULESET_VERSION,
    decision_policy: DECISION_POLICY,
    rules: sorted,
  });
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}

export const RULESET_HASH = computeRulesetHash();
