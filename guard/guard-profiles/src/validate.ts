import { GUARD_CATEGORIES } from "@dekimuhq/guard-detect";
import type { GuardInputBody } from "./body.ts";

export interface ValidationResult { ok: boolean; errors: string[]; }

const HEX64 = /^[0-9a-f]{64}$/;
const SEVERITIES = new Set(["info", "warn", "critical"]);
const DECISIONS = new Set(["pass", "flagged", "blocked"]);
const CATS = new Set<string>(GUARD_CATEGORIES as readonly string[]);

function isRfc3339(s: unknown): boolean {
  if (typeof s !== "string") return false;
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(s)) return false;
  return !Number.isNaN(Date.parse(s));
}

export function validateGuardInput(body: unknown): ValidationResult {
  const e: string[] = [];
  const b = body as Partial<GuardInputBody>;
  if (b?.profile !== "guard.input") e.push("profile must be guard.input");
  if (typeof b?.ruleset_id !== "string" || !b.ruleset_id) e.push("ruleset_id required");
  if (!HEX64.test(String(b?.ruleset_hash))) e.push("ruleset_hash must be 64-char hex");
  if (typeof b?.ruleset_version !== "string" || !b.ruleset_version) e.push("ruleset_version required");
  if (!HEX64.test(String(b?.content_commit))) e.push("content_commit must be 64-char hex");
  if (!DECISIONS.has(String(b?.decision))) e.push("decision invalid");
  if (!Array.isArray(b?.matched_rules)) e.push("matched_rules must be array");
  else {
    for (const m of b.matched_rules) {
      if (!m || typeof m.id !== "string" || !m.id) e.push("match.id required");
      if (!CATS.has(String(m?.category))) e.push(`match.category invalid: ${m?.category}`);
      if (!SEVERITIES.has(String(m?.severity))) e.push("match.severity invalid");
    }
    if (b.decision === "pass" && b.matched_rules.length !== 0) e.push("pass must have empty matched_rules");
    if (b.decision !== "pass" && b.matched_rules.length === 0) e.push("non-pass must have matched_rules");
  }
  if (!b?.detector || b.detector.engine !== "deterministic" || !b.detector.name || !b.detector.version)
    e.push("detector must be {engine:deterministic,name,version}");
  if (!isRfc3339(b?.screened_at)) e.push("screened_at must be RFC 3339");
  return { ok: e.length === 0, errors: e };
}
