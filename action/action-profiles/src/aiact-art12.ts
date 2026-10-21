/**
 * `aiact.art12` profile validator — EU AI Act Article 12 (record-keeping).
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/blob/main/action/aiact-art12-mapping.md.
 *
 * An `aiact.art12` receipt is the SAME Hub-automation action as `hub.automation`,
 * declared as a high-risk-AI-system **log entry** and carrying the `aiact_art12`
 * overlay. This validator asserts:
 *
 *   - `body.profile === "aiact.art12"`
 *   - `body.verb` matches `<ns>.<op>` (the action is still a real, legible verb)
 *   - the `aiact_art12` overlay is PRESENT and well-formed:
 *       - `system_id` / `system_version` non-empty  (Art.12(1) lifetime anchor + version)
 *       - `period_start` is RFC 3339                (Art.12(3)(a) start of use)
 *       - `period_end`, when present, is RFC 3339 and ≥ `period_start`
 *       - `risk_event`, when present, ∈ {none, risk_flagged, substantial_modification} (Art.12(2)(a))
 *       - `oversight_ref`, when present, is `sha256:<64-hex>` (Art.12(3)(d) → an aiact.art14 receipt)
 *
 * SCOPE — this validates that a single receipt is a well-formed Art-12 log record.
 * It is the **record-keeping primitive** that helps satisfy Art. 12 + Art. 19; it is
 * NOT "Article 12 compliance" (conformity assessment, risk management Art. 9, data
 * governance Art. 10 are out of scope and live elsewhere). The base body verifier
 * (`verifyActionBody`) independently enforces the universal action-shape invariants
 * (commits, outcome, executed_at) on every receipt regardless of profile.
 */

import type { AActRBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const AIACT_ART12_PROFILE_ID = "aiact.art12" as const;

/**
 * Engine verb-allowlist shape: dot-separated segments, `<ns>.<op>`. Each segment is
 * lowercase-alphanumeric and MAY contain internal hyphens (kebab-case ops, e.g.
 * `operator.draft-reminder`) — a hyphen must sit between two alphanumerics, so no
 * leading/trailing/double hyphen. Matches the engine's real capability ids.
 */
const VERB_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*(?:\.[a-z0-9]+(?:-[a-z0-9]+)*)+$/;
const SHA256_HEX_RE = /^sha256:[0-9a-f]{64}$/;
/** RFC 3339 / ISO 8601 date-time with a mandatory offset (`Z` or `±hh:mm`). */
const RFC3339_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
const RISK_EVENTS = new Set<string>([
  "none",
  "risk_flagged",
  "substantial_modification",
]);

function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.length > 0;
}

/** RFC 3339 string that also parses to a real instant (rejects e.g. month 13). */
function isRfc3339(v: unknown): v is string {
  if (typeof v !== "string" || !RFC3339_RE.test(v)) return false;
  return !Number.isNaN(new Date(v).getTime());
}

export function validateAiactArt12(body: AActRBody): ProfileValidationResult {
  const errors: string[] = [];
  const b = body as unknown as Record<string, unknown>;

  if (b.profile !== "aiact.art12") {
    errors.push("aiact.art12.wrong_profile");
  }

  // The action is still a real, legible verb (parity with hub.automation).
  if (!isNonEmptyString(b.verb)) {
    errors.push("aiact.art12.verb_missing");
  } else if (!VERB_RE.test(b.verb)) {
    errors.push("aiact.art12.verb_malformed");
  }

  const a = b.aiact_art12;
  if (typeof a !== "object" || a === null) {
    errors.push("aiact.art12.field_missing");
    return { errors };
  }
  const art12 = a as Record<string, unknown>;

  if (!isNonEmptyString(art12.system_id)) {
    errors.push("aiact.art12.system_id_missing");
  }
  if (!isNonEmptyString(art12.system_version)) {
    errors.push("aiact.art12.system_version_missing");
  }

  if (!isRfc3339(art12.period_start)) {
    errors.push("aiact.art12.period_start_invalid");
  }
  if (art12.period_end !== undefined) {
    if (!isRfc3339(art12.period_end)) {
      errors.push("aiact.art12.period_end_invalid");
    } else if (
      isRfc3339(art12.period_start) &&
      new Date(art12.period_end).getTime() <
        new Date(art12.period_start).getTime()
    ) {
      // End of use cannot precede start of use (offset-safe instant comparison).
      errors.push("aiact.art12.period_end_before_start");
    }
  }

  if (
    art12.risk_event !== undefined &&
    (typeof art12.risk_event !== "string" || !RISK_EVENTS.has(art12.risk_event))
  ) {
    errors.push("aiact.art12.risk_event_invalid");
  }

  if (
    art12.oversight_ref !== undefined &&
    (typeof art12.oversight_ref !== "string" ||
      !SHA256_HEX_RE.test(art12.oversight_ref))
  ) {
    errors.push("aiact.art12.oversight_ref_malformed");
  }

  return { errors };
}

export const validateAiactArt12Profile = makeProfileAdapter(
  AIACT_ART12_PROFILE_ID,
  (body) => validateAiactArt12(body as AActRBody)
);
