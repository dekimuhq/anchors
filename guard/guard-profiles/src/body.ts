/**
 * AGR (Anchored Guard Verdicts) body-type definitions. Asserts screening
 * PROVENANCE, not safety. Envelope-level fields come from @dekimuhq/anchors-envelope
 * and are NOT repeated. field_root is added issuer-side by mintGuardV1.
 */
import type { AGRProfile, GuardMatch, GuardDetector, GuardDecision } from "./types.ts";

export interface AGRCaveatsConsumed {
  data_scope: string;
  spend_step: number;
  spend_currency?: string;
  capability: string;
}

export interface GuardInputBody {
  profile: "guard.input";
  ruleset_id: string;
  ruleset_hash: string;
  ruleset_version: string;
  content_commit: string;
  decision: GuardDecision;
  matched_rules: GuardMatch[];
  detector: GuardDetector;
  screened_at: string;
  content_media_type?: string;
  credential_id?: string;
  caveats_consumed?: AGRCaveatsConsumed;
}

export type AGRBody = GuardInputBody;

// Keep AGRProfile in scope to avoid unused-import lint when only body.ts is imported.
export type { AGRProfile };
