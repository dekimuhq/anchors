/**
 * APIIR (Anchored PII-Redaction Receipts) body type. Asserts redaction
 * PROVENANCE, not a PII-free guarantee. The reversible map + salt are NEVER
 * here. Envelope-level fields come from @dekimuhq/anchors-envelope and are not
 * repeated. field_root is added issuer-side by mintRedactionV1.
 */
import type { RedactionProfile, RedactionCounts } from "./types.ts";

export interface APIIRBody {
  profile: RedactionProfile;          // "redaction.prompt"
  counts: RedactionCounts;            // per-category removal counts
  ruleset_hash: string;               // sha256:<hex> — golden-pinned detector corpus+version
  input_commit: string;               // sha256:<hex> = commit(salt, original_input)
  output_commit: string;              // sha256:<hex> = commit(salt, sanitized_output)
  commit_alg: "sha256";
  redactor: string;                   // provenance, e.g. "@dekimuhq/ai@2.4.0"
}
