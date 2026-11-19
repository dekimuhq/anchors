import { createHash } from "node:crypto";
import { canonicalize } from "@dekimuhq/anchors-envelope";
import type { ScreeningMatcher } from "./types.ts";

/** Envelope `policy_hash` for a matcher: sha256 of JCS `{package, version, threshold}` (spec §2.1). */
export function matcherPolicyHash(m: ScreeningMatcher): string {
  const jcs = canonicalize({ package: m.name, version: m.version, threshold: m.threshold });
  return "sha256:" + createHash("sha256").update(jcs, "utf8").digest("hex");
}
