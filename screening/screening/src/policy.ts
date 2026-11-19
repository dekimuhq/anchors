import { createHash } from "node:crypto";
import { canonicalize } from "@dekimuhq/anchors-envelope";
import type { ScreeningMatcher } from "./types.ts";

/** Envelope `policy_hash` for a matcher: sha256 of JCS `{package, version, threshold}` (spec §2.1). */
export function matcherPolicyHash(m: ScreeningMatcher): string {
  if (typeof m?.name !== "string" || typeof m.version !== "string" || typeof m.threshold !== "number" || !Number.isFinite(m.threshold)) {
    throw new Error("matcherPolicyHash: matcher must be {name: string, version: string, threshold: finite number}");
  }
  const jcs = canonicalize({ package: m.name, version: m.version, threshold: m.threshold });
  return "sha256:" + createHash("sha256").update(jcs, "utf8").digest("hex");
}
