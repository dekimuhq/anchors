/**
 * Content hash of a contract. Uses the envelope's RFC 8785 (JCS) canonicaliser
 * so key order never affects the hash, then SHA-256 over the canonical bytes.
 */
import { createHash } from "node:crypto";
import { canonicalize } from "@dekimuhq/anchors-envelope";
import type { AnchorContract } from "./types.ts";

export function contractHash(contract: AnchorContract): string {
  const canonical = canonicalize(contract as unknown);
  const hex = createHash("sha256").update(canonical, "utf8").digest("hex");
  return `sha256:${hex}`;
}
