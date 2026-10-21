/**
 * JCS (RFC 8785) canonicalization of TslServiceEntry → deterministic SHA-256 hash.
 *
 * Uses canonicalize() from @dekimuhq/anchors-envelope for RFC 8785 compliance.
 */

import * as crypto from "node:crypto";
import { canonicalize } from "@dekimuhq/anchors-envelope";
import type { TslServiceEntry } from "./types.ts";

/**
 * Canonicalize a TslServiceEntry via JCS and return its SHA-256 hash.
 * Returns "sha256:<64-hex>".
 */
export function hashEntry(entry: TslServiceEntry): string {
  const canonical = canonicalize(entry);
  const hash = crypto.createHash("sha256").update(canonical, "utf8").digest("hex");
  return `sha256:${hash}`;
}
