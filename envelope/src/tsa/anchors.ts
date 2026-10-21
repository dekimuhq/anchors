/**
 * TSA trust-anchor catalog loader — Phase B Task 10.
 *
 * Loads trust anchors from a JSON catalog file and verifies each cert's
 * SHA-256 DER fingerprint against the pinned value to detect tampering.
 */

import { readFileSync } from "node:fs";
import { createHash, X509Certificate } from "node:crypto";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface TrustAnchor {
  id: string;
  name: string;
  eutl_listed: boolean;
  cert_pem: string;
  cert_sha256_der: string;
  key_usage: string[];
  valid_until: string;
}

// ── Internal catalog shape (not exported — implementation detail) ─────────────

interface AnchorCatalog {
  anchors: TrustAnchor[];
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Load trust anchors from one or more catalog JSON files.
 *
 * Each anchor's PEM cert is decoded and its SHA-256 DER fingerprint is
 * verified against the pinned `cert_sha256_der` value. Throws if any
 * anchor fails the pin check (fast-fail — never silently trust a mismatched cert).
 */
export function loadTrustAnchors(paths: string[]): TrustAnchor[] {
  const out: TrustAnchor[] = [];
  for (const p of paths) {
    const data = JSON.parse(readFileSync(resolve(p), "utf8")) as AnchorCatalog;
    for (const a of data.anchors) {
      const cert = new X509Certificate(a.cert_pem);
      const der = cert.raw;
      const sha = "sha256:" + createHash("sha256").update(der).digest("hex");
      if (sha !== a.cert_sha256_der) {
        throw new Error(
          `tsa: anchor ${a.id} cert sha mismatch (pin: ${a.cert_sha256_der}, got: ${sha})`,
        );
      }
      out.push(a);
    }
  }
  return out;
}

/**
 * Return the path to the bundled FreeTSA trust-anchor catalog.
 *
 * Uses `import.meta.url` for ESM-safe resolution:
 *   envelope/src/tsa/ → ../../../data/freetsa-trust-anchor.json
 *   = anchors/data/freetsa-trust-anchor.json (workspace root)
 */
export function defaultTrustAnchorPath(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  return resolve(here, "../../../data/freetsa-trust-anchor.json");
}
