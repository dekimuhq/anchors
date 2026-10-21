import { hkdfSync } from "node:crypto";
import { base64UrlEncode } from "@dekimuhq/anchors-envelope";
import type { SaltSource } from "./types.ts";

const EMPTY_SALT = new Uint8Array(0);

/** Deterministic per-leaf salt = HKDF-SHA256(seed, salt="", info=path, len=32),
 *  base64url. One per-receipt random `seed` (32 bytes) is the holder's secret. */
export function seedSaltSource(seed: Uint8Array): SaltSource {
  return {
    saltFor(resolvedPath: string): string {
      const info = new TextEncoder().encode(resolvedPath);
      const derived = hkdfSync("sha256", seed, EMPTY_SALT, info, 32);
      return base64UrlEncode(new Uint8Array(derived));
    },
  };
}

/** Explicit per-path salt bundle (ACR back-compat / non-deterministic issuers). */
export function bundleSaltSource(bundle: Readonly<Record<string, string>>): SaltSource {
  return {
    saltFor(resolvedPath: string): string {
      const salt = bundle[resolvedPath];
      if (salt === undefined) throw new Error(`bundleSaltSource: no salt for ${resolvedPath}`);
      return salt;
    },
  };
}
