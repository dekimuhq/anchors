import * as crypto from "node:crypto";
import { base64UrlEncode, base64UrlDecode } from "./base64url.ts";

/**
 * Commit to a value with a salt: `sha256(salt_bytes || value_utf8)`.
 *
 * Salt is a base64url-encoded byte string (no padding). 256 bits recommended.
 * Returns `sha256:<hex>`.
 */
export function commit(saltB64u: string, value: string): string {
  const salt = base64UrlDecode(saltB64u);
  const h = crypto.createHash("sha256");
  h.update(salt);
  h.update(value, "utf8");
  return `sha256:${h.digest("hex")}`;
}

/** Constant-time-ish check that the given commitment matches (salt, value). */
export function verifyCommitment(c: string, saltB64u: string, value: string): boolean {
  const expected = commit(saltB64u, value);
  if (c.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < c.length; i++) diff |= c.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}

/** Generate a fresh 256-bit salt, base64url-encoded, no padding. */
export function randomSalt(): string {
  return base64UrlEncode(crypto.randomBytes(32));
}
