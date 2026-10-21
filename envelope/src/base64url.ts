/**
 * Base64url encode/decode utilities.
 *
 * Self-contained copy for @dekimuhq/anchors-envelope — this package is upstream
 * of apr-verifier in the build graph and must not import from member packages.
 * apr-verifier keeps its own copy for v=1 backward-compat.
 *
 * Source of truth: anchors/apr/apr-verifier/src/base64url.ts
 */

export function base64UrlDecode(s: string): Uint8Array {
  if (typeof s !== "string") {
    throw new Error("base64UrlDecode: expected string");
  }
  return new Uint8Array(Buffer.from(s, "base64url"));
}

export function base64UrlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}
