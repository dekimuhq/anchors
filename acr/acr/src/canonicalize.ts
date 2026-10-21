/**
 * RFC 8785 JSON Canonicalization Scheme. ACR reuses APR's implementation
 * to guarantee bit-identical canonicalisation across the family.
 */

export { canonicalize, base64UrlEncode, base64UrlDecode } from "@dekimuhq/anchors-envelope";
