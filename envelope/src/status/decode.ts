/**
 * Status List 2021 bitstring decode — gzip + base64url + MSB-first bit read.
 *
 * Phase D Task 17. Pure-additive utility module: no I/O, no caching, no policy.
 * The verifier path consumes `decodeEncodedList` + `readBitAt` to interrogate
 * a fetched Status List Credential; the issuer/log-publisher path uses
 * `encodedListFromBitstring` to produce the `encodedList` field.
 *
 * Wire format (per W3C VC Bitstring Status List 2021):
 *   bitstring (Uint8Array, MSB-first within each byte) → gzip → base64url
 */

import { gzipSync, gunzipSync } from "node:zlib";
import { base64UrlEncode, base64UrlDecode } from "../base64url.ts";

/**
 * Encode a packed bitstring as a Status List 2021 `encodedList` string.
 *
 * Input is a byte-packed bitstring with MSB-first bit ordering inside each
 * byte (bit 0 = high bit of byte 0). Output is gzip → base64url per the W3C
 * Status List 2021 `encodedList` shape.
 *
 * Used by the log-publisher worker; included here for symmetry with the
 * decoder and to share a single round-trip-tested implementation. The
 * verifier code path uses {@link decodeEncodedList} only.
 */
export function encodedListFromBitstring(bits: Uint8Array): string {
  return base64UrlEncode(new Uint8Array(gzipSync(Buffer.from(bits))));
}

/**
 * Decode a Status List 2021 `encodedList` string back to a packed bitstring.
 *
 * Throws on malformed input — any base64url decode error or gzip corruption
 * propagates verbatim. Verifier callers wrap this in their own state machine
 * (typically downgrading the receipt status to a verification failure rather
 * than crashing the request).
 */
export function decodeEncodedList(encoded: string): Uint8Array {
  const gzipped = base64UrlDecode(encoded);
  return new Uint8Array(gunzipSync(Buffer.from(gzipped)));
}

/**
 * Read a single bit from a packed bitstring, MSB-first within each byte.
 *
 * Bit 0 is the high bit (0x80) of byte 0; bit 7 is the low bit (0x01) of
 * byte 0; bit 8 is the high bit of byte 1. This matches W3C Status List 2021
 * (`(byte >>> (7 - (index & 7))) & 1`) — DO NOT swap to LSB-first.
 *
 * Throws when `index` is out of range (≥ `bits.length * 8`). The error
 * message embeds both the requested index and the bitstring length in bits
 * to make Status List drift diagnosable from logs alone.
 */
export function readBitAt(bits: Uint8Array, index: number): 0 | 1 {
  const byte = bits[index >>> 3];
  if (byte === undefined) {
    throw new Error(
      `status: index ${index} out of range (bitstring ${bits.length * 8} bits)`,
    );
  }
  const bit = (byte >>> (7 - (index & 7))) & 1;
  return bit as 0 | 1;
}
