/**
 * Phase D Task 17 — Status List 2021 bitstring decode.
 *
 * Covers:
 *   - readBitAt: MSB-first bit ordering within each byte, out-of-range throw.
 *   - encodedListFromBitstring + decodeEncodedList: gzip+base64url round-trip.
 *   - Malformed-input rejection (base64url / gzip errors propagate).
 *   - 131 072-bit (W3C minimum) round-trips, both zero-filled and all-ones.
 *   - High-index single-bit-set round-trip preserves byte + bit position.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  encodedListFromBitstring,
  readBitAt,
  decodeEncodedList,
} from "../../src/status/decode.ts";

test("readBitAt reads the right bit from a 131072-bit array", () => {
  const N = 131072;
  const bits = new Uint8Array(N / 8);
  bits[0] = 0b10000000; // bit 0 set
  bits[7] = 0b00000001; // bit 63 set
  assert.equal(readBitAt(bits, 0), 1);
  assert.equal(readBitAt(bits, 1), 0);
  assert.equal(readBitAt(bits, 63), 1);
  assert.equal(readBitAt(bits, 64), 0);
});

test("readBitAt MSB-first bit ordering — boundaries 0 / 7 / 8", () => {
  const bits = new Uint8Array(2);
  bits[0] = 0b10000000; // bit 0 = MSB of byte 0
  assert.equal(readBitAt(bits, 0), 1);
  assert.equal(readBitAt(bits, 7), 0);

  bits[0] = 0b00000001; // bit 7 = LSB of byte 0
  assert.equal(readBitAt(bits, 0), 0);
  assert.equal(readBitAt(bits, 7), 1);

  bits[1] = 0b10000000; // bit 8 = MSB of byte 1
  assert.equal(readBitAt(bits, 8), 1);
  assert.equal(readBitAt(bits, 15), 0);
});

test("readBitAt throws on out-of-range index", () => {
  const bits = new Uint8Array(4); // 32 bits
  assert.throws(
    () => readBitAt(bits, 32),
    (err: Error) => {
      assert.match(err.message, /32/);
      assert.match(err.message, /32 bits/);
      return true;
    },
  );
  assert.throws(
    () => readBitAt(bits, 1000),
    (err: Error) => {
      assert.match(err.message, /1000/);
      assert.match(err.message, /32 bits/);
      return true;
    },
  );
});

test("encodedListFromBitstring + decodeEncodedList round-trips", () => {
  const bits = new Uint8Array(131072 / 8);
  bits[5] = 0x80;
  const enc = encodedListFromBitstring(bits);
  const dec = decodeEncodedList(enc);
  assert.deepEqual(Array.from(dec.slice(0, 6)), [0, 0, 0, 0, 0, 0x80]);
});

test("decodeEncodedList rejects malformed input", () => {
  assert.throws(() => decodeEncodedList("not-base64-or-gzip"));
});

test("131 072-bit zero array round-trips byte-equal (and compresses small)", () => {
  const bits = new Uint8Array(131072 / 8); // all zero
  const enc = encodedListFromBitstring(bits);
  // gzip of 16 384 zero bytes is well under 1 KB
  assert.ok(
    enc.length < 1000,
    `expected gzipped zeros encoded < 1000 chars, got ${enc.length}`,
  );
  const dec = decodeEncodedList(enc);
  assert.equal(dec.length, bits.length);
  assert.deepEqual(dec, bits);
});

test("131 072-bit all-ones array round-trips byte-equal", () => {
  const bits = new Uint8Array(131072 / 8).fill(0xff);
  const enc = encodedListFromBitstring(bits);
  const dec = decodeEncodedList(enc);
  assert.equal(dec.length, bits.length);
  assert.deepEqual(dec, bits);
});

test("mid-string-only bit set survives round-trip at correct byte+bit position", () => {
  const bits = new Uint8Array(131072 / 8);
  const index = 70_000;
  // MSB-first: bit `index` lives in byte `index >>> 3`, mask = 1 << (7 - (index & 7))
  const byteIdx = index >>> 3;
  const mask = 1 << (7 - (index & 7));
  bits[byteIdx] = mask;

  const enc = encodedListFromBitstring(bits);
  const dec = decodeEncodedList(enc);

  assert.equal(dec[byteIdx], mask);
  assert.equal(readBitAt(dec, index), 1);
  assert.equal(readBitAt(dec, index - 1), 0);
  assert.equal(readBitAt(dec, index + 1), 0);

  // All other bytes still zero.
  for (let i = 0; i < dec.length; i++) {
    if (i !== byteIdx) assert.equal(dec[i], 0, `byte ${i} should be 0`);
  }
});
