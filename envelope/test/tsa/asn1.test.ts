/**
 * Tests for envelope/src/tsa/asn1.ts — minimal ASN.1 DER reader.
 * Phase B Task 8.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readTLV, decodeOID, readOctetString, readInteger, readGeneralizedTime } from "../../src/tsa/asn1.ts";

// ── readTLV ───────────────────────────────────────────────────────────────────

test("readTLV walks a SEQUENCE-of-INTEGERs", () => {
  // SEQUENCE { INTEGER 42, INTEGER 65535 }  →  30 07 02 01 2A 02 02 FF FF
  const der = new Uint8Array([0x30, 0x07, 0x02, 0x01, 0x2a, 0x02, 0x02, 0xff, 0xff]);
  const top = readTLV(der, 0);
  assert.equal(top.tag, 0x30);
  assert.equal(top.length, 7);
  const inner1 = readTLV(der, top.contentStart);
  assert.equal(inner1.tag, 0x02);
  assert.equal(der[inner1.contentStart], 0x2a);
  const inner2 = readTLV(der, inner1.contentStart + inner1.length);
  assert.equal(inner2.tag, 0x02);
  assert.equal(inner2.length, 2);
});

test("readTLV handles long-form length (>127 bytes)", () => {
  const der = new Uint8Array(3 + 200);
  der[0] = 0x30; der[1] = 0x81; der[2] = 0xc8;
  const t = readTLV(der, 0);
  assert.equal(t.length, 200);
  assert.equal(t.contentStart, 3);
});

test("readTLV throws when offset is past end of buffer", () => {
  const der = new Uint8Array([0x02, 0x01, 0x01]);
  assert.throws(() => readTLV(der, 10), /read past end/);
});

test("readTLV throws when TLV content exceeds buffer bounds", () => {
  // Tag=0x02, length=10, but buffer only has 2 content bytes
  const der = new Uint8Array([0x02, 0x0a, 0x01, 0x02]);
  assert.throws(() => readTLV(der, 0), /TLV exceeds buffer/);
});

// ── decodeOID ─────────────────────────────────────────────────────────────────

test("decodeOID handles SHA-256 OID", () => {
  // OID 2.16.840.1.101.3.4.2.1  encoded: 60 86 48 01 65 03 04 02 01
  const der = new Uint8Array([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);
  assert.equal(decodeOID(der, 0, der.length), "2.16.840.1.101.3.4.2.1");
});

test("decodeOID throws on empty OID", () => {
  const der = new Uint8Array([]);
  assert.throws(() => decodeOID(der, 0, 0), /empty OID/);
});

// ── readOctetString ───────────────────────────────────────────────────────────

test("readOctetString returns content bytes", () => {
  // OCTET STRING { 0xDE, 0xAD, 0xBE, 0xEF }
  const der = new Uint8Array([0x04, 0x04, 0xde, 0xad, 0xbe, 0xef]);
  const result = readOctetString(der, 0);
  assert.deepEqual(result, new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
});

test("readOctetString throws on wrong tag", () => {
  // INTEGER 42 — wrong tag for OCTET STRING
  const der = new Uint8Array([0x02, 0x01, 0x2a]);
  assert.throws(() => readOctetString(der, 0), /expected OCTET STRING/);
});

// ── readInteger ───────────────────────────────────────────────────────────────

test("readInteger returns bigint value for multi-byte integer", () => {
  // INTEGER 0x0102 = 258
  const der = new Uint8Array([0x02, 0x02, 0x01, 0x02]);
  assert.equal(readInteger(der, 0), 258n);
});

test("readInteger throws on wrong tag", () => {
  // OCTET STRING — wrong tag for INTEGER
  const der = new Uint8Array([0x04, 0x01, 0x42]);
  assert.throws(() => readInteger(der, 0), /expected INTEGER/);
});

// ── readGeneralizedTime ───────────────────────────────────────────────────────

test("readGeneralizedTime parses UTC GeneralizedTime to ISO 8601", () => {
  // GeneralizedTime "20260517143000Z"
  const raw = "20260517143000Z";
  const content = new TextEncoder().encode(raw);
  const der = new Uint8Array(2 + content.length);
  der[0] = 0x18; // GeneralizedTime tag
  der[1] = content.length;
  der.set(content, 2);
  assert.equal(readGeneralizedTime(der, 0), "2026-05-17T14:30:00Z");
});

test("readGeneralizedTime throws on wrong tag", () => {
  // UTCTime tag 0x17 instead of GeneralizedTime 0x18
  const raw = "260517143000Z";
  const content = new TextEncoder().encode(raw);
  const der = new Uint8Array(2 + content.length);
  der[0] = 0x17; // UTCTime tag — wrong
  der[1] = content.length;
  der.set(content, 2);
  assert.throws(() => readGeneralizedTime(der, 0), /expected GeneralizedTime/);
});

test("readGeneralizedTime throws on malformed content", () => {
  const raw = "NOTADATE";
  const content = new TextEncoder().encode(raw);
  const der = new Uint8Array(2 + content.length);
  der[0] = 0x18;
  der[1] = content.length;
  der.set(content, 2);
  assert.throws(() => readGeneralizedTime(der, 0), /malformed GeneralizedTime/);
});

// ── bounds hardening (code review fix) ───────────────────────────────────────

test("decodeOID rejects truncated component (continuation bit never clears)", () => {
  // Last byte has high bit set — continuation never terminates
  const der = new Uint8Array([0x60, 0x86]); // valid first byte, then truncated continuation
  assert.throws(() => decodeOID(der, 0, der.length), /truncated OID/);
});

test("readTLV rejects buffer with tag but no length byte", () => {
  const der = new Uint8Array([0x30]); // only the tag, no length
  assert.throws(() => readTLV(der, 0), /past end|no length byte/);
});
