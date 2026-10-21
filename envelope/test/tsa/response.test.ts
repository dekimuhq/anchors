/**
 * Tests for envelope/src/tsa/response.ts — RFC 3161 TimeStampResp parser.
 * Phase B Task 9.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { parseTimeStampResp } from "../../src/tsa/response.ts";

const __dir = dirname(fileURLToPath(import.meta.url));
const TSR_PATH = join(__dir, "fixtures/freetsa-sample.tsr");
const IMPRINT_PATH = join(__dir, "fixtures/freetsa-sample.imprint");

const tsr = new Uint8Array(readFileSync(TSR_PATH));
const expectedImprint = new Uint8Array(readFileSync(IMPRINT_PATH));

// ── Live FreeTSA fixture ──────────────────────────────────────────────────────

test("parseTimeStampResp: FreeTSA fixture status is 0 (granted)", () => {
  const result = parseTimeStampResp(tsr);
  assert.equal(result.granted, true);
  assert.equal(result.status, 0);
});

test("parseTimeStampResp: FreeTSA fixture hashAlg is SHA-256 OID", () => {
  const result = parseTimeStampResp(tsr);
  if (!result.granted) throw new Error("fixture not granted");
  assert.equal(result.tstInfo.hashAlg, "2.16.840.1.101.3.4.2.1");
});

test("parseTimeStampResp: FreeTSA fixture hashedMessage is 32 bytes", () => {
  const result = parseTimeStampResp(tsr);
  if (!result.granted) throw new Error("fixture not granted");
  assert.equal(result.tstInfo.hashedMessage.length, 32);
});

test("parseTimeStampResp: FreeTSA fixture hashedMessage matches the captured imprint", () => {
  const result = parseTimeStampResp(tsr);
  if (!result.granted) throw new Error("fixture not granted");
  assert.deepEqual(result.tstInfo.hashedMessage, expectedImprint);
});

test("parseTimeStampResp: FreeTSA fixture serialNumber is a positive bigint", () => {
  const result = parseTimeStampResp(tsr);
  if (!result.granted) throw new Error("fixture not granted");
  assert.equal(typeof result.tstInfo.serialNumber, "bigint");
  assert.ok(result.tstInfo.serialNumber > 0n);
});

test("parseTimeStampResp: FreeTSA fixture genTime parses to ISO 8601", () => {
  const result = parseTimeStampResp(tsr);
  if (!result.granted) throw new Error("fixture not granted");
  // Must match YYYY-MM-DDTHH:MM:SSZ
  assert.match(result.tstInfo.genTime, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
});

test("parseTimeStampResp: FreeTSA fixture signerInfo contains ≥1 cert DER", () => {
  const result = parseTimeStampResp(tsr);
  if (!result.granted) throw new Error("fixture not granted");
  assert.ok(result.signerInfo.certChainDer.length >= 1);
  // Each cert must start with SEQUENCE (0x30)
  for (const cert of result.signerInfo.certChainDer) {
    assert.equal(cert[0], 0x30, "cert DER must start with SEQUENCE tag");
  }
});

test("parseTimeStampResp: FreeTSA fixture signature is non-empty Uint8Array", () => {
  const result = parseTimeStampResp(tsr);
  if (!result.granted) throw new Error("fixture not granted");
  assert.ok(result.signerInfo.signature instanceof Uint8Array);
  assert.ok(result.signerInfo.signature.length > 0);
});

// ── Error cases ───────────────────────────────────────────────────────────────

test("parseTimeStampResp throws when input is not a SEQUENCE", () => {
  // Just an INTEGER: 02 01 01
  const bad = new Uint8Array([0x02, 0x01, 0x01]);
  assert.throws(() => parseTimeStampResp(bad), /not a SEQUENCE/);
});

test("parseTimeStampResp returns granted=false without tstInfo for rejected responses", () => {
  // Minimal synthetic TSR with status=2 (rejection):
  // SEQUENCE { SEQUENCE { INTEGER 2 } }
  // 30 05 30 03 02 01 02
  const rejected = new Uint8Array([0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02]);
  const result = parseTimeStampResp(rejected);
  assert.equal(result.granted, false);
  assert.equal(result.status, 2);
  assert.equal(result.tstInfo, null);
  assert.equal(result.signerInfo, null);
});
