/**
 * Tests for envelope/src/tsa/request.ts — RFC 3161 TimeStampReq encoder.
 * Phase B Task 9.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { buildTimeStampReq } from "../../src/tsa/request.ts";

const IMPRINT_32 = new Uint8Array(32).fill(0xab);

test("buildTimeStampReq produces DER starting with SEQUENCE tag (0x30)", () => {
  const der = buildTimeStampReq(IMPRINT_32, "sha-256");
  assert.equal(der[0], 0x30, "must start with SEQUENCE tag");
  assert.ok(der.length > 50, "unreasonably short DER");
});

test("buildTimeStampReq without policyOid is smaller than with policyOid", () => {
  const without = buildTimeStampReq(IMPRINT_32, "sha-256");
  const with_ = buildTimeStampReq(IMPRINT_32, "sha-256", {
    policyOid: "1.2.840.113549.1.9.16.1.4",
  });
  assert.ok(with_.length > without.length, "policy OID must grow the request");
});

test("buildTimeStampReq with nonce includes additional INTEGER in output", () => {
  const without = buildTimeStampReq(IMPRINT_32, "sha-256");
  const withNonce = buildTimeStampReq(IMPRINT_32, "sha-256", {
    nonce: 0xdeadbeefn,
  });
  // Nonce is an INTEGER — output should be larger
  assert.ok(
    withNonce.length > without.length,
    "nonce INTEGER must grow the request"
  );
});

test("buildTimeStampReq throws when imprint is not 32 bytes", () => {
  const bad = new Uint8Array(16);
  assert.throws(
    () => buildTimeStampReq(bad, "sha-256"),
    /sha-256 imprint must be 32 bytes/
  );
});

test("buildTimeStampReq throws when hashAlg is not sha-256", () => {
  // @ts-expect-error — intentional bad input
  assert.throws(() => buildTimeStampReq(IMPRINT_32, "sha-512"), /only sha-256/);
});
