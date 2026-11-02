/**
 * MANDATORY TSA fails closed — real RFC 3161 tokens through the shared
 * pipeline (ARR `arr.gdpr.art17.erasure-finalized`, a MANDATORY profile).
 *
 * `tsa` is zeroed out of the signing input, so anyone can attach any block to
 * a genuine receipt. Under a MANDATORY mandate only `tsa_verified` satisfies
 * it; every other TSA outcome is a hard fail with `reason: "tsa_required"`,
 * and `tsa_state` keeps the real TSA reason. Without the MANDATORY profile the
 * same receipts stay `signature_valid: true` (advisory TSA outcome).
 *
 * Reuses the v1.1/v1.2 ARR TSA vectors (verified + imprint mismatch + anchor
 * expired + drift exceeded).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyReceipt as verifyArr } from "@dekimuhq/arr";
import { prepareVerify, type VerifyOptsWire } from "./_helpers/mock-status.ts";

const __dirname = dirname(fileURLToPath(import.meta.url));
const MANDATORY_PROFILE = "arr.gdpr.art17.erasure-finalized";

interface Vector {
  receipt: { tsa?: { issued_at?: string } | null } & Record<string, unknown>;
  publicKey_b64url: string;
  verify_opts?: VerifyOptsWire;
  expected: { tsa_state: string };
}

function load(name: string): Vector {
  return JSON.parse(readFileSync(join(__dirname, "vectors-v1-1", name), "utf8")) as Vector;
}

async function run(v: Vector, profile?: string): Promise<Record<string, unknown>> {
  const spki = new Uint8Array(
    Buffer.concat([
      Buffer.from("302a300506032b6570032100", "hex"),
      Buffer.from(v.publicKey_b64url, "base64url"),
    ]),
  );
  const prepared = prepareVerify(v.verify_opts);
  try {
    const ref =
      !prepared.opts.tsaReferenceTime && v.receipt.tsa?.issued_at
        ? { tsaReferenceTime: new Date(v.receipt.tsa.issued_at) }
        : {};
    return (await verifyArr(v.receipt, {
      resolveKey: async () => spki,
      ...prepared.opts,
      ...ref,
      ...(profile ? { profile } : {}),
    })) as unknown as Record<string, unknown>;
  } finally {
    prepared.teardown();
  }
}

test("MANDATORY + tsa_verified (real FreeTSA token) → passes", async () => {
  const r = await run(load("arr-erasure-v2-tsa.json"), MANDATORY_PROFILE);
  assert.equal(r.tsa_state, "tsa_verified");
  assert.equal(r.signature_valid, true, JSON.stringify(r));
  assert.equal(r.reason, undefined);
});

for (const file of [
  "arr-erasure-v2-tsa-imprint-mismatch.json",
  "arr-erasure-v2-tsa-anchor-expired.json",
  "arr-erasure-v2-tsa-drift-exceeded.json",
]) {
  test(`MANDATORY + ${file} → tsa_required hard fail, real tsa_state preserved`, async () => {
    const v = load(file);
    const r = await run(v, MANDATORY_PROFILE);
    assert.equal(r.signature_valid, false);
    assert.equal(r.reason, "tsa_required");
    assert.equal(r.tsa_state, v.expected.tsa_state);
  });

  test(`no MANDATORY profile + ${file} → unchanged (signature_valid, advisory tsa_state)`, async () => {
    const v = load(file);
    const r = await run(v);
    assert.equal(r.signature_valid, true);
    assert.equal(r.tsa_state, v.expected.tsa_state);
  });
}
