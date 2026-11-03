/**
 * MANDATORY TSA fails closed — real RFC 3161 tokens through the shared
 * pipeline (ARR `arr.gdpr.art17.erasure-finalized`, a MANDATORY profile).
 *
 * `tsa` is zeroed out of the signing input, so anyone can attach any block to
 * a genuine receipt. Under a MANDATORY mandate only `tsa_verified` satisfies
 * it; every other TSA outcome is a hard fail with `reason: "tsa_unverified"`
 * ("timestamp not confirmed" — distinct from the absent case's
 * `"tsa_required"`), and `tsa_state` keeps the real TSA reason. Without the
 * MANDATORY profile the same receipts stay `signature_valid: true`.
 *
 * Reference time: NO test here pins `tsaReferenceTime` (and none uses the
 * unsigned `tsa.issued_at`). The verifier's default reference is the receipt's
 * SIGNED `iat`, so a genuine token verifies however long after mint it is
 * checked. The wall clock is shifted explicitly where the test is about time,
 * so the result does not depend on when the suite runs.
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
  receipt: { iat: string; tsa?: { tsr?: string } | null } & Record<string, unknown>;
  publicKey_b64url: string;
  verify_opts?: VerifyOptsWire;
  expected: { tsa_state: string };
}

function load(name: string): Vector {
  return JSON.parse(readFileSync(join(__dirname, "vectors-v1-1", name), "utf8")) as Vector;
}

/**
 * Run `fn` with the wall clock (`Date.now()` / `new Date()`) set to `at`.
 * Explicit `new Date(x)` arguments pass through unchanged.
 */
async function atWallClock<T>(at: Date, fn: () => Promise<T>): Promise<T> {
  const RealDate = Date;
  const offset = at.getTime() - RealDate.now();
  globalThis.Date = new Proxy(RealDate, {
    construct(T, args: unknown[]) {
      return args.length ? new RealDate(...(args as [string])) : new RealDate(RealDate.now() + offset);
    },
    get(T, p, r) {
      return p === "now" ? () => RealDate.now() + offset : Reflect.get(T, p, r);
    },
  });
  try {
    return await fn();
  } finally {
    globalThis.Date = RealDate;
  }
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
    // Drop any vector-pinned reference time: the default (signed iat) is
    // what is under test.
    const { tsaReferenceTime: _pinned, ...opts } = prepared.opts;
    return (await verifyArr(v.receipt, {
      resolveKey: async () => spki,
      ...opts,
      ...(profile ? { profile } : {}),
    })) as unknown as Record<string, unknown>;
  } finally {
    prepared.teardown();
  }
}

const DAY_MS = 86_400_000;

test("MANDATORY + real verified token, no reference-time pin, checked 30 days after mint → passes", async () => {
  const v = load("arr-erasure-v2-tsa-iat-aligned.json");
  const later = new Date(Date.parse(v.receipt.iat) + 30 * DAY_MS);
  const r = await atWallClock(later, () => run(v, MANDATORY_PROFILE));
  assert.equal(r.tsa_state, "tsa_verified", JSON.stringify(r));
  assert.equal(r.signature_valid, true);
  assert.equal(r.reason, undefined);
});

test("MANDATORY + real verified token, no pin, checked today → passes", async () => {
  const r = await run(load("arr-erasure-v2-tsa-iat-aligned.json"), MANDATORY_PROFILE);
  assert.equal(r.tsa_state, "tsa_verified", JSON.stringify(r));
  assert.equal(r.signature_valid, true);
});

test("drift is measured against the signed iat: genTime 13h after iat → tsa_drift_exceeded → tsa_unverified, even with the wall clock AT genTime", async () => {
  // arr-erasure-v2-tsa.json: iat 2026-05-17T00:00:00Z, token genTime
  // 2026-05-17T13:44:08Z. With the wall clock exactly at genTime a
  // wall-clock reference would verify; the iat reference must not.
  const v = load("arr-erasure-v2-tsa.json");
  const r = await atWallClock(new Date("2026-05-17T13:44:08Z"), () => run(v, MANDATORY_PROFILE));
  assert.equal(r.tsa_state, "tsa_drift_exceeded");
  assert.equal(r.signature_valid, false);
  assert.equal(r.reason, "tsa_unverified");
});

test("explicit tsaReferenceTime still overrides the iat default", async () => {
  const v = load("arr-erasure-v2-tsa-iat-aligned.json");
  const prepared = prepareVerify(undefined);
  try {
    const spki = new Uint8Array(
      Buffer.concat([
        Buffer.from("302a300506032b6570032100", "hex"),
        Buffer.from(v.publicKey_b64url, "base64url"),
      ]),
    );
    const r = (await verifyArr(v.receipt, {
      resolveKey: async () => spki,
      ...prepared.opts,
      profile: MANDATORY_PROFILE,
      tsaReferenceTime: new Date(Date.parse(v.receipt.iat) + DAY_MS),
    })) as unknown as Record<string, unknown>;
    assert.equal(r.tsa_state, "tsa_drift_exceeded");
    assert.equal(r.reason, "tsa_unverified");
  } finally {
    prepared.teardown();
  }
});

for (const file of [
  "arr-erasure-v2-tsa-imprint-mismatch.json",
  "arr-erasure-v2-tsa-anchor-expired.json",
  "arr-erasure-v2-tsa-drift-exceeded.json",
]) {
  test(`MANDATORY + ${file} → tsa_unverified hard fail, real tsa_state preserved`, async () => {
    const v = load(file);
    const r = await run(v, MANDATORY_PROFILE);
    assert.equal(r.signature_valid, false);
    assert.equal(r.reason, "tsa_unverified");
    assert.equal(r.tsa_state, v.expected.tsa_state);
  });

  test(`no MANDATORY profile + ${file} → unchanged (signature_valid, advisory tsa_state)`, async () => {
    const v = load(file);
    const r = await run(v);
    assert.equal(r.signature_valid, true);
    assert.equal(r.tsa_state, v.expected.tsa_state);
  });
}
