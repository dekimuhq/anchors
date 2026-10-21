/**
 * Pure-function tests for attachCredentialStatus — Phase D Task 20.
 *
 * Covers:
 *   - Happy-path pointer fields match spec (id, type, statusPurpose,
 *     statusListIndex, statusListCredential).
 *   - Bucket format: `YYYY/MM` UTC, padded to 2 digits.
 *   - getNextStatusIndex called exactly once with the bucket string.
 *   - now() override produces deterministic bucket.
 *   - Throws when index is negative.
 *   - Throws when index > MAX_STATUS_INDEX (131_071).
 *   - Throws when index is non-integer: NaN / Infinity / 1.5.
 *   - Boundary values 0 and 131_071 are accepted.
 *   - Input envelope is NOT mutated; returned envelope is a new object.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  attachCredentialStatus,
  MAX_STATUS_INDEX,
} from "../../src/status/attach.ts";
import type { StatusListConfig } from "../../src/status/attach.ts";
import type { Envelope } from "../../src/envelope-types.ts";

function baseEnvelope(): Envelope {
  return {
    v: 2,
    id: "01HXX00000000000000ATTACHTST",
    iat: "2026-05-17T00:00:00Z",
    claim_type: "ar.consent.v1",
    iss: "did:web:bank.example",
    iss_key: `ed25519:${"A".repeat(43)}`,
    subject: "sha256:" + "b".repeat(64),
    exp: null,
    prev: null,
    policy_uri: "https://bank.example/policy",
    policy_hash: "sha256:" + "c".repeat(64),
    policy_version: "1.0.0",
    tsa: null,
    credentialStatus: null,
    anchor: null as unknown as Envelope["anchor"],
    sig: "sig-placeholder",
    countersig: null,
    body: { lawful_basis: "6(1)(a)", purposes: ["test"] },
  };
}

function makeConfig(
  idx: number,
  opts?: { now?: () => Date; buckets?: string[] },
): StatusListConfig {
  return {
    baseUrl: "https://verify.dekimu.com/acr/v1/status",
    getNextStatusIndex: async (bucket: string) => {
      if (opts?.buckets) opts.buckets.push(bucket);
      return idx;
    },
    ...(opts?.now ? { now: opts.now } : {}),
  };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test("attach: happy path — populates credentialStatus per W3C spec", async () => {
  const env = baseEnvelope();
  const out = await attachCredentialStatus(
    env,
    makeConfig(42, { now: () => new Date("2026-05-17T00:00:00Z") }),
  );

  assert.ok(out.credentialStatus !== null);
  const cs = out.credentialStatus!;
  assert.equal(
    cs.statusListCredential,
    "https://verify.dekimu.com/acr/v1/status/2026/05",
  );
  assert.equal(cs.id, "https://verify.dekimu.com/acr/v1/status/2026/05#42");
  assert.equal(cs.type, "StatusList2021Entry");
  assert.equal(cs.statusPurpose, "revocation");
  assert.equal(cs.statusListIndex, "42");
});

test("attach: getNextStatusIndex called exactly once with the bucket string", async () => {
  const env = baseEnvelope();
  const buckets: string[] = [];
  await attachCredentialStatus(
    env,
    makeConfig(7, { now: () => new Date("2026-05-17T10:00:00Z"), buckets }),
  );
  assert.equal(buckets.length, 1);
  assert.equal(buckets[0], "2026/05");
});

test("attach: now() override produces deterministic bucket (UTC, padded)", async () => {
  const env = baseEnvelope();
  // January → `01` (zero-padded).
  const jan = await attachCredentialStatus(
    env,
    makeConfig(0, { now: () => new Date("2026-01-15T12:00:00Z") }),
  );
  assert.ok(jan.credentialStatus!.statusListCredential.endsWith("/2026/01"));

  // December → `12`.
  const dec = await attachCredentialStatus(
    env,
    makeConfig(0, { now: () => new Date("2026-12-31T23:59:59Z") }),
  );
  assert.ok(dec.credentialStatus!.statusListCredential.endsWith("/2026/12"));

  // UTC-only — local-time interpretation would shift this.
  const utc = await attachCredentialStatus(
    env,
    makeConfig(0, { now: () => new Date(Date.UTC(2027, 2, 1, 0, 0, 0)) }),
  );
  assert.ok(utc.credentialStatus!.statusListCredential.endsWith("/2027/03"));
});

test("attach: throws on negative index", async () => {
  const env = baseEnvelope();
  await assert.rejects(
    () => attachCredentialStatus(env, makeConfig(-1)),
    /out of range/,
  );
});

test("attach: throws on index > MAX_STATUS_INDEX (131_071)", async () => {
  const env = baseEnvelope();
  await assert.rejects(
    () => attachCredentialStatus(env, makeConfig(MAX_STATUS_INDEX + 1)),
    /out of range/,
  );
});

test("attach: throws on non-integer index — NaN, Infinity, 1.5", async () => {
  const env = baseEnvelope();
  await assert.rejects(
    () => attachCredentialStatus(env, makeConfig(NaN)),
    /out of range/,
  );
  await assert.rejects(
    () => attachCredentialStatus(env, makeConfig(Number.POSITIVE_INFINITY)),
    /out of range/,
  );
  await assert.rejects(
    () => attachCredentialStatus(env, makeConfig(1.5)),
    /out of range/,
  );
});

test("attach: accepts boundary values 0 and MAX_STATUS_INDEX", async () => {
  const env = baseEnvelope();
  const lo = await attachCredentialStatus(env, makeConfig(0));
  assert.equal(lo.credentialStatus!.statusListIndex, "0");

  const hi = await attachCredentialStatus(env, makeConfig(MAX_STATUS_INDEX));
  assert.equal(hi.credentialStatus!.statusListIndex, String(MAX_STATUS_INDEX));
});

test("attach: returns a NEW object; input envelope's credentialStatus stays null", async () => {
  const env = baseEnvelope();
  const out = await attachCredentialStatus(
    env,
    makeConfig(5, { now: () => new Date("2026-05-17T00:00:00Z") }),
  );
  assert.notStrictEqual(out, env, "must return a new object reference");
  assert.strictEqual(env.credentialStatus, null, "input envelope not mutated");
  assert.notStrictEqual(out.credentialStatus, null);
});

test("attach: MAX_STATUS_INDEX is exported as 131_071 (2^17 - 1)", () => {
  assert.equal(MAX_STATUS_INDEX, 131_071);
});

test("attach: rejects baseUrl that is not https://", async () => {
  const env = baseEnvelope();
  for (const badBase of [
    "http://verify.dekimu.com/acr/v1/status",
    "ftp://verify.dekimu.com/acr/v1/status",
    "//verify.dekimu.com/acr/v1/status",
    "verify.dekimu.com/acr/v1/status",
  ]) {
    await assert.rejects(
      () =>
        attachCredentialStatus(env, {
          baseUrl: badBase,
          getNextStatusIndex: async () => 5,
          now: () => new Date("2026-05-17T00:00:00Z"),
        }),
      /baseUrl must start with https:\/\//,
    );
  }
});
