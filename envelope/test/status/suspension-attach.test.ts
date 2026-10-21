/**
 * Tests for attachSuspensionStatus — Wave 3.
 * Mirrors attach.test.ts structure but for suspensionStatus field.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  attachSuspensionStatus,
  MAX_STATUS_INDEX,
} from "../../src/status/suspension-attach.ts";
import type { SuspensionListConfig } from "../../src/status/suspension-attach.ts";
import type { Envelope } from "../../src/envelope-types.ts";

function baseEnvelope(): Envelope {
  return {
    v: 2,
    id: "01HXX00000000000000SUSATTCHTST",
    iat: "2026-05-22T00:00:00Z",
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
): SuspensionListConfig {
  return {
    baseUrl: "https://verify.dekimu.com/acr/v1/suspension",
    getNextStatusIndex: async (bucket: string) => {
      if (opts?.buckets) opts.buckets.push(bucket);
      return idx;
    },
    ...(opts?.now ? { now: opts.now } : {}),
  };
}

test("attach suspension: happy path — populates suspensionStatus", async () => {
  const env = baseEnvelope();
  const out = await attachSuspensionStatus(
    env,
    makeConfig(42, { now: () => new Date("2026-05-22T00:00:00Z") }),
  );

  assert.ok(out.suspensionStatus != null);
  const ss = out.suspensionStatus!;
  assert.equal(
    ss.statusListCredential,
    "https://verify.dekimu.com/acr/v1/suspension/2026/05",
  );
  assert.equal(ss.id, "https://verify.dekimu.com/acr/v1/suspension/2026/05#42");
  assert.equal(ss.type, "StatusList2021Entry");
  assert.equal(ss.statusPurpose, "suspension");
  assert.equal(ss.statusListIndex, "42");
});

test("attach suspension: does not touch credentialStatus", async () => {
  const env = baseEnvelope();
  const out = await attachSuspensionStatus(
    env,
    makeConfig(5, { now: () => new Date("2026-05-22T00:00:00Z") }),
  );
  assert.strictEqual(out.credentialStatus, null);
  assert.ok(out.suspensionStatus != null);
});

test("attach suspension: getNextStatusIndex called once with bucket string", async () => {
  const env = baseEnvelope();
  const buckets: string[] = [];
  await attachSuspensionStatus(
    env,
    makeConfig(7, { now: () => new Date("2026-05-22T10:00:00Z"), buckets }),
  );
  assert.equal(buckets.length, 1);
  assert.equal(buckets[0], "2026/05");
});

test("attach suspension: now() override produces deterministic bucket", async () => {
  const env = baseEnvelope();
  const jan = await attachSuspensionStatus(
    env,
    makeConfig(0, { now: () => new Date("2026-01-15T12:00:00Z") }),
  );
  assert.ok(jan.suspensionStatus!.statusListCredential.endsWith("/2026/01"));
});

test("attach suspension: throws on negative index", async () => {
  const env = baseEnvelope();
  await assert.rejects(
    () => attachSuspensionStatus(env, makeConfig(-1)),
    /out of range/,
  );
});

test("attach suspension: throws on index > MAX_STATUS_INDEX", async () => {
  const env = baseEnvelope();
  await assert.rejects(
    () => attachSuspensionStatus(env, makeConfig(MAX_STATUS_INDEX + 1)),
    /out of range/,
  );
});

test("attach suspension: throws on non-integer index", async () => {
  const env = baseEnvelope();
  await assert.rejects(() => attachSuspensionStatus(env, makeConfig(NaN)), /out of range/);
  await assert.rejects(() => attachSuspensionStatus(env, makeConfig(1.5)), /out of range/);
});

test("attach suspension: accepts boundary values 0 and MAX_STATUS_INDEX", async () => {
  const env = baseEnvelope();
  const lo = await attachSuspensionStatus(env, makeConfig(0));
  assert.equal(lo.suspensionStatus!.statusListIndex, "0");
  const hi = await attachSuspensionStatus(env, makeConfig(MAX_STATUS_INDEX));
  assert.equal(hi.suspensionStatus!.statusListIndex, String(MAX_STATUS_INDEX));
});

test("attach suspension: returns new object, does not mutate input", async () => {
  const env = baseEnvelope();
  const out = await attachSuspensionStatus(
    env,
    makeConfig(5, { now: () => new Date("2026-05-22T00:00:00Z") }),
  );
  assert.notStrictEqual(out, env);
  assert.strictEqual(env.suspensionStatus, undefined);
});

test("attach suspension: rejects non-https baseUrl", async () => {
  const env = baseEnvelope();
  await assert.rejects(
    () => attachSuspensionStatus(env, {
      baseUrl: "http://verify.dekimu.com/acr/v1/suspension",
      getNextStatusIndex: async () => 5,
      now: () => new Date("2026-05-22T00:00:00Z"),
    }),
    /baseUrl must start with https:\/\//,
  );
});
