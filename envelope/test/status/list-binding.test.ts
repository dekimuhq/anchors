/**
 * Status-list substitution + rollback (security audit finding F3).
 *
 * A list signature alone does not bind the list to the URL the pointer named,
 * nor to a point in time: a validly-signed list for a DIFFERENT url, or an
 * OLDER genuine snapshot of the same list, must not be accepted as the answer.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { verifyCredentialStatus } from "../../src/status/reconcile.ts";
import { verifySuspensionStatus } from "../../src/status/suspension-verify.ts";
import { InMemoryStatusCache } from "../../src/status/cache.ts";
import type { Envelope } from "../../src/envelope-types.ts";
import { makeSignedStatusList } from "./_make-signed-list.mts";

const URL_A = "https://verify.dekimu.com/status/tenantA";
const URL_B = "https://verify.dekimu.com/status/tenantB";

function env(url: string, idx = 5): Envelope {
  return {
    v: 2,
    id: "01HXX0000000000000000BINDING1",
    claim_type: "ar.consent.v1",
    iss: "did:web:bank.example",
    iss_key: `ed25519:${"A".repeat(43)}`,
    subject: "sha256:" + "a".repeat(64),
    iat: "2026-05-17T00:00:00Z",
    exp: null,
    prev: null,
    policy_uri: "https://bank.example/policy",
    policy_hash: "sha256:" + "b".repeat(64),
    policy_version: "1.0.0",
    tsa: null,
    credentialStatus: {
      id: `${url}#${idx}`,
      type: "StatusList2021Entry",
      statusPurpose: "revocation",
      statusListIndex: String(idx),
      statusListCredential: url,
    },
    anchor: null as unknown as Envelope["anchor"],
    sig: "sig-placeholder",
    countersig: null,
    body: { lawful_basis: "6(1)(a)", purposes: ["test"] },
  } as Envelope;
}

const serve = (body: unknown): typeof fetch =>
  (async () =>
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { "content-type": "application/json" },
    })) as unknown as typeof fetch;

// freshTtl 0 → every call refetches (so the served body is what gets judged).
const cfg = (storage?: InMemoryStatusCache) => ({
  freshTtlSec: 0,
  staleTtlSec: 86400,
  maxEntries: 8,
  ...(storage ? { storage } : {}),
});

test("F3: a validly-signed list whose id is a DIFFERENT url is rejected (list_id_mismatch)", async () => {
  // tenant B's genuine list, signed by the same root key, served at tenant A's url.
  const { credential, rootKey } = makeSignedStatusList({
    bitIndex: 5,
    bitValue: 0,
    credentialUrl: URL_B,
  });
  const r = await verifyCredentialStatus(env(URL_A), {
    rootKey,
    cacheConfig: cfg(),
    _testFetch: serve(credential),
  });
  assert.equal(r.state, "list_mismatch");
  if (r.state === "list_mismatch") assert.equal(r.reason, "list_id_mismatch");
});

test("F3: matching list id still verifies (active) — no regression", async () => {
  const { credential, rootKey } = makeSignedStatusList({
    bitIndex: 5,
    bitValue: 0,
    credentialUrl: URL_A,
  });
  const r = await verifyCredentialStatus(env(URL_A), {
    rootKey,
    cacheConfig: cfg(),
    _testFetch: serve(credential),
  });
  assert.equal(r.state, "active");
});

test("F3: replay of an OLDER genuine list is rejected when a cache has seen a newer one (list_rollback)", async () => {
  const keypair = generateKeyPairSync("ed25519");
  const current = makeSignedStatusList({
    bitIndex: 5, bitValue: 1, credentialUrl: URL_A, keypair, validFrom: "2026-11-20T00:00:00Z",
  });
  const older = makeSignedStatusList({
    bitIndex: 5, bitValue: 0, credentialUrl: URL_A, keypair, validFrom: "2026-01-01T00:00:00Z",
  });
  const storage = new InMemoryStatusCache(8);
  const first = await verifyCredentialStatus(env(URL_A), {
    rootKey: current.rootKey, cacheConfig: cfg(storage), _testFetch: serve(current.credential),
  });
  assert.equal(first.state, "revoked", "genuine current list reports the revocation");

  const replay = await verifyCredentialStatus(env(URL_A), {
    rootKey: current.rootKey, cacheConfig: cfg(storage), _testFetch: serve(older.credential),
  });
  assert.equal(replay.state, "list_mismatch", "rolled-back list must not report active");
  if (replay.state === "list_mismatch") assert.equal(replay.reason, "list_rollback");

  // The high-water mark survives the rejected replay (second replay still rejected).
  const replay2 = await verifyCredentialStatus(env(URL_A), {
    rootKey: current.rootKey, cacheConfig: cfg(storage), _testFetch: serve(older.credential),
  });
  assert.equal(replay2.state, "list_mismatch");
});

test("F3: a newer list after an older one is accepted (monotonic, not frozen)", async () => {
  const keypair = generateKeyPairSync("ed25519");
  const a = makeSignedStatusList({ bitIndex: 5, bitValue: 0, credentialUrl: URL_A, keypair, validFrom: "2026-01-01T00:00:00Z" });
  const b = makeSignedStatusList({ bitIndex: 5, bitValue: 1, credentialUrl: URL_A, keypair, validFrom: "2026-11-20T00:00:00Z" });
  const storage = new InMemoryStatusCache(8);
  const r1 = await verifyCredentialStatus(env(URL_A), { rootKey: a.rootKey, cacheConfig: cfg(storage), _testFetch: serve(a.credential) });
  assert.equal(r1.state, "active");
  const r2 = await verifyCredentialStatus(env(URL_A), { rootKey: a.rootKey, cacheConfig: cfg(storage), _testFetch: serve(b.credential) });
  assert.equal(r2.state, "revoked");
});

test("F3: minListValidFrom bound rejects a stale-but-genuine list with no cache history (list_too_old)", async () => {
  const older = makeSignedStatusList({
    bitIndex: 5, bitValue: 0, credentialUrl: URL_A, validFrom: "2026-01-01T00:00:00Z",
  });
  const r = await verifyCredentialStatus(env(URL_A), {
    rootKey: older.rootKey,
    cacheConfig: cfg(),
    minListValidFrom: "2026-11-01T00:00:00Z",
    _testFetch: serve(older.credential),
  });
  assert.equal(r.state, "list_mismatch");
  if (r.state === "list_mismatch") assert.equal(r.reason, "list_too_old");
});

test("F3: maxListAgeSec bound rejects a list older than the allowed age; fresh list passes", async () => {
  const oldL = makeSignedStatusList({ bitIndex: 5, bitValue: 0, credentialUrl: URL_A, validFrom: "2026-01-01T00:00:00Z" });
  const rOld = await verifyCredentialStatus(env(URL_A), {
    rootKey: oldL.rootKey, cacheConfig: cfg(), maxListAgeSec: 86400, _testFetch: serve(oldL.credential),
  });
  assert.equal(rOld.state, "list_mismatch");
  const newL = makeSignedStatusList({ bitIndex: 5, bitValue: 0, credentialUrl: URL_A, validFrom: new Date(Date.now() - 3600_000).toISOString() });
  const rNew = await verifyCredentialStatus(env(URL_A), {
    rootKey: newL.rootKey, cacheConfig: cfg(), maxListAgeSec: 86400, _testFetch: serve(newL.credential),
  });
  assert.equal(rNew.state, "active");
});

test("F3: unparseable validFrom is rejected (fail closed) once a freshness bound is in force", async () => {
  const l = makeSignedStatusList({ bitIndex: 5, bitValue: 0, credentialUrl: URL_A, validFrom: "not-a-date" });
  const r = await verifyCredentialStatus(env(URL_A), {
    rootKey: l.rootKey, cacheConfig: cfg(), minListValidFrom: "2026-01-01T00:00:00Z", _testFetch: serve(l.credential),
  });
  assert.equal(r.state, "list_mismatch");
});

test("F3: suspension verifier has the same url binding", async () => {
  const { credential, rootKey } = makeSignedStatusList({
    bitIndex: 5, bitValue: 0, credentialUrl: URL_B, statusPurpose: "suspension",
  });
  const e = env(URL_A);
  (e as unknown as { credentialStatus: null }).credentialStatus = null;
  (e as unknown as Record<string, unknown>).suspensionStatus = {
    id: `${URL_A}#5`,
    type: "StatusList2021Entry",
    statusPurpose: "suspension",
    statusListIndex: "5",
    statusListCredential: URL_A,
  };
  const r = await verifySuspensionStatus(e, { rootKey, cacheConfig: cfg(), _testFetch: serve(credential) });
  assert.equal(r.state, "list_mismatch");
});
