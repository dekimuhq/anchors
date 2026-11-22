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

// ── Review round 2 ───────────────────────────────────────────────────────────

test("F3b: same-validFrom replay (publisher signs the BUCKET START) — pre-revocation snapshot is rejected once the cache saw the revoked bit", async () => {
  // Real publisher behaviour: validFrom is constant across re-signs inside a bucket,
  // so `validFrom < high-water` can never fire. The only signal left is the bitstring.
  const keypair = generateKeyPairSync("ed25519");
  const VF = "2026-11-01T00:00:00Z";
  const pre = makeSignedStatusList({ bitIndex: 5, bitValue: 0, credentialUrl: URL_A, keypair, validFrom: VF });
  const post = makeSignedStatusList({ bitIndex: 5, bitValue: 1, credentialUrl: URL_A, keypair, validFrom: VF });
  const storage = new InMemoryStatusCache(8);
  const o = (c: unknown) => ({ rootKey: pre.rootKey, cacheConfig: cfg(storage), _testFetch: serve(c) });

  assert.equal((await verifyCredentialStatus(env(URL_A), o(post.credential))).state, "revoked");
  const replay = await verifyCredentialStatus(env(URL_A), o(pre.credential));
  assert.equal(replay.state, "list_mismatch", "un-revoking a known-revoked index at equal validFrom is a rollback");
  if (replay.state === "list_mismatch") assert.equal(replay.reason, "list_rollback");
  // Sticky: the replay did not erase what the cache knew.
  assert.equal((await verifyCredentialStatus(env(URL_A), o(pre.credential))).state, "list_mismatch");
  // The genuine list is still accepted.
  assert.equal((await verifyCredentialStatus(env(URL_A), o(post.credential))).state, "revoked");
});

test("F3b: same-validFrom, pre-revocation seen FIRST then post-revocation → accepted (monotone growth of the revoked set)", async () => {
  const keypair = generateKeyPairSync("ed25519");
  const VF = "2026-11-01T00:00:00Z";
  const pre = makeSignedStatusList({ bitIndex: 5, bitValue: 0, credentialUrl: URL_A, keypair, validFrom: VF });
  const post = makeSignedStatusList({ bitIndex: 5, bitValue: 1, credentialUrl: URL_A, keypair, validFrom: VF });
  const storage = new InMemoryStatusCache(8);
  const o = (c: unknown) => ({ rootKey: pre.rootKey, cacheConfig: cfg(storage), _testFetch: serve(c) });
  assert.equal((await verifyCredentialStatus(env(URL_A), o(pre.credential))).state, "active");
  assert.equal((await verifyCredentialStatus(env(URL_A), o(post.credential))).state, "revoked");
});

test("F3c: a garbage 200 (bad signature) does not erase the high-water mark", async () => {
  const keypair = generateKeyPairSync("ed25519");
  const current = makeSignedStatusList({ bitIndex: 5, bitValue: 1, credentialUrl: URL_A, keypair, validFrom: "2026-11-20T00:00:00Z" });
  const older = makeSignedStatusList({ bitIndex: 5, bitValue: 0, credentialUrl: URL_A, keypair, validFrom: "2026-01-01T00:00:00Z" });
  const storage = new InMemoryStatusCache(8);
  const o = (c: unknown) => ({ rootKey: current.rootKey, cacheConfig: cfg(storage), _testFetch: serve(c) });

  assert.equal((await verifyCredentialStatus(env(URL_A), o(current.credential))).state, "revoked");
  assert.equal((await verifyCredentialStatus(env(URL_A), o({ garbage: true }))).state, "list_signature_invalid");
  const replay = await verifyCredentialStatus(env(URL_A), o(older.credential));
  assert.equal(replay.state, "list_mismatch", "older list must still be rejected after a garbage fetch");
});

test("F3c: suspension verifier — garbage 200 does not erase the high-water mark", async () => {
  const keypair = generateKeyPairSync("ed25519");
  const mk = (vf: string, bit: 0 | 1) =>
    makeSignedStatusList({ bitIndex: 5, bitValue: bit, credentialUrl: URL_A, statusPurpose: "suspension", keypair, validFrom: vf });
  const current = mk("2026-11-20T00:00:00Z", 1);
  const older = mk("2026-01-01T00:00:00Z", 0);
  const e = env(URL_A);
  (e as unknown as { credentialStatus: null }).credentialStatus = null;
  (e as unknown as Record<string, unknown>).suspensionStatus = {
    id: `${URL_A}#5`, type: "StatusList2021Entry", statusPurpose: "suspension",
    statusListIndex: "5", statusListCredential: URL_A,
  };
  const storage = new InMemoryStatusCache(8);
  const o = (c: unknown) => ({ rootKey: current.rootKey, cacheConfig: cfg(storage), _testFetch: serve(c) });
  assert.equal((await verifySuspensionStatus(e, o(current.credential))).state, "suspended");
  assert.equal((await verifySuspensionStatus(e, o({ garbage: true }))).state, "list_signature_invalid");
  assert.equal((await verifySuspensionStatus(e, o(older.credential))).state, "list_mismatch");
});

test("F3b: suspension lists may legitimately clear a bit at equal validFrom (no revocation-stickiness)", async () => {
  const keypair = generateKeyPairSync("ed25519");
  const VF = "2026-11-01T00:00:00Z";
  const mk = (bit: 0 | 1) =>
    makeSignedStatusList({ bitIndex: 5, bitValue: bit, credentialUrl: URL_A, statusPurpose: "suspension", keypair, validFrom: VF });
  const e = env(URL_A);
  (e as unknown as { credentialStatus: null }).credentialStatus = null;
  (e as unknown as Record<string, unknown>).suspensionStatus = {
    id: `${URL_A}#5`, type: "StatusList2021Entry", statusPurpose: "suspension",
    statusListIndex: "5", statusListCredential: URL_A,
  };
  const storage = new InMemoryStatusCache(8);
  const s = mk(1), u = mk(0);
  const o = (c: unknown) => ({ rootKey: s.rootKey, cacheConfig: cfg(storage), _testFetch: serve(c) });
  assert.equal((await verifySuspensionStatus(e, o(s.credential))).state, "suspended");
  assert.equal((await verifySuspensionStatus(e, o(u.credential))).state, "not_suspended");
});

test("F3d: a signed but UNDECODABLE list never becomes the known set (cannot disable the equal-validFrom rollback check)", async () => {
  const keypair = generateKeyPairSync("ed25519");
  const VF = "2026-11-01T00:00:00Z";
  const pre = makeSignedStatusList({ bitIndex: 5, bitValue: 0, credentialUrl: URL_A, keypair, validFrom: VF });
  const post = makeSignedStatusList({ bitIndex: 5, bitValue: 1, credentialUrl: URL_A, keypair, validFrom: VF });
  const junk = makeSignedStatusList({ bitIndex: 5, bitValue: 0, credentialUrl: URL_A, keypair, validFrom: VF, encodedList: "AAAA-not-gzip" });
  const storage = new InMemoryStatusCache(8);
  const o = (c: unknown) => ({ rootKey: pre.rootKey, cacheConfig: cfg(storage), _testFetch: serve(c) });

  assert.equal((await verifyCredentialStatus(env(URL_A), o(post.credential))).state, "revoked");
  assert.equal((await verifyCredentialStatus(env(URL_A), o(junk.credential))).state, "list_mismatch");
  const replay = await verifyCredentialStatus(env(URL_A), o(pre.credential));
  assert.equal(replay.state, "list_mismatch", "pre-revocation replay must still be rejected");
  if (replay.state === "list_mismatch") assert.equal(replay.reason, "list_rollback");
});

test("F3d: a signed list with the wrong statusPurpose does not advance the high-water mark", async () => {
  const keypair = generateKeyPairSync("ed25519");
  const wrong = makeSignedStatusList({ bitIndex: 5, bitValue: 0, credentialUrl: URL_A, keypair, validFrom: "2026-12-31T00:00:00Z", statusPurpose: "suspension" });
  const genuine = makeSignedStatusList({ bitIndex: 5, bitValue: 1, credentialUrl: URL_A, keypair, validFrom: "2026-11-01T00:00:00Z" });
  const storage = new InMemoryStatusCache(8);
  const o = (c: unknown) => ({ rootKey: wrong.rootKey, cacheConfig: cfg(storage), _testFetch: serve(c) });
  assert.equal((await verifyCredentialStatus(env(URL_A), o(genuine.credential))).state, "revoked");
  assert.equal((await verifyCredentialStatus(env(URL_A), o(wrong.credential))).state, "list_mismatch");
  // had the wrong-purpose list advanced hw to 2026-12-31, the genuine list would now read as a rollback
  assert.equal((await verifyCredentialStatus(env(URL_A), o(genuine.credential))).state, "revoked");
});
