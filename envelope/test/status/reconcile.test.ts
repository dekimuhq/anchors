/**
 * Smoke tests for `verifyCredentialStatus` — Phase D Task 19.
 *
 * Covers:
 *   - `no_status_pointer` when envelope.credentialStatus is null.
 *   - `not_attempted` when rootKey is omitted.
 *   - `invalid_pointer` when the pointer fails T15 validation.
 *   - happy-path `active` reconciliation against a pre-seeded fresh cache.
 *
 * The pre-seed avoids any real fetch; helper builds a per-test signed list.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyCredentialStatus } from "../../src/status/reconcile.ts";
import { InMemoryStatusCache } from "../../src/status/cache.ts";
import type { Envelope } from "../../src/envelope-types.ts";
import { makeSignedStatusList } from "./_make-signed-list.mts";

function baseEnvelope(): Envelope {
  return {
    v: 2,
    id: "01HXX0000000000000000RECONS1",
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
    credentialStatus: null,
    anchor: null as unknown as Envelope["anchor"],
    sig: "sig-placeholder",
    countersig: null,
    body: { lawful_basis: "6(1)(a)", purposes: ["test"] },
  };
}

test("reconcile: no credentialStatus → no_status_pointer", async () => {
  const env = baseEnvelope();
  const { rootKey } = makeSignedStatusList({ bitIndex: 0, bitValue: 0 });
  const r = await verifyCredentialStatus(env, { rootKey });
  assert.equal(r.state, "no_status_pointer");
});

test("reconcile: rootKey omitted → not_attempted", async () => {
  const env = baseEnvelope();
  env.credentialStatus = {
    id: "https://verify.dekimu.com/test/status/2026/05#42",
    type: "StatusList2021Entry",
    statusPurpose: "revocation",
    statusListIndex: "42",
    statusListCredential: "https://verify.dekimu.com/test/status/2026/05",
  };
  const r = await verifyCredentialStatus(env, {} as never);
  assert.equal(r.state, "not_attempted");
});

test("reconcile: malformed pointer (non-https URL) → invalid_pointer", async () => {
  const env = baseEnvelope();
  env.credentialStatus = {
    id: "x",
    type: "StatusList2021Entry",
    statusPurpose: "revocation",
    statusListIndex: "0",
    statusListCredential: "http://insecure.example/list",
  };
  const { rootKey } = makeSignedStatusList({ bitIndex: 0, bitValue: 0 });
  const r = await verifyCredentialStatus(env, { rootKey });
  assert.equal(r.state, "invalid_pointer");
  if (r.state === "invalid_pointer") {
    assert.equal(r.reason, "invalid_status_list_credential");
  }
});

test("reconcile: stale cache, bit=1, no chain successor → revoked_stale with both status_stale and status_chain_inconsistency warnings", async () => {
  const credentialUrl = "https://verify.dekimu.com/test/status/2026/05";
  const { credential, rootKey } = makeSignedStatusList({
    bitIndex: 42,
    bitValue: 1,
    credentialUrl,
  });

  const env = baseEnvelope();
  env.credentialStatus = {
    id: `${credentialUrl}#42`,
    type: "StatusList2021Entry",
    statusPurpose: "revocation",
    statusListIndex: "42",
    statusListCredential: credentialUrl,
  };

  // Pre-seed with an entry that is expired (past freshTtl) but still inside
  // staleTtl. The injected fetch throws, so fetchStatusListCredential returns
  // `state: "stale"` with a cached_age_sec ≥ freshTtlSec.
  const cache = new InMemoryStatusCache(8);
  const oldFetched = Date.now() - 7200_000;
  await cache.set(credentialUrl, {
    fetched_at: oldFetched,
    fresh_until: oldFetched + 3600_000,
    body: credential,
  });

  const r = await verifyCredentialStatus(env, {
    rootKey,
    cacheConfig: {
      freshTtlSec: 3600,
      staleTtlSec: 86400,
      storage: cache,
    },
    // chainSuccessorExists omitted → defaults to async () => false.
    _testFetch: async () => {
      throw new Error("net");
    },
  });

  assert.equal(r.state, "revoked_stale");
  if (r.state === "revoked_stale") {
    assert.equal(r.status_list_id, credentialUrl);
    assert.ok(r.cached_age_sec >= 3600);
    assert.ok(r.warnings.includes("status_stale"));
    assert.ok(r.warnings.includes("status_chain_inconsistency"));
    // Invariant: status_stale is first.
    assert.equal(r.warnings[0], "status_stale");
  }
});

test("reconcile: pre-seeded fresh cache, bit=0, no chain → active", async () => {
  const credentialUrl = "https://verify.dekimu.com/test/status/2026/05";
  const { credential, rootKey } = makeSignedStatusList({
    bitIndex: 7,
    bitValue: 0,
    credentialUrl,
  });

  const env = baseEnvelope();
  env.credentialStatus = {
    id: `${credentialUrl}#7`,
    type: "StatusList2021Entry",
    statusPurpose: "revocation",
    statusListIndex: "7",
    statusListCredential: credentialUrl,
  };

  // Pre-seed the cache as far-in-the-future fresh so no HTTP is attempted.
  const cache = new InMemoryStatusCache(8);
  await cache.set(credentialUrl, {
    fetched_at: Date.now(),
    fresh_until: Date.now() + 60 * 60 * 1000,
    body: credential,
  });

  const r = await verifyCredentialStatus(env, {
    rootKey,
    cacheConfig: {
      freshTtlSec: 3600,
      staleTtlSec: 86400,
      storage: cache,
    },
  });
  assert.equal(r.state, "active");
  if (r.state === "active") {
    assert.equal(r.status_list_id, credentialUrl);
    assert.ok(r.fresh_until > Date.now());
  }
});

test("reconcile: oversized statusListIndex (> bitstring length) → list_mismatch with statusListIndex_out_of_range", async () => {
  const credentialUrl = "https://verify.dekimu.com/test/status/oversized";
  const { credential, rootKey } = makeSignedStatusList({
    bitIndex: 0,
    bitValue: 0,
    credentialUrl,
  });

  const env = baseEnvelope();
  env.credentialStatus = {
    id: `${credentialUrl}#big`,
    type: "StatusList2021Entry",
    statusPurpose: "revocation",
    // 2^40 — passes /^\d+$/ regex but would alias under uint32 truncation
    // inside readBitAt (`index >>> 3`) to a small in-range index without the
    // pre-guard. The guard must reject before readBitAt is called.
    statusListIndex: "1099511627776",
    statusListCredential: credentialUrl,
  };

  const cache = new InMemoryStatusCache(8);
  await cache.set(credentialUrl, {
    fetched_at: Date.now(),
    fresh_until: Date.now() + 60 * 60 * 1000,
    body: credential,
  });

  const r = await verifyCredentialStatus(env, {
    rootKey,
    cacheConfig: {
      freshTtlSec: 3600,
      staleTtlSec: 86400,
      storage: cache,
    },
  });
  assert.equal(r.state, "list_mismatch");
  if (r.state === "list_mismatch") {
    assert.equal(r.reason, "statusListIndex_out_of_range");
  }
});
