/**
 * Status List integration tests for @dekimuhq/arr — Phase D Task 19.
 *
 * Covers: active, revoked, revoked_by_chain (stale), active_stale,
 * unreachable, not_attempted, no_status_pointer.
 *
 * The `_testFetch` injection cannot be threaded through `EnvelopeVerifyOptions`
 * directly — status list HTTP mocking is done via pre-seeded InMemoryStatusCache.
 * For the `unreachable` case, an empty cache + no real server → unreachable.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { signEnvelope, base64UrlEncode, base64UrlDecode } from "@dekimuhq/anchors-envelope";
import type { Envelope } from "@dekimuhq/anchors-envelope";
import {
  InMemoryStatusCache,
  encodedListFromBitstring,
} from "@dekimuhq/anchors-envelope/status";
import type { StatusListEntry, RootKeyMaterial } from "@dekimuhq/anchors-envelope/status";
import { arrFamily } from "../../src/family.ts";
import { canonicalize as jcsCanonicalizeRaw } from "@dekimuhq/anchors-envelope";

// ── Helpers ──────────────────────────────────────────────────────────────────

function mintStatusKey(): {
  privateKey: crypto.KeyObject;
  rootKey: RootKeyMaterial;
} {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const kid = "did:web:verify.example#root";
  return {
    privateKey,
    rootKey: { kid, publicKeyDer: base64UrlEncode(new Uint8Array(pkDer)) },
  };
}

function mintStatusListCredential(
  bits: Uint8Array,
  privateKey: crypto.KeyObject,
  kid: string,
  statusListUrl: string,
): unknown {
  const encodedList = encodedListFromBitstring(bits);
  const unsigned = {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://w3id.org/vc/status-list/2021/v1",
    ],
    id: statusListUrl,
    type: ["VerifiableCredential", "StatusList2021Credential"],
    issuer: "did:web:verify.example",
    validFrom: "2026-05-17T00:00:00Z",
    credentialSubject: {
      id: `${statusListUrl}#list`,
      type: "StatusList2021",
      statusPurpose: "revocation",
      encodedList,
    },
  };
  const canonical = jcsCanonicalizeRaw(unsigned);
  const sigBytes = crypto.sign(null, Buffer.from(canonical, "utf8"), privateKey);
  return {
    ...unsigned,
    proof: {
      type: "Ed25519Signature2020",
      created: "2026-05-17T00:00:00Z",
      verificationMethod: kid,
      proofPurpose: "assertionMethod",
      proofValue: base64UrlEncode(new Uint8Array(sigBytes)),
    },
  };
}

async function buildFreshCache(
  bits: Uint8Array,
  privateKey: crypto.KeyObject,
  kid: string,
  statusListUrl: string,
): Promise<InMemoryStatusCache> {
  const now = Date.now();
  const credential = mintStatusListCredential(bits, privateKey, kid, statusListUrl);
  const entry: StatusListEntry = {
    fetched_at: now,
    fresh_until: now + 3600 * 1000,
    body: credential,
  };
  const cache = new InMemoryStatusCache(64);
  await cache.set(statusListUrl, entry);
  return cache;
}

async function buildStaleCache(
  bits: Uint8Array,
  privateKey: crypto.KeyObject,
  kid: string,
  statusListUrl: string,
): Promise<{ cache: InMemoryStatusCache; cachedAgeSec: number }> {
  const now = Date.now();
  const fetchedAt = now - 2 * 3600 * 1000;
  const freshUntil = now - 3600 * 1000;
  const credential = mintStatusListCredential(bits, privateKey, kid, statusListUrl);
  const entry: StatusListEntry = {
    fetched_at: fetchedAt,
    fresh_until: freshUntil,
    body: credential,
  };
  const cache = new InMemoryStatusCache(64);
  await cache.set(statusListUrl, entry);
  return { cache, cachedAgeSec: Math.floor((now - fetchedAt) / 1000) };
}

async function buildArrEnvelope(
  credentialStatusUrl: string,
  statusListIndex: string,
): Promise<{ envelope: Envelope; publicKeyDer: Uint8Array }> {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const pkRaw = pkDer.subarray(-32);
  const issKey = `ed25519:${base64UrlEncode(new Uint8Array(pkRaw))}` as const;

  const unsigned: Envelope = {
    v: 2,
    id: "01HXX0000000000000000ARRSTS1",
    claim_type: "ar.erasure.v1",
    iss: "did:web:processor.example",
    iss_key: issKey,
    subject: "sha256:" + "a".repeat(64),
    iat: "2026-05-17T00:00:00Z",
    exp: null,
    prev: null,
    policy_uri: "https://processor.example/policy",
    policy_hash: "sha256:" + "b".repeat(64),
    policy_version: "1.0.0",
    tsa: null,
    credentialStatus: {
      id: `${credentialStatusUrl}#0`,
      type: "StatusList2021Entry",
      statusPurpose: "revocation",
      statusListIndex,
      statusListCredential: credentialStatusUrl,
    },
    anchor: null as unknown as Envelope["anchor"],
    sig: "",
    countersig: null,
    body: { erasure_target: "sha256:" + "c".repeat(64) },
  };

  const signed = await signEnvelope(unsigned, privateKey);
  return { envelope: signed, publicKeyDer: new Uint8Array(pkDer) };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

const STATUS_LIST_URL = "https://verify.example/arr/v1/status/2026/05";
const INDEX = "0";

test("ARR status: active — bit=0 on fresh list", async () => {
  const { privateKey, rootKey } = mintStatusKey();
  const bits = new Uint8Array(131072 / 8);
  const cache = await buildFreshCache(bits, privateKey, rootKey.kid, STATUS_LIST_URL);
  const { envelope, publicKeyDer } = await buildArrEnvelope(STATUS_LIST_URL, INDEX);

  const result = await arrFamily.verifyReceipt(envelope as unknown as Record<string, unknown>, {
    resolveKey: async () => publicKeyDer,
    statusListRootKey: rootKey,
    statusCacheConfig: { freshTtlSec: 3600, staleTtlSec: 86400, storage: cache },
  });

  assert.equal(result.signature_valid, true);
  assert.equal(result.status_state, "active");
  assert.equal(result.status_list_id, STATUS_LIST_URL);
});

test("ARR status: revoked — bit=1 on fresh list + no chain successor", async () => {
  const { privateKey, rootKey } = mintStatusKey();
  const bits = new Uint8Array(131072 / 8);
  bits[0] = 0x80; // bit 0 = 1
  const cache = await buildFreshCache(bits, privateKey, rootKey.kid, STATUS_LIST_URL);
  const { envelope, publicKeyDer } = await buildArrEnvelope(STATUS_LIST_URL, INDEX);

  const result = await arrFamily.verifyReceipt(envelope as unknown as Record<string, unknown>, {
    resolveKey: async () => publicKeyDer,
    statusListRootKey: rootKey,
    statusCacheConfig: { freshTtlSec: 3600, staleTtlSec: 86400, storage: cache },
    chainResolver: async () => false,
  });

  assert.equal(result.signature_valid, true);
  assert.equal(result.status_state, "revoked");
  assert.ok(result.warnings?.includes("status_chain_inconsistency"));
});

test("ARR status: revoked_by_chain — chain successor exists, bit=0, stale list", async () => {
  const { privateKey, rootKey } = mintStatusKey();
  const bits = new Uint8Array(131072 / 8); // bit 0 = 0
  const { cache, cachedAgeSec } = await buildStaleCache(bits, privateKey, rootKey.kid, STATUS_LIST_URL);
  const { envelope, publicKeyDer } = await buildArrEnvelope(STATUS_LIST_URL, INDEX);

  const result = await arrFamily.verifyReceipt(envelope as unknown as Record<string, unknown>, {
    resolveKey: async () => publicKeyDer,
    statusListRootKey: rootKey,
    statusCacheConfig: { freshTtlSec: 3600, staleTtlSec: 86400, storage: cache },
    chainResolver: async () => true,
  });

  assert.equal(result.signature_valid, true);
  assert.equal(result.status_state, "revoked_by_chain");
  assert.ok(result.warnings?.includes("status_stale"));
  assert.ok((result.status_cached_age_sec ?? 0) >= cachedAgeSec - 2);
});

test("ARR status: active_stale — bit=0 on stale list, no chain", async () => {
  const { privateKey, rootKey } = mintStatusKey();
  const bits = new Uint8Array(131072 / 8);
  const { cache } = await buildStaleCache(bits, privateKey, rootKey.kid, STATUS_LIST_URL);
  const { envelope, publicKeyDer } = await buildArrEnvelope(STATUS_LIST_URL, INDEX);

  const result = await arrFamily.verifyReceipt(envelope as unknown as Record<string, unknown>, {
    resolveKey: async () => publicKeyDer,
    statusListRootKey: rootKey,
    statusCacheConfig: { freshTtlSec: 3600, staleTtlSec: 86400, storage: cache },
    chainResolver: async () => false,
  });

  assert.equal(result.signature_valid, true);
  assert.equal(result.status_state, "active_stale");
  assert.ok(result.warnings?.includes("status_stale"));
  assert.ok(result.status_cached_age_sec !== undefined);
});

test("ARR status: unreachable — fetch fails, no cache", async () => {
  const { rootKey } = mintStatusKey();
  const { envelope, publicKeyDer } = await buildArrEnvelope(STATUS_LIST_URL, INDEX);
  const emptyCache = new InMemoryStatusCache(64);

  const result = await arrFamily.verifyReceipt(envelope as unknown as Record<string, unknown>, {
    resolveKey: async () => publicKeyDer,
    statusListRootKey: rootKey,
    statusCacheConfig: { freshTtlSec: 3600, staleTtlSec: 86400, storage: emptyCache },
  });

  assert.equal(result.signature_valid, true);
  assert.equal(result.status_state, "unreachable");
});

test("ARR status: not_attempted — no statusListRootKey", async () => {
  const { envelope, publicKeyDer } = await buildArrEnvelope(STATUS_LIST_URL, INDEX);

  const result = await arrFamily.verifyReceipt(envelope as unknown as Record<string, unknown>, {
    resolveKey: async () => publicKeyDer,
  });

  assert.equal(result.signature_valid, true);
  assert.equal(result.status_state, "not_attempted");
});

test("ARR status: no_status_pointer — null credentialStatus with rootKey", async () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const pkRaw = pkDer.subarray(-32);
  const issKey = `ed25519:${base64UrlEncode(new Uint8Array(pkRaw))}` as const;
  const { rootKey } = mintStatusKey();

  const unsigned: Envelope = {
    v: 2,
    id: "01HXX0000000000000000ARRNULL",
    claim_type: "ar.erasure.v1",
    iss: "did:web:processor.example",
    iss_key: issKey,
    subject: "sha256:" + "a".repeat(64),
    iat: "2026-05-17T00:00:00Z",
    exp: null,
    prev: null,
    policy_uri: "https://processor.example/policy",
    policy_hash: "sha256:" + "b".repeat(64),
    policy_version: "1.0.0",
    tsa: null,
    credentialStatus: null,
    anchor: null as unknown as Envelope["anchor"],
    sig: "",
    countersig: null,
    body: { erasure_target: "sha256:" + "c".repeat(64) },
  };

  const signed = await signEnvelope(unsigned, privateKey);

  const result = await arrFamily.verifyReceipt(signed as unknown as Record<string, unknown>, {
    resolveKey: async () => new Uint8Array(pkDer),
    statusListRootKey: rootKey,
  });

  assert.equal(result.signature_valid, true);
  assert.equal(result.status_state, "no_status_pointer");
});
