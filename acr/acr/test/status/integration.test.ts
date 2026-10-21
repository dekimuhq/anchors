/**
 * Status List integration tests for @dekimuhq/acr-verifier — Phase D Task 19.
 *
 * Tests the full status reconciliation path wired into verifyV2:
 *   active, active_stale, revoked, revoked_by_chain, unreachable,
 *   status_chain_inconsistency warning, and no-root-key (not_attempted).
 *
 * All status list credentials are minted inline — no dependency on committed
 * JSON fixture files. The `_testFetch` seam in `fetchStatusListCredential`
 * is threaded through via `ReconcileOpts._testFetch` and forwarded to
 * `verifyCredentialStatus` via the `EnvelopeVerifyOptions.statusListRootKey`
 * path (test-only: the verifier calls `verifyCredentialStatus` which calls
 * `fetchStatusListCredential` internally — we can't inject _testFetch
 * through the verifier options. Instead: we pre-warm the cache for stale/fresh
 * tests, or use a real mock server approach with a local HTTP mock).
 *
 * Practical approach: use `InMemoryStatusCache` pre-seeded with a fresh entry
 * to simulate a cache hit (avoiding real HTTP in tests). This is the pattern
 * used in Task 18 tests.
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
import { acrFamily } from "../../src/family.ts";
import { canonicalize as jcsCanonicalizeRaw } from "@dekimuhq/anchors-envelope";

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Mint a fresh Ed25519 keypair + derive RootKeyMaterial for use as a status list signing key. */
function mintStatusKey(): {
  privateKey: crypto.KeyObject;
  rootKey: RootKeyMaterial;
} {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const kid = "did:web:verify.example#root";
  return {
    privateKey,
    rootKey: {
      kid,
      publicKeyDer: base64UrlEncode(new Uint8Array(pkDer)),
    },
  };
}

/**
 * Mint a signed Status List 2021 Credential with a given bitstring.
 * All bits 0 = active; flip individual bits before calling to test revocation.
 */
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

/** Build a pre-seeded InMemoryStatusCache with a fresh status list entry. */
async function buildFreshCache(
  bits: Uint8Array,
  privateKey: crypto.KeyObject,
  kid: string,
  statusListUrl: string,
  nowOverride?: number,
): Promise<InMemoryStatusCache> {
  const now = nowOverride ?? Date.now();
  const credential = mintStatusListCredential(bits, privateKey, kid, statusListUrl);
  const entry: StatusListEntry = {
    fetched_at: now,
    fresh_until: now + 3600 * 1000, // 1 hour fresh
    body: credential,
  };
  const cache = new InMemoryStatusCache(64);
  await cache.set(statusListUrl, entry);
  return cache;
}

/** Build a stale cache entry: fetched 2h ago, freshUntil 1h ago, staleTtl 24h. */
async function buildStaleCache(
  bits: Uint8Array,
  privateKey: crypto.KeyObject,
  kid: string,
  statusListUrl: string,
): Promise<{ cache: InMemoryStatusCache; cachedAgeSec: number }> {
  const now = Date.now();
  const fetchedAt = now - 2 * 3600 * 1000; // 2h ago
  const freshUntil = now - 3600 * 1000; // 1h ago (expired)
  const credential = mintStatusListCredential(bits, privateKey, kid, statusListUrl);
  const entry: StatusListEntry = {
    fetched_at: fetchedAt,
    fresh_until: freshUntil,
    body: credential,
  };
  const cache = new InMemoryStatusCache(64);
  await cache.set(statusListUrl, entry);
  return {
    cache,
    cachedAgeSec: Math.floor((now - fetchedAt) / 1000),
  };
}

/** Build a signed v=2 ACR consent envelope with a credentialStatus pointer. */
async function buildEnvelope(
  credentialStatusUrl: string,
  statusListIndex: string,
): Promise<{ envelope: Envelope; publicKeyDer: Uint8Array }> {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const pkRaw = pkDer.subarray(-32);
  const issKey = `ed25519:${base64UrlEncode(new Uint8Array(pkRaw))}` as const;

  const unsigned: Envelope = {
    v: 2,
    id: "01HXX0000000000000000ACRSTS1",
    claim_type: "ar.consent.v1",
    iss: "did:web:bank.example",
    iss_key: issKey,
    subject: "sha256:" + "a".repeat(64),
    iat: "2026-05-17T00:00:00Z",
    exp: null,
    prev: null,
    policy_uri: "https://bank.example/policy",
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
    body: { lawful_basis: "6(1)(a)", purposes: ["test"] },
  };

  const signed = await signEnvelope(unsigned, privateKey);
  return { envelope: signed, publicKeyDer: new Uint8Array(pkDer) };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

const STATUS_LIST_URL = "https://verify.example/acr/v1/status/2026/05";
const INDEX = "0"; // bit position 0

test("status integration: active — bit=0 on fresh list", async () => {
  const { privateKey, rootKey } = mintStatusKey();
  // All-zero bitstring → bit 0 = 0 → active
  const bits = new Uint8Array(131072 / 8);
  const cache = await buildFreshCache(bits, privateKey, rootKey.kid, STATUS_LIST_URL);
  const { envelope, publicKeyDer } = await buildEnvelope(STATUS_LIST_URL, INDEX);

  const result = await acrFamily.verifyReceipt(envelope as unknown as Record<string, unknown>, {
    resolveKey: async () => publicKeyDer,
    statusListRootKey: rootKey,
    statusCacheConfig: {
      freshTtlSec: 3600,
      staleTtlSec: 86400,
      storage: cache,
    },
  });

  assert.equal(result.signature_valid, true);
  assert.equal(result.status_state, "active");
  assert.ok(result.status_fresh_until !== undefined);
  assert.equal(result.status_list_id, STATUS_LIST_URL);
});

test("status integration: revoked — bit=1 on fresh list + no chain successor", async () => {
  const { privateKey, rootKey } = mintStatusKey();
  // Set bit 0 to 1 → revoked
  const bits = new Uint8Array(131072 / 8);
  bits[0] = 0x80; // MSB of byte 0 = bit index 0
  const cache = await buildFreshCache(bits, privateKey, rootKey.kid, STATUS_LIST_URL);
  const { envelope, publicKeyDer } = await buildEnvelope(STATUS_LIST_URL, INDEX);

  const result = await acrFamily.verifyReceipt(envelope as unknown as Record<string, unknown>, {
    resolveKey: async () => publicKeyDer,
    statusListRootKey: rootKey,
    statusCacheConfig: {
      freshTtlSec: 3600,
      staleTtlSec: 86400,
      storage: cache,
    },
    chainResolver: async () => false,
  });

  assert.equal(result.signature_valid, true);
  assert.equal(result.status_state, "revoked");
  // No chain successor: status_chain_inconsistency warning expected
  assert.ok(result.warnings?.includes("status_chain_inconsistency"), `expected status_chain_inconsistency in warnings, got: ${JSON.stringify(result.warnings)}`);
});

test("status integration: revoked_by_chain — chain successor exists but bit=0 (list stale)", async () => {
  const { privateKey, rootKey } = mintStatusKey();
  // All-zero bitstring → bit 0 = 0, but chain says withdrawn → revoked_by_chain
  const bits = new Uint8Array(131072 / 8);
  const { cache, cachedAgeSec } = await buildStaleCache(bits, privateKey, rootKey.kid, STATUS_LIST_URL);
  const { envelope, publicKeyDer } = await buildEnvelope(STATUS_LIST_URL, INDEX);

  const result = await acrFamily.verifyReceipt(envelope as unknown as Record<string, unknown>, {
    resolveKey: async () => publicKeyDer,
    statusListRootKey: rootKey,
    statusCacheConfig: {
      freshTtlSec: 3600,
      staleTtlSec: 86400,
      storage: cache,
    },
    chainResolver: async () => true, // chain says revoked
  });

  assert.equal(result.signature_valid, true);
  assert.equal(result.status_state, "revoked_by_chain");
  assert.ok(result.warnings?.includes("status_stale"), `expected status_stale in warnings, got: ${JSON.stringify(result.warnings)}`);
  assert.ok((result.status_cached_age_sec ?? 0) >= cachedAgeSec - 2, "expected cached_age_sec to be approximately correct");
});

test("status integration: active_stale — bit=0 on stale list, no chain", async () => {
  const { privateKey, rootKey } = mintStatusKey();
  const bits = new Uint8Array(131072 / 8);
  const { cache } = await buildStaleCache(bits, privateKey, rootKey.kid, STATUS_LIST_URL);
  const { envelope, publicKeyDer } = await buildEnvelope(STATUS_LIST_URL, INDEX);

  const result = await acrFamily.verifyReceipt(envelope as unknown as Record<string, unknown>, {
    resolveKey: async () => publicKeyDer,
    statusListRootKey: rootKey,
    statusCacheConfig: {
      freshTtlSec: 3600,
      staleTtlSec: 86400,
      storage: cache,
    },
    chainResolver: async () => false,
  });

  assert.equal(result.signature_valid, true);
  assert.equal(result.status_state, "active_stale");
  assert.ok(result.warnings?.includes("status_stale"), `expected status_stale, got: ${JSON.stringify(result.warnings)}`);
  assert.ok(result.status_cached_age_sec !== undefined);
});

test("status integration: unreachable — fetch fails, no cache", async () => {
  const { rootKey } = mintStatusKey();
  const { envelope, publicKeyDer } = await buildEnvelope(STATUS_LIST_URL, INDEX);

  // Empty cache + always-fail fetch → unreachable
  const emptyCache = new InMemoryStatusCache(64);

  const result = await acrFamily.verifyReceipt(envelope as unknown as Record<string, unknown>, {
    resolveKey: async () => publicKeyDer,
    statusListRootKey: rootKey,
    statusCacheConfig: {
      freshTtlSec: 3600,
      staleTtlSec: 86400,
      storage: emptyCache,
    },
    // No _testFetch — real fetch will fail since the URL is not a real server.
    // We rely on the fetch throwing and the stale window being empty.
  });

  assert.equal(result.signature_valid, true);
  assert.equal(result.status_state, "unreachable");
});

test("status integration: not_attempted — no statusListRootKey provided", async () => {
  const { envelope, publicKeyDer } = await buildEnvelope(STATUS_LIST_URL, INDEX);

  const result = await acrFamily.verifyReceipt(envelope as unknown as Record<string, unknown>, {
    resolveKey: async () => publicKeyDer,
    // No statusListRootKey — reconciliation skipped
  });

  assert.equal(result.signature_valid, true);
  assert.equal(result.status_state, "not_attempted");
});

// ── I2 e2e: tampered list body → list_signature_invalid surfaces through verifyV2 ──
//
// Tamper-coverage exists at the sig-helper unit level
// (envelope/test/status/verify-list-sig.test.ts). This test proves the full
// path: tampered list in cache → verifyCredentialStatus returns
// `list_signature_invalid` → verifier surfaces `status_state: "list_signature_invalid"`.

test("status integration: tampered list body → status_state list_signature_invalid", async () => {
  const { privateKey, rootKey } = mintStatusKey();
  // Build a valid signed list (bit 0 = active).
  const bits = new Uint8Array(131072 / 8);
  const credential = mintStatusListCredential(bits, privateKey, rootKey.kid, STATUS_LIST_URL) as {
    credentialSubject: { encodedList: string };
    [k: string]: unknown;
  };

  // Tamper: flip the encodedList to a different (valid base64url) value.
  // The signature now no longer matches.
  const tampered = {
    ...credential,
    credentialSubject: {
      ...credential.credentialSubject,
      encodedList: "AAAA", // valid base64url, clearly different from the signed bitstring
    },
  };

  const now = Date.now();
  const cache = new InMemoryStatusCache(64);
  await cache.set(STATUS_LIST_URL, {
    fetched_at: now,
    fresh_until: now + 3600 * 1000,
    body: tampered,
  });

  const { envelope, publicKeyDer } = await buildEnvelope(STATUS_LIST_URL, INDEX);
  const result = await acrFamily.verifyReceipt(envelope as unknown as Record<string, unknown>, {
    resolveKey: async () => publicKeyDer,
    statusListRootKey: rootKey,
    statusCacheConfig: {
      freshTtlSec: 3600,
      staleTtlSec: 86400,
      storage: cache,
    },
  });

  assert.equal(result.signature_valid, true);
  assert.equal(result.status_state, "list_signature_invalid");
});

test("status integration: no_status_pointer — envelope has null credentialStatus", async () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const pkRaw = pkDer.subarray(-32);
  const issKey = `ed25519:${base64UrlEncode(new Uint8Array(pkRaw))}` as const;
  const { rootKey } = mintStatusKey();

  const unsigned: Envelope = {
    v: 2,
    id: "01HXX0000000000000000ACRNULL",
    claim_type: "ar.consent.v1",
    iss: "did:web:bank.example",
    iss_key: issKey,
    subject: "sha256:" + "a".repeat(64),
    iat: "2026-05-17T00:00:00Z",
    exp: null,
    prev: null,
    policy_uri: "https://bank.example/policy",
    policy_hash: "sha256:" + "b".repeat(64),
    policy_version: "1.0.0",
    tsa: null,
    credentialStatus: null, // ← null pointer
    anchor: null as unknown as Envelope["anchor"],
    sig: "",
    countersig: null,
    body: { lawful_basis: "6(1)(a)", purposes: ["test"] },
  };

  const signed = await signEnvelope(unsigned, privateKey);
  const result = await acrFamily.verifyReceipt(signed as unknown as Record<string, unknown>, {
    resolveKey: async () => new Uint8Array(pkDer),
    statusListRootKey: rootKey,
  });

  assert.equal(result.signature_valid, true);
  assert.equal(result.status_state, "no_status_pointer");
});
