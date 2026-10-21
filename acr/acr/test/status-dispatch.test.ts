/**
 * Tests for ACR v=2 dispatch status-list integration (Phase D Task 19).
 *
 * Covers the reconciliation matrix surfaced via `status_state` on the
 * verifier result:
 *   - null pointer + rootKey → no_status_pointer
 *   - bit=0, no chain successor → active
 *   - bit=0, chain successor=yes → revoked_by_chain
 *   - bit=1, no chain successor → revoked + warnings:["status_chain_inconsistency"]
 *   - bit=1, chain successor=yes → revoked (no chain_inconsistency warning)
 *   - bad pointer (http://...) → invalid_pointer
 *   - rootKey not provided → not_attempted
 *
 * Status verification failures are advisory — `signature_valid` stays true
 * (the only signature-poison path on ACR is policy_fields_required).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { signEnvelope, base64UrlEncode } from "@dekimuhq/anchors-envelope";
import type { Envelope, CredentialStatus } from "@dekimuhq/anchors-envelope";
import { InMemoryStatusCache } from "@dekimuhq/anchors-envelope/status";
import type { RootKeyMaterial } from "@dekimuhq/anchors-envelope/status";
import { acrFamily } from "../src/family.ts";
import { makeSignedStatusList } from "../../../envelope/test/status/_make-signed-list.mts";

interface BuildOpts {
  credentialStatus?: CredentialStatus | null;
}

async function buildAcrEnvelope(
  opts: BuildOpts = {},
): Promise<{ envelope: Envelope; publicKey: Uint8Array }> {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const pkRaw = pkDer.subarray(-32);
  const issKey = `ed25519:${base64UrlEncode(new Uint8Array(pkRaw))}` as const;

  const unsigned: Envelope = {
    v: 2,
    id: "01HXX0000000000000000ACRSTAT",
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
    credentialStatus: opts.credentialStatus ?? null,
    anchor: null as unknown as Envelope["anchor"],
    sig: "",
    countersig: null,
    body: { lawful_basis: "6(1)(a)", purposes: ["test"] },
  };
  const signed = await signEnvelope(unsigned, privateKey);
  return { envelope: signed, publicKey: new Uint8Array(pkDer) };
}

/**
 * Build a pre-seeded cache + matching root key for a per-test signed list.
 * The fresh_until is far enough in the future that the fetcher never touches
 * the network.
 */
async function seedSignedList(args: {
  bitIndex: number;
  bitValue: 0 | 1;
  credentialUrl: string;
}): Promise<{ cache: InMemoryStatusCache; rootKey: RootKeyMaterial }> {
  const { credential, rootKey } = makeSignedStatusList({
    bitIndex: args.bitIndex,
    bitValue: args.bitValue,
    credentialUrl: args.credentialUrl,
  });
  const cache = new InMemoryStatusCache(8);
  await cache.set(args.credentialUrl, {
    fetched_at: Date.now(),
    fresh_until: Date.now() + 60 * 60 * 1000,
    body: credential,
  });
  return { cache, rootKey };
}

function makePointer(credentialUrl: string, index: number): CredentialStatus {
  return {
    id: `${credentialUrl}#${index}`,
    type: "StatusList2021Entry",
    statusPurpose: "revocation",
    statusListIndex: String(index),
    statusListCredential: credentialUrl,
  };
}

test("ACR v=2: credentialStatus null + rootKey → no_status_pointer", async () => {
  const { envelope, publicKey } = await buildAcrEnvelope();
  const { rootKey } = makeSignedStatusList({ bitIndex: 0, bitValue: 0 });
  const result = await acrFamily.verifyReceipt(envelope as unknown as Record<string, unknown>, {
    resolveKey: async () => publicKey,
    statusListRootKey: rootKey,
  });
  assert.equal(result.signature_valid, true);
  assert.equal(result.status_state, "no_status_pointer");
});

test("ACR v=2: bit=0, no chain successor → active", async () => {
  const url = "https://verify.dekimu.com/acr/v1/status/2026/05";
  const { cache, rootKey } = await seedSignedList({
    bitIndex: 7,
    bitValue: 0,
    credentialUrl: url,
  });
  const { envelope, publicKey } = await buildAcrEnvelope({
    credentialStatus: makePointer(url, 7),
  });
  const result = await acrFamily.verifyReceipt(envelope as unknown as Record<string, unknown>, {
    resolveKey: async () => publicKey,
    statusListRootKey: rootKey,
    statusCacheConfig: {
      freshTtlSec: 3600,
      staleTtlSec: 86400,
      storage: cache,
    },
  });
  assert.equal(result.signature_valid, true);
  assert.equal(result.status_state, "active");
  assert.equal(result.status_list_id, url);
});

test("ACR v=2: bit=0, chain successor=yes → revoked_by_chain", async () => {
  const url = "https://verify.dekimu.com/acr/v1/status/2026/05";
  const { cache, rootKey } = await seedSignedList({
    bitIndex: 12,
    bitValue: 0,
    credentialUrl: url,
  });
  const { envelope, publicKey } = await buildAcrEnvelope({
    credentialStatus: makePointer(url, 12),
  });
  const result = await acrFamily.verifyReceipt(envelope as unknown as Record<string, unknown>, {
    resolveKey: async () => publicKey,
    statusListRootKey: rootKey,
    statusCacheConfig: {
      freshTtlSec: 3600,
      staleTtlSec: 86400,
      storage: cache,
    },
    chainResolver: async () => true,
  });
  assert.equal(result.signature_valid, true);
  assert.equal(result.status_state, "revoked_by_chain");
  assert.equal(result.status_list_id, url);
});

test("ACR v=2: bit=1, no chain successor → revoked + status_chain_inconsistency warning", async () => {
  const url = "https://verify.dekimu.com/acr/v1/status/2026/05";
  const { cache, rootKey } = await seedSignedList({
    bitIndex: 33,
    bitValue: 1,
    credentialUrl: url,
  });
  const { envelope, publicKey } = await buildAcrEnvelope({
    credentialStatus: makePointer(url, 33),
  });
  const result = await acrFamily.verifyReceipt(envelope as unknown as Record<string, unknown>, {
    resolveKey: async () => publicKey,
    statusListRootKey: rootKey,
    statusCacheConfig: {
      freshTtlSec: 3600,
      staleTtlSec: 86400,
      storage: cache,
    },
  });
  assert.equal(result.signature_valid, true);
  assert.equal(result.status_state, "revoked");
  assert.ok(result.warnings?.includes("status_chain_inconsistency"));
});

test("ACR v=2: bit=1, chain successor=yes → revoked (no chain_inconsistency warning)", async () => {
  const url = "https://verify.dekimu.com/acr/v1/status/2026/05";
  const { cache, rootKey } = await seedSignedList({
    bitIndex: 55,
    bitValue: 1,
    credentialUrl: url,
  });
  const { envelope, publicKey } = await buildAcrEnvelope({
    credentialStatus: makePointer(url, 55),
  });
  const result = await acrFamily.verifyReceipt(envelope as unknown as Record<string, unknown>, {
    resolveKey: async () => publicKey,
    statusListRootKey: rootKey,
    statusCacheConfig: {
      freshTtlSec: 3600,
      staleTtlSec: 86400,
      storage: cache,
    },
    chainResolver: async () => true,
  });
  assert.equal(result.signature_valid, true);
  assert.equal(result.status_state, "revoked");
  assert.ok(!result.warnings?.includes("status_chain_inconsistency"));
});

test("ACR v=2: bad pointer (http:// not https://) → invalid_pointer", async () => {
  const cs: CredentialStatus = {
    id: "http://insecure.example/status#0",
    type: "StatusList2021Entry",
    statusPurpose: "revocation",
    statusListIndex: "0",
    statusListCredential: "http://insecure.example/status",
  };
  const { envelope, publicKey } = await buildAcrEnvelope({ credentialStatus: cs });
  const { rootKey } = makeSignedStatusList({ bitIndex: 0, bitValue: 0 });
  const result = await acrFamily.verifyReceipt(envelope as unknown as Record<string, unknown>, {
    resolveKey: async () => publicKey,
    statusListRootKey: rootKey,
  });
  assert.equal(result.signature_valid, true);
  assert.equal(result.status_state, "invalid_pointer");
});

test("ACR v=2: rootKey not provided → not_attempted", async () => {
  const url = "https://verify.dekimu.com/acr/v1/status/2026/05";
  const { envelope, publicKey } = await buildAcrEnvelope({
    credentialStatus: makePointer(url, 1),
  });
  const result = await acrFamily.verifyReceipt(envelope as unknown as Record<string, unknown>, {
    resolveKey: async () => publicKey,
  });
  assert.equal(result.signature_valid, true);
  assert.equal(result.status_state, "not_attempted");
});
