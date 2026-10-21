/**
 * Tests for ARR v=2 dispatch status-list integration (Phase D Task 19).
 *
 * Mirrors the ACR status-dispatch suite, using an `ar.erasure.v1` body
 * instead of `ar.consent.v1`. ARR claim types in scope here are POLICY_BOUND;
 * the policy + signature gates already pass before status reconciliation runs.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { signEnvelope, base64UrlEncode } from "@dekimuhq/anchors-envelope";
import type { Envelope, CredentialStatus } from "@dekimuhq/anchors-envelope";
import { InMemoryStatusCache } from "@dekimuhq/anchors-envelope/status";
import type { RootKeyMaterial } from "@dekimuhq/anchors-envelope/status";
import { arrFamily } from "../src/family.ts";
import { makeSignedStatusList } from "../../../envelope/test/status/_make-signed-list.mts";

async function buildArrEnvelope(opts: {
  credentialStatus?: CredentialStatus | null;
} = {}): Promise<{ envelope: Envelope; publicKey: Uint8Array }> {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const pkRaw = pkDer.subarray(-32);
  const issKey = `ed25519:${base64UrlEncode(new Uint8Array(pkRaw))}` as const;
  const unsigned: Envelope = {
    v: 2,
    id: "01HXX0000000000000000ARRSTAT",
    claim_type: "ar.erasure.v1",
    iss: "did:web:bank.example",
    iss_key: issKey,
    subject: "sha256:" + "a".repeat(64),
    iat: "2026-05-17T00:00:00Z",
    exp: null,
    prev: null,
    policy_uri: "https://bank.example/policy",
    policy_hash: "sha256:" + "c".repeat(64),
    policy_version: "1.0.0",
    tsa: null,
    credentialStatus: opts.credentialStatus ?? null,
    anchor: null as unknown as Envelope["anchor"],
    sig: "",
    countersig: null,
    body: { rights: ["art_17"], lawful_basis_termination: "withdrawal" },
  };
  const signed = await signEnvelope(unsigned, privateKey);
  return { envelope: signed, publicKey: new Uint8Array(pkDer) };
}

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

test("ARR v=2: credentialStatus null + rootKey → no_status_pointer", async () => {
  const { envelope, publicKey } = await buildArrEnvelope();
  const { rootKey } = makeSignedStatusList({ bitIndex: 0, bitValue: 0 });
  const r = await arrFamily.verifyReceipt(envelope as unknown as Record<string, unknown>, {
    resolveKey: async () => publicKey,
    statusListRootKey: rootKey,
  });
  assert.equal(r.signature_valid, true);
  assert.equal(r.status_state, "no_status_pointer");
});

test("ARR v=2: bit=0, no chain successor → active", async () => {
  const url = "https://verify.dekimu.com/arr/v1/status/2026/05";
  const { cache, rootKey } = await seedSignedList({
    bitIndex: 9,
    bitValue: 0,
    credentialUrl: url,
  });
  const { envelope, publicKey } = await buildArrEnvelope({
    credentialStatus: makePointer(url, 9),
  });
  const r = await arrFamily.verifyReceipt(envelope as unknown as Record<string, unknown>, {
    resolveKey: async () => publicKey,
    statusListRootKey: rootKey,
    statusCacheConfig: { freshTtlSec: 3600, staleTtlSec: 86400, storage: cache },
  });
  assert.equal(r.signature_valid, true);
  assert.equal(r.status_state, "active");
  assert.equal(r.status_list_id, url);
});

test("ARR v=2: bit=0, chain successor=yes → revoked_by_chain", async () => {
  const url = "https://verify.dekimu.com/arr/v1/status/2026/05";
  const { cache, rootKey } = await seedSignedList({
    bitIndex: 20,
    bitValue: 0,
    credentialUrl: url,
  });
  const { envelope, publicKey } = await buildArrEnvelope({
    credentialStatus: makePointer(url, 20),
  });
  const r = await arrFamily.verifyReceipt(envelope as unknown as Record<string, unknown>, {
    resolveKey: async () => publicKey,
    statusListRootKey: rootKey,
    statusCacheConfig: { freshTtlSec: 3600, staleTtlSec: 86400, storage: cache },
    chainResolver: async () => true,
  });
  assert.equal(r.signature_valid, true);
  assert.equal(r.status_state, "revoked_by_chain");
  assert.equal(r.status_list_id, url);
});

test("ARR v=2: bit=1, no chain successor → revoked + status_chain_inconsistency", async () => {
  const url = "https://verify.dekimu.com/arr/v1/status/2026/05";
  const { cache, rootKey } = await seedSignedList({
    bitIndex: 41,
    bitValue: 1,
    credentialUrl: url,
  });
  const { envelope, publicKey } = await buildArrEnvelope({
    credentialStatus: makePointer(url, 41),
  });
  const r = await arrFamily.verifyReceipt(envelope as unknown as Record<string, unknown>, {
    resolveKey: async () => publicKey,
    statusListRootKey: rootKey,
    statusCacheConfig: { freshTtlSec: 3600, staleTtlSec: 86400, storage: cache },
  });
  assert.equal(r.signature_valid, true);
  assert.equal(r.status_state, "revoked");
  assert.ok(r.warnings?.includes("status_chain_inconsistency"));
});

test("ARR v=2: bit=1, chain successor=yes → revoked (no chain_inconsistency)", async () => {
  const url = "https://verify.dekimu.com/arr/v1/status/2026/05";
  const { cache, rootKey } = await seedSignedList({
    bitIndex: 88,
    bitValue: 1,
    credentialUrl: url,
  });
  const { envelope, publicKey } = await buildArrEnvelope({
    credentialStatus: makePointer(url, 88),
  });
  const r = await arrFamily.verifyReceipt(envelope as unknown as Record<string, unknown>, {
    resolveKey: async () => publicKey,
    statusListRootKey: rootKey,
    statusCacheConfig: { freshTtlSec: 3600, staleTtlSec: 86400, storage: cache },
    chainResolver: async () => true,
  });
  assert.equal(r.signature_valid, true);
  assert.equal(r.status_state, "revoked");
  assert.ok(!r.warnings?.includes("status_chain_inconsistency"));
});

test("ARR v=2: bad pointer (http://) → invalid_pointer", async () => {
  const cs: CredentialStatus = {
    id: "http://insecure.example/list#0",
    type: "StatusList2021Entry",
    statusPurpose: "revocation",
    statusListIndex: "0",
    statusListCredential: "http://insecure.example/list",
  };
  const { envelope, publicKey } = await buildArrEnvelope({ credentialStatus: cs });
  const { rootKey } = makeSignedStatusList({ bitIndex: 0, bitValue: 0 });
  const r = await arrFamily.verifyReceipt(envelope as unknown as Record<string, unknown>, {
    resolveKey: async () => publicKey,
    statusListRootKey: rootKey,
  });
  assert.equal(r.signature_valid, true);
  assert.equal(r.status_state, "invalid_pointer");
});

test("ARR v=2: rootKey not provided → not_attempted", async () => {
  const url = "https://verify.dekimu.com/arr/v1/status/2026/05";
  const { envelope, publicKey } = await buildArrEnvelope({
    credentialStatus: makePointer(url, 1),
  });
  const r = await arrFamily.verifyReceipt(envelope as unknown as Record<string, unknown>, {
    resolveKey: async () => publicKey,
  });
  assert.equal(r.signature_valid, true);
  assert.equal(r.status_state, "not_attempted");
});
