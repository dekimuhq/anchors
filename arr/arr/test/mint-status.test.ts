/**
 * Tests for credentialStatus pointer attachment in ARR v=2 mint path.
 * Phase D Task 20.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as crypto from "node:crypto";

import { mintArrV2Single, mintArrV2Batch } from "../src/issue/index.ts";
import type {
  MintArrV2SingleInput,
  MintArrV2BatchInput,
  BatchTarget,
  StatusListConfig,
} from "../src/issue/index.ts";
import {
  verifyEnvelopeSignature,
  base64UrlDecode,
} from "@dekimuhq/anchors-envelope";
import type { AnchorProof } from "@dekimuhq/anchors-envelope";
import type { ArrStateSnapshot } from "../src/index.ts";

const ED25519_SPKI_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

function spkiFromIssKey(issKey: string): Uint8Array {
  const raw = base64UrlDecode(issKey.replace("ed25519:", ""));
  return new Uint8Array(Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]));
}

// ── Shared helpers ─────────────────────────────────────────────────────────────

function makeSigningKey(): { kid: string; privateKey: Uint8Array } {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const seed = (
    privateKey.export({ format: "der", type: "pkcs8" }) as Buffer
  ).subarray(-32);
  return {
    kid: "test-kid-" + Math.random().toString(36).slice(2),
    privateKey: new Uint8Array(seed),
  };
}

const anchor: AnchorProof = {
  log: "https://verify.dekimu.com/arr/v1",
  leaf_index: 0,
  inclusion_proof: [],
  tree_head_root: "sha256:" + "0".repeat(64),
  tree_size: 1,
  log_time: "2026-05-17T00:00:00Z",
};

const snapshot: ArrStateSnapshot = {
  retention_status: "erased",
  current_policy_hash: "sha256:" + "a".repeat(64),
  hold_active: false,
  hold_reason_commit: null,
  anonymized: false,
  archived: false,
};

function makeBaseSingleInput(
  signingKey: MintArrV2SingleInput["signingKey"],
  overrides?: Partial<MintArrV2SingleInput>,
): MintArrV2SingleInput {
  return {
    issuer: "did:web:invoiceup.app",
    signingKey,
    kind: "ar.erasure.v1",
    subject: "sha256:" + "b".repeat(64),
    profile: "gdpr.art17",
    target_kind: "subject",
    target_commit: "sha256:" + "c".repeat(64),
    salt_epoch: "2026-01",
    policy_hash: "sha256:" + "d".repeat(64),
    policy_uri: "https://example.com/policy.pdf",
    policy_version: "1.0.0",
    trigger: "operator",
    trigger_receipt: null,
    event_at: "2026-05-17T10:00:00Z",
    granted_at: "2026-05-17T10:00:01Z",
    state_snapshot: snapshot,
    anchor,
    ...overrides,
  };
}

function makeBaseBatchInput(
  signingKey: MintArrV2BatchInput["signingKey"],
  overrides?: Partial<MintArrV2BatchInput>,
): MintArrV2BatchInput {
  const targets: BatchTarget[] = [
    { target_commit: "sha256:" + "e".repeat(64), state_snapshot: snapshot },
    { target_commit: "sha256:" + "f".repeat(64), state_snapshot: { ...snapshot, retention_status: "archived" } },
  ];
  return {
    issuer: "did:web:invoiceup.app",
    signingKey,
    subject: "sha256:" + "0".repeat(64),
    profile: "gdpr.art17",
    batch_event_kind: "ar.erasure.v1",
    target_kind: "subject",
    salt_epoch: "2026-01",
    policy_hash: "sha256:" + "d".repeat(64),
    policy_uri: "https://example.com/policy.pdf",
    policy_version: "1.0.0",
    trigger: "scheduled",
    trigger_receipt: null,
    event_at: "2026-05-17T10:00:00Z",
    granted_at: "2026-05-17T10:00:01Z",
    targets,
    anchor,
    ...overrides,
  };
}

// Fixed clock pinned to 2026-05-17 for deterministic bucket assertions.
const FIXED_NOW = new Date("2026-05-17T10:00:00Z");

function makeStatusListConfig(indexReturnValue: number, captureArgs?: { bucket: string[] }): StatusListConfig {
  return {
    baseUrl: "https://verify.dekimu.com/arr/v1/status",
    getNextStatusIndex: async (bucket) => {
      if (captureArgs) {
        captureArgs.bucket.push(bucket);
      }
      return indexReturnValue;
    },
    now: () => FIXED_NOW,
  };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test("R1: mintArrV2Single erasure — with statusList embeds pointer and calls callback with correct bucket", async () => {
  const signingKey = makeSigningKey();
  const captured: { bucket: string[] } = { bucket: [] };

  const env = await mintArrV2Single(makeBaseSingleInput(signingKey, {
    statusList: makeStatusListConfig(42, captured),
  }));

  assert.equal(captured.bucket.length, 1, "callback called exactly once");
  assert.match(captured.bucket[0]!, /^2026\/\d{2}$/, "bucket matches YYYY/MM format");
  assert.equal(captured.bucket[0], "2026/05", "bucket is 2026/05 for fixed clock");

  assert.ok(env.credentialStatus !== null, "credentialStatus must not be null");
  assert.equal(env.credentialStatus!.statusListIndex, "42");
  assert.equal(env.credentialStatus!.type, "StatusList2021Entry");
  assert.equal(env.credentialStatus!.statusPurpose, "revocation");
  assert.equal(
    env.credentialStatus!.statusListCredential,
    "https://verify.dekimu.com/arr/v1/status/2026/05",
  );
  assert.equal(
    env.credentialStatus!.id,
    "https://verify.dekimu.com/arr/v1/status/2026/05#42",
  );

  assert.ok(typeof env.sig === "string" && env.sig.length > 0);
});

test("R2: mintArrV2Single erasure — without statusList produces credentialStatus=null", async () => {
  const signingKey = makeSigningKey();

  const env = await mintArrV2Single(makeBaseSingleInput(signingKey));

  assert.strictEqual(env.credentialStatus, null);
});

test("R3: mintArrV2Batch — with statusList embeds one shared pointer per batch envelope", async () => {
  const signingKey = makeSigningKey();
  const captured: { bucket: string[] } = { bucket: [] };

  const env = await mintArrV2Batch(makeBaseBatchInput(signingKey, {
    statusList: makeStatusListConfig(77, captured),
  }));

  assert.equal(env.claim_type, "ar.batch.v1");

  // Batch receives ONE pointer for the envelope (not per-target).
  assert.equal(captured.bucket.length, 1, "callback called exactly once for batch");
  assert.ok(env.credentialStatus !== null, "batch credentialStatus must not be null");
  assert.equal(env.credentialStatus!.statusListIndex, "77");
  assert.equal(
    env.credentialStatus!.statusListCredential,
    "https://verify.dekimu.com/arr/v1/status/2026/05",
  );
});

test("R4: mintArrV2Batch — without statusList produces credentialStatus=null", async () => {
  const signingKey = makeSigningKey();

  const env = await mintArrV2Batch(makeBaseBatchInput(signingKey));

  assert.strictEqual(env.credentialStatus, null);
});

test("R5: mintArrV2Single — index boundary values 0 and 131071 are accepted", async () => {
  const signingKey = makeSigningKey();

  const envMin = await mintArrV2Single(makeBaseSingleInput(signingKey, {
    statusList: makeStatusListConfig(0),
  }));
  assert.equal(envMin.credentialStatus!.statusListIndex, "0");

  const signingKey2 = makeSigningKey();
  const envMax = await mintArrV2Single(makeBaseSingleInput(signingKey2, {
    statusList: makeStatusListConfig(131_071),
  }));
  assert.equal(envMax.credentialStatus!.statusListIndex, "131071");
});

test("R5b: mintArrV2Single + Batch signature roundtrip — credentialStatus is signed-in", async () => {
  // Single mint
  const signingKey = makeSigningKey();
  const env = await mintArrV2Single(makeBaseSingleInput(signingKey, {
    statusList: makeStatusListConfig(321),
  }));
  assert.ok(env.credentialStatus !== null);
  const spki = spkiFromIssKey(env.iss_key);
  assert.equal(verifyEnvelopeSignature(env, spki), true);

  // Tamper with credentialStatus → signature breaks (proves signed-in).
  const tampered = {
    ...env,
    credentialStatus: { ...env.credentialStatus!, statusListIndex: "999" },
  };
  assert.equal(verifyEnvelopeSignature(tampered, spki), false);

  // Batch mint
  const signingKey2 = makeSigningKey();
  const envBatch = await mintArrV2Batch(makeBaseBatchInput(signingKey2, {
    statusList: makeStatusListConfig(654),
  }));
  assert.ok(envBatch.credentialStatus !== null);
  const spki2 = spkiFromIssKey(envBatch.iss_key);
  assert.equal(verifyEnvelopeSignature(envBatch, spki2), true);

  const tamperedBatch = {
    ...envBatch,
    credentialStatus: { ...envBatch.credentialStatus!, statusListIndex: "1" },
  };
  assert.equal(verifyEnvelopeSignature(tamperedBatch, spki2), false);
});

test("R6: mintArrV2Single — index out of range throws", async () => {
  const signingKey = makeSigningKey();

  await assert.rejects(
    () => mintArrV2Single(makeBaseSingleInput(signingKey, {
      statusList: makeStatusListConfig(131_072),
    })),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.ok(
        (err as Error).message.includes("index"),
        `expected 'index' in message, got: ${(err as Error).message}`,
      );
      return true;
    },
    "should throw for index > 131071",
  );
});
