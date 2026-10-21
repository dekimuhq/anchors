/**
 * Tests for credentialStatus pointer attachment in ACR v=2 mint path.
 * Phase D Task 20.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as crypto from "node:crypto";

import { mintAcrV2 } from "../src/issue/index.ts";
import type { MintAcrV2Input, StatusListConfig } from "../src/issue/index.ts";
import {
  verifyEnvelopeSignature,
  base64UrlDecode,
} from "@dekimuhq/anchors-envelope";
import type { AnchorProof } from "@dekimuhq/anchors-envelope";

const ED25519_SPKI_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

function spkiFromIssKey(issKey: string): Uint8Array {
  const raw = base64UrlDecode(issKey.replace("ed25519:", ""));
  return new Uint8Array(Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]));
}

// ── Shared helpers ─────────────────────────────────────────────────────────────

function makeKeypair(): { kid: string; privateKey: Uint8Array } {
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
  log: "https://verify.dekimu.com/acr/v1",
  leaf_index: 0,
  inclusion_proof: [],
  tree_head_root: "sha256:" + "0".repeat(64),
  tree_size: 1,
  log_time: "2026-05-17T00:00:00Z",
};

function makeBaseInput(
  keypair: MintAcrV2Input["keypair"],
  overrides?: Partial<MintAcrV2Input>,
): MintAcrV2Input {
  return {
    issuer: "did:web:bank.example",
    keypair,
    kind: "ar.consent.v1",
    subject: "sha256:" + "b".repeat(64),
    profile: "gdpr.art7",
    fields: {
      sub_commit: { value: "user@example.com" },
      purposes: [{ value: "marketing" }],
      policy_hash: { value: "sha256:" + "a".repeat(64) },
    },
    lawful_basis: "6(1)(a)",
    granted_at: "2026-05-17T10:00:00Z",
    anchor,
    policy_uri: "https://bank.example/privacy",
    policy_hash: "sha256:" + "f".repeat(64),
    policy_version: "1.0.0",
    ...overrides,
  };
}

// Fixed clock pinned to 2026-05-17 for deterministic bucket assertions.
const FIXED_NOW = new Date("2026-05-17T10:00:00Z");

function makeStatusListConfig(indexReturnValue: number, captureArgs?: { bucket: string[] }): StatusListConfig {
  return {
    baseUrl: "https://verify.dekimu.com/acr/v1/status",
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

test("S1: mintAcrV2 consent — with statusList embeds pointer and calls callback with correct bucket", async () => {
  const keypair = makeKeypair();
  const captured: { bucket: string[] } = { bucket: [] };

  const env = await mintAcrV2(makeBaseInput(keypair, {
    kind: "ar.consent.v1",
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
    "https://verify.dekimu.com/acr/v1/status/2026/05",
  );
  assert.equal(
    env.credentialStatus!.id,
    "https://verify.dekimu.com/acr/v1/status/2026/05#42",
  );

  // credentialStatus is included in the signature (pointer signed-in per §5.5)
  // — sig must be present and valid length
  assert.ok(typeof env.sig === "string" && env.sig.length > 0);
});

test("S2: mintAcrV2 consent — without statusList config produces credentialStatus=null", async () => {
  const keypair = makeKeypair();

  const env = await mintAcrV2(makeBaseInput(keypair));

  assert.strictEqual(env.credentialStatus, null);
});

test("S3: mintAcrV2 withdrawal — with statusList embeds pointer", async () => {
  const keypair = makeKeypair();
  const captured: { bucket: string[] } = { bucket: [] };

  const env = await mintAcrV2(makeBaseInput(keypair, {
    kind: "ar.withdrawal.v1",
    statusList: makeStatusListConfig(99, captured),
  }));

  assert.equal(env.claim_type, "ar.withdrawal.v1");
  assert.ok(env.credentialStatus !== null);
  assert.equal(env.credentialStatus!.statusListIndex, "99");
  assert.match(captured.bucket[0]!, /^2026\/\d{2}$/);
});

test("S4: mintAcrV2 withdrawal — without statusList produces credentialStatus=null", async () => {
  const keypair = makeKeypair();

  const env = await mintAcrV2(makeBaseInput(keypair, { kind: "ar.withdrawal.v1" }));

  assert.strictEqual(env.credentialStatus, null);
});

test("S5: mintAcrV2 modification — with statusList embeds pointer", async () => {
  const keypair = makeKeypair();

  const env = await mintAcrV2(makeBaseInput(keypair, {
    kind: "ar.modification.v1",
    statusList: makeStatusListConfig(7),
  }));

  assert.equal(env.claim_type, "ar.modification.v1");
  assert.ok(env.credentialStatus !== null);
  assert.equal(env.credentialStatus!.statusListIndex, "7");
});

test("S6: mintAcrV2 modification — without statusList produces credentialStatus=null", async () => {
  const keypair = makeKeypair();

  const env = await mintAcrV2(makeBaseInput(keypair, { kind: "ar.modification.v1" }));

  assert.strictEqual(env.credentialStatus, null);
});

test("S7: statusList index at boundary values — 0 and 131071 are accepted", async () => {
  const keypair = makeKeypair();

  const envMin = await mintAcrV2(makeBaseInput(keypair, {
    statusList: makeStatusListConfig(0),
  }));
  assert.equal(envMin.credentialStatus!.statusListIndex, "0");

  const keypair2 = makeKeypair();
  const envMax = await mintAcrV2(makeBaseInput(keypair2, {
    statusList: makeStatusListConfig(131_071),
  }));
  assert.equal(envMax.credentialStatus!.statusListIndex, "131071");
});

test("S7b: statusList signature roundtrip — credentialStatus is signed-in (catches mint-order regression)", async () => {
  const keypair = makeKeypair();

  const env = await mintAcrV2(makeBaseInput(keypair, {
    statusList: makeStatusListConfig(123),
  }));

  // 1. Signature must verify as-minted (attachCredentialStatus was called
  //    BEFORE signEnvelope — the signature covers credentialStatus).
  assert.ok(env.credentialStatus !== null);
  const spki = spkiFromIssKey(env.iss_key);
  assert.equal(verifyEnvelopeSignature(env, spki), true);

  // 2. Tampering with credentialStatus breaks the signature (proves it's
  //    signed-in, not signed-out). If attachCredentialStatus had been called
  //    AFTER signEnvelope, tampering here would still verify — that's the
  //    regression this test catches.
  const tampered = {
    ...env,
    credentialStatus: {
      ...env.credentialStatus!,
      statusListIndex: "999",
    },
  };
  assert.equal(verifyEnvelopeSignature(tampered, spki), false);
});

test("S8: statusList index out of range — throws", async () => {
  const keypair = makeKeypair();

  await assert.rejects(
    () => mintAcrV2(makeBaseInput(keypair, {
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

  const keypair2 = makeKeypair();
  await assert.rejects(
    () => mintAcrV2(makeBaseInput(keypair2, {
      statusList: makeStatusListConfig(-1),
    })),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.ok((err as Error).message.includes("index"));
      return true;
    },
    "should throw for negative index",
  );
});
