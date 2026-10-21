/**
 * Tests for mintArrV2Single + mintArrV2Batch — ARR v=2 envelope mint path.
 * Phase B Task 12d.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as crypto from "node:crypto";

import {
  mintArrV2Single,
  mintArrV2Batch,
  TsaMintError,
} from "../src/issue/index.ts";
import type {
  MintArrV2SingleInput,
  MintArrV2BatchInput,
  ArrV2SingleKind,
  BatchTarget,
} from "../src/issue/index.ts";
import { verifyReceipt } from "../src/index.ts";
import { base64UrlDecode } from "@dekimuhq/anchors-envelope";
import type { AnchorProof, FamilyVerifyResult } from "@dekimuhq/anchors-envelope";
import type { TsaConfig } from "@dekimuhq/anchors-envelope/tsa";
import type { ArrStateSnapshot } from "../src/index.ts";

// ── Shared helpers ────────────────────────────────────────────────────────────

const ED25519_SPKI_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

function makeSigningKey(): {
  signingKey: { kid: string; privateKey: Uint8Array };
  spkiDer: Buffer;
} {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const seed = (
    privateKey.export({ format: "der", type: "pkcs8" }) as Buffer
  ).subarray(-32);
  const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  return {
    signingKey: {
      kid: "test-kid-" + Math.random().toString(36).slice(2),
      privateKey: new Uint8Array(seed),
    },
    spkiDer: pkDer,
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

const TSA_CFG: TsaConfig = {
  url: "https://freetsa.org/tsr",
  hashAlg: "sha-256",
  timeoutMs: 5000,
  trustAnchorIds: [],
  driftToleranceSec: 60,
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

// ── resolveKey helper for round-trip tests ────────────────────────────────────

function makeResolveKey() {
  return async (envelope: unknown): Promise<Uint8Array> => {
    const issKey = (envelope as { iss_key: string }).iss_key;
    const raw = base64UrlDecode(issKey.replace("ed25519:", ""));
    return new Uint8Array(Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]));
  };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test("T1: mintArrV2Single happy path WITHOUT TSA — ar.erasure.v1 round-trip", async () => {
  const { signingKey } = makeSigningKey();

  const env = await mintArrV2Single(makeBaseSingleInput(signingKey));

  // Envelope version
  assert.equal(env.v, 2);
  assert.equal(env.claim_type, "ar.erasure.v1");

  // id — 26-char Crockford-Base32 ULID
  assert.match(env.id, /^[0-9A-HJKMNP-TV-Z]{26}$/);

  // iat — valid ISO 8601
  assert.ok(!isNaN(Date.parse(env.iat)), "iat must be a valid date");

  // iss_key format
  assert.match(env.iss_key, /^ed25519:[A-Za-z0-9_-]+$/);

  // sig present — 64 bytes
  assert.ok(typeof env.sig === "string" && env.sig.length > 0);
  const sigBytes = base64UrlDecode(env.sig);
  assert.equal(sigBytes.length, 64, "Ed25519 sig must be 64 bytes");

  // tsa and credentialStatus null
  assert.equal(env.tsa, null);
  assert.equal(env.credentialStatus, null);

  // Optional fields default to null
  assert.strictEqual(env.prev, null);
  assert.strictEqual(env.exp, null);
  assert.strictEqual(env.countersig, null);

  // body has ARR-specific fields
  const body = env.body as Record<string, unknown>;
  assert.equal(body.profile, "gdpr.art17");
  assert.equal(body.target_kind, "subject");
  assert.ok(typeof body.field_root === "string" && (body.field_root as string).startsWith("sha256:"), "field_root must be sha256:");
  assert.deepEqual(body.state_snapshot, snapshot);

  // v=2 round-trip with arr-verifier
  const result = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(result.envelope_version, 2);
  assert.equal(result.signature_valid, true);
  assert.equal(result.claim_type, "ar.erasure.v1");
});

test("T2: each single kind mints with correct claim_type", async () => {
  const kinds: ArrV2SingleKind[] = [
    "ar.erasure.v1",
    "ar.expiry.v1",
    "ar.hold.v1",
    "ar.anonymization.v1",
    "ar.archive.v1",
  ];

  for (const kind of kinds) {
    const { signingKey } = makeSigningKey();
    const overrides: Partial<MintArrV2SingleInput> = { kind };
    // ar.archive.v1 requires effective_until
    if (kind === "ar.archive.v1") {
      overrides.effective_until = "2027-05-17T00:00:00Z";
    }
    const env = await mintArrV2Single(makeBaseSingleInput(signingKey, overrides));
    assert.equal(env.v, 2, `v=2 for kind ${kind}`);
    assert.equal(env.claim_type, kind, `claim_type matches for ${kind}`);

    // verifier round-trip
    const result = await verifyReceipt(env, { resolveKey: makeResolveKey() }) as FamilyVerifyResult;
    assert.equal(result.signature_valid, true, `sig_valid for ${kind}`);
    assert.equal(result.claim_type, kind);
  }
});

test("T3: mintArrV2Batch happy path — ar.batch.v1", async () => {
  const { signingKey } = makeSigningKey();

  const env = await mintArrV2Batch(makeBaseBatchInput(signingKey));

  assert.equal(env.v, 2);
  assert.equal(env.claim_type, "ar.batch.v1");

  assert.match(env.id, /^[0-9A-HJKMNP-TV-Z]{26}$/);
  assert.ok(!isNaN(Date.parse(env.iat)));
  assert.match(env.iss_key, /^ed25519:[A-Za-z0-9_-]+$/);

  assert.ok(typeof env.sig === "string" && env.sig.length > 0);
  const sigBytes = base64UrlDecode(env.sig);
  assert.equal(sigBytes.length, 64);

  assert.equal(env.tsa, null);
  assert.equal(env.credentialStatus, null);
  assert.strictEqual(env.prev, null);
  assert.strictEqual(env.countersig, null);

  const body = env.body as Record<string, unknown>;
  assert.equal(body.target_count, 2);
  assert.ok(typeof body.target_root === "string");
  assert.ok(typeof body.state_snapshot_root === "string");
  assert.ok(typeof body.field_root === "string");

  // v=2 round-trip
  const result = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(result.envelope_version, 2);
  assert.equal(result.signature_valid, true);
  assert.equal(result.claim_type, "ar.batch.v1");
});

test("T4: TSA config without fetcher — throws mentioning tsaFetcher (both single + batch)", async () => {
  const { signingKey } = makeSigningKey();

  // Single
  await assert.rejects(
    () => mintArrV2Single(makeBaseSingleInput(signingKey, { tsa: TSA_CFG })),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.ok(
        (err as Error).message.includes("tsaFetcher"),
        `expected 'tsaFetcher' in message, got: ${(err as Error).message}`,
      );
      return true;
    },
    "mintArrV2Single: should throw when tsa config present but fetcher absent",
  );

  // Batch
  await assert.rejects(
    () => mintArrV2Batch(makeBaseBatchInput(signingKey, { tsa: TSA_CFG })),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.ok(
        (err as Error).message.includes("tsaFetcher"),
        `expected 'tsaFetcher' in message, got: ${(err as Error).message}`,
      );
      return true;
    },
    "mintArrV2Batch: should throw when tsa config present but fetcher absent",
  );
});

test("T5: TSA fetcher that rejects — propagates TsaMintError (single + batch)", async () => {
  const { signingKey } = makeSigningKey();

  const rejectingFetcher = async (_req: Uint8Array, _url: string): Promise<Uint8Array> => {
    throw new Error("network error: connection refused");
  };

  // Single
  await assert.rejects(
    () =>
      mintArrV2Single(
        makeBaseSingleInput(signingKey, {
          tsa: TSA_CFG,
          tsaFetcher: rejectingFetcher,
        }),
      ),
    (err: unknown) => {
      assert.ok(
        err instanceof TsaMintError,
        `expected TsaMintError, got: ${(err as Error).constructor.name}`,
      );
      return true;
    },
    "mintArrV2Single: should propagate TsaMintError when fetcher rejects",
  );

  // Batch
  await assert.rejects(
    () =>
      mintArrV2Batch(
        makeBaseBatchInput(signingKey, {
          tsa: TSA_CFG,
          tsaFetcher: rejectingFetcher,
        }),
      ),
    (err: unknown) => {
      assert.ok(
        err instanceof TsaMintError,
        `expected TsaMintError, got: ${(err as Error).constructor.name}`,
      );
      return true;
    },
    "mintArrV2Batch: should propagate TsaMintError when fetcher rejects",
  );
});

test("T6: prev chain field round-trips on single envelope", async () => {
  const { signingKey } = makeSigningKey();
  const priorId = "01HZABC0000000000000000ERASE";

  const env = await mintArrV2Single(
    makeBaseSingleInput(signingKey, { prev: priorId }),
  );

  assert.equal(env.prev, priorId);
  assert.equal(env.claim_type, "ar.erasure.v1");

  // Verify signature still valid with prev set
  const result = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(result.signature_valid, true);
});

test("T7: mintArrV2Single subject_request trigger requires trigger_receipt", async () => {
  const { signingKey } = makeSigningKey();

  await assert.rejects(
    () =>
      mintArrV2Single(
        makeBaseSingleInput(signingKey, {
          trigger: "subject_request",
          trigger_receipt: null,
        }),
      ),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.ok(
        (err as Error).message.includes("trigger_receipt"),
        `expected 'trigger_receipt' in message`,
      );
      return true;
    },
    "should reject subject_request without trigger_receipt",
  );

  // Providing trigger_receipt should succeed
  const env = await mintArrV2Single(
    makeBaseSingleInput(signingKey, {
      trigger: "subject_request",
      trigger_receipt: "receipt-abc-123",
    }),
  );
  assert.equal(env.claim_type, "ar.erasure.v1");
  assert.equal((env.body as Record<string, unknown>).trigger, "subject_request");
  assert.equal((env.body as Record<string, unknown>).trigger_receipt, "receipt-abc-123");
});

test("T8: mintArrV2Batch zero targets throws", async () => {
  const { signingKey } = makeSigningKey();

  await assert.rejects(
    () => mintArrV2Batch(makeBaseBatchInput(signingKey, { targets: [] })),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.ok((err as Error).message.includes("target_count.zero"));
      return true;
    },
    "should throw for empty targets",
  );
});

// ── Phase C Task 14: envelope-level policy field dual-carry ───────────────────

test("T9 (Phase C): mintArrV2Single mirrors body policy fields onto envelope slots", async () => {
  const { signingKey } = makeSigningKey();

  const env = await mintArrV2Single(makeBaseSingleInput(signingKey));

  // Envelope-level slots must match body — POLICY_BOUND requirement for ARR
  // single-target kinds (Phase C Task 14). Body is the source of truth for
  // ARR semantics; envelope copy is what the policy matrix enforces.
  const body = env.body as Record<string, unknown>;
  assert.equal(env.policy_uri, "https://example.com/policy.pdf");
  assert.equal(env.policy_hash, "sha256:" + "d".repeat(64));
  assert.equal(env.policy_version, "1.0.0");
  assert.equal(env.policy_uri, body.policy_uri);
  assert.equal(env.policy_hash, body.policy_hash);
  assert.equal(env.policy_version, body.policy_version);
});

test("T10 (Phase C): mintArrV2Batch keeps envelope policy_* null (per-item lives in body)", async () => {
  const { signingKey } = makeSigningKey();

  const env = await mintArrV2Batch(makeBaseBatchInput(signingKey));

  // ar.batch.v1 is excluded from POLICY_BOUND; per-item policy lives inside
  // the body per batch target. Envelope-level slots stay null.
  assert.strictEqual(env.policy_uri, null);
  assert.strictEqual(env.policy_hash, null);
  assert.strictEqual(env.policy_version, null);

  // Body still carries the batch-wide policy (unchanged).
  const body = env.body as Record<string, unknown>;
  assert.equal(body.policy_uri, "https://example.com/policy.pdf");
  assert.equal(body.policy_hash, "sha256:" + "d".repeat(64));
  assert.equal(body.policy_version, "1.0.0");
});

// ── v1.2 envelope additions (Phase E4) ────────────────────────────────────────

test("T-v1.2: mintArrV2Single sets iat_ms = Date.parse(iat)", async () => {
  const { signingKey } = makeSigningKey();
  const env = await mintArrV2Single(makeBaseSingleInput(signingKey));
  assert.equal(typeof env.iat_ms, "number");
  assert.equal(env.iat_ms, Date.parse(env.iat));
});

test("T-v1.2: mintArrV2Single defaults envelope kind to 'decision'", async () => {
  const { signingKey } = makeSigningKey();
  const env = await mintArrV2Single(makeBaseSingleInput(signingKey));
  assert.equal(env.kind, "decision");
});

test("T-v1.2: mintArrV2Single explicit envelope_kind: null passes through", async () => {
  const { signingKey } = makeSigningKey();
  const env = await mintArrV2Single(
    makeBaseSingleInput(signingKey, { envelope_kind: null }),
  );
  assert.strictEqual(env.kind, null);
});

test("T-v1.2: mintArrV2Single plumbs optional cause", async () => {
  const { signingKey } = makeSigningKey();
  const env = await mintArrV2Single(
    makeBaseSingleInput(signingKey, { cause: "erasure_request" }),
  );
  assert.equal(env.cause, "erasure_request");
});

test("T-v1.2: mintArrV2Single omitted cause defaults to null", async () => {
  const { signingKey } = makeSigningKey();
  const env = await mintArrV2Single(makeBaseSingleInput(signingKey));
  assert.strictEqual(env.cause, null);
});

test("T-v1.2: mintArrV2Single roundtrips with a satisfied predicate", async () => {
  const { signingKey } = makeSigningKey();
  const predicate = { "===": [1, 1] } as unknown as NonNullable<
    Parameters<typeof mintArrV2Single>[0]["predicate"]
  >;
  const env = await mintArrV2Single(
    makeBaseSingleInput(signingKey, { predicate }),
  );
  assert.deepEqual(env.predicate, { "===": [1, 1] });

  const result = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(result.signature_valid, true, `unexpected reason: ${result.reason}`);
});

test("T-v1.2: mintArrV2Single omitted predicate defaults to null", async () => {
  const { signingKey } = makeSigningKey();
  const env = await mintArrV2Single(makeBaseSingleInput(signingKey));
  assert.strictEqual(env.predicate, null);
});

test("T-v1.2: mintArrV2Batch sets iat_ms = Date.parse(iat)", async () => {
  const { signingKey } = makeSigningKey();
  const env = await mintArrV2Batch(makeBaseBatchInput(signingKey));
  assert.equal(typeof env.iat_ms, "number");
  assert.equal(env.iat_ms, Date.parse(env.iat));
});

test("T-v1.2: mintArrV2Batch always sets kind = null (spec §6)", async () => {
  const { signingKey } = makeSigningKey();
  const env = await mintArrV2Batch(makeBaseBatchInput(signingKey));
  assert.strictEqual(env.kind, null);
});

test("T-v1.2: mintArrV2Batch plumbs optional cause", async () => {
  const { signingKey } = makeSigningKey();
  const env = await mintArrV2Batch(
    makeBaseBatchInput(signingKey, { cause: "scheduled" }),
  );
  assert.equal(env.cause, "scheduled");
});

test("T-v1.2: mintArrV2Batch never emits a predicate field (forbidden on ar.batch.v1)", async () => {
  const { signingKey } = makeSigningKey();
  const env = await mintArrV2Batch(makeBaseBatchInput(signingKey));
  // Per spec §6 + L9 ar.batch.v1 predicate is forbidden — the mint path
  // does not accept a predicate input and does not emit the field.
  assert.equal(env.predicate, undefined);
});

// ── T_QTS: non-null qts_attestation_hash round-trips ────────────────────────

test("T_QTS: non-null qts_attestation_hash round-trips (single)", async () => {
  const QTS = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
  const { signingKey } = makeSigningKey();
  const env = await mintArrV2Single(
    makeBaseSingleInput(signingKey, { qts_attestation_hash: QTS }),
  );
  const body = env.body as Record<string, unknown>;
  assert.equal(body.qts_attestation_hash, QTS);
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("T_QTS: non-null qts_attestation_hash round-trips (batch)", async () => {
  const QTS = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
  const { signingKey } = makeSigningKey();
  const env = await mintArrV2Batch(
    makeBaseBatchInput(signingKey, { qts_attestation_hash: QTS }),
  );
  const body = env.body as Record<string, unknown>;
  assert.equal(body.qts_attestation_hash, QTS);
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});
