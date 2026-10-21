/**
 * Tests for mintAprV2 — APR v=2 envelope mint path.
 * Phase B Task 12b.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as crypto from "node:crypto";

import { mintAprV2, TsaMintError } from "../src/issue/index.ts";
import type { MintAprV2Input } from "../src/issue/index.ts";
import { verifyReceipt } from "../src/index.ts";
import { base64UrlDecode } from "@dekimuhq/anchors-envelope";
import type { APRBody } from "../src/index.ts";
import type { AnchorProof } from "@dekimuhq/anchors-envelope";
import type { TsaConfig } from "@dekimuhq/anchors-envelope/tsa";

// ── Shared fixtures ───────────────────────────────────────────────────────────

const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const ED25519_SPKI_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

function makeSigningKey(): { signingKey: { kid: string; privateKey: Uint8Array }; spkiDer: Buffer } {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const seed = (privateKey.export({ format: "der", type: "pkcs8" }) as Buffer).subarray(-32);
  const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  return {
    signingKey: { kid: "test-kid-" + Math.random().toString(36).slice(2), privateKey: new Uint8Array(seed) },
    spkiDer: pkDer,
  };
}

const body: APRBody = {
  artifact: {
    type: "miniterms.document",
    id: "art-v2-001",
    hash: "a".repeat(64),
    hashAlgorithm: "sha256",
  },
  agent: { kind: "template" },
  authorization: { principalId: "principal-v2" },
  startedAt: 1_747_440_000,
  completedAt: 1_747_440_001,
  disclosure: "public_minimal",
  qts_attestation_hash: null,
};

const anchor: AnchorProof = {
  log: "https://verify.dekimu.com/apr/v1",
  leaf_index: 0,
  inclusion_proof: [],
  tree_head_root: "sha256:" + "0".repeat(64),
  tree_size: 1,
  log_time: "2026-05-17T00:00:00Z",
};

// ── Tests ─────────────────────────────────────────────────────────────────────

test("T1: mintAprV2 happy path WITHOUT TSA", async () => {
  const { signingKey } = makeSigningKey();

  const env = await mintAprV2({
    issuer: "did:web:invoiceup.app",
    signingKey,
    subject: "sha256:" + "b".repeat(64),
    body,
    anchor,
  });

  // Envelope version
  assert.equal(env.v, 2);

  // claim_type
  assert.equal(env.claim_type, "ar.provenance.v1");

  // id — 26-char Crockford-Base32 ULID
  assert.match(env.id, /^[0-9A-HJKMNP-TV-Z]{26}$/);

  // iat — valid ISO 8601 UTC
  assert.ok(!isNaN(Date.parse(env.iat)), "iat must be a valid date");

  // iss_key format
  assert.match(env.iss_key, /^ed25519:[A-Za-z0-9_-]+$/);

  // subject passes through
  assert.equal(env.subject, "sha256:" + "b".repeat(64));

  // body passes through
  assert.deepEqual(env.body, body);

  // tsa is null (no TSA config supplied)
  assert.equal(env.tsa, null);

  // credentialStatus is null
  assert.equal(env.credentialStatus, null);

  // sig present and base64url-shaped
  assert.ok(typeof env.sig === "string" && env.sig.length > 0);
  const sigBytes = base64UrlDecode(env.sig);
  assert.equal(sigBytes.length, 64, "Ed25519 sig must be 64 bytes");

  // Optional fields default to null when not supplied
  assert.equal(env.prev, null);
  assert.equal(env.exp, null);
  assert.equal(env.policy_uri, null);
  assert.equal(env.policy_hash, null);
  assert.equal(env.policy_version, null);
  assert.equal(env.countersig, null);
});

test("T2: mintAprV2 round-trip with v=2 verifier (signature_valid: true)", async () => {
  const { signingKey, spkiDer } = makeSigningKey();

  const env = await mintAprV2({
    issuer: "did:web:invoiceup.app",
    signingKey,
    subject: "sha256:" + "c".repeat(64),
    body,
    anchor,
  });

  // resolveKey: strip "ed25519:" prefix, decode raw 32 bytes, wrap in SPKI DER
  const result = await verifyReceipt(env, {
    resolveKey: async (envelope: unknown) => {
      const issKey = (envelope as { iss_key: string }).iss_key;
      const raw = base64UrlDecode(issKey.replace("ed25519:", ""));
      return new Uint8Array(Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]));
    },
  });

  assert.equal(result.envelope_version, 2);
  assert.equal(result.signature_valid, true);
  assert.equal(result.claim_type, "ar.provenance.v1");
});

test("T3: mintAprV2 with TSA stub returning malformed TSR — propagates error from attachTsaBlock", async () => {
  const { signingKey } = makeSigningKey();

  const tsaCfg: TsaConfig = {
    url: "https://freetsa.org/tsr",
    hashAlg: "sha-256",
    timeoutMs: 5000,
    trustAnchorIds: [],
    driftToleranceSec: 60,
  };

  // Stub fetcher returns bytes that are not a valid TSR.
  // parseTimeStampResp inside attachTsaBlock will throw — mintAprV2 must NOT
  // swallow it. We assert only that mintAprV2 rejects (any error type is fine;
  // wrapping the parse error in TsaMintError is a future hardening concern).
  const stubFetcher = async (_req: Uint8Array, _url: string): Promise<Uint8Array> => {
    return new Uint8Array([0x00, 0x01, 0x02]);
  };

  await assert.rejects(
    () => mintAprV2({ issuer: "did:web:test.example", signingKey, subject: "sha256:xx", body, anchor, tsa: tsaCfg, tsaFetcher: stubFetcher }),
    (err: unknown) => {
      assert.ok(err instanceof Error, `expected Error, got: ${String(err)}`);
      return true;
    },
    "should propagate error from attachTsaBlock — not swallow it",
  );
});

test("T4: mintAprV2 with TSA config but no fetcher — throws clear error", async () => {
  const { signingKey } = makeSigningKey();

  const tsaCfg: TsaConfig = {
    url: "https://freetsa.org/tsr",
    hashAlg: "sha-256",
    timeoutMs: 5000,
    trustAnchorIds: [],
    driftToleranceSec: 60,
  };

  await assert.rejects(
    () => mintAprV2({ issuer: "did:web:test.example", signingKey, subject: "sha256:xx", body, anchor, tsa: tsaCfg }),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.ok((err as Error).message.includes("tsaFetcher"), `expected 'tsaFetcher' in message, got: ${(err as Error).message}`);
      return true;
    },
    "should throw when tsa config present but fetcher absent",
  );
});

test("T5: mintAprV2 with TSA fetcher that rejects — propagates TsaMintError", async () => {
  const { signingKey } = makeSigningKey();

  const tsaCfg: TsaConfig = {
    url: "https://freetsa.org/tsr",
    hashAlg: "sha-256",
    timeoutMs: 5000,
    trustAnchorIds: [],
    driftToleranceSec: 60,
  };

  const rejectingFetcher = async (_req: Uint8Array, _url: string): Promise<Uint8Array> => {
    throw new Error("network error: connection refused");
  };

  await assert.rejects(
    () => mintAprV2({ issuer: "did:web:test.example", signingKey, subject: "sha256:yy", body, anchor, tsa: tsaCfg, tsaFetcher: rejectingFetcher }),
    (err: unknown) => {
      assert.ok(err instanceof TsaMintError, `expected TsaMintError, got: ${(err as Error).constructor.name}`);
      return true;
    },
    "should propagate TsaMintError when fetcher rejects",
  );
});

test("T6: mintAprV2 without optional fields — those fields are null, not undefined", async () => {
  const { signingKey } = makeSigningKey();

  const env = await mintAprV2({
    issuer: "did:web:invoiceup.app",
    signingKey,
    subject: "sha256:" + "d".repeat(64),
    body,
    anchor,
    // No prev, exp, policy_uri, policy_hash, policy_version
  });

  // All optional fields must be null (not undefined) for correct JSON serialisation.
  assert.strictEqual(env.prev, null);
  assert.strictEqual(env.exp, null);
  assert.strictEqual(env.policy_uri, null);
  assert.strictEqual(env.policy_hash, null);
  assert.strictEqual(env.policy_version, null);
  assert.strictEqual(env.tsa, null);
  assert.strictEqual(env.credentialStatus, null);
  assert.strictEqual(env.countersig, null);

  // Confirm none are undefined
  assert.notStrictEqual(env.prev, undefined);
  assert.notStrictEqual(env.exp, undefined);
  assert.notStrictEqual(env.policy_uri, undefined);
});

// ── v1.2 envelope additions (Phase E2) ────────────────────────────────────────

test("T-v1.2: minted envelope has iat_ms populated and matching Date.parse(iat)", async () => {
  const { signingKey } = makeSigningKey();
  const env = await mintAprV2({
    issuer: "did:web:invoiceup.app",
    signingKey,
    subject: "sha256:" + "b".repeat(64),
    body,
    anchor,
  });
  assert.equal(typeof env.iat_ms, "number");
  assert.equal(env.iat_ms, Date.parse(env.iat));
});

test("T-v1.2: minted envelope has kind === null per spec §6", async () => {
  const { signingKey } = makeSigningKey();
  const env = await mintAprV2({
    issuer: "did:web:invoiceup.app",
    signingKey,
    subject: "sha256:" + "b".repeat(64),
    body,
    anchor,
  });
  assert.strictEqual(env.kind, null);
});

test("T-v1.2: explicit kind: null passes through (API symmetry)", async () => {
  const { signingKey } = makeSigningKey();
  const env = await mintAprV2({
    issuer: "did:web:invoiceup.app",
    signingKey,
    subject: "sha256:" + "b".repeat(64),
    body,
    anchor,
    kind: null,
  });
  assert.strictEqual(env.kind, null);
});

test("T-v1.2: kind: 'decision' on APR throws (spec §6 + L9)", async () => {
  const { signingKey } = makeSigningKey();
  await assert.rejects(
    async () =>
      mintAprV2({
        issuer: "did:web:invoiceup.app",
        signingKey,
        subject: "sha256:" + "b".repeat(64),
        body,
        anchor,
        kind: "decision",
      }),
    /kind must be null on ar\.provenance\.v1/,
  );
});

test("T-v1.2: kind: 'observation' on APR throws (spec §6 + L9)", async () => {
  const { signingKey } = makeSigningKey();
  await assert.rejects(
    async () =>
      mintAprV2({
        issuer: "did:web:invoiceup.app",
        signingKey,
        subject: "sha256:" + "b".repeat(64),
        body,
        anchor,
        kind: "observation",
      }),
    /kind must be null on ar\.provenance\.v1/,
  );
});

test("T-v1.2: optional cause is plumbed through to the envelope", async () => {
  const { signingKey } = makeSigningKey();
  const env = await mintAprV2({
    issuer: "did:web:invoiceup.app",
    signingKey,
    subject: "sha256:" + "b".repeat(64),
    body,
    anchor,
    cause: "manual",
  });
  assert.equal(env.cause, "manual");
});

test("T-qts: non-null qts_attestation_hash round-trips through mint and verify", async () => {
  const { signingKey, spkiDer } = makeSigningKey();
  const qtsHash = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
  const qtsBody: APRBody = { ...body, qts_attestation_hash: qtsHash };

  const env = await mintAprV2({
    issuer: "did:web:invoiceup.app",
    signingKey,
    subject: "sha256:" + "q".repeat(64),
    body: qtsBody,
    anchor,
  });

  // body.qts_attestation_hash preserved in envelope
  assert.equal((env.body as APRBody).qts_attestation_hash, qtsHash);

  // round-trip through verifier
  const result = await verifyReceipt(env, {
    resolveKey: async (envelope: unknown) => {
      const issKey = (envelope as { iss_key: string }).iss_key;
      const raw = base64UrlDecode(issKey.replace("ed25519:", ""));
      return new Uint8Array(Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]));
    },
  });

  assert.equal(result.envelope_version, 2);
  assert.equal(result.signature_valid, true);
});

test("T-v1.2: omitted cause defaults to null", async () => {
  const { signingKey } = makeSigningKey();
  const env = await mintAprV2({
    issuer: "did:web:invoiceup.app",
    signingKey,
    subject: "sha256:" + "b".repeat(64),
    body,
    anchor,
  });
  assert.strictEqual(env.cause, null);
});
