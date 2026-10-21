/**
 * Tests for mintAcrV2 — ACR v=2 envelope mint path.
 * Phase B Task 12c.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as crypto from "node:crypto";

import { mintAcrV2, TsaMintError } from "../src/issue/index.ts";
import type { MintAcrV2Input, AcrV2Body } from "../src/issue/index.ts";
import { verifyReceipt } from "../src/index.ts";
import { base64UrlDecode } from "@dekimuhq/anchors-envelope";
import type { AnchorProof } from "@dekimuhq/anchors-envelope";
import type { TsaConfig } from "@dekimuhq/anchors-envelope/tsa";

// ── Shared helpers ─────────────────────────────────────────────────────────────

const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const ED25519_SPKI_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

function makeKeypair(): {
  keypair: { kid: string; privateKey: Uint8Array };
  spkiDer: Buffer;
} {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const seed = (
    privateKey.export({ format: "der", type: "pkcs8" }) as Buffer
  ).subarray(-32);
  const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  return {
    keypair: {
      kid: "test-kid-" + Math.random().toString(36).slice(2),
      privateKey: new Uint8Array(seed),
    },
    spkiDer: pkDer,
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

const baseFields: MintAcrV2Input["fields"] = {
  sub_commit: { value: "user@example.com" },
  purposes: [{ value: "marketing" }, { value: "analytics" }],
  policy_hash: { value: "sha256:" + "a".repeat(64) },
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
    fields: baseFields,
    lawful_basis: "6(1)(a)",
    granted_at: "2026-05-17T10:00:00Z",
    anchor,
    // ACR claim types are POLICY_BOUND (Phase C Task 14) — envelope-level
    // policy_* fields are required for verifier round-trips to pass.
    policy_uri: "https://bank.example/privacy",
    policy_hash: "sha256:" + "f".repeat(64),
    policy_version: "1.0.0",
    ...overrides,
  };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test("T1: mintAcrV2 happy path WITHOUT TSA — valid v=2 consent envelope", async () => {
  const { keypair } = makeKeypair();

  const env = await mintAcrV2(makeBaseInput(keypair));

  // Envelope version
  assert.equal(env.v, 2);

  // claim_type
  assert.equal(env.claim_type, "ar.consent.v1");

  // id — 26-char Crockford-Base32 ULID
  assert.match(env.id, /^[0-9A-HJKMNP-TV-Z]{26}$/);

  // iat — valid ISO 8601 UTC
  assert.ok(!isNaN(Date.parse(env.iat)), "iat must be a valid date");

  // iss_key format
  assert.match(env.iss_key, /^ed25519:[A-Za-z0-9_-]+$/);

  // subject passes through
  assert.equal(env.subject, "sha256:" + "b".repeat(64));

  // tsa is null (no TSA config supplied)
  assert.equal(env.tsa, null);

  // credentialStatus is null
  assert.equal(env.credentialStatus, null);

  // sig present — 64 bytes
  assert.ok(typeof env.sig === "string" && env.sig.length > 0);
  const sigBytes = base64UrlDecode(env.sig);
  assert.equal(sigBytes.length, 64, "Ed25519 sig must be 64 bytes");

  // body contains ACR-specific fields including field_root
  const body = env.body as AcrV2Body;
  assert.ok(
    typeof body.field_root === "string" && body.field_root.length > 0,
    "body.field_root must be present",
  );
  assert.ok(
    typeof body.sub_commit === "string",
    "body.sub_commit must be present",
  );
  assert.ok(Array.isArray(body.purposes), "body.purposes must be an array");
  assert.equal(body.purposes.length, 2);
  assert.equal(body.profile, "gdpr.art7");
  assert.equal(body.lawful_basis, "6(1)(a)");
  assert.equal(body.granted_at, "2026-05-17T10:00:00Z");
});

test("T2: each claim_type mints correctly — consent, withdrawal, modification", async () => {
  const kinds = [
    "ar.consent.v1",
    "ar.withdrawal.v1",
    "ar.modification.v1",
  ] as const;

  for (const kind of kinds) {
    const { keypair } = makeKeypair();
    const env = await mintAcrV2(makeBaseInput(keypair, { kind }));
    assert.equal(env.v, 2, `v=2 for kind ${kind}`);
    assert.equal(env.claim_type, kind, `claim_type matches for kind ${kind}`);
    assert.ok(
      (env.body as AcrV2Body).field_root,
      `field_root present for kind ${kind}`,
    );
  }
});

test("T3: withdrawal with prev — sets prev correctly on the envelope", async () => {
  const { keypair } = makeKeypair();
  const priorId = "01HXX0000000000000000CONSENT";

  const env = await mintAcrV2(
    makeBaseInput(keypair, {
      kind: "ar.withdrawal.v1",
      prev: priorId,
    }),
  );

  assert.equal(env.prev, priorId);
  assert.equal(env.claim_type, "ar.withdrawal.v1");
});

test("T4: TSA config without fetcher — throws error mentioning tsaFetcher", async () => {
  const { keypair } = makeKeypair();

  const tsaCfg: TsaConfig = {
    url: "https://freetsa.org/tsr",
    hashAlg: "sha-256",
    timeoutMs: 5000,
    trustAnchorIds: [],
    driftToleranceSec: 60,
  };

  await assert.rejects(
    () => mintAcrV2(makeBaseInput(keypair, { tsa: tsaCfg })),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.ok(
        (err as Error).message.includes("tsaFetcher"),
        `expected 'tsaFetcher' in message, got: ${(err as Error).message}`,
      );
      return true;
    },
    "should throw when tsa config present but fetcher absent",
  );
});

test("T5: TSA fetcher that rejects — propagates TsaMintError", async () => {
  const { keypair } = makeKeypair();

  const tsaCfg: TsaConfig = {
    url: "https://freetsa.org/tsr",
    hashAlg: "sha-256",
    timeoutMs: 5000,
    trustAnchorIds: [],
    driftToleranceSec: 60,
  };

  const rejectingFetcher = async (
    _req: Uint8Array,
    _url: string,
  ): Promise<Uint8Array> => {
    throw new Error("network error: connection refused");
  };

  await assert.rejects(
    () =>
      mintAcrV2(
        makeBaseInput(keypair, { tsa: tsaCfg, tsaFetcher: rejectingFetcher }),
      ),
    (err: unknown) => {
      assert.ok(
        err instanceof TsaMintError,
        `expected TsaMintError, got: ${(err as Error).constructor.name}`,
      );
      return true;
    },
    "should propagate TsaMintError when fetcher rejects",
  );
});

test("T6: envelope fields are null (not undefined) when not supplied; policy_* are surfaced when supplied", async () => {
  const { keypair } = makeKeypair();

  const env = await mintAcrV2(makeBaseInput(keypair));

  // Truly-optional fields default to null (not undefined) for correct JSON serialisation.
  assert.strictEqual(env.prev, null);
  assert.strictEqual(env.exp, null);
  assert.strictEqual(env.tsa, null);
  assert.strictEqual(env.credentialStatus, null);
  assert.strictEqual(env.countersig, null);

  // policy_* fields are populated from makeBaseInput (POLICY_BOUND requirement
  // for ACR claim types — Phase C Task 14).
  assert.strictEqual(env.policy_uri, "https://bank.example/privacy");
  assert.strictEqual(env.policy_hash, "sha256:" + "f".repeat(64));
  assert.strictEqual(env.policy_version, "1.0.0");

  // Confirm none are undefined
  assert.notStrictEqual(env.prev, undefined);
  assert.notStrictEqual(env.exp, undefined);
  assert.notStrictEqual(env.policy_uri, undefined);
});

test("T7: round-trip with acr-verifier v=2 dispatch — signature_valid: true", async () => {
  const { keypair, spkiDer } = makeKeypair();

  const env = await mintAcrV2(makeBaseInput(keypair));

  const result = await verifyReceipt(env, {
    resolveKey: async (envelope: unknown) => {
      const issKey = (envelope as { iss_key: string }).iss_key;
      const raw = base64UrlDecode(issKey.replace("ed25519:", ""));
      return new Uint8Array(
        Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]),
      );
    },
  });

  assert.equal(result.envelope_version, 2);
  assert.equal(result.signature_valid, true);
  assert.equal(result.claim_type, "ar.consent.v1");
});

// ── v1.2 envelope additions (Phase E3) ────────────────────────────────────────

test("T-v1.2: minted ACR envelope has iat_ms matching Date.parse(iat)", async () => {
  const { keypair } = makeKeypair();
  const env = await mintAcrV2(makeBaseInput(keypair));
  assert.equal(typeof env.iat_ms, "number");
  assert.equal(env.iat_ms, Date.parse(env.iat));
});

test("T-v1.2: minted ACR envelope defaults envelope kind to 'decision'", async () => {
  const { keypair } = makeKeypair();
  const env = await mintAcrV2(makeBaseInput(keypair));
  assert.equal(env.kind, "decision");
});

test("T-v1.2: explicit envelope_kind: null passes through (v1.1-compat issuance)", async () => {
  const { keypair } = makeKeypair();
  const env = await mintAcrV2(makeBaseInput(keypair, { envelope_kind: null }));
  assert.strictEqual(env.kind, null);
});

test("T-v1.2: explicit envelope_kind: 'observation' passes through", async () => {
  const { keypair } = makeKeypair();
  const env = await mintAcrV2(makeBaseInput(keypair, { envelope_kind: "observation" }));
  assert.equal(env.kind, "observation");
});

test("T-v1.2: optional cause is plumbed through", async () => {
  const { keypair } = makeKeypair();
  const env = await mintAcrV2(makeBaseInput(keypair, { cause: "manual" }));
  assert.equal(env.cause, "manual");
});

test("T-v1.2: omitted cause defaults to null", async () => {
  const { keypair } = makeKeypair();
  const env = await mintAcrV2(makeBaseInput(keypair));
  assert.strictEqual(env.cause, null);
});

test("T-v1.2: optional predicate is plumbed through and roundtrips through verify", async () => {
  const { keypair, spkiDer } = makeKeypair();
  const predicate = { "===": [1, 1] } as unknown as NonNullable<
    Parameters<typeof mintAcrV2>[0]["predicate"]
  >;
  const env = await mintAcrV2(makeBaseInput(keypair, { predicate }));
  assert.deepEqual(env.predicate, { "===": [1, 1] });

  // The verifier accepts a satisfied predicate.
  const result = await verifyReceipt(env, {
    resolveKey: async () => new Uint8Array(spkiDer),
  });
  assert.equal(result.signature_valid, true, `unexpected reason: ${result.reason}`);
});

test("T-v1.2: omitted predicate defaults to null", async () => {
  const { keypair } = makeKeypair();
  const env = await mintAcrV2(makeBaseInput(keypair));
  assert.strictEqual(env.predicate, null);
});

// ── QTS cross-sibling attestation hash ───────────────────────────────────────

test("T-qts: non-null qts_attestation_hash round-trips through mint and verify", async () => {
  const { keypair, spkiDer } = makeKeypair();
  const QTS_HASH = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
  const env = await mintAcrV2(makeBaseInput(keypair, { qts_attestation_hash: QTS_HASH }));

  const body = env.body as AcrV2Body;
  assert.equal(body.qts_attestation_hash, QTS_HASH);

  const result = await verifyReceipt(env, {
    resolveKey: async () => new Uint8Array(spkiDer),
  });
  assert.equal(result.signature_valid, true);
  assert.equal((result as { claim_type?: string }).claim_type, "ar.consent.v1");
});

test("T-qts: omitted qts_attestation_hash defaults to null in body", async () => {
  const { keypair } = makeKeypair();
  const env = await mintAcrV2(makeBaseInput(keypair));
  const body = env.body as AcrV2Body;
  assert.strictEqual(body.qts_attestation_hash, null);
});
