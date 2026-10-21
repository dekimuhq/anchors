/**
 * Tests for `mintAlrV2` — Phase 1 §H of the 10-spec batch.
 *
 * Covers each of the four ALR event types end-to-end through
 * `@dekimuhq/alr-verifier`'s `verifyReceipt` to prove the issuer-kit emits
 * receipts the verifier accepts as `signature_valid` + `body_valid`.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";

import { mintAlrV2, type MintAlrV2Input } from "../src/issue/index.ts";
import { verifyReceipt } from "../src/index.ts";
import { base64UrlDecode } from "@dekimuhq/anchors-envelope";
import type { AnchorProof } from "@dekimuhq/anchors-envelope";

const ED25519_SPKI_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

const H = (b: string) => `sha256:${b.repeat(64)}`;
const A = H("a");
const B = H("b");
const C = H("c");
const D = H("d");

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
  log: "https://verify.dekimu.com/alr/v1",
  leaf_index: 0,
  inclusion_proof: [],
  tree_head_root: "sha256:" + "0".repeat(64),
  tree_size: 1,
  log_time: "2026-05-17T00:00:00Z",
};

function makeResolveKey() {
  return async (envelope: unknown): Promise<Uint8Array> => {
    const issKey = (envelope as { iss_key: string }).iss_key;
    const raw = base64UrlDecode(issKey.replace("ed25519:", ""));
    return new Uint8Array(Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]));
  };
}

function common(signingKey: ReturnType<typeof makeSigningKey>["signingKey"]) {
  return {
    issuer: "did:web:processor.example",
    signingKey,
    profile: "aiact.art13.transparency" as const,
    artifact_hash: C,
    event_at: "2026-05-16T14:23:00Z",
    policy_uri: "https://processor.example/lineage-policy",
    policy_hash: "sha256:" + "e".repeat(64),
    policy_version: "1.0.0",
    anchor,
  };
}

test("T1: derived_from happy path — round-trips through verifier", async () => {
  const { signingKey } = makeSigningKey();
  const input: MintAlrV2Input = {
    ...common(signingKey),
    event_type: "derived_from",
    parents: [
      { artifact_hash: B, parent_apr_id: null, parent_alr_id: null, uri: null },
      { artifact_hash: A, parent_apr_id: null, parent_alr_id: null, uri: null },
    ],
    transform_claim: { summary: "fine-tune", uri: null },
  };

  const env = await mintAlrV2(input);

  assert.equal(env.v, 2);
  assert.equal(env.claim_type, "ar.lineage.v1");
  assert.match(env.id, /^[0-9A-HJKMNP-TV-Z]{26}$/);
  assert.ok(!isNaN(Date.parse(env.iat)));
  assert.match(env.iss_key, /^ed25519:[A-Za-z0-9_-]+$/);
  assert.equal(base64UrlDecode(env.sig).length, 64);
  assert.strictEqual(env.subject, null);

  const body = env.body as Record<string, unknown>;
  assert.equal(body.event_type, "derived_from");
  assert.ok(typeof body.field_root === "string");
  assert.ok((body.field_root as string).startsWith("sha256:"));

  // Issuer sorts parents canonically by artifact_hash; A < B.
  const parents = body.parents as Array<{ artifact_hash: string }>;
  assert.equal(parents[0]?.artifact_hash, A);
  assert.equal(parents[1]?.artifact_hash, B);

  const result = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(result.envelope_version, 2);
  assert.equal(result.signature_valid, true, result.reason ?? "ok");
  assert.equal(result.claim_type, "ar.lineage.v1");
});

test("T2: forked_from happy path", async () => {
  const { signingKey } = makeSigningKey();
  const env = await mintAlrV2({
    ...common(signingKey),
    event_type: "forked_from",
    parents: [{ artifact_hash: A, parent_apr_id: null, parent_alr_id: null, uri: null }],
    transform_claim: { summary: "fork", uri: null },
  });

  const result = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(result.signature_valid, true, result.reason ?? "ok");
  const body = env.body as Record<string, unknown>;
  assert.equal(body.event_type, "forked_from");
  assert.equal((body.parents as unknown[]).length, 1);
});

test("T3: superseded_by happy path", async () => {
  const { signingKey } = makeSigningKey();
  const env = await mintAlrV2({
    ...common(signingKey),
    event_type: "superseded_by",
    successor: { artifact_hash: B, parent_apr_id: null, parent_alr_id: null, uri: null },
    transform_claim: { summary: "supersede", uri: null },
  });

  const result = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(result.signature_valid, true, result.reason ?? "ok");
  const body = env.body as Record<string, unknown>;
  assert.equal(body.event_type, "superseded_by");
  assert.deepEqual(body.parents, []);
  assert.ok(body.successor);
});

test("T4: disclosed happy path", async () => {
  const { signingKey } = makeSigningKey();
  const env = await mintAlrV2({
    ...common(signingKey),
    event_type: "disclosed",
    disclosure: {
      recipient: "did:web:auditor.example",
      recipient_role: "auditor",
      scope_hash: D,
      basis: "gdpr.art6.1.c",
    },
  });

  const result = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(result.signature_valid, true, result.reason ?? "ok");
  const body = env.body as Record<string, unknown>;
  assert.equal(body.event_type, "disclosed");
  assert.equal(body.transform_claim, null);
  assert.ok(body.disclosure);
});

test("T5: subject is null on every event_type (FAMILY-CONSISTENCY §3)", async () => {
  const { signingKey } = makeSigningKey();
  const cases: MintAlrV2Input[] = [
    {
      ...common(signingKey),
      event_type: "derived_from",
      parents: [{ artifact_hash: A, parent_apr_id: null, parent_alr_id: null, uri: null }],
      transform_claim: { summary: "x", uri: null },
    },
    {
      ...common(signingKey),
      event_type: "forked_from",
      parents: [{ artifact_hash: A, parent_apr_id: null, parent_alr_id: null, uri: null }],
    },
    {
      ...common(signingKey),
      event_type: "superseded_by",
      successor: { artifact_hash: B, parent_apr_id: null, parent_alr_id: null, uri: null },
      transform_claim: { summary: "x", uri: null },
    },
    {
      ...common(signingKey),
      event_type: "disclosed",
      disclosure: {
        recipient: "did:web:r",
        recipient_role: "auditor",
        scope_hash: D,
        basis: "gdpr.art6.1.c",
      },
    },
  ];
  for (const input of cases) {
    const env = await mintAlrV2(input);
    assert.strictEqual(env.subject, null, `subject must be null for ${input.event_type}`);
  }
});

test("T6: v1.2 envelope_kind defaults to 'decision' but is overridable", async () => {
  const { signingKey } = makeSigningKey();
  const baseInput = {
    ...common(signingKey),
    event_type: "forked_from" as const,
    parents: [{ artifact_hash: A, parent_apr_id: null, parent_alr_id: null, uri: null }] as [
      { artifact_hash: string; parent_apr_id: null; parent_alr_id: null; uri: null },
    ],
  };

  const envDefault = await mintAlrV2(baseInput);
  assert.equal(envDefault.kind, "decision");

  const envObs = await mintAlrV2({ ...baseInput, envelope_kind: "observation" });
  assert.equal(envObs.kind, "observation");

  const envNull = await mintAlrV2({ ...baseInput, envelope_kind: null });
  assert.equal(envNull.kind, null);
});

test("T7: v1.2 cause + predicate plumbed verbatim", async () => {
  const { signingKey } = makeSigningKey();
  const env = await mintAlrV2({
    ...common(signingKey),
    event_type: "forked_from",
    parents: [{ artifact_hash: A, parent_apr_id: null, parent_alr_id: null, uri: null }],
    cause: "material_change",
    predicate: { "==": [1, 1] },
  });
  assert.equal(env.cause, "material_change");
  assert.deepEqual(env.predicate, { "==": [1, 1] });
});

test("T8: prev + exp pass-through", async () => {
  const { signingKey } = makeSigningKey();
  const env = await mintAlrV2({
    ...common(signingKey),
    event_type: "forked_from",
    parents: [{ artifact_hash: A, parent_apr_id: null, parent_alr_id: null, uri: null }],
    prev: "01HXX0000000000000000PREVID0",
    exp: "2027-01-01T00:00:00Z",
  });
  assert.equal(env.prev, "01HXX0000000000000000PREVID0");
  assert.equal(env.exp, "2027-01-01T00:00:00Z");
});

test("T9: signingKey size validation", async () => {
  await assert.rejects(
    () => mintAlrV2({
      ...common({ kid: "k", privateKey: new Uint8Array(31) }),
      event_type: "forked_from",
      parents: [{ artifact_hash: A, parent_apr_id: null, parent_alr_id: null, uri: null }],
    }),
    /32-byte Ed25519 seed/,
  );
});

test("T10: derived_from requires ≥1 parent", async () => {
  const { signingKey } = makeSigningKey();
  await assert.rejects(
    () => mintAlrV2({
      ...common(signingKey),
      event_type: "derived_from",
      parents: [],
      transform_claim: { summary: "x", uri: null },
    }),
    /≥1 parent/,
  );
});

test("T11: disclosed requires all four disclosure sub-fields", async () => {
  const { signingKey } = makeSigningKey();
  await assert.rejects(
    () => mintAlrV2({
      ...common(signingKey),
      event_type: "disclosed",
      disclosure: {
        recipient: "did:web:r",
        recipient_role: "",
        scope_hash: D,
        basis: "gdpr.art6.1.c",
      },
    }),
    /all 4 disclosure sub-fields/,
  );
});

test("T12: iat_ms equals Date.parse(iat)", async () => {
  const { signingKey } = makeSigningKey();
  const env = await mintAlrV2({
    ...common(signingKey),
    event_type: "forked_from",
    parents: [{ artifact_hash: A, parent_apr_id: null, parent_alr_id: null, uri: null }],
  });
  assert.equal(env.iat_ms, Date.parse(env.iat));
});

test("T13: tsa config without fetcher throws", async () => {
  const { signingKey } = makeSigningKey();
  await assert.rejects(
    () => mintAlrV2({
      ...common(signingKey),
      event_type: "forked_from",
      parents: [{ artifact_hash: A, parent_apr_id: null, parent_alr_id: null, uri: null }],
      tsa: {
        url: "https://freetsa.org/tsr",
        hashAlg: "sha-256",
        timeoutMs: 5000,
        trustAnchorIds: [],
        driftToleranceSec: 60,
      },
    }),
    /tsaFetcher required/,
  );
});

test("T_QTS: non-null qts_attestation_hash round-trips through verifier", async () => {
  const QTS = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
  const { signingKey } = makeSigningKey();
  const env = await mintAlrV2({
    ...common(signingKey),
    event_type: "derived_from",
    parents: [{ artifact_hash: A, parent_apr_id: null, parent_alr_id: null, uri: null }],
    transform_claim: { summary: "fine-tune", uri: null },
    qts_attestation_hash: QTS,
  });
  const body = env.body as Record<string, unknown>;
  assert.equal(body.qts_attestation_hash, QTS);
  const result = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(result.signature_valid, true, result.reason ?? "ok");
});
