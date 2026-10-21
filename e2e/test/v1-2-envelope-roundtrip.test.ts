/**
 * v1.2 envelope amendment — end-to-end mint + verify conformance vectors.
 *
 * Builds envelopes directly via `signEnvelope` so the test exercises the
 * verifier predicate path against arbitrary synthetic bodies — independent
 * of any one member's issuer-kit body shape (ACR's `field_root` commits,
 * ARR's retention fields, etc.). This is the same shortcut taken in
 * `_helpers/v2-receipt-acr.ts` for the cross-issuer trusted-logs tests.
 *
 * Each test asserts the verifier's signature_valid + reason against the
 * v1.2 predicate contract. The four §5.5 worked examples all use ACR
 * (`ar.consent.v1`) — the predicate-recommended member per spec §6.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/envelope §5.5 + §7
 * Plan: Phase F.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";

import { verifyReceipt as verifyAcr } from "@dekimuhq/acr";
import { verifyReceipt as verifyApr } from "@dekimuhq/apr";
import { signEnvelope, base64UrlEncode } from "@dekimuhq/anchors-envelope";
import type {
  Envelope,
  JsonLogicAst,
  ClaimType,
  Kind,
  Cause,
} from "@dekimuhq/anchors-envelope";

// ── helpers ──────────────────────────────────────────────────────────────────

interface KeyMaterial {
  privateKey: crypto.KeyObject;
  pubDer: Uint8Array;
  issKey: `ed25519:${string}`;
}

function makeKey(): KeyMaterial {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const pubDer = new Uint8Array(publicKey.export({ format: "der", type: "spki" }) as Buffer);
  const pkRaw = pubDer.subarray(-32);
  const issKey: `ed25519:${string}` = `ed25519:${base64UrlEncode(new Uint8Array(pkRaw))}`;
  return { privateKey, pubDer, issKey };
}

interface BuildOpts {
  claim_type: ClaimType;
  body: unknown;
  predicate?: JsonLogicAst | null;
  kind?: Kind | null;
  cause?: Cause | null;
  iat_ms_override?: number; // for the iat_ms_mismatch test
  policy?: boolean;
}

async function build(km: KeyMaterial, opts: BuildOpts): Promise<Envelope> {
  const iat = "2026-05-17T00:00:00Z";
  const unsigned: Envelope = {
    v: 2,
    id: `01HZX${Math.floor(Math.random() * 1e10).toString(32).toUpperCase().padStart(21, "0")}`,
    iat,
    iat_ms: opts.iat_ms_override ?? Date.parse(iat),
    claim_type: opts.claim_type,
    iss: "did:web:example.com",
    iss_key: km.issKey,
    subject: "sha256:" + "a".repeat(64),
    exp: null,
    prev: null,
    policy_uri: opts.policy ? "https://example.com/policy" : null,
    policy_hash: opts.policy ? "sha256:" + "a".repeat(64) : null,
    policy_version: opts.policy ? "1.0" : null,
    kind: opts.kind ?? null,
    cause: opts.cause ?? null,
    predicate: opts.predicate ?? null,
    tsa: null,
    credentialStatus: null,
    anchor: {
      log: "https://verify.dekimu.com/test/v1",
      leaf_index: 0,
      inclusion_proof: [],
      tree_head_root: "sha256:" + "0".repeat(64),
      tree_size: 1,
      log_time: "2026-05-17T00:00:00Z",
    },
    sig: "",
    countersig: null,
    body: opts.body,
  };
  return signEnvelope(unsigned, km.privateKey);
}

// ── ACR § 5.5 example 1 — age + purpose ──────────────────────────────────────

test("acr v1.2 — §5.5 ex.1 (age + purpose) satisfied", async () => {
  const km = makeKey();
  const predicate: JsonLogicAst = {
    and: [
      { ">=": [{ var: "body.subject_age" }, 16] },
      { in: [{ var: "body.purpose" }, ["analytics", "fraud"]] },
    ],
  };
  const env = await build(km, {
    claim_type: "ar.consent.v1",
    body: { subject_age: 18, purpose: "analytics" },
    predicate,
    kind: "decision",
    cause: "manual",
    policy: true,
  });
  const r = await verifyAcr(env, { resolveKey: async () => km.pubDer });
  assert.strictEqual(r.signature_valid, true, `expected valid, got reason=${r.reason}`);
});

// ── ACR § 5.5 example 2 — retention vs iat_ms (false case) ───────────────────

test("acr v1.2 — §5.5 ex.2 (retention vs iat_ms) — not-yet-expired => predicate_evaluation_false", async () => {
  const km = makeKey();
  const predicate: JsonLogicAst = {
    "<": [{ var: "body.retention_expires_at" }, { var: "iat_ms" }],
  };
  const env = await build(km, {
    claim_type: "ar.consent.v1",
    body: { retention_expires_at: Date.parse("2030-01-01T00:00:00Z") }, // far future
    predicate,
    kind: "decision",
    policy: true,
  });
  const r = await verifyAcr(env, { resolveKey: async () => km.pubDer });
  assert.strictEqual(r.signature_valid, false);
  assert.strictEqual(r.reason, "predicate_evaluation_false");
});

// ── ACR § 5.5 example 2b — retention vs iat_ms (true case) ───────────────────

test("acr v1.2 — §5.5 ex.2 — expired-retention satisfies <", async () => {
  const km = makeKey();
  const predicate: JsonLogicAst = {
    "<": [{ var: "body.retention_expires_at" }, { var: "iat_ms" }],
  };
  const env = await build(km, {
    claim_type: "ar.consent.v1",
    body: { retention_expires_at: Date.parse("2020-01-01T00:00:00Z") },
    predicate,
    kind: "decision",
    cause: "scheduled",
    policy: true,
  });
  const r = await verifyAcr(env, { resolveKey: async () => km.pubDer });
  assert.strictEqual(r.signature_valid, true, `expected valid, got reason=${r.reason}`);
});

// ── ACR § 5.5 example 3 — EEA membership OR adequacy ─────────────────────────

test("acr v1.2 — §5.5 ex.3 (EEA OR adequacy) — EEA path satisfies", async () => {
  const km = makeKey();
  const predicate: JsonLogicAst = {
    or: [
      {
        in: [
          { var: "body.destination_country" },
          ["AT", "BE", "BG", "DE", "ES", "FR", "IT", "NL", "PT", "SE"],
        ],
      },
      { "===": [{ var: "body.adequacy_basis" }, "art45_adequacy_decision"] },
    ],
  };
  const env = await build(km, {
    claim_type: "ar.consent.v1",
    body: { destination_country: "ES", adequacy_basis: null },
    predicate,
    kind: "decision",
    policy: true,
  });
  const r = await verifyAcr(env, { resolveKey: async () => km.pubDer });
  assert.strictEqual(r.signature_valid, true, `expected valid, got reason=${r.reason}`);
});

// ── ACR § 5.5 example 4 — 'some' over principal-approvals ────────────────────

test("acr v1.2 — §5.5 ex.4 ('some' over array) satisfied", async () => {
  const km = makeKey();
  const predicate: JsonLogicAst = {
    some: [{ var: "body.principal_approvals" }, { "===": [{ var: "" }, true] }],
  };
  const env = await build(km, {
    claim_type: "ar.consent.v1",
    body: { principal_approvals: [false, false, true] },
    predicate,
    kind: "decision",
    policy: true,
  });
  const r = await verifyAcr(env, { resolveKey: async () => km.pubDer });
  assert.strictEqual(r.signature_valid, true, `expected valid, got reason=${r.reason}`);
});

// ── APR — forbidden predicate on ar.provenance.v1 ────────────────────────────

test("apr v1.2 — predicate on ar.provenance.v1 surfaces predicate_forbidden_on_claim_type", async () => {
  const km = makeKey();
  const env = await build(km, {
    claim_type: "ar.provenance.v1",
    body: { artifact_hash: "sha256:" + "f".repeat(64) },
    predicate: { "===": [1, 1] },
    cause: "scheduled",
  });
  const r = await verifyApr(env, { resolveKey: async () => km.pubDer });
  assert.strictEqual(r.signature_valid, false);
  assert.strictEqual(r.reason, "predicate_forbidden_on_claim_type");
});

// ── ACR — iat_ms mismatch surfaces error code ────────────────────────────────

test("acr v1.2 — iat_ms !== Date.parse(iat) surfaces iat_ms_mismatch", async () => {
  const km = makeKey();
  const env = await build(km, {
    claim_type: "ar.consent.v1",
    body: { subject_age: 18 },
    kind: "decision",
    iat_ms_override: 12345, // wrong
    policy: true,
  });
  const r = await verifyAcr(env, { resolveKey: async () => km.pubDer });
  assert.strictEqual(r.signature_valid, false);
  assert.strictEqual(r.reason, "iat_ms_mismatch");
});

// ── ACR — disallowed operator (map) surfaces predicate_operator_not_allowed ─

test("acr v1.2 — disallowed operator surfaces predicate_operator_not_allowed", async () => {
  const km = makeKey();
  const predicate = { map: [[], { var: "" }] } as unknown as JsonLogicAst;
  const env = await build(km, {
    claim_type: "ar.consent.v1",
    body: {},
    predicate,
    kind: "decision",
    policy: true,
  });
  const r = await verifyAcr(env, { resolveKey: async () => km.pubDer });
  assert.strictEqual(r.signature_valid, false);
  assert.strictEqual(r.reason, "predicate_operator_not_allowed");
});

// ── Backwards-compat: v1.1-shaped envelope (no v1.2 fields) verifies cleanly ─

test("acr v1.2 — v1.1-shaped envelope (no iat_ms / kind / cause / predicate) still verifies", async () => {
  const km = makeKey();
  const iat = "2026-05-17T00:00:00Z";
  const v11Env: Envelope = {
    v: 2,
    id: "01HZX0000000000000000000ABCD",
    iat,
    claim_type: "ar.consent.v1",
    iss: "did:web:example.com",
    iss_key: km.issKey,
    subject: "sha256:" + "a".repeat(64),
    exp: null,
    prev: null,
    policy_uri: "https://example.com/policy",
    policy_hash: "sha256:" + "a".repeat(64),
    policy_version: "1.0",
    tsa: null,
    credentialStatus: null,
    anchor: {
      log: "https://verify.dekimu.com/test/v1",
      leaf_index: 0,
      inclusion_proof: [],
      tree_head_root: "sha256:" + "0".repeat(64),
      tree_size: 1,
      log_time: iat,
    },
    sig: "",
    countersig: null,
    body: { lawful_basis: "6(1)(a)" },
  };
  const signed = await signEnvelope(v11Env, km.privateKey);
  const r = await verifyAcr(signed, { resolveKey: async () => km.pubDer });
  assert.strictEqual(r.signature_valid, true, `expected valid, got reason=${r.reason}`);
});
