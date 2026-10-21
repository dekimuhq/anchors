/**
 * Type-shape tests for @dekimuhq/anchors-envelope — Phase A Task 2.
 *
 * Covers:
 *   1. Package exports expected symbols (updated Task 4: sign/verify aliases removed).
 *   2. CLAIM_TYPES const has exactly 28 members (16 baseline + 4 closure-set + 1 ATokR + 1 AActR + 1 AQR + 1 AGR + 1 AGrR + 1 AgTR + 1 APIIR + 1 ACBR).
 *   3. Envelope construction with real shapes type-checks (updated from Task 1).
 *   4. AnchorProof literal compiles with all 6 fields.
 *   5. TsaBlock literal compiles with discriminant fields.
 *   6. CredentialStatus literal compiles with Status List 2021 Entry shape.
 *   7. countersig accepts string and null (reconciled from CounterSig object).
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";

// ── Test 1: package exports expected symbols ─────────────────────────────────

test("package exports expected symbols", async () => {
  const mod = await import("../src/index.ts");

  // Functions
  assert.strictEqual(typeof mod.canonicalize, "function", "canonicalize (raw JCS) export missing");
  assert.strictEqual(typeof mod.canonicalizeEnvelope, "function", "canonicalizeEnvelope (envelope wrapper) export missing");
  assert.strictEqual(typeof mod.signEnvelope, "function", "signEnvelope export missing");
  assert.strictEqual(typeof mod.verifyEnvelopeSignature, "function", "verifyEnvelopeSignature export missing");

  // Runtime const
  assert.ok(Array.isArray(mod.CLAIM_TYPES), "CLAIM_TYPES export missing or not array");
});

// ── Test 2: CLAIM_TYPES has exactly 28 members ───────────────────────────────
// Updated from 16 → 20 by Phase 0 Task 0.1 (closure-set: ANR/ABR/ASR/AIR).
// Updated from 20 → 21 by ATokR registration (ar.tokenization.v1, chip 14).
// Updated from 21 → 22 by AActR registration (ar.action.v1, chip 15).
// Updated from 22 → 23 by AQR registration (ar.quality.v1, chip 16).
// Updated from 23 → 24 by AGR registration (ar.guard.v1, chip 17).
// Updated from 24 → 26 by AGrR (ar.grounding.v1, chip 18) + AgTR (ar.trace.v1, chip 19) registration.
// Updated from 26 → 27 by APIIR registration (ar.redaction.v1, chip 20).
// Updated from 27 → 28 by ACBR registration (ar.compliance.v1, chip 21).
// Updated from 28 → 29 by AgTR v2 registration (ar.trace.v2, chip 19 — OTel span tree).

test("CLAIM_TYPES const has exactly 29 members", async () => {
  const { CLAIM_TYPES } = await import("../src/index.ts");
  assert.strictEqual(
    CLAIM_TYPES.length,
    29,
    `Expected 29 ClaimType literals, got ${CLAIM_TYPES.length}`,
  );
});

// ── Test 3: Envelope construction with real shapes ───────────────────────────
// Constructing a valid Envelope literal exercises exactOptionalPropertyTypes
// + all required fields. tsc --noEmit catches shape mismatches at compile time.

test("Envelope construction type-checks with real shapes (compile-time guard)", async () => {
  const { CLAIM_TYPES } = await import("../src/index.ts");

  const anchor: import("../src/envelope-types.ts").AnchorProof = {
    log: "https://verify.dekimu.com/apr/v1",
    leaf_index: 0,
    inclusion_proof: ["sha256:aabbcc"],
    tree_head_root: "sha256:deadbeef",
    tree_size: 1,
    log_time: "2026-05-16T14:00:00Z",
  };

  const envelope: import("../src/envelope-types.ts").Envelope = {
    v: 2,
    id: "01HZ0000000000000000000000",
    iat: "2026-05-16T14:00:00Z",
    claim_type: CLAIM_TYPES[0]!,
    iss: "did:key:z6Mk...",
    iss_key: "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    subject: "did:key:z6Mk...",
    exp: null,
    prev: null,
    policy_uri: null,
    policy_hash: null,
    policy_version: null,
    tsa: null,
    credentialStatus: null,
    anchor,
    sig: "base64url-sig-placeholder",
    countersig: null,
    body: { _placeholder: true },
  };

  assert.notStrictEqual(envelope, null, "Envelope construction should not be null");
  assert.strictEqual(envelope.v, 2, "Envelope v field should be 2");
});

// ── Test 4: AnchorProof real shape ───────────────────────────────────────────

test("AnchorProof literal compiles with all 6 fields", async () => {
  const anchor: import("../src/envelope-types.ts").AnchorProof = {
    log: "https://verify.dekimu.com/acr/v1",
    leaf_index: 0,
    inclusion_proof: ["sha256:aabbccdd", "sha256:eeff0011"],
    tree_head_root: "sha256:cafebabe",
    tree_size: 1,
    log_time: "2026-05-17T00:00:00Z",
  };

  assert.strictEqual(anchor.tree_size, 1, "tree_size should round-trip as 1");
  assert.strictEqual(anchor.leaf_index, 0, "leaf_index should be 0");
  assert.strictEqual(anchor.inclusion_proof.length, 2, "inclusion_proof should have 2 entries");
});

// ── Test 5: TsaBlock real shape ──────────────────────────────────────────────

test("TsaBlock literal compiles with v:1, alg:sha-256, and one cert pin", async () => {
  const tsa: import("../src/envelope-types.ts").TsaBlock = {
    v: 1,
    tsr: "AQIDBA==",
    alg: "sha-256",
    tsa_url: "https://freetsa.org/tsr",
    tsa_cert_chain_sha256: ["sha256:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"],
    issued_at: "2026-05-16T14:00:00Z",
  };

  assert.strictEqual(tsa.v, 1, "TsaBlock v should be 1");
  assert.strictEqual(tsa.alg, "sha-256", "TsaBlock alg should be sha-256");
  assert.strictEqual(tsa.tsa_cert_chain_sha256.length, 1, "Should have one cert pin");
});

// ── Test 6: CredentialStatus real shape ──────────────────────────────────────

test("CredentialStatus literal compiles with StatusList2021Entry shape", async () => {
  const status: import("../src/envelope-types.ts").CredentialStatus = {
    id: "https://verify.dekimu.com/status/1#94567",
    type: "StatusList2021Entry",
    statusPurpose: "revocation",
    statusListIndex: "94567",
    statusListCredential: "https://verify.dekimu.com/status/1",
  };

  assert.strictEqual(status.type, "StatusList2021Entry", "type literal should be StatusList2021Entry");
  assert.strictEqual(status.statusPurpose, "revocation", "statusPurpose should be revocation");
});

// ── Test 7: countersig accepts string or null ─────────────────────────────────

test("countersig field accepts string and null (string | null contract)", async () => {
  const { CLAIM_TYPES } = await import("../src/index.ts");

  const anchor: import("../src/envelope-types.ts").AnchorProof = {
    log: "https://verify.dekimu.com/apr/v1",
    leaf_index: 0,
    inclusion_proof: [],
    tree_head_root: "sha256:deadbeef",
    tree_size: 1,
    log_time: "2026-05-16T14:00:00Z",
  };

  // Envelope with countersig as string
  const withSig: import("../src/envelope-types.ts").Envelope = {
    v: 2,
    id: "01HZ0000000000000000000001",
    iat: "2026-05-16T14:00:00Z",
    claim_type: CLAIM_TYPES[1]!,
    iss: "did:key:z6Mk...",
    iss_key: "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    subject: "sha256:0000",
    exp: null,
    prev: null,
    policy_uri: null,
    policy_hash: null,
    policy_version: null,
    tsa: null,
    credentialStatus: null,
    anchor,
    sig: "primary-sig-b64url",
    countersig: "AAAA",
    body: {},
  };

  // Envelope with countersig as null
  const withNull: import("../src/envelope-types.ts").Envelope = {
    ...withSig,
    id: "01HZ0000000000000000000002",
    countersig: null,
  };

  assert.strictEqual(withSig.countersig, "AAAA", "countersig should be string 'AAAA'");
  assert.strictEqual(withNull.countersig, null, "countersig should be null");
});

// ── closure-set discriminator tests ──────────────────────────────────────────
//
// Phase 0 Task 0.1 — extends CLAIM_TYPES with ANR/ABR/ASR/AIR discriminators.
// Spec: anchors/meta/REGISTRY.md "Specced Members" table.
// Plan: an internal design record (not published) Phase 0

test("CLAIM_TYPES includes ar.quality.v1 (AQR, chip 16)", async () => {
  const { CLAIM_TYPES } = await import("../src/index.ts");
  assert.ok((CLAIM_TYPES as readonly string[]).includes("ar.quality.v1"));
});

test("CLAIM_TYPES includes ar.guard.v1 (AGR, chip 17)", async () => {
  const { CLAIM_TYPES } = await import("../src/index.ts");
  assert.ok((CLAIM_TYPES as readonly string[]).includes("ar.guard.v1"));
});

test("ar.grounding.v1 is a known claim type", async () => {
  const { CLAIM_TYPES } = await import("../src/index.ts");
  assert.ok((CLAIM_TYPES as readonly string[]).includes("ar.grounding.v1"));
});

test("ar.grounding.v1 is policy-optional", async () => {
  const { POLICY_OPTIONAL } = await import("../src/policy.ts");
  assert.equal(POLICY_OPTIONAL.has("ar.grounding.v1" as never), true);
});

test("CLAIM_TYPES includes ar.trace.v1 (AgTR, chip 19)", async () => {
  const { CLAIM_TYPES } = await import("../src/index.ts");
  assert.ok((CLAIM_TYPES as readonly string[]).includes("ar.trace.v1"));
});

test("ar.trace.v1 is policy-optional", async () => {
  const { POLICY_OPTIONAL } = await import("../src/policy.ts");
  assert.equal(POLICY_OPTIONAL.has("ar.trace.v1" as never), true);
});

test("CLAIM_TYPES includes ar.trace.v2 (AgTR OTel span tree)", async () => {
  const { CLAIM_TYPES } = await import("../src/index.ts");
  assert.ok((CLAIM_TYPES as readonly string[]).includes("ar.trace.v2"), "ar.trace.v2 registered");
});

test("ar.trace.v2 is policy-optional", async () => {
  const { POLICY_OPTIONAL } = await import("../src/policy.ts");
  assert.equal(POLICY_OPTIONAL.has("ar.trace.v2" as never), true);
});

test("CLAIM_TYPES includes the 4 closure-set discriminators", async () => {
  const { CLAIM_TYPES } = await import("../src/index.ts");
  const closure = [
    "ar.notice.v1",
    "ar.breach.v1",
    "ar.subject_rights.v1",
    "ar.impact.v1",
  ] as const;
  for (const t of closure) assert.ok((CLAIM_TYPES as readonly string[]).includes(t), `${t} missing`);
});

test("CLAIM_TYPES length is 29 (10 shipped + 6 pre-canonical-specced + 4 closure + 1 ATokR + 1 AActR + 1 AQR + 1 AGR + 1 AGrR + 1 AgTR + 1 AgTR v2 + 1 APIIR + 1 ACBR)", async () => {
  const { CLAIM_TYPES } = await import("../src/index.ts");
  assert.equal(CLAIM_TYPES.length, 29);
});

// ── v1.2 envelope amendment tests ────────────────────────────────────────────
//
// Spec: https://github.com/dekimuhq/anchors-spec/tree/main/envelope
// Plan: Phase A — exposed surface only (allowlist, enums, optional fields).
// No evaluator / validator / verifier wiring tested here; those land in B–D.

test("v1.2 — JSON_LOGIC_ALLOWLIST_V1_2 has exactly 27 entries and no duplicates", async () => {
  const { JSON_LOGIC_ALLOWLIST_V1_2 } = await import("../src/index.ts");
  assert.ok(Array.isArray(JSON_LOGIC_ALLOWLIST_V1_2), "allowlist must be an array");
  assert.strictEqual(
    JSON_LOGIC_ALLOWLIST_V1_2.length,
    27,
    `Expected 27 operators, got ${JSON_LOGIC_ALLOWLIST_V1_2.length}`,
  );
  const set = new Set<string>(JSON_LOGIC_ALLOWLIST_V1_2);
  assert.strictEqual(
    set.size,
    JSON_LOGIC_ALLOWLIST_V1_2.length,
    "allowlist contains duplicate operator keys",
  );
});

test("v1.2 — KIND_VALUES covers the two non-null enum members", async () => {
  const { KIND_VALUES } = await import("../src/index.ts");
  assert.deepStrictEqual([...KIND_VALUES].sort(), ["decision", "observation"]);
});

test("v1.2 — CAUSE_VALUES covers the thirteen enum members per spec §4.2 + D-anchors-7", async () => {
  const { CAUSE_VALUES } = await import("../src/index.ts");
  assert.deepStrictEqual([...CAUSE_VALUES], [
    "manual",
    "scheduled",
    "event",
    "api",
    "regulatory_request",
    "rectification",
    "erasure_request",
    "portability_request",
    "objection",
    "automated_decision_review",
    "breach",
    "review_cycle",
    "material_change",
  ]);
});

test("v1.2 — Envelope accepts iat_ms + kind + cause + predicate as optional fields (compile-time)", async () => {
  const { CLAIM_TYPES } = await import("../src/index.ts");

  const anchor: import("../src/envelope-types.ts").AnchorProof = {
    log: "https://verify.dekimu.com/acr/v1",
    leaf_index: 0,
    inclusion_proof: [],
    tree_head_root: "sha256:deadbeef",
    tree_size: 1,
    log_time: "2026-05-17T00:00:00Z",
  };

  const predicate: import("../src/envelope-types.ts").Envelope["predicate"] = {
    and: [
      { ">=": [{ var: "body.subject_age" }, 16] },
      { in: [{ var: "body.purpose" }, ["analytics", "fraud"]] },
    ],
  };

  // v1.2 envelope — all new fields populated.
  const v12: import("../src/envelope-types.ts").Envelope = {
    v: 2,
    id: "01HZ0000000000000000000003",
    iat: "2026-05-17T00:00:00Z",
    iat_ms: Date.parse("2026-05-17T00:00:00Z"),
    claim_type: CLAIM_TYPES[1]!,
    iss: "did:key:z6Mk...",
    iss_key: "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    subject: "sha256:0000",
    exp: null,
    prev: null,
    policy_uri: null,
    policy_hash: null,
    policy_version: null,
    kind: "decision",
    cause: "regulatory_request",
    predicate,
    tsa: null,
    credentialStatus: null,
    anchor,
    sig: "primary-sig-b64url",
    countersig: null,
    body: { subject_age: 18, purpose: "analytics" },
  };

  // v1.1-style envelope — none of the new fields populated. MUST still satisfy
  // the Envelope type because all four additions are optional.
  const v11: import("../src/envelope-types.ts").Envelope = {
    v: 2,
    id: "01HZ0000000000000000000004",
    iat: "2026-05-16T14:00:00Z",
    claim_type: CLAIM_TYPES[0]!,
    iss: "did:key:z6Mk...",
    iss_key: "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    subject: "sha256:0000",
    exp: null,
    prev: null,
    policy_uri: null,
    policy_hash: null,
    policy_version: null,
    tsa: null,
    credentialStatus: null,
    anchor,
    sig: "primary-sig-b64url",
    countersig: null,
    body: {},
  };

  assert.strictEqual(v12.iat_ms, Date.parse("2026-05-17T00:00:00Z"), "iat_ms should equal Date.parse(iat)");
  assert.strictEqual(v12.kind, "decision");
  assert.strictEqual(v12.cause, "regulatory_request");
  assert.ok(v12.predicate, "predicate should be set");
  assert.strictEqual(v11.iat_ms, undefined, "v1.1 envelope should omit iat_ms");
  assert.strictEqual(v11.kind, undefined, "v1.1 envelope should omit kind");
});

