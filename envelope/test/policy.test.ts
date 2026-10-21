/**
 * Tests for validatePolicyFields + fetchAndCheckPolicy.
 *
 * Phase C Task 14 — @dekimuhq/anchors-envelope 0.2.0
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import {
  validatePolicyFields,
  fetchAndCheckPolicy,
  POLICY_BOUND,
} from "../src/policy.ts";
import type { Envelope } from "../src/envelope-types.ts";

// Minimal shape — matrix only reads four fields.
type PolicyInput = Pick<
  Envelope,
  "claim_type" | "policy_uri" | "policy_hash" | "policy_version"
>;

function build(
  claim_type: Envelope["claim_type"],
  overrides: Partial<Omit<PolicyInput, "claim_type">> = {},
): PolicyInput {
  return {
    claim_type,
    policy_uri: null,
    policy_hash: null,
    policy_version: null,
    ...overrides,
  };
}

const VALID_HASH = "sha256:" + "0".repeat(64);

// ── APR (ar.provenance.v1): policy_* FORBIDDEN ───────────────────────────────

test("APR ar.provenance.v1: all-null is valid", () => {
  const r = validatePolicyFields(build("ar.provenance.v1"));
  assert.equal(r.ok, true);
});

test("APR ar.provenance.v1: policy_uri set rejects with policy_fields_forbidden_for_apr", () => {
  const r = validatePolicyFields(
    build("ar.provenance.v1", { policy_uri: "https://x" }),
  );
  assert.equal(r.ok, false);
  assert.equal(r.reason, "policy_fields_forbidden_for_apr");
});

test("APR ar.provenance.v1: policy_hash set rejects", () => {
  const r = validatePolicyFields(
    build("ar.provenance.v1", { policy_hash: VALID_HASH }),
  );
  assert.equal(r.ok, false);
  assert.equal(r.reason, "policy_fields_forbidden_for_apr");
});

test("APR ar.provenance.v1: policy_version set rejects", () => {
  const r = validatePolicyFields(
    build("ar.provenance.v1", { policy_version: "1.0.0" }),
  );
  assert.equal(r.ok, false);
  assert.equal(r.reason, "policy_fields_forbidden_for_apr");
});

// ── POLICY_BOUND set — per-claim-type coverage ───────────────────────────────

test("ACR ar.consent.v1: missing all three rejects with policy_fields_required:policy_uri", () => {
  const r = validatePolicyFields(build("ar.consent.v1"));
  assert.equal(r.ok, false);
  assert.equal(r.reason, "policy_fields_required:policy_uri");
});

test("ACR ar.consent.v1: missing policy_hash rejects with policy_fields_required:policy_hash", () => {
  const r = validatePolicyFields(
    build("ar.consent.v1", {
      policy_uri: "https://x",
      policy_version: "1.0.0",
    }),
  );
  assert.equal(r.ok, false);
  assert.equal(r.reason, "policy_fields_required:policy_hash");
});

test("ACR ar.consent.v1: missing policy_version rejects with policy_fields_required:policy_version", () => {
  const r = validatePolicyFields(
    build("ar.consent.v1", {
      policy_uri: "https://x",
      policy_hash: VALID_HASH,
    }),
  );
  assert.equal(r.ok, false);
  assert.equal(r.reason, "policy_fields_required:policy_version");
});

test("ACR ar.consent.v1: all three valid is ok", () => {
  const r = validatePolicyFields(
    build("ar.consent.v1", {
      policy_uri: "https://x",
      policy_hash: VALID_HASH,
      policy_version: "1.0.0",
    }),
  );
  assert.equal(r.ok, true);
});

test("ACR ar.withdrawal.v1: requires all three", () => {
  const r = validatePolicyFields(build("ar.withdrawal.v1"));
  assert.equal(r.ok, false);
  const r2 = validatePolicyFields(
    build("ar.withdrawal.v1", {
      policy_uri: "https://x",
      policy_hash: VALID_HASH,
      policy_version: "1.0.0",
    }),
  );
  assert.equal(r2.ok, true);
});

test("ACR ar.modification.v1: requires all three", () => {
  const r = validatePolicyFields(build("ar.modification.v1"));
  assert.equal(r.ok, false);
  const r2 = validatePolicyFields(
    build("ar.modification.v1", {
      policy_uri: "https://x",
      policy_hash: VALID_HASH,
      policy_version: "1.0.0",
    }),
  );
  assert.equal(r2.ok, true);
});

test("ARR ar.erasure.v1: requires all three", () => {
  const r = validatePolicyFields(build("ar.erasure.v1"));
  assert.equal(r.ok, false);
  const r2 = validatePolicyFields(
    build("ar.erasure.v1", {
      policy_uri: "https://x",
      policy_hash: VALID_HASH,
      policy_version: "1.0.0",
    }),
  );
  assert.equal(r2.ok, true);
});

test("ARR ar.expiry.v1: requires all three", () => {
  const r = validatePolicyFields(build("ar.expiry.v1"));
  assert.equal(r.ok, false);
  const r2 = validatePolicyFields(
    build("ar.expiry.v1", {
      policy_uri: "https://x",
      policy_hash: VALID_HASH,
      policy_version: "1.0.0",
    }),
  );
  assert.equal(r2.ok, true);
});

test("ARR ar.hold.v1: requires all three", () => {
  const r = validatePolicyFields(build("ar.hold.v1"));
  assert.equal(r.ok, false);
  const r2 = validatePolicyFields(
    build("ar.hold.v1", {
      policy_uri: "https://x",
      policy_hash: VALID_HASH,
      policy_version: "1.0.0",
    }),
  );
  assert.equal(r2.ok, true);
});

test("ARR ar.anonymization.v1: requires all three", () => {
  const r = validatePolicyFields(build("ar.anonymization.v1"));
  assert.equal(r.ok, false);
  const r2 = validatePolicyFields(
    build("ar.anonymization.v1", {
      policy_uri: "https://x",
      policy_hash: VALID_HASH,
      policy_version: "1.0.0",
    }),
  );
  assert.equal(r2.ok, true);
});

test("ARR ar.archive.v1: requires all three", () => {
  const r = validatePolicyFields(build("ar.archive.v1"));
  assert.equal(r.ok, false);
  const r2 = validatePolicyFields(
    build("ar.archive.v1", {
      policy_uri: "https://x",
      policy_hash: VALID_HASH,
      policy_version: "1.0.0",
    }),
  );
  assert.equal(r2.ok, true);
});

// ── policy_hash algorithm enforcement ────────────────────────────────────────

test("POLICY_BOUND: policy_hash without sha256: prefix rejects with policy_hash_alg_unsupported", () => {
  const r = validatePolicyFields(
    build("ar.consent.v1", {
      policy_uri: "https://x",
      policy_hash: "blake3:" + "0".repeat(64),
      policy_version: "1.0.0",
    }),
  );
  assert.equal(r.ok, false);
  assert.equal(r.reason, "policy_hash_alg_unsupported");
});

// ── ar.batch.v1: no envelope-level enforcement ───────────────────────────────

test("ar.batch.v1: all-null is valid (per-item policy lives in body)", () => {
  const r = validatePolicyFields(build("ar.batch.v1"));
  assert.equal(r.ok, true);
});

test("ar.batch.v1: policy_* set is also valid (not enforced at envelope level)", () => {
  const r = validatePolicyFields(
    build("ar.batch.v1", {
      policy_uri: "https://x",
      policy_hash: VALID_HASH,
      policy_version: "1.0.0",
    }),
  );
  assert.equal(r.ok, true);
});

// ── Empty string treated like null ───────────────────────────────────────────

test("POLICY_BOUND: empty-string policy_uri rejects same as null", () => {
  const r = validatePolicyFields(
    build("ar.consent.v1", {
      policy_uri: "",
      policy_hash: VALID_HASH,
      policy_version: "1.0.0",
    }),
  );
  assert.equal(r.ok, false);
  assert.equal(r.reason, "policy_fields_required:policy_uri");
});

// ── POLICY_OPTIONAL — AQR / AGR / AgTR ──────────────────────────────────────

test("ar.trace.v1 (AgTR, chip 19): all-null policy fields are valid (POLICY_OPTIONAL)", () => {
  const r = validatePolicyFields(build("ar.trace.v1"));
  assert.equal(r.ok, true);
});

test("ar.trace.v1 (AgTR, chip 19): policy fields present are also valid (passthrough)", () => {
  const r = validatePolicyFields(
    build("ar.trace.v1", {
      policy_uri: "https://example.com/trace-policy",
      policy_hash: VALID_HASH,
      policy_version: "1.0.0",
    }),
  );
  assert.equal(r.ok, true);
});

test("ar.trace.v2 (AgTR OTel span tree): all-null policy fields are valid (POLICY_OPTIONAL)", () => {
  const r = validatePolicyFields(build("ar.trace.v2"));
  assert.equal(r.ok, true);
});

test("ar.trace.v2 (AgTR OTel span tree): policy fields present are also valid (passthrough)", () => {
  const r = validatePolicyFields(
    build("ar.trace.v2", {
      policy_uri: "https://example.com/trace-policy",
      policy_hash: VALID_HASH,
      policy_version: "1.0.0",
    }),
  );
  assert.equal(r.ok, true);
});

test("POLICY_BOUND set contains the ACR/ARR base 8 plus shipping closure-set additions", () => {
  // Base 8 from Phase C Task 14 (ACR + ARR families) PLUS closure-set
  // additions registered as each new family ships. ALR (ar.lineage.v1) was
  // added during ALR Phase 1 §D. ANR (ar.notice.v1) was added during ANR
  // Phase 2 §D per spec D10-ANR-3 (notice IS the policy artifact). ABR
  // (ar.breach.v1) was added during ABR Phase 3 §D per spec §3.1
  // (policy_uri references the controller's incident-response policy).
  // AIR (ar.impact.v1) was added during AIR Phase 5 §D per spec §3.1
  // (policy_uri references the controller's published DPIA methodology).
  // ASR (ar.subject_rights.v1) was added during defineFamily() A.2-full
  // Phase 3 §D per spec §3.1 (policy_uri references the controller's
  // published subject-rights policy).
  // ATokR (ar.tokenization.v1) was added during ATokR Phase 8 (issuer-kit)
  // per spec §3 (policy_uri references the controller's published tokenization
  // policy under which the receipt is issued).
  // AAR (ar.attestation.v1) was added during AAR Task 9 (aar-issuer-kit)
  // per spec §3 (policy_uri references the QTSP's published attestation policy).
  // APuR (ar.purpose.v1) was added during APuR Task 10 (apur-issuer-kit)
  // per spec §3 (policy_uri references the controller's published purpose-limitation
  // policy under which the receipt is issued).
  // ATR (ar.transfer.v1) was added during ATR Task 9 (atr-issuer-kit)
  // per spec §3 (policy_uri references the controller's published transfer policy).
  // ADR (ar.delegation.v1) was added during ADR Task 10 (adr-issuer-kit)
  // per spec §3 (policy_uri references the delegating principal's published
  // delegation policy).
  // AActR (ar.action.v1) was added during AActR build per spec §4.1
  // (policy_uri references the Hub automations surface, policy_hash the
  // recipe-catalog version under which the autonomous action was authorized).
  const expected = [
    "ar.consent.v1",
    "ar.modification.v1",
    "ar.withdrawal.v1",
    "ar.erasure.v1",
    "ar.expiry.v1",
    "ar.hold.v1",
    "ar.anonymization.v1",
    "ar.archive.v1",
    "ar.lineage.v1",
    "ar.notice.v1",
    "ar.breach.v1",
    "ar.impact.v1",
    "ar.subject_rights.v1",
    "ar.tokenization.v1",
    "ar.attestation.v1",
    "ar.purpose.v1",
    "ar.transfer.v1",
    "ar.delegation.v1",
    "ar.action.v1",
  ].sort();
  const actual = [...POLICY_BOUND].sort();
  assert.deepEqual(actual, expected);
});

// ── fetchAndCheckPolicy ──────────────────────────────────────────────────────

test("fetchAndCheckPolicy: matching hash returns true", async () => {
  const body = "policy document content v1.0";
  const expected = "sha256:" + createHash("sha256").update(body).digest("hex");

  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () =>
    new Response(body, { status: 200 })) as typeof fetch;
  try {
    const ok = await fetchAndCheckPolicy("https://x.example/p", expected);
    assert.equal(ok, true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("fetchAndCheckPolicy: mismatched hash returns false", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () =>
    new Response("some body", { status: 200 })) as typeof fetch;
  try {
    const ok = await fetchAndCheckPolicy(
      "https://x.example/p",
      "sha256:" + "f".repeat(64),
    );
    assert.equal(ok, false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("fetchAndCheckPolicy: non-2xx response returns false", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () =>
    new Response("not found", { status: 404 })) as typeof fetch;
  try {
    const ok = await fetchAndCheckPolicy(
      "https://x.example/p",
      "sha256:" + "0".repeat(64),
    );
    assert.equal(ok, false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("fetchAndCheckPolicy: network failure returns false (does not throw)", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () => {
    throw new Error("network down");
  }) as typeof fetch;
  try {
    const ok = await fetchAndCheckPolicy(
      "https://x.example/p",
      "sha256:" + "0".repeat(64),
    );
    assert.equal(ok, false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
