import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { canonicalize } from "../src/index.ts";
import { resolveTargetChain } from "../src/index.ts";
import type { ARRReceipt } from "../src/index.ts";

function hashOf(r: ARRReceipt): string {
  const stripped: ARRReceipt = { ...r, anchor: null, sig: null };
  const h = createHash("sha256").update(canonicalize(stripped)).digest("hex");
  return `sha256:${h}`;
}

function base(overrides: Partial<ARRReceipt> = {}): ARRReceipt {
  return {
    kind: "ar.expiry.v1",
    profile: "gdpr.art5e",
    iss: "did:web:bank.example",
    iss_key: "ed25519:AAAA",
    target_kind: "subject",
    target_commit: "sha256:" + "ab".repeat(32),
    salt_epoch: "2026Q2",
    policy_hash: "sha256:" + "cd".repeat(32),
    policy_uri: "https://bank.example/p",
    policy_version: "1.0.0",
    trigger: "scheduled",
    trigger_receipt: null,
    event_at: "2026-05-16T03:00:00Z",
    granted_at: "2026-05-16T03:01:00Z",
    effective_until: null,
    state_snapshot: {
      retention_status: "expired",
      current_policy_hash: "sha256:" + "cd".repeat(32),
      hold_active: false,
      hold_reason_commit: null,
      anonymized: false,
      archived: false,
    },
    prev: null,
    field_root: "sha256:" + "11".repeat(32),
    anchor: null,
    sig: null,
    ...overrides,
  };
}

test("single-receipt chain resolves current state from the only link", () => {
  const r = base();
  const out = resolveTargetChain([r]);
  assert.equal(out.errors.length, 0);
  assert.equal(out.currentState?.retention_status, "expired");
  assert.equal(out.terminal, false);
});

test("two-link chain: prev hash must match prior receipt hash", () => {
  const r1 = base();
  const r2 = base({
    kind: "ar.erasure.v1",
    event_at: "2026-06-01T00:00:00Z",
    granted_at: "2026-06-01T00:01:00Z",
    prev: hashOf(r1),
    state_snapshot: {
      retention_status: "erased",
      current_policy_hash: "sha256:" + "cd".repeat(32),
      hold_active: false,
      hold_reason_commit: null,
      anonymized: false,
      archived: false,
    },
  });
  const out = resolveTargetChain([r1, r2]);
  assert.equal(out.errors.length, 0);
  assert.equal(out.currentState?.retention_status, "erased");
  assert.equal(out.terminal, true);
  assert.equal(out.terminalKind, "ar.erasure.v1");
});

test("broken prev hash -> invalid", () => {
  const r1 = base();
  const r2 = base({
    kind: "ar.erasure.v1",
    prev: "sha256:" + "ff".repeat(32),
    event_at: "2026-06-01T00:00:00Z",
    granted_at: "2026-06-01T00:01:00Z",
  });
  const out = resolveTargetChain([r1, r2]);
  assert.ok(out.errors.some((e) => e.startsWith("chain.prev")));
});

test("mixed target_commit -> invalid", () => {
  const r1 = base();
  const r2 = base({
    target_commit: "sha256:" + "00".repeat(32),
    prev: hashOf(r1),
  });
  const out = resolveTargetChain([r1, r2]);
  assert.ok(out.errors.includes("chain.target_mismatch"));
});

test("terminal anonymization closes chain", () => {
  const r1 = base();
  const r2 = base({
    kind: "ar.anonymization.v1",
    prev: hashOf(r1),
    event_at: "2026-06-01T00:00:00Z",
    granted_at: "2026-06-01T00:01:00Z",
    state_snapshot: {
      retention_status: "anonymized",
      current_policy_hash: "sha256:" + "cd".repeat(32),
      hold_active: false,
      hold_reason_commit: null,
      anonymized: true,
      archived: false,
    },
  });
  const out = resolveTargetChain([r1, r2]);
  assert.equal(out.terminal, true);
  assert.equal(out.terminalKind, "ar.anonymization.v1");
});

test("appending after terminal -> invalid", () => {
  const r1 = base({ kind: "ar.erasure.v1" });
  const r2 = base({
    kind: "ar.expiry.v1",
    prev: hashOf(r1),
  });
  const out = resolveTargetChain([r1, r2]);
  assert.ok(out.errors.includes("chain.append_after_terminal"));
});

test("empty input -> invalid", () => {
  const out = resolveTargetChain([]);
  assert.ok(out.errors.includes("chain.empty"));
});
