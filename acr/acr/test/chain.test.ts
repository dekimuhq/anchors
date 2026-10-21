// anchors/acr/acr-verifier/test/chain.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { resolveChainState, hashReceipt } from "../src/chain.ts";
import type { ACRReceipt } from "../src/types.ts";

function rcpt(overrides: Partial<ACRReceipt>): ACRReceipt {
  return {
    kind: "ar.consent.v1",
    profile: "gdpr.art7",
    iss: "did:web:bank.example",
    iss_key: "ed25519:x",
    sub_commit: "sha256:a",
    purposes: [],
    lawful_basis: "6(1)(a)",
    policy_hash: "sha256:b",
    granted_at: "2026-05-15T10:00:00Z",
    prev: null,
    field_root: "sha256:c",
    anchor: null,
    sig: "ed25519:s",
    countersig: null,
    qts_attestation_hash: null,
    ...overrides,
  };
}

test("hashReceipt is deterministic and ignores anchor/countersig", () => {
  const a = rcpt({});
  const b = { ...a, anchor: null };
  assert.equal(hashReceipt(a), hashReceipt(b));
});

test("resolveChainState returns 'active' for a single consent receipt", () => {
  const r = rcpt({});
  const state = resolveChainState([r]);
  assert.equal(state.status, "active");
  assert.equal(state.terminal_kind, "ar.consent.v1");
});

test("resolveChainState returns 'modified' for consent→modification", () => {
  const consent = rcpt({});
  const mod = rcpt({ kind: "ar.modification.v1", prev: hashReceipt(consent) });
  const state = resolveChainState([consent, mod]);
  assert.equal(state.status, "modified");
  assert.equal(state.terminal_kind, "ar.modification.v1");
});

test("resolveChainState returns 'withdrawn' when chain terminates in withdrawal", () => {
  const consent = rcpt({});
  const wdr = rcpt({ kind: "ar.withdrawal.v1", prev: hashReceipt(consent) });
  const state = resolveChainState([consent, wdr]);
  assert.equal(state.status, "withdrawn");
  assert.equal(state.terminal_kind, "ar.withdrawal.v1");
});

test("resolveChainState rejects a chain with broken prev pointer", () => {
  const consent = rcpt({});
  const broken = rcpt({
    kind: "ar.withdrawal.v1",
    prev: "sha256:" + "f".repeat(64), // doesn't match consent hash
  });
  assert.throws(() => resolveChainState([consent, broken]), /broken prev pointer/);
});

test("resolveChainState rejects a chain where the first receipt has prev !== null", () => {
  const orphan = rcpt({ prev: "sha256:" + "0".repeat(64) });
  assert.throws(() => resolveChainState([orphan]), /first receipt must have prev === null/);
});
