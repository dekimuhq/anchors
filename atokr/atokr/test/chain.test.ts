/**
 * Tests for the ATokR chain walker (spec §6.1 + §6.2).
 *
 * Coverage: linear prev-chain integrity, rotation tree validation,
 * issuer/subject/scope/format_class consistency, single-use enforcement,
 * and post-revocation event detection.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { AtokrChainReceipt, AtokrScope } from "../src/types.ts";
import { buildAtokrChainIndex, walkAtokrChain } from "../src/chain.ts";

// ── Shared fixtures ───────────────────────────────────────────────────────────

const SUBJECT = "sha256:" + "a".repeat(64);

function validScope(): AtokrScope {
  return {
    audience: "did:web:a.example.com",
    purpose: "invoice_share",
    valid_from: "2026-01-01T00:00:00Z",
    valid_until: "2026-12-31T23:59:59Z",
    single_use: false,
  };
}

function makeReceipt(
  overrides: Partial<AtokrChainReceipt> & { body: AtokrChainReceipt["body"] },
): AtokrChainReceipt {
  return {
    id: "r-" + Math.random().toString(36).slice(2, 8),
    iss: "did:web:dekimu.com",
    iat: "2026-05-21T10:00:00Z",
    prev: null,
    subject: SUBJECT,
    ...overrides,
  };
}

// ── 1. Valid chain: issued → redeemed → revoked (happy path) ────────────────

test("valid chain: issued → redeemed → revoked", () => {
  const r1 = makeReceipt({
    id: "r1",
    body: {
      event_type: "token.issued",
      token_id: "tok1",
      format_class: "pan",
      scope: validScope(),
      rotation_of: null,
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  const r2 = makeReceipt({
    id: "r2",
    prev: "r1",
    body: {
      event_type: "token.redeemed",
      token_id: "tok1",
      format_class: null,
      scope: validScope(),
      rotation_of: null,
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  const r3 = makeReceipt({
    id: "r3",
    prev: "r2",
    body: {
      event_type: "token.revoked",
      token_id: "tok1",
      format_class: null,
      scope: validScope(),
      rotation_of: null,
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  const idx = buildAtokrChainIndex([r1, r2, r3]);
  const res = walkAtokrChain("r3", idx);
  assert.equal(res.ok, true, res.hard_invalid_reasons.join("|"));
  assert.equal(res.warnings.length, 0);
});

// ── 2. Valid rotation: issued(T1) → rotated(T1→T2) (happy path) ────────────

test("valid rotation: issued(T1) → rotated(T1→T2)", () => {
  const r1 = makeReceipt({
    id: "r1",
    body: {
      event_type: "token.issued",
      token_id: "tok1",
      format_class: "pan",
      scope: validScope(),
      rotation_of: null,
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  const r2 = makeReceipt({
    id: "r2",
    prev: "r1",
    body: {
      event_type: "token.rotated",
      token_id: "tok2",
      format_class: "pan",
      scope: validScope(),
      rotation_of: "tok1",
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  const idx = buildAtokrChainIndex([r1, r2]);
  const res = walkAtokrChain("r2", idx);
  assert.equal(res.ok, true, res.hard_invalid_reasons.join("|"));
});

// ── 3. Issuer mismatch fails ────────────────────────────────────────────────

test("issuer mismatch → atokr.issuer_inconsistent", () => {
  const r1 = makeReceipt({
    id: "r1",
    iss: "did:web:other.com",
    body: {
      event_type: "token.issued",
      token_id: "tok1",
      format_class: "pan",
      scope: validScope(),
      rotation_of: null,
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  const r2 = makeReceipt({
    id: "r2",
    prev: "r1",
    iss: "did:web:dekimu.com",
    body: {
      event_type: "token.redeemed",
      token_id: "tok1",
      format_class: null,
      scope: validScope(),
      rotation_of: null,
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  const idx = buildAtokrChainIndex([r1, r2]);
  const res = walkAtokrChain("r2", idx);
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("atokr.issuer_inconsistent"));
});

// ── 4. Subject mismatch within token_id chain fails ─────────────────────────

test("subject mismatch → atokr.subject_inconsistent", () => {
  const r1 = makeReceipt({
    id: "r1",
    subject: "sha256:" + "a".repeat(64),
    body: {
      event_type: "token.issued",
      token_id: "tok1",
      format_class: "pan",
      scope: validScope(),
      rotation_of: null,
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  const r2 = makeReceipt({
    id: "r2",
    prev: "r1",
    subject: "sha256:" + "b".repeat(64),
    body: {
      event_type: "token.redeemed",
      token_id: "tok1",
      format_class: null,
      scope: validScope(),
      rotation_of: null,
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  const idx = buildAtokrChainIndex([r1, r2]);
  const res = walkAtokrChain("r2", idx);
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("atokr.subject_inconsistent"));
});

// ── 5. Redeemed scope audience mismatch fails ──────────────────────────────

test("redeemed scope audience mismatch → atokr.scope_mismatch", () => {
  const r1 = makeReceipt({
    id: "r1",
    body: {
      event_type: "token.issued",
      token_id: "tok1",
      format_class: "pan",
      scope: validScope(),
      rotation_of: null,
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  const r2 = makeReceipt({
    id: "r2",
    prev: "r1",
    body: {
      event_type: "token.redeemed",
      token_id: "tok1",
      format_class: null,
      scope: { ...validScope(), audience: "did:web:evil.com" },
      rotation_of: null,
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  const idx = buildAtokrChainIndex([r1, r2]);
  const res = walkAtokrChain("r2", idx);
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("atokr.scope_mismatch"));
});

// ── 6. Redeemed after scope.valid_until fails (scope_expired) ──────────────

test("redeemed after scope.valid_until → atokr.scope_expired", () => {
  const scope = validScope();
  scope.valid_until = "2026-06-01T00:00:00Z";
  const r1 = makeReceipt({
    id: "r1",
    body: {
      event_type: "token.issued",
      token_id: "tok1",
      format_class: "pan",
      scope,
      rotation_of: null,
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  const r2 = makeReceipt({
    id: "r2",
    prev: "r1",
    iat: "2026-07-01T00:00:00Z",
    body: {
      event_type: "token.redeemed",
      token_id: "tok1",
      format_class: null,
      scope,
      rotation_of: null,
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  const idx = buildAtokrChainIndex([r1, r2]);
  const res = walkAtokrChain("r2", idx);
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("atokr.scope_expired"));
});

// ── 7. Rotation widens scope fails (scope_widened) ─────────────────────────

test("rotation widens scope → atokr.scope_widened", () => {
  const issuanceScope = validScope();
  issuanceScope.valid_until = "2026-06-30T23:59:59Z";
  const r1 = makeReceipt({
    id: "r1",
    body: {
      event_type: "token.issued",
      token_id: "tok1",
      format_class: "pan",
      scope: issuanceScope,
      rotation_of: null,
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  // Rotation widens valid_until
  const r2 = makeReceipt({
    id: "r2",
    prev: "r1",
    body: {
      event_type: "token.rotated",
      token_id: "tok2",
      format_class: "pan",
      scope: { ...issuanceScope, valid_until: "2027-12-31T23:59:59Z" },
      rotation_of: "tok1",
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  const idx = buildAtokrChainIndex([r1, r2]);
  const res = walkAtokrChain("r2", idx);
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("atokr.scope_widened"));
});

// ── 8. Rotation narrows scope passes ────────────────────────────────────────

test("rotation narrows scope (valid_until moved backward) → ok", () => {
  const issuanceScope = validScope();
  issuanceScope.valid_until = "2026-12-31T23:59:59Z";
  const r1 = makeReceipt({
    id: "r1",
    body: {
      event_type: "token.issued",
      token_id: "tok1",
      format_class: "pan",
      scope: issuanceScope,
      rotation_of: null,
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  const r2 = makeReceipt({
    id: "r2",
    prev: "r1",
    body: {
      event_type: "token.rotated",
      token_id: "tok2",
      format_class: "pan",
      scope: { ...issuanceScope, valid_until: "2026-06-30T23:59:59Z" },
      rotation_of: "tok1",
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  const idx = buildAtokrChainIndex([r1, r2]);
  const res = walkAtokrChain("r2", idx);
  assert.equal(res.ok, true, res.hard_invalid_reasons.join("|"));
});

// ── 9. Second redeemed on single_use token fails ───────────────────────────

test("second redeemed on single_use token → atokr.single_use_exhausted", () => {
  const scope = { ...validScope(), single_use: true };
  const r1 = makeReceipt({
    id: "r1",
    body: {
      event_type: "token.issued",
      token_id: "tok1",
      format_class: "pan",
      scope,
      rotation_of: null,
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  const r2 = makeReceipt({
    id: "r2",
    prev: "r1",
    body: {
      event_type: "token.redeemed",
      token_id: "tok1",
      format_class: null,
      scope,
      rotation_of: null,
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  const r3 = makeReceipt({
    id: "r3",
    prev: "r2",
    body: {
      event_type: "token.redeemed",
      token_id: "tok1",
      format_class: null,
      scope,
      rotation_of: null,
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  const idx = buildAtokrChainIndex([r1, r2, r3]);
  const res = walkAtokrChain("r3", idx);
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("atokr.single_use_exhausted"));
});

// ── 10. First redeemed on single_use token passes ──────────────────────────

test("first redeemed on single_use token → ok", () => {
  const scope = { ...validScope(), single_use: true };
  const r1 = makeReceipt({
    id: "r1",
    body: {
      event_type: "token.issued",
      token_id: "tok1",
      format_class: "pan",
      scope,
      rotation_of: null,
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  const r2 = makeReceipt({
    id: "r2",
    prev: "r1",
    body: {
      event_type: "token.redeemed",
      token_id: "tok1",
      format_class: null,
      scope,
      rotation_of: null,
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  const idx = buildAtokrChainIndex([r1, r2]);
  const res = walkAtokrChain("r2", idx);
  assert.equal(res.ok, true, res.hard_invalid_reasons.join("|"));
});

// ── 11. Redeemed with wrong format_class fails ─────────────────────────────

test("redeemed with wrong format_class → atokr.format_class_mismatch", () => {
  const r1 = makeReceipt({
    id: "r1",
    body: {
      event_type: "token.issued",
      token_id: "tok1",
      format_class: "pan",
      scope: validScope(),
      rotation_of: null,
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  const r2 = makeReceipt({
    id: "r2",
    prev: "r1",
    body: {
      event_type: "token.redeemed",
      token_id: "tok1",
      format_class: "email",
      scope: validScope(),
      rotation_of: null,
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  const idx = buildAtokrChainIndex([r1, r2]);
  const res = walkAtokrChain("r2", idx);
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("atokr.format_class_mismatch"));
});

// ── 12. Rotation after revocation fails ─────────────────────────────────────

test("rotation after revocation → atokr.rotation_after_revocation", () => {
  const r1 = makeReceipt({
    id: "r1",
    body: {
      event_type: "token.issued",
      token_id: "tok1",
      format_class: "pan",
      scope: validScope(),
      rotation_of: null,
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  const r2 = makeReceipt({
    id: "r2",
    prev: "r1",
    body: {
      event_type: "token.revoked",
      token_id: "tok1",
      format_class: null,
      scope: validScope(),
      rotation_of: null,
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  // tok2 rotates from tok1 — but tok1 is revoked
  const r3 = makeReceipt({
    id: "r3",
    prev: "r2",
    body: {
      event_type: "token.rotated",
      token_id: "tok2",
      format_class: "pan",
      scope: validScope(),
      rotation_of: "tok1",
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  const idx = buildAtokrChainIndex([r1, r2, r3]);
  const res = walkAtokrChain("r3", idx);
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("atokr.rotation_after_revocation"));
});

// ── 13. Dangling prev reference fails ──────────────────────────────────────

test("dangling prev reference → atokr.chain_prev_unresolved", () => {
  const r1 = makeReceipt({
    id: "r1",
    prev: "r-missing",
    body: {
      event_type: "token.redeemed",
      token_id: "tok1",
      format_class: null,
      scope: validScope(),
      rotation_of: null,
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  const idx = buildAtokrChainIndex([r1]);
  const res = walkAtokrChain("r1", idx);
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("atokr.chain_prev_unresolved"));
});

// ── 14. Cycle in prev chain fails ──────────────────────────────────────────

test("cycle in prev chain → atokr.chain_cycle_detected", () => {
  const r1 = makeReceipt({
    id: "r1",
    prev: "r2",
    body: {
      event_type: "token.redeemed",
      token_id: "tok1",
      format_class: null,
      scope: validScope(),
      rotation_of: null,
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  const r2 = makeReceipt({
    id: "r2",
    prev: "r1",
    body: {
      event_type: "token.issued",
      token_id: "tok1",
      format_class: "pan",
      scope: validScope(),
      rotation_of: null,
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  const idx = buildAtokrChainIndex([r1, r2]);
  const res = walkAtokrChain("r1", idx);
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("atokr.chain_cycle_detected"));
});

// ── 15. Non-issuance receipt with prev=null fails ──────────────────────────

test("non-issuance with prev=null → atokr.chain_prev_unresolved", () => {
  const r1 = makeReceipt({
    id: "r1",
    prev: null,
    body: {
      event_type: "token.redeemed",
      token_id: "tok1",
      format_class: null,
      scope: validScope(),
      rotation_of: null,
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  const idx = buildAtokrChainIndex([r1]);
  const res = walkAtokrChain("r1", idx);
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("atokr.chain_prev_unresolved"));
});

// ── 16. rotation_of references unknown token_id fails ──────────────────────

test("rotation_of references unknown token_id → atokr.rotation_chain_broken", () => {
  const r1 = makeReceipt({
    id: "r1",
    body: {
      event_type: "token.issued",
      token_id: "tok2",
      format_class: "pan",
      scope: validScope(),
      rotation_of: null,
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  // Rotates from tok-unknown which has no receipts in the index
  const r2 = makeReceipt({
    id: "r2",
    prev: "r1",
    body: {
      event_type: "token.rotated",
      token_id: "tok2",
      format_class: "pan",
      scope: validScope(),
      rotation_of: "tok-unknown",
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  const idx = buildAtokrChainIndex([r1, r2]);
  const res = walkAtokrChain("r2", idx);
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("atokr.rotation_chain_broken"));
});

// ── 17. Post-revocation redeemed fails ─────────────────────────────────────

test("post-revocation redeemed → atokr.token_revoked_prior", () => {
  const r1 = makeReceipt({
    id: "r1",
    iat: "2026-05-01T00:00:00Z",
    body: {
      event_type: "token.issued",
      token_id: "tok1",
      format_class: "pan",
      scope: validScope(),
      rotation_of: null,
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  const r2 = makeReceipt({
    id: "r2",
    prev: "r1",
    iat: "2026-05-10T00:00:00Z",
    body: {
      event_type: "token.revoked",
      token_id: "tok1",
      format_class: null,
      scope: validScope(),
      rotation_of: null,
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  const r3 = makeReceipt({
    id: "r3",
    prev: "r2",
    iat: "2026-05-15T00:00:00Z",
    body: {
      event_type: "token.redeemed",
      token_id: "tok1",
      format_class: null,
      scope: validScope(),
      rotation_of: null,
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
      qts_attestation_hash: null,
    },
  });
  const idx = buildAtokrChainIndex([r1, r2, r3]);
  const res = walkAtokrChain("r3", idx);
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("atokr.token_revoked_prior"));
});
