/**
 * Tests for the AAR chain walker (spec §7).
 *
 * Coverage: prev-chain integrity, issuer/subject consistency,
 * at-most-one-revocation, and revocation-references-issuance.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { AarChainReceipt } from "../src/types.ts";
import { buildAarChainIndex, walkAarChain } from "../src/chain.ts";

// ── Helpers ───────────────────────────────────────────────────────────────────

const H = (c: string): string => "sha256:" + c.repeat(64);

function makeIssuance(id: string, iss: string, subject: string): AarChainReceipt {
  return {
    id,
    iss,
    iat: "2026-05-21T10:00:00Z",
    prev: null,
    subject,
    body: {
      event_type: "issuance",
      service_type: "qes",
      service_policy_oid: "1.2.3.4.5",
      service_recipient_commit: H("a"),
      artefact_hash: null,
      artefact_metadata_commit: H("b"),
      signature_format: "pades_b_lt",
      qcert_serial_commit: null,
      tsl_country: "ES",
      tsl_entry_hash: H("c"),
      tsl_signed_tree_head_root: H("d"),
      tsl_tree_size: 100,
      tsl_inclusion_proof: [H("e"), H("f")],
      tsl_log_time: "2026-05-21T09:00:00Z",
      atr_transfer_hash: null,
      qts_attestation_hash: null,
    },
  };
}

function makeRevocation(
  id: string,
  iss: string,
  subject: string,
  prev: string,
): AarChainReceipt {
  return {
    id,
    iss,
    iat: "2026-05-21T11:00:00Z",
    prev,
    subject,
    body: {
      event_type: "revocation",
      reason: "key_compromise",
      reason_ref_hash: null,
      tsl_country: "ES",
      tsl_entry_hash: H("g"),
      tsl_signed_tree_head_root: H("h"),
      tsl_tree_size: 101,
      tsl_inclusion_proof: [H("i")],
      tsl_log_time: "2026-05-21T10:30:00Z",
      qts_attestation_hash: null,
    },
  };
}

// ── 1. Accepts standalone issuance (prev=null) ────────────────────────────────

test("accepts standalone issuance", () => {
  const r1 = makeIssuance("r1", "did:web:issuer.example.com", H("s"));
  const idx = buildAarChainIndex([r1]);
  const res = walkAarChain("r1", idx);
  assert.equal(res.ok, true, res.hard_invalid_reasons.join("|"));
  assert.equal(res.warnings.length, 0);
});

// ── 2. Accepts issuance → revocation chain ────────────────────────────────────

test("accepts issuance → revocation chain", () => {
  const r1 = makeIssuance("r1", "did:web:issuer.example.com", H("s"));
  const r2 = makeRevocation("r2", "did:web:issuer.example.com", H("s"), "r1");
  const idx = buildAarChainIndex([r1, r2]);
  const res = walkAarChain("r2", idx);
  assert.equal(res.ok, true, res.hard_invalid_reasons.join("|"));
  assert.equal(res.warnings.length, 0);
});

// ── 3. Rejects receipt_not_found (empty index) ────────────────────────────────

test("rejects receipt_not_found on empty index", () => {
  const idx = buildAarChainIndex([]);
  const res = walkAarChain("missing", idx);
  assert.equal(res.ok, false);
  assert.ok(
    res.hard_invalid_reasons.includes("aar.receipt_not_found"),
    res.hard_invalid_reasons.join("|"),
  );
});

// ── 4. Detects cycle (r1.prev=r2, r2.prev=r1) ────────────────────────────────

test("detects chain cycle", () => {
  // Build manually to create a cycle
  const r1: AarChainReceipt = {
    ...makeRevocation("r1", "did:web:issuer.example.com", H("s"), "r2"),
  };
  const r2: AarChainReceipt = {
    ...makeRevocation("r2", "did:web:issuer.example.com", H("s"), "r1"),
  };
  const idx = buildAarChainIndex([r1, r2]);
  const res = walkAarChain("r1", idx);
  assert.equal(res.ok, false);
  assert.ok(
    res.hard_invalid_reasons.includes("aar.chain_cycle_detected"),
    res.hard_invalid_reasons.join("|"),
  );
});

// ── 5. Detects dangling prev (revocation refs missing receipt) ─────────────────

test("detects dangling prev", () => {
  const r2 = makeRevocation("r2", "did:web:issuer.example.com", H("s"), "r-missing");
  const idx = buildAarChainIndex([r2]);
  const res = walkAarChain("r2", idx);
  assert.equal(res.ok, false);
  assert.ok(
    res.hard_invalid_reasons.includes("aar.chain_prev_unresolved"),
    res.hard_invalid_reasons.join("|"),
  );
});

// ── 6. Detects chain head not issuance (revocation with prev=null) ────────────

test("detects chain head not issuance", () => {
  const r1 = makeRevocation("r1", "did:web:issuer.example.com", H("s"), "r1");
  // Override prev to null manually
  const r1NullPrev: AarChainReceipt = { ...r1, prev: null };
  const idx = buildAarChainIndex([r1NullPrev]);
  const res = walkAarChain("r1", idx);
  assert.equal(res.ok, false);
  assert.ok(
    res.hard_invalid_reasons.includes("aar.chain_head_not_issuance"),
    res.hard_invalid_reasons.join("|"),
  );
});

// ── 7. Detects issuer inconsistency ───────────────────────────────────────────

test("detects issuer inconsistency", () => {
  const r1 = makeIssuance("r1", "did:web:issuer-a.example.com", H("s"));
  const r2 = makeRevocation("r2", "did:web:issuer-b.example.com", H("s"), "r1");
  const idx = buildAarChainIndex([r1, r2]);
  const res = walkAarChain("r2", idx);
  assert.equal(res.ok, false);
  assert.ok(
    res.hard_invalid_reasons.includes("aar.issuer_inconsistent"),
    res.hard_invalid_reasons.join("|"),
  );
});

// ── 8. Detects subject inconsistency ──────────────────────────────────────────

test("detects subject inconsistency", () => {
  const r1 = makeIssuance("r1", "did:web:issuer.example.com", H("s"));
  const r2: AarChainReceipt = {
    ...makeRevocation("r2", "did:web:issuer.example.com", H("s"), "r1"),
    subject: H("t"), // different subject
  };
  const idx = buildAarChainIndex([r1, r2]);
  const res = walkAarChain("r2", idx);
  assert.equal(res.ok, false);
  assert.ok(
    res.hard_invalid_reasons.includes("aar.subject_inconsistent"),
    res.hard_invalid_reasons.join("|"),
  );
});

// ── 9. Detects multiple revocations (issuance → rev1 → rev2) ─────────────────

test("detects multiple revocations", () => {
  const r1 = makeIssuance("r1", "did:web:issuer.example.com", H("s"));
  const r2 = makeRevocation("r2", "did:web:issuer.example.com", H("s"), "r1");
  // r3 is a second revocation pointing to r2 (not an issuance — rule 5 also fires,
  // but rule 4 fires first on the count check)
  const r3 = makeRevocation("r3", "did:web:issuer.example.com", H("s"), "r2");
  const idx = buildAarChainIndex([r1, r2, r3]);
  const res = walkAarChain("r3", idx);
  assert.equal(res.ok, false);
  assert.ok(
    res.hard_invalid_reasons.includes("aar.multiple_revocations") ||
      res.hard_invalid_reasons.includes("aar.revocation_references_non_issuance"),
    res.hard_invalid_reasons.join("|"),
  );
});
