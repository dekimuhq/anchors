/**
 * Tests for composeAer (spec §7 — conformity chain-walk + transparency-backing).
 *
 * Coverage:
 *   C1 — No resolver supplied → returns { ok: true } (no-op).
 *   C2 — Conformity receipt with issuer mismatch in chain → surfaces
 *        aer.issuer_inconsistent warning.
 *   C3 — Transparency receipt without resolver → returns { ok: true } (no-op).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { composeAer } from "../src/compose.ts";
import type { AerBody, AerChainReceipt } from "../src/types.ts";
import { makeConformityBody, makeTransparencyBody, sha256Hex } from "./_helpers/fixtures.ts";

const STUB_RESOLVE_KEY = async () => new Uint8Array(0);

function makeConformityEnvelope(id: string, prev: string | null = null, iss = "did:web:issuer.example.com") {
  return {
    id,
    claim_type: "ar.evaluation.v1",
    iss,
    iat: "2026-09-01T00:00:00Z",
    prev,
    subject: null,
    body: makeConformityBody() as AerBody,
  };
}

function makeTransparencyEnvelope(id: string, conformityHash: string) {
  return {
    id,
    claim_type: "ar.evaluation.v1",
    iss: "did:web:deployer.example.com",
    iat: "2026-09-01T12:00:00Z",
    prev: null,
    subject: sha256Hex(),
    body: makeTransparencyBody({ conformity_receipt_hash: conformityHash }) as AerBody,
  };
}

function makeChainReceipt(id: string, prev: string | null, iss: string): AerChainReceipt {
  return {
    id,
    iss,
    iat: "2026-09-01T00:00:00Z",
    prev,
    subject: null,
    body: makeConformityBody(),
  };
}

test("C1 — no resolver supplied → returns { ok: true } (no-op)", async () => {
  const result = await composeAer({
    envelope: makeConformityEnvelope("r-001"),
    opts: { resolveKey: STUB_RESOLVE_KEY },
  });
  assert.deepEqual(result, { ok: true });
});

test("C2 — conformity chain with issuer mismatch → surfaces aer.issuer_inconsistent warning", async () => {
  // Chain: r-002 (iss=B) → r-001 (iss=A). Issuer inconsistency.
  const root = makeChainReceipt("r-001", null, "did:web:issuer-a.example.com");
  const child = makeChainReceipt("r-002", "r-001", "did:web:issuer-b.example.com");

  const corpus = new Map<string, AerChainReceipt>([
    [root.id, root],
    [child.id, child],
  ]);

  const result = await composeAer({
    envelope: makeConformityEnvelope("r-002", "r-001", "did:web:issuer-b.example.com"),
    opts: {
      resolveKey: STUB_RESOLVE_KEY,
      resolveReceiptById: async (id: string) => corpus.get(id) ?? null,
    },
  });

  assert.ok(result.ok);
  assert.ok(
    Array.isArray(result.warnings) && result.warnings.includes("aer.issuer_inconsistent"),
    `Expected aer.issuer_inconsistent in warnings, got: ${JSON.stringify(result.warnings)}`,
  );
});

test("C3 — transparency receipt without resolver → returns { ok: true } (no-op)", async () => {
  const conformityHash = sha256Hex();
  const result = await composeAer({
    envelope: makeTransparencyEnvelope("t-001", conformityHash),
    opts: { resolveKey: STUB_RESOLVE_KEY },
  });
  assert.deepEqual(result, { ok: true });
});
