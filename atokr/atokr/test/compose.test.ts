/**
 * Tests for composeAtokr (spec §6 — chain-walk compose-warnings).
 *
 * Coverage:
 *   C1 — No resolver supplied → returns { ok: true } (no-op).
 *   C2 — Resolver returns null for prev → returns { ok: true } (dangling ref,
 *        no crash).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { composeAtokr } from "../src/compose.ts";
import type { AtokrBody } from "../src/types.ts";

const VALID_SHA = "sha256:" + "a".repeat(64);

const STUB_RESOLVE_KEY = async () => new Uint8Array(0);

function makeEnvelope(prev: string | null = null) {
  return {
    id: "r-001",
    claim_type: "ar.tokenization.v1",
    iss: "did:web:dekimu.com",
    iat: "2026-05-21T10:00:00Z",
    prev,
    subject: VALID_SHA,
    body: {
      event_type: "token.issued",
      token_id: "tok-001",
      format_class: "email",
      scope: {
        audience: "did:web:a.example.com",
        purpose: "invoice_share",
        valid_from: "2026-01-01T00:00:00Z",
        valid_until: null,
        single_use: false,
      },
      rotation_of: null,
      redemption_audit_ref: null,
      asr_ref: null,
      arr_ref: null,
      alr_ref: null,
      apur_ref: null,
    } as AtokrBody,
  };
}

test("C1 — no resolver → returns { ok: true }", async () => {
  const result = await composeAtokr({
    envelope: makeEnvelope(),
    opts: { resolveKey: STUB_RESOLVE_KEY },
  });
  assert.deepEqual(result, { ok: true });
});

test("C2 — resolver returns null for prev → returns { ok: true } (dangling ref)", async () => {
  const result = await composeAtokr({
    envelope: makeEnvelope("r-prev-missing"),
    opts: {
      resolveKey: STUB_RESOLVE_KEY,
      resolveReceiptById: async (_id: string) => null,
    },
  });
  assert.deepEqual(result, { ok: true });
});
