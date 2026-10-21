/**
 * Tests for the tokenization.eudi.wallet_arf profile validator (ATokR §5.4).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { AtokrBody } from "@dekimuhq/atokr";
import {
  EUDI_WALLET_ARF_PROFILE_ID,
  validateEudiWalletArf,
  validateEudiWalletArfProfile,
} from "../src/eudi-wallet-arf.ts";

function makeBody(overrides?: Record<string, unknown>): AtokrBody {
  return {
    event_type: "token.issued",
    token_id: "tok_123",
    format_class: "email",
    scope: {
      audience: "a",
      purpose: "p",
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
    wallet_provider_did: "did:web:wallet.example.com",
    attribute_category: "pid",
    ...overrides,
  } as AtokrBody;
}

test("eudi-wallet-arf: valid body with pid category passes", () => {
  const out = validateEudiWalletArf(makeBody());
  assert.deepEqual(out.errors, []);
});

test("eudi-wallet-arf: all valid attribute_category values pass", () => {
  for (const cat of ["pid", "qeaa", "eaa", "pda"]) {
    const out = validateEudiWalletArf(makeBody({ attribute_category: cat }));
    assert.deepEqual(out.errors, [], `expected no errors for category=${cat}`);
  }
});

test("eudi-wallet-arf: missing wallet_provider_did produces .missing error", () => {
  const body = makeBody();
  const b = body as unknown as Record<string, unknown>;
  delete b["wallet_provider_did"];
  const out = validateEudiWalletArf(body);
  assert.ok(
    out.errors.includes(
      "tokenization.eudi.wallet_arf.wallet_provider_did.missing",
    ),
  );
});

test("eudi-wallet-arf: empty wallet_provider_did produces .missing error", () => {
  const out = validateEudiWalletArf(
    makeBody({ wallet_provider_did: "" }),
  );
  assert.ok(
    out.errors.includes(
      "tokenization.eudi.wallet_arf.wallet_provider_did.missing",
    ),
  );
});

test("eudi-wallet-arf: invalid attribute_category produces .invalid error", () => {
  const out = validateEudiWalletArf(
    makeBody({ attribute_category: "unknown_cat" }),
  );
  assert.ok(
    out.errors.includes(
      "tokenization.eudi.wallet_arf.attribute_category.invalid",
    ),
  );
});

// ── Adapter ──────────────────────────────────────────────────────────────────

test("eudi-wallet-arf adapter: ok=true on valid body", () => {
  const out = validateEudiWalletArfProfile({} as never, makeBody(), {});
  assert.equal(out.profile_id, EUDI_WALLET_ARF_PROFILE_ID);
  assert.equal(out.ok, true);
  assert.equal(out.reason, undefined);
});

test("eudi-wallet-arf adapter: ok=false with reason on missing wallet_provider_did", () => {
  const body = makeBody();
  const b = body as unknown as Record<string, unknown>;
  delete b["wallet_provider_did"];
  const out = validateEudiWalletArfProfile({} as never, body, {});
  assert.equal(out.ok, false);
  assert.equal(
    out.reason,
    "tokenization.eudi.wallet_arf.wallet_provider_did.missing",
  );
});
