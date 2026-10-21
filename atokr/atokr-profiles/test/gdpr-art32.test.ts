/**
 * Tests for the tokenization.gdpr.art32 profile validator (ATokR §5.1).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { AtokrBody } from "@dekimuhq/atokr";
import {
  GDPR_ART32_PROFILE_ID,
  validateGdprArt32,
  validateGdprArt32Profile,
} from "../src/gdpr-art32.ts";

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
    ...overrides,
  } as AtokrBody;
}

test("gdpr-art32: valid body with non-empty purpose passes", () => {
  const out = validateGdprArt32(makeBody());
  assert.deepEqual(out.errors, []);
});

test("gdpr-art32: empty purpose string produces purpose_missing error", () => {
  const out = validateGdprArt32(
    makeBody({ scope: { audience: "a", purpose: "", valid_from: "2026-01-01T00:00:00Z", valid_until: null, single_use: false } }),
  );
  assert.ok(out.errors.includes("tokenization.gdpr.art32.purpose_missing"));
});

test("gdpr-art32: whitespace-only purpose string produces purpose_missing error", () => {
  const out = validateGdprArt32(
    makeBody({ scope: { audience: "a", purpose: "   ", valid_from: "2026-01-01T00:00:00Z", valid_until: null, single_use: false } }),
  );
  assert.ok(out.errors.includes("tokenization.gdpr.art32.purpose_missing"));
});

// ── Adapter ──────────────────────────────────────────────────────────────────

test("gdpr-art32 adapter: ok=true on valid body", () => {
  const out = validateGdprArt32Profile({} as never, makeBody(), {});
  assert.equal(out.profile_id, GDPR_ART32_PROFILE_ID);
  assert.equal(out.ok, true);
  assert.equal(out.reason, undefined);
});

test("gdpr-art32 adapter: ok=false and reason set on empty purpose", () => {
  const out = validateGdprArt32Profile(
    {} as never,
    makeBody({ scope: { audience: "a", purpose: "", valid_from: "2026-01-01T00:00:00Z", valid_until: null, single_use: false } }),
    {},
  );
  assert.equal(out.ok, false);
  assert.equal(out.reason, "tokenization.gdpr.art32.purpose_missing");
});
