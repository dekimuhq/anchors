/**
 * Tests for the tokenization.sector.health profile validator (ATokR §5.5).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { AtokrBody } from "@dekimuhq/atokr";
import {
  SECTOR_HEALTH_PROFILE_ID,
  validateSectorHealth,
  validateSectorHealthProfile,
} from "../src/sector-health.ts";

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
    data_use_category: "primary_care",
    ...overrides,
  } as AtokrBody;
}

test("sector-health: valid body with primary_care passes", () => {
  const out = validateSectorHealth(makeBody());
  assert.deepEqual(out.errors, []);
});

test("sector-health: all valid data_use_category values pass", () => {
  for (const duc of [
    "primary_care",
    "secondary_research",
    "clinical_trial",
    "public_health",
  ]) {
    const out = validateSectorHealth(makeBody({ data_use_category: duc }));
    assert.deepEqual(
      out.errors,
      [],
      `expected no errors for data_use_category=${duc}`,
    );
  }
});

test("sector-health: invalid data_use_category produces .invalid error", () => {
  const out = validateSectorHealth(
    makeBody({ data_use_category: "unknown_category" }),
  );
  assert.ok(
    out.errors.includes(
      "tokenization.sector.health.data_use_category.invalid",
    ),
  );
});

test("sector-health: missing data_use_category produces .invalid error", () => {
  const body = makeBody();
  const b = body as unknown as Record<string, unknown>;
  delete b["data_use_category"];
  const out = validateSectorHealth(body);
  assert.ok(
    out.errors.includes(
      "tokenization.sector.health.data_use_category.invalid",
    ),
  );
});

// ── Adapter ──────────────────────────────────────────────────────────────────

test("sector-health adapter: ok=true on valid body", () => {
  const out = validateSectorHealthProfile({} as never, makeBody(), {});
  assert.equal(out.profile_id, SECTOR_HEALTH_PROFILE_ID);
  assert.equal(out.ok, true);
  assert.equal(out.reason, undefined);
});

test("sector-health adapter: ok=false with reason on invalid category", () => {
  const out = validateSectorHealthProfile(
    {} as never,
    makeBody({ data_use_category: "billing" }),
    {},
  );
  assert.equal(out.ok, false);
  assert.equal(
    out.reason,
    "tokenization.sector.health.data_use_category.invalid",
  );
});
