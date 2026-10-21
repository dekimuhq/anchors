/**
 * Tests for the tokenization.gdpr.art4_5 profile validator (ATokR §5.2).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { AtokrBody } from "@dekimuhq/atokr";
import {
  GDPR_ART4_5_PROFILE_ID,
  validateGdprArt4_5,
  validateGdprArt4_5Profile,
} from "../src/gdpr-art4-5.ts";

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
    separation_attestation: true,
    ...overrides,
  } as AtokrBody;
}

test("gdpr-art4_5: body with separation_attestation=true passes", () => {
  const out = validateGdprArt4_5(makeBody());
  assert.deepEqual(out.errors, []);
});

test("gdpr-art4_5: missing separation_attestation produces .missing error", () => {
  const body = makeBody();
  // Remove the field via casting since it's optional
  const b = body as unknown as Record<string, unknown>;
  delete b["separation_attestation"];
  const out = validateGdprArt4_5(body);
  assert.ok(
    out.errors.includes(
      "tokenization.gdpr.art4_5.separation_attestation.missing",
    ),
  );
});

test("gdpr-art4_5: separation_attestation=false produces separation_not_attested", () => {
  const out = validateGdprArt4_5(makeBody({ separation_attestation: false }));
  assert.ok(
    out.errors.includes("tokenization.gdpr.art4_5.separation_not_attested"),
  );
});

test("gdpr-art4_5: non-boolean separation_attestation produces .invalid error", () => {
  const out = validateGdprArt4_5(makeBody({ separation_attestation: "yes" }));
  assert.ok(
    out.errors.includes(
      "tokenization.gdpr.art4_5.separation_attestation.invalid",
    ),
  );
});

// ── Adapter ──────────────────────────────────────────────────────────────────

test("gdpr-art4_5 adapter: ok=true on valid body", () => {
  const out = validateGdprArt4_5Profile({} as never, makeBody(), {});
  assert.equal(out.profile_id, GDPR_ART4_5_PROFILE_ID);
  assert.equal(out.ok, true);
  assert.equal(out.reason, undefined);
});

test("gdpr-art4_5 adapter: ok=false with reason on false attestation", () => {
  const out = validateGdprArt4_5Profile(
    {} as never,
    makeBody({ separation_attestation: false }),
    {},
  );
  assert.equal(out.ok, false);
  assert.equal(
    out.reason,
    "tokenization.gdpr.art4_5.separation_not_attested",
  );
});
