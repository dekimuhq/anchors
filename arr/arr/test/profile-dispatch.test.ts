/**
 * E2E tests for verifier-level profile-validator dispatch (ARR side).
 *
 * Post-A2 migration: profile validators are wired into the family manifest.
 * The factory dispatches the validator when `opts.profile` matches a registered
 * profile ID. The factory's tsa_mandate enforcement is HARD — a MANDATORY
 * profile with absent TSA poisons signature_valid (spec-correct behavior).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { arrFamily } from "../src/family.ts";
import v2Fixture from "./fixtures/v2-arr-erasure.ts";

// ── no profile option → profile_state undefined ─────────────────────────────

test("arrFamily.verifyReceipt: no profile option → result.profile_state undefined", async () => {
  const { envelope, publicKey } = v2Fixture;
  const result = await arrFamily.verifyReceipt(
    envelope as unknown as Record<string, unknown>,
    { resolveKey: async () => publicKey },
  );
  assert.equal(result.signature_valid, true);
  assert.equal(result.profile_state, undefined);
});

// ── profile on a TSA-less receipt → hard fail (MANDATORY) ───────────────────

test("arrFamily.verifyReceipt: gdpr.art17.erasure-finalized on TSA-less receipt → signature_valid: false (mandatory TSA)", async () => {
  const { envelope, publicKey } = v2Fixture;
  const result = await arrFamily.verifyReceipt(
    envelope as unknown as Record<string, unknown>,
    { resolveKey: async () => publicKey, profile: "arr.gdpr.art17.erasure-finalized" },
  );
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "tsa_required");
});

// ── signature_valid=false → no dispatch (profile_state undefined) ───────────

test("arrFamily.verifyReceipt: tampered envelope (signature_valid=false) → profile_state undefined", async () => {
  const { envelope, publicKey } = v2Fixture;
  const tampered = { ...envelope, body: { tampered: true } };
  const result = await arrFamily.verifyReceipt(
    tampered as unknown as Record<string, unknown>,
    { resolveKey: async () => publicKey, profile: "arr.gdpr.art17.erasure-finalized" },
  );
  assert.equal(result.signature_valid, false);
  assert.equal(result.profile_state, undefined);
});
