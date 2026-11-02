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
import { validateGdprArt17ErasureFinalizedProfile } from "@dekimuhq/arr-profiles";
import type { Envelope } from "@dekimuhq/anchors-envelope";

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

// ── finalized adapter reads the signed v=2 envelope, not the body ───────────

test("gdpr.art17.erasure-finalized adapter: real v=2 envelope (no kind/tsa in body) + verified TSA → ok", () => {
  const { envelope } = v2Fixture;
  assert.equal("kind" in (envelope.body as object), false);
  assert.equal("tsa" in (envelope.body as object), false);
  const stamped = {
    ...envelope,
    tsa: {
      v: 1,
      tsr: "base64url",
      alg: "sha-256",
      tsa_url: "https://tsa.example",
      tsa_cert_chain_sha256: ["sha256:" + "a".repeat(64)],
      issued_at: "2026-05-17T12:00:00Z",
    },
  } as unknown as Envelope;
  const r = validateGdprArt17ErasureFinalizedProfile(stamped, stamped.body, { tsa_state: "tsa_verified" });
  assert.deepEqual(r, { profile_id: "arr.gdpr.art17.erasure-finalized", ok: true });
});

// ── malformed tsa (outside the signature) is a TSA outcome, never a throw ───

const TSA_SHAPE = {
  v: 1,
  alg: "sha-256",
  tsa_url: "https://tsa.example",
  tsa_cert_chain_sha256: ["sha256:" + "a".repeat(64)],
  issued_at: "2026-05-17T12:00:00Z",
};

for (const [label, tsr] of [["garbage tsr", "AAAA"], ["non-string tsr", 5]] as const) {
  test(`arrFamily.verifyReceipt: v=2 erasure + ${label} → signature_valid, tsa_malformed, profile reaches the TSA check`, async () => {
    const { envelope, publicKey } = v2Fixture;
    const stamped = { ...envelope, tsa: { ...TSA_SHAPE, tsr } };
    const result = await arrFamily.verifyReceipt(
      stamped as unknown as Record<string, unknown>,
      { resolveKey: async () => publicKey, profile: "arr.gdpr.art17.erasure-finalized", tsaAnchors: [] },
    );
    assert.equal(result.signature_valid, true);
    assert.equal(result.tsa_state, "tsa_malformed");
    const entry = result.profile_state?.find((p) => p.profile_id === "arr.gdpr.art17.erasure-finalized");
    assert.ok(entry, `profile not dispatched: ${JSON.stringify(result)}`);
    assert.deepEqual(entry, {
      profile_id: "arr.gdpr.art17.erasure-finalized",
      ok: false,
      reason: "tsa_failed:tsa_malformed",
    });
  });
}
