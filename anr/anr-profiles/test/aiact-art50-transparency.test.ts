/**
 * Tests for the notice.aiact.art50_transparency profile validator (ANR §5.5).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  AIACT_ART50_TRANSPARENCY_PROFILE_ID,
  validateAiactArt50Transparency,
  validateAiactArt50TransparencyProfile,
} from "../src/aiact-art50-transparency.ts";
import {
  acknowledged,
  jointControllerEssence,
  presented,
  rePresented,
  translated,
  withdrawn,
} from "./_helpers/bodies.ts";

const AI_FIELDS = {
  ai_system_kind: "synthetic_content" as const,
  ai_system_provider_did: "did:web:openai.example",
};

test("art50: presented with ai_system_kind + ai_system_provider_did passes", () => {
  const out = validateAiactArt50Transparency(
    presented(AIACT_ART50_TRANSPARENCY_PROFILE_ID, AI_FIELDS),
  );
  assert.deepEqual(out.errors, []);
});

test("art50: re_presented with required fields passes", () => {
  const out = validateAiactArt50Transparency(
    rePresented(AIACT_ART50_TRANSPARENCY_PROFILE_ID, AI_FIELDS),
  );
  assert.deepEqual(out.errors, []);
});

test("art50: presented missing ai_system_kind flagged", () => {
  const out = validateAiactArt50Transparency(
    presented(AIACT_ART50_TRANSPARENCY_PROFILE_ID, {
      ai_system_provider_did: "did:web:openai.example",
    }),
  );
  assert.deepEqual(out.errors, [
    "notice.aiact.art50_transparency.ai_system_kind.required",
  ]);
});

test("art50: presented missing ai_system_provider_did flagged", () => {
  const out = validateAiactArt50Transparency(
    presented(AIACT_ART50_TRANSPARENCY_PROFILE_ID, {
      ai_system_kind: "interaction",
    }),
  );
  assert.deepEqual(out.errors, [
    "notice.aiact.art50_transparency.ai_system_provider_did.required",
  ]);
});

test("art50: empty-string provider_did flagged", () => {
  const out = validateAiactArt50Transparency(
    presented(AIACT_ART50_TRANSPARENCY_PROFILE_ID, {
      ai_system_kind: "deepfake",
      ai_system_provider_did: "",
    }),
  );
  assert.deepEqual(out.errors, [
    "notice.aiact.art50_transparency.ai_system_provider_did.required",
  ]);
});

test("art50: presented missing both fields flags both", () => {
  const out = validateAiactArt50Transparency(
    presented(AIACT_ART50_TRANSPARENCY_PROFILE_ID),
  );
  assert.deepEqual(out.errors, [
    "notice.aiact.art50_transparency.ai_system_kind.required",
    "notice.aiact.art50_transparency.ai_system_provider_did.required",
  ]);
});

test("art50: acknowledged passes (ai_* pinned null on non-presented events)", () => {
  const out = validateAiactArt50Transparency(
    acknowledged(AIACT_ART50_TRANSPARENCY_PROFILE_ID),
  );
  assert.deepEqual(out.errors, []);
});

test("art50: withdrawn passes", () => {
  const out = validateAiactArt50Transparency(
    withdrawn(AIACT_ART50_TRANSPARENCY_PROFILE_ID),
  );
  assert.deepEqual(out.errors, []);
});

test("art50: translated passes", () => {
  const out = validateAiactArt50Transparency(
    translated(AIACT_ART50_TRANSPARENCY_PROFILE_ID),
  );
  assert.deepEqual(out.errors, []);
});

test("art50: joint_controller_essence event_type rejected", () => {
  const out = validateAiactArt50Transparency(
    jointControllerEssence(AIACT_ART50_TRANSPARENCY_PROFILE_ID),
  );
  assert.deepEqual(out.errors, [
    "notice.aiact.art50_transparency.event_type.disallowed",
  ]);
});

test("art50: profile mismatch short-circuits", () => {
  const out = validateAiactArt50Transparency(
    presented("notice.art13.collected_direct", AI_FIELDS),
  );
  assert.deepEqual(out.errors, [
    "notice.aiact.art50_transparency.profile.mismatch",
  ]);
});

// ── Adapter ──────────────────────────────────────────────────────────────────

const QTS_CTX = {
  tsa_state: "tsa_verified",
  tsa_listed: true,
  tsa_policy_oid: "0.4.0.2023.1.1",
};

test("art50 adapter: ok=true with valid body + QTS ctx", () => {
  const out = validateAiactArt50TransparencyProfile(
    {} as never,
    presented(AIACT_ART50_TRANSPARENCY_PROFILE_ID, AI_FIELDS),
    QTS_CTX,
  );
  assert.equal(out.profile_id, AIACT_ART50_TRANSPARENCY_PROFILE_ID);
  assert.equal(out.ok, true);
});

test("art50 adapter: surfaces first body error on reject", () => {
  const out = validateAiactArt50TransparencyProfile(
    {} as never,
    presented(AIACT_ART50_TRANSPARENCY_PROFILE_ID),
    QTS_CTX,
  );
  assert.equal(out.ok, false);
  assert.equal(
    out.reason,
    "notice.aiact.art50_transparency.ai_system_kind.required",
  );
});

// ── QTS OID pinning ─────────────────────────────────────────────────────────

test("art50 adapter: tsa_listed=false fails with tsa_listed_required", () => {
  const out = validateAiactArt50TransparencyProfile(
    {} as never,
    presented(AIACT_ART50_TRANSPARENCY_PROFILE_ID, AI_FIELDS),
    { tsa_state: "tsa_verified", tsa_listed: false, tsa_policy_oid: "0.4.0.2023.1.1" },
  );
  assert.equal(out.ok, false);
  assert.equal(out.reason, "notice.aiact.art50_transparency.tsa_listed_required");
});

test("art50 adapter: tsa_listed undefined fails with tsa_listed_required", () => {
  const out = validateAiactArt50TransparencyProfile(
    {} as never,
    presented(AIACT_ART50_TRANSPARENCY_PROFILE_ID, AI_FIELDS),
    { tsa_state: "tsa_verified", tsa_policy_oid: "0.4.0.2023.1.1" },
  );
  assert.equal(out.ok, false);
  assert.equal(out.reason, "notice.aiact.art50_transparency.tsa_listed_required");
});

test("art50 adapter: wrong tsa_policy_oid fails with mismatch", () => {
  const out = validateAiactArt50TransparencyProfile(
    {} as never,
    presented(AIACT_ART50_TRANSPARENCY_PROFILE_ID, AI_FIELDS),
    { tsa_state: "tsa_verified", tsa_listed: true, tsa_policy_oid: "1.2.3.4.5" },
  );
  assert.equal(out.ok, false);
  assert.equal(out.reason, "notice.aiact.art50_transparency.tsa_policy_oid_mismatch");
});

test("art50 adapter: missing tsa_policy_oid fails with mismatch", () => {
  const out = validateAiactArt50TransparencyProfile(
    {} as never,
    presented(AIACT_ART50_TRANSPARENCY_PROFILE_ID, AI_FIELDS),
    { tsa_state: "tsa_verified", tsa_listed: true },
  );
  assert.equal(out.ok, false);
  assert.equal(out.reason, "notice.aiact.art50_transparency.tsa_policy_oid_mismatch");
});

test("art50 adapter: tsa_state not verified fails", () => {
  const out = validateAiactArt50TransparencyProfile(
    {} as never,
    presented(AIACT_ART50_TRANSPARENCY_PROFILE_ID, AI_FIELDS),
    { tsa_state: "tsa_failed", tsa_listed: true, tsa_policy_oid: "0.4.0.2023.1.1" },
  );
  assert.equal(out.ok, false);
  assert.equal(out.reason, "notice.aiact.art50_transparency.tsa_not_verified");
});

test("art50 adapter: tsa_absent skips QTS check (mandate handles it)", () => {
  const out = validateAiactArt50TransparencyProfile(
    {} as never,
    presented(AIACT_ART50_TRANSPARENCY_PROFILE_ID, AI_FIELDS),
    { tsa_state: "tsa_absent" },
  );
  assert.equal(out.ok, true);
});

test("art50 adapter: empty ctx skips QTS check (no TSA data)", () => {
  const out = validateAiactArt50TransparencyProfile(
    {} as never,
    presented(AIACT_ART50_TRANSPARENCY_PROFILE_ID, AI_FIELDS),
    {},
  );
  assert.equal(out.ok, true);
});
