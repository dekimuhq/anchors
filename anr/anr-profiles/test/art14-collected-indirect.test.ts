/**
 * Tests for the notice.art14.collected_indirect profile validator (ANR §5.2).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ART14_COLLECTED_INDIRECT_PROFILE_ID,
  validateArt14CollectedIndirect,
  validateArt14CollectedIndirectProfile,
} from "../src/art14-collected-indirect.ts";
import {
  acknowledged,
  jointControllerEssence,
  presented,
  rePresented,
  translated,
  withdrawn,
} from "./_helpers/bodies.ts";

test("art14: presented with data_source + collection_horizon passes", () => {
  const out = validateArt14CollectedIndirect(
    presented(ART14_COLLECTED_INDIRECT_PROFILE_ID, {
      data_source: "https://registry.example.gov/dataset/42",
      collection_horizon: "one_month",
    }),
  );
  assert.deepEqual(out.errors, []);
});

test("art14: re_presented with required fields passes", () => {
  const out = validateArt14CollectedIndirect(
    rePresented(ART14_COLLECTED_INDIRECT_PROFILE_ID, {
      data_source: "https://registry.example.gov/dataset/42",
      collection_horizon: "first_communication",
    }),
  );
  assert.deepEqual(out.errors, []);
});

test("art14: presented missing data_source flagged", () => {
  const out = validateArt14CollectedIndirect(
    presented(ART14_COLLECTED_INDIRECT_PROFILE_ID, {
      data_source: null,
      collection_horizon: "one_month",
    }),
  );
  assert.deepEqual(out.errors, [
    "notice.art14.collected_indirect.data_source.required",
  ]);
});

test("art14: presented missing collection_horizon flagged", () => {
  const out = validateArt14CollectedIndirect(
    presented(ART14_COLLECTED_INDIRECT_PROFILE_ID, {
      data_source: "https://example.com/source",
      collection_horizon: null,
    }),
  );
  assert.deepEqual(out.errors, [
    "notice.art14.collected_indirect.collection_horizon.required",
  ]);
});

test("art14: presented missing both fields flags both", () => {
  const out = validateArt14CollectedIndirect(
    presented(ART14_COLLECTED_INDIRECT_PROFILE_ID),
  );
  assert.deepEqual(out.errors, [
    "notice.art14.collected_indirect.data_source.required",
    "notice.art14.collected_indirect.collection_horizon.required",
  ]);
});

test("art14: empty-string data_source flagged", () => {
  const out = validateArt14CollectedIndirect(
    presented(ART14_COLLECTED_INDIRECT_PROFILE_ID, {
      data_source: "",
      collection_horizon: "one_month",
    }),
  );
  assert.deepEqual(out.errors, [
    "notice.art14.collected_indirect.data_source.required",
  ]);
});

test("art14: acknowledged passes (field-presence checks skipped on non-presented)", () => {
  const out = validateArt14CollectedIndirect(
    acknowledged(ART14_COLLECTED_INDIRECT_PROFILE_ID),
  );
  assert.deepEqual(out.errors, []);
});

test("art14: withdrawn passes", () => {
  const out = validateArt14CollectedIndirect(
    withdrawn(ART14_COLLECTED_INDIRECT_PROFILE_ID),
  );
  assert.deepEqual(out.errors, []);
});

test("art14: translated passes", () => {
  const out = validateArt14CollectedIndirect(
    translated(ART14_COLLECTED_INDIRECT_PROFILE_ID),
  );
  assert.deepEqual(out.errors, []);
});

test("art14: joint_controller_essence event_type rejected", () => {
  const out = validateArt14CollectedIndirect(
    jointControllerEssence(ART14_COLLECTED_INDIRECT_PROFILE_ID),
  );
  assert.ok(
    out.errors.includes(
      "notice.art14.collected_indirect.event_type.disallowed",
    ),
  );
});

test("art14: profile mismatch short-circuits", () => {
  const out = validateArt14CollectedIndirect(
    presented("notice.art13.collected_direct"),
  );
  assert.deepEqual(out.errors, [
    "notice.art14.collected_indirect.profile.mismatch",
  ]);
});

// ── Adapter ──────────────────────────────────────────────────────────────────

test("art14 adapter: ok=true on valid", () => {
  const out = validateArt14CollectedIndirectProfile(
    {} as never,
    presented(ART14_COLLECTED_INDIRECT_PROFILE_ID, {
      data_source: "https://example.com/source",
      collection_horizon: "one_month",
    }),
    {},
  );
  assert.equal(out.profile_id, ART14_COLLECTED_INDIRECT_PROFILE_ID);
  assert.equal(out.ok, true);
});

test("art14 adapter: surfaces first error on reject", () => {
  const out = validateArt14CollectedIndirectProfile(
    {} as never,
    presented(ART14_COLLECTED_INDIRECT_PROFILE_ID),
    {},
  );
  assert.equal(out.ok, false);
  assert.equal(
    out.reason,
    "notice.art14.collected_indirect.data_source.required",
  );
});
