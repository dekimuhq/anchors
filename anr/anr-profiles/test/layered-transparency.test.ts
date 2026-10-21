/**
 * Tests for the notice.layered_transparency profile validator (ANR §5.4).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  LAYERED_TRANSPARENCY_PROFILE_ID,
  validateLayeredTransparency,
  validateLayeredTransparencyProfile,
} from "../src/layered-transparency.ts";
import {
  acknowledged,
  H,
  jointControllerEssence,
  presented,
  rePresented,
  translated,
  withdrawn,
} from "./_helpers/bodies.ts";

const layers = (kinds: readonly ("summary" | "full" | "jit")[]) =>
  kinds.map((k, i) => ({
    layer: k,
    uri: `https://example.com/notice/${k}/${i}`,
    hash: H(String.fromCharCode(97 + i)),
  }));

test("layered: presented with summary + full passes", () => {
  const out = validateLayeredTransparency(
    presented(LAYERED_TRANSPARENCY_PROFILE_ID, {
      layer_uris: layers(["summary", "full"]),
    }),
  );
  assert.deepEqual(out.errors, []);
});

test("layered: presented with summary + full + jit passes", () => {
  const out = validateLayeredTransparency(
    presented(LAYERED_TRANSPARENCY_PROFILE_ID, {
      layer_uris: layers(["summary", "full", "jit"]),
    }),
  );
  assert.deepEqual(out.errors, []);
});

test("layered: re_presented with summary + full passes", () => {
  const out = validateLayeredTransparency(
    rePresented(LAYERED_TRANSPARENCY_PROFILE_ID, {
      layer_uris: layers(["summary", "full"]),
    }),
  );
  assert.deepEqual(out.errors, []);
});

test("layered: null layer_uris on presented flagged", () => {
  const out = validateLayeredTransparency(
    presented(LAYERED_TRANSPARENCY_PROFILE_ID),
  );
  assert.deepEqual(out.errors, [
    "notice.layered_transparency.layer_uris.required",
  ]);
});

test("layered: empty layer_uris on presented flagged", () => {
  const out = validateLayeredTransparency(
    presented(LAYERED_TRANSPARENCY_PROFILE_ID, { layer_uris: [] }),
  );
  assert.deepEqual(out.errors, [
    "notice.layered_transparency.layer_uris.required",
  ]);
});

test("layered: first layer not summary flagged", () => {
  const out = validateLayeredTransparency(
    presented(LAYERED_TRANSPARENCY_PROFILE_ID, {
      layer_uris: layers(["full", "summary"]),
    }),
  );
  assert.ok(
    out.errors.includes("notice.layered_transparency.layer_uris.summary_first"),
  );
});

test("layered: missing full layer flagged", () => {
  const out = validateLayeredTransparency(
    presented(LAYERED_TRANSPARENCY_PROFILE_ID, {
      layer_uris: layers(["summary", "jit"]),
    }),
  );
  assert.deepEqual(out.errors, [
    "notice.layered_transparency.layer_uris.full_required",
  ]);
});

test("layered: missing summary AND full on the same body flags both", () => {
  const out = validateLayeredTransparency(
    presented(LAYERED_TRANSPARENCY_PROFILE_ID, {
      layer_uris: layers(["jit"]),
    }),
  );
  assert.deepEqual(out.errors, [
    "notice.layered_transparency.layer_uris.summary_first",
    "notice.layered_transparency.layer_uris.full_required",
  ]);
});

test("layered: acknowledged passes (layer_uris pinned null is body-level invariant)", () => {
  const out = validateLayeredTransparency(
    acknowledged(LAYERED_TRANSPARENCY_PROFILE_ID),
  );
  assert.deepEqual(out.errors, []);
});

test("layered: withdrawn passes", () => {
  const out = validateLayeredTransparency(
    withdrawn(LAYERED_TRANSPARENCY_PROFILE_ID),
  );
  assert.deepEqual(out.errors, []);
});

test("layered: translated passes", () => {
  const out = validateLayeredTransparency(
    translated(LAYERED_TRANSPARENCY_PROFILE_ID),
  );
  assert.deepEqual(out.errors, []);
});

test("layered: joint_controller_essence event_type rejected", () => {
  const out = validateLayeredTransparency(
    jointControllerEssence(LAYERED_TRANSPARENCY_PROFILE_ID),
  );
  assert.deepEqual(out.errors, [
    "notice.layered_transparency.event_type.disallowed",
  ]);
});

test("layered: profile mismatch short-circuits", () => {
  const out = validateLayeredTransparency(
    presented("notice.art13.collected_direct"),
  );
  assert.deepEqual(out.errors, [
    "notice.layered_transparency.profile.mismatch",
  ]);
});

// ── Adapter ──────────────────────────────────────────────────────────────────

test("layered adapter: ok=true on valid", () => {
  const out = validateLayeredTransparencyProfile(
    {} as never,
    presented(LAYERED_TRANSPARENCY_PROFILE_ID, {
      layer_uris: layers(["summary", "full"]),
    }),
    {},
  );
  assert.equal(out.profile_id, LAYERED_TRANSPARENCY_PROFILE_ID);
  assert.equal(out.ok, true);
});

test("layered adapter: surfaces first error on reject", () => {
  const out = validateLayeredTransparencyProfile(
    {} as never,
    presented(LAYERED_TRANSPARENCY_PROFILE_ID),
    {},
  );
  assert.equal(out.ok, false);
  assert.equal(
    out.reason,
    "notice.layered_transparency.layer_uris.required",
  );
});
