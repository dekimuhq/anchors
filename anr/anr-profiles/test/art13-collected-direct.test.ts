/**
 * Tests for the notice.art13.collected_direct profile validator (ANR §5.1).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ART13_COLLECTED_DIRECT_PROFILE_ID,
  ART13_RIGHTS_SURFACE_MINIMUM,
  validateArt13CollectedDirect,
  validateArt13CollectedDirectProfile,
} from "../src/art13-collected-direct.ts";
import {
  acknowledged,
  jointControllerEssence,
  presented,
  rePresented,
  translated,
  withdrawn,
} from "./_helpers/bodies.ts";

test("art13: presented with full rights_surface minimum passes", () => {
  const out = validateArt13CollectedDirect(
    presented(ART13_COLLECTED_DIRECT_PROFILE_ID),
  );
  assert.deepEqual(out.errors, []);
});

test("art13: re_presented with full rights_surface minimum passes", () => {
  const out = validateArt13CollectedDirect(
    rePresented(ART13_COLLECTED_DIRECT_PROFILE_ID),
  );
  assert.deepEqual(out.errors, []);
});

test("art13: acknowledged passes (rights_surface pinned null is body-level invariant)", () => {
  const out = validateArt13CollectedDirect(
    acknowledged(ART13_COLLECTED_DIRECT_PROFILE_ID),
  );
  assert.deepEqual(out.errors, []);
});

test("art13: withdrawn passes (rights_surface pinned null)", () => {
  const out = validateArt13CollectedDirect(
    withdrawn(ART13_COLLECTED_DIRECT_PROFILE_ID),
  );
  assert.deepEqual(out.errors, []);
});

test("art13: translated passes (rights_surface pinned null)", () => {
  const out = validateArt13CollectedDirect(
    translated(ART13_COLLECTED_DIRECT_PROFILE_ID),
  );
  assert.deepEqual(out.errors, []);
});

test("art13: joint_controller_essence event_type rejected", () => {
  const out = validateArt13CollectedDirect(
    jointControllerEssence(ART13_COLLECTED_DIRECT_PROFILE_ID),
  );
  assert.ok(
    out.errors.includes("notice.art13.collected_direct.event_type.disallowed"),
  );
});

test("art13: profile mismatch short-circuits", () => {
  const out = validateArt13CollectedDirect(
    presented("notice.art14.collected_indirect"),
  );
  assert.deepEqual(out.errors, [
    "notice.art13.collected_direct.profile.mismatch",
  ]);
});

test("art13: missing single right flagged with field name", () => {
  const out = validateArt13CollectedDirect(
    presented(ART13_COLLECTED_DIRECT_PROFILE_ID, {
      rights_surface: ["art15", "art16", "art17", "art18", "art20"],
    }),
  );
  assert.deepEqual(out.errors, [
    "notice.art13.collected_direct.rights_surface.missing:art21",
  ]);
});

test("art13: missing multiple rights flagged individually", () => {
  const out = validateArt13CollectedDirect(
    presented(ART13_COLLECTED_DIRECT_PROFILE_ID, {
      rights_surface: ["art15"],
    }),
  );
  assert.deepEqual(out.errors, [
    "notice.art13.collected_direct.rights_surface.missing:art16",
    "notice.art13.collected_direct.rights_surface.missing:art17",
    "notice.art13.collected_direct.rights_surface.missing:art18",
    "notice.art13.collected_direct.rights_surface.missing:art20",
    "notice.art13.collected_direct.rights_surface.missing:art21",
  ]);
});

test("art13: empty rights_surface flags all six required rights", () => {
  const out = validateArt13CollectedDirect(
    presented(ART13_COLLECTED_DIRECT_PROFILE_ID, { rights_surface: [] }),
  );
  assert.equal(out.errors.length, 6);
});

test("art13: rights_surface SUPERSET of minimum passes", () => {
  const out = validateArt13CollectedDirect(
    presented(ART13_COLLECTED_DIRECT_PROFILE_ID, {
      rights_surface: [...ART13_RIGHTS_SURFACE_MINIMUM, "art22"],
    }),
  );
  assert.deepEqual(out.errors, []);
});

test("art13: re_presented with deficient rights_surface flagged", () => {
  const out = validateArt13CollectedDirect(
    rePresented(ART13_COLLECTED_DIRECT_PROFILE_ID, {
      rights_surface: ["art15", "art16"],
    }),
  );
  assert.equal(out.errors.length, 4);
});

// ── Adapter ──────────────────────────────────────────────────────────────────

test("art13 adapter: ok=true on valid", () => {
  const out = validateArt13CollectedDirectProfile(
    {} as never,
    presented(ART13_COLLECTED_DIRECT_PROFILE_ID),
    {},
  );
  assert.equal(out.profile_id, ART13_COLLECTED_DIRECT_PROFILE_ID);
  assert.equal(out.ok, true);
  assert.equal(out.reason, undefined);
});

test("art13 adapter: surfaces first error on reject", () => {
  const out = validateArt13CollectedDirectProfile(
    {} as never,
    presented(ART13_COLLECTED_DIRECT_PROFILE_ID, { rights_surface: [] }),
    {},
  );
  assert.equal(out.ok, false);
  assert.equal(
    out.reason,
    "notice.art13.collected_direct.rights_surface.missing:art15",
  );
});
