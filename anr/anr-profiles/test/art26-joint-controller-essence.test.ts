/**
 * Tests for the notice.art26.joint_controller_essence profile validator (ANR §5.3).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ART26_JOINT_CONTROLLER_ESSENCE_PROFILE_ID,
  validateArt26JointControllerEssence,
  validateArt26JointControllerEssenceProfile,
} from "../src/art26-joint-controller-essence.ts";
import {
  jointControllerEssence,
  presented,
} from "./_helpers/bodies.ts";

test("art26: joint_controller_essence with one joint controller passes", () => {
  const out = validateArt26JointControllerEssence(
    jointControllerEssence(ART26_JOINT_CONTROLLER_ESSENCE_PROFILE_ID),
  );
  assert.deepEqual(out.errors, []);
});

test("art26: joint_controller_essence with multiple controllers passes", () => {
  const out = validateArt26JointControllerEssence(
    jointControllerEssence(ART26_JOINT_CONTROLLER_ESSENCE_PROFILE_ID, {
      joint_controllers: [
        {
          did: "did:web:a.example",
          role: "controller",
          contact_point_uri: "https://a.example/dpo",
          adr_id: "01HADR1AAAAAAAAAAAAAAAAAAA",
        },
        {
          did: "did:web:b.example",
          role: "co-controller",
          contact_point_uri: "https://b.example/dpo",
          adr_id: null,
        },
      ],
    }),
  );
  assert.deepEqual(out.errors, []);
});

test("art26: empty joint_controllers array flagged", () => {
  const out = validateArt26JointControllerEssence(
    jointControllerEssence(ART26_JOINT_CONTROLLER_ESSENCE_PROFILE_ID, {
      joint_controllers: [],
    }),
  );
  assert.deepEqual(out.errors, [
    "notice.art26.joint_controller_essence.joint_controllers.empty",
  ]);
});

test("art26: non-joint_controller_essence event_type rejected (presented)", () => {
  const out = validateArt26JointControllerEssence(
    presented(ART26_JOINT_CONTROLLER_ESSENCE_PROFILE_ID),
  );
  assert.deepEqual(out.errors, [
    "notice.art26.joint_controller_essence.event_type.disallowed",
  ]);
});

test("art26: profile mismatch short-circuits", () => {
  const out = validateArt26JointControllerEssence(
    jointControllerEssence("notice.art13.collected_direct"),
  );
  assert.deepEqual(out.errors, [
    "notice.art26.joint_controller_essence.profile.mismatch",
  ]);
});

// ── Adapter ──────────────────────────────────────────────────────────────────

test("art26 adapter: ok=true on valid", () => {
  const out = validateArt26JointControllerEssenceProfile(
    {} as never,
    jointControllerEssence(ART26_JOINT_CONTROLLER_ESSENCE_PROFILE_ID),
    {},
  );
  assert.equal(out.profile_id, ART26_JOINT_CONTROLLER_ESSENCE_PROFILE_ID);
  assert.equal(out.ok, true);
});

test("art26 adapter: surfaces first error on empty array", () => {
  const out = validateArt26JointControllerEssenceProfile(
    {} as never,
    jointControllerEssence(ART26_JOINT_CONTROLLER_ESSENCE_PROFILE_ID, {
      joint_controllers: [],
    }),
    {},
  );
  assert.equal(out.ok, false);
  assert.equal(
    out.reason,
    "notice.art26.joint_controller_essence.joint_controllers.empty",
  );
});
