/**
 * Smoke tests for the @dekimuhq/action-profiles public surface.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as profiles from "../src/index.ts";

test("X1: exports validateHubAutomation", () => {
  assert.equal(typeof profiles.validateHubAutomation, "function");
});

test("X2: exports validateHubAutomationProfile", () => {
  assert.equal(typeof profiles.validateHubAutomationProfile, "function");
});

test("X3: exports HUB_AUTOMATION_PROFILE_ID", () => {
  assert.equal(profiles.HUB_AUTOMATION_PROFILE_ID, "hub.automation");
});

test("X4: validator result shape has an errors array", () => {
  const r = profiles.validateHubAutomation({
    profile: "hub.automation",
    verb: "a.b",
    rule_id: "r",
    recipe_id: "x",
    outcome: "executed",
    executed_at: "2026-06-08T00:00:00Z",
    decision_commit: `sha256:${"a".repeat(64)}`,
    params_commit: `sha256:${"b".repeat(64)}`,
    request_id_commit: `sha256:${"c".repeat(64)}`,
  });
  assert.ok(Array.isArray(r.errors));
});
