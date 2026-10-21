/**
 * Assignability tests for the AGR v1 body union (spec §4).
 *
 * These are compile-time guarantees surfaced as runtime smoke checks: a valid
 * `guard.input` body must be assignable to `AGRBody`. `npx tsc --noEmit` is
 * the real gate; the runtime asserts keep the test runner honest.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { AGRBody, GuardInputBody } from "../src/body.ts";

const H64 = "a".repeat(64);

test("B1: a valid guard.input body is assignable to AGRBody", () => {
  const input: GuardInputBody = {
    profile: "guard.input",
    ruleset_id: "prompt-injection-v1",
    ruleset_hash: H64,
    ruleset_version: "1.0.0",
    content_commit: H64,
    decision: "blocked",
    matched_rules: [
      { id: "PI-001", category: "instruction_override", severity: "critical" },
    ],
    detector: { engine: "deterministic", name: "guard-detect", version: "0.1.0" },
    screened_at: "2026-06-20T10:00:00.000Z",
  };
  const body: AGRBody = input;
  assert.equal(body.profile, "guard.input");
});
