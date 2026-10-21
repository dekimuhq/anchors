/**
 * Tests for getAtrTsaMandate (FAMILY-CONSISTENCY.md §2).
 *
 * Coverage:
 *   T1 — arrangement → recommended
 *   T2 — suspension → recommended
 *   T3 — transfer → optional
 *   T4 — tia → optional
 *   T5 — unknown event type → optional (fallback)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { getAtrTsaMandate } from "../src/tsa-mandate.ts";

test("T1 — arrangement → recommended", () => {
  assert.equal(getAtrTsaMandate("arrangement"), "recommended");
});

test("T2 — suspension → recommended", () => {
  assert.equal(getAtrTsaMandate("suspension"), "recommended");
});

test("T3 — transfer → optional", () => {
  assert.equal(getAtrTsaMandate("transfer"), "optional");
});

test("T4 — tia → optional", () => {
  assert.equal(getAtrTsaMandate("tia"), "optional");
});

test("T5 — unknown event type → optional (fallback)", () => {
  assert.equal(getAtrTsaMandate("unknown_event"), "optional");
});
