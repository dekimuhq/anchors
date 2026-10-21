/**
 * Standalone tests for the v1.2 cause enum extension (D-anchors-7).
 *
 * Kept separate so `node --test test/cause-enum.test.ts` gives a definitive
 * non-zero exit when these two assertions fail — avoids the silent-pass trap
 * that occurs when a missing file matches zero tests and exits 0.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { CAUSE_VALUES } from "../src/index.ts";

test("v1.2 — CAUSE_VALUES includes D-anchors-7 additions (breach, review_cycle, material_change)", () => {
  for (const v of ["breach", "review_cycle", "material_change"] as const) {
    assert.ok((CAUSE_VALUES as readonly string[]).includes(v), `${v} missing`);
  }
});

test("v1.2 — CAUSE_VALUES length is 13 after D-anchors-7", () => {
  assert.strictEqual(CAUSE_VALUES.length, 13);
});
