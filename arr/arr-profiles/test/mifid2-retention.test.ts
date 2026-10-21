import { test } from "node:test";
import assert from "node:assert/strict";
import { validateMifid2Retention } from "../src/index.ts";

function base(overrides: Record<string, unknown> = {}) {
  return {
    kind: "ar.expiry.v1",
    profile: "mifid2.retention",
    trigger: "scheduled",
    target_kind: "artifact",
    trade_commit: "sha256:" + "11".repeat(32),
    instrument_commit: "sha256:" + "22".repeat(32),
    venue_commit: "sha256:" + "33".repeat(32),
    mifid_class: "derivative",
    record_origin_at: "2016-01-01T00:00:00Z",
    event_at: "2024-06-01T00:00:00Z",
    ...overrides,
  };
}

test("derivative 7+ years passes", () => {
  const out = validateMifid2Retention(base() as never);
  assert.deepEqual(out.errors, []);
});

test("equity 5-year boundary respected", () => {
  const out = validateMifid2Retention(base({
    mifid_class: "equity",
    record_origin_at: "2019-01-01T00:00:00Z",
    event_at: "2024-06-01T00:00:00Z",
  }) as never);
  assert.deepEqual(out.errors, []);
});

test("derivative under 7 years fails", () => {
  const out = validateMifid2Retention(base({ event_at: "2020-06-01T00:00:00Z" }) as never);
  assert.ok(out.errors.includes("mifid2.retention.min_period.violated"));
});

test("invalid mifid_class flagged", () => {
  const out = validateMifid2Retention(base({ mifid_class: "crypto" }) as never);
  assert.ok(out.errors.includes("mifid2.retention.mifid_class.invalid"));
});
