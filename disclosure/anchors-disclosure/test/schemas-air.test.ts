import { test } from "node:test";
import assert from "node:assert/strict";
import { resolveLayout } from "../src/tree.ts";
import { AIR_DISCLOSURE_SCHEMA } from "../src/schemas/air.ts";

// An AIR dpia.threshold_triggered body shape (every union field present; nulls allowed).
const airBody = {
  air_receipt_id: "AIR-2026-0001",
  processing_activity_id: "PA-customer-analytics-v1",
  qts_attestation_hash: null,
  event_type: "dpia.threshold_triggered",
  processing_activity_hash: "sha256:" + "a".repeat(64),
  processing_start_at: "2026-05-19T00:00:00Z",
  scope_hash: null,
  field_root: "sha256:" + "f".repeat(64), // present at verify time; not a declared leaf
};

test("AIR schema declares the three always-present scalar leaves (no profile in body)", () => {
  assert.deepEqual(AIR_DISCLOSURE_SCHEMA.leaves.map((l) => l.path), [
    "/air_receipt_id",
    "/processing_activity_id",
    "/event_type",
  ]);
  assert.equal(AIR_DISCLOSURE_SCHEMA.leaves.every((l) => !l.array), true);
});

test("AIR schema resolves cleanly against a threshold_triggered body (3 leaves, declared order)", () => {
  const layout = resolveLayout(airBody, AIR_DISCLOSURE_SCHEMA);
  assert.deepEqual(layout.map((l) => l.path), ["/air_receipt_id", "/processing_activity_id", "/event_type"]);
  assert.deepEqual(layout.map((l) => l.value), ["AIR-2026-0001", "PA-customer-analytics-v1", "dpia.threshold_triggered"]);
});

test("AIR schema resolves on a terminal (processing_authorised) body", () => {
  const authorised = { ...airBody, event_type: "dpia.processing_authorised", terminal_disposition: "authorised" };
  const layout = resolveLayout(authorised, AIR_DISCLOSURE_SCHEMA);
  assert.deepEqual(layout.map((l) => l.value), ["AIR-2026-0001", "PA-customer-analytics-v1", "dpia.processing_authorised"]);
});
