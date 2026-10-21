import { test } from "node:test";
import assert from "node:assert/strict";
import { resolveLayout } from "../src/tree.ts";
import { ABR_DISCLOSURE_SCHEMA } from "../src/schemas/abr.ts";

// An ABR breach.detected body shape (every union field present; nulls allowed).
const abrBody = {
  profile: "breach.gdpr.art33",
  incident_correlation_id: "INC-2026-0001",
  qts_attestation_hash: null,
  event_type: "breach.detected",
  detected_at: "2026-05-19T00:00:00Z",
  severity_class: "high",
  affected_data_categories: ["contact"],
  affected_data_hash: "sha256:" + "a".repeat(64),
  affected_count: 42,
  jurisdiction: "EU",
  field_root: "sha256:" + "f".repeat(64), // present at verify time; not a declared leaf
};

test("ABR schema declares the four always-present scalar leaves", () => {
  assert.deepEqual(ABR_DISCLOSURE_SCHEMA.leaves.map((l) => l.path), [
    "/profile",
    "/incident_correlation_id",
    "/event_type",
    "/jurisdiction",
  ]);
  assert.equal(ABR_DISCLOSURE_SCHEMA.leaves.every((l) => !l.array), true);
});

test("ABR schema resolves cleanly against a detected body (4 leaves, declared order)", () => {
  const layout = resolveLayout(abrBody, ABR_DISCLOSURE_SCHEMA);
  assert.deepEqual(layout.map((l) => l.path), ["/profile", "/incident_correlation_id", "/event_type", "/jurisdiction"]);
  assert.deepEqual(layout.map((l) => l.value), ["breach.gdpr.art33", "INC-2026-0001", "breach.detected", "EU"]);
});

test("ABR schema resolves on an assessed body where jurisdiction is null", () => {
  const assessed = { ...abrBody, event_type: "breach.assessed", jurisdiction: null };
  const layout = resolveLayout(assessed, ABR_DISCLOSURE_SCHEMA);
  assert.deepEqual(layout.map((l) => l.value), ["breach.gdpr.art33", "INC-2026-0001", "breach.assessed", null]);
});
