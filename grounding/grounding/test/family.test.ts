/**
 * Tests for the AGrR family manifest (defineFamily wiring). Chip 18, ar.grounding.v1.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { groundingFamily } from "../src/family.ts";

const H = "a".repeat(64);
const H2 = "b".repeat(64);

test("F1: acronym is AGrR", () => {
  assert.equal(groundingFamily.meta.acronym, "AGrR");
});

test("F2: name is Anchored Grounding Receipts", () => {
  assert.equal(groundingFamily.meta.name, "Anchored Grounding Receipts");
});

test("F3: owns ar.grounding.v1 claim_type", () => {
  assert.ok(groundingFamily.meta.claim_types.includes("ar.grounding.v1"));
});

test("F4: chip is 18", () => {
  assert.equal(groundingFamily.meta.chip, 18);
});

test("F5: status_list_slot is null (non-revocable)", () => {
  assert.equal(groundingFamily.meta.status_list_slot, null);
});

test("F6: subject_presence is must-be-null", () => {
  assert.equal(groundingFamily.meta.subject_presence, "must-be-null");
});

test("F7: tsa_upgrade_path is free", () => {
  assert.equal(groundingFamily.meta.tsa_upgrade_path, "free");
});

test("F8: continuity is false (single-receipt, no chain)", () => {
  assert.equal(groundingFamily.meta.continuity, false);
});

test("F9: spec_path points at the AGrR design doc", () => {
  assert.match(groundingFamily.meta.spec_path, /^https:\/\/github\.com\/dekimuhq\/anchors-spec\/tree\/main\/grounding$/);
});

test("F10: grounding.rag profile is registered", () => {
  assert.equal(groundingFamily.hasProfile("grounding.rag"), true);
});

test("F11: only grounding.rag profile registered, no extras", () => {
  assert.deepEqual([...groundingFamily.profileIds].sort(), ["grounding.rag"]);
});

test("F12: validateBody accepts a valid grounding.rag body", () => {
  const r = groundingFamily.validateBody({
    profile: "grounding.rag",
    answer_commit: H,
    sources: [{ source_id: "s1", source_commit: H }],
    claims: [{ claim_id: "c1", claim_commit: H }, { claim_id: "c2", claim_commit: H2 }],
    citations: [{ claim_id: "c1", source_id: "s1", start: 0, end: 5, span_commit: H, support: "supported", score: 0.9 }],
    coverage: 0.5,
    grounded_count: 1,
    scorer: { method: "lexical_overlap", name: "dekimu/grounding-check", version: "1.0.0", threshold: 0.6 },
    scored_at: "2026-06-20T10:00:00Z",
  });
  assert.equal(r.ok, true);
});

test("F13: validateBody rejects a non-object with body.not_object reason", () => {
  const r = groundingFamily.validateBody("nope");
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, "body.not_object");
});

test("F14: validateBody rejects wrong profile", () => {
  const r = groundingFamily.validateBody({ profile: "guard.input" });
  assert.equal(r.ok, false);
});
