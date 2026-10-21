import { test } from "node:test";
import assert from "node:assert/strict";
import { resolveLayout } from "../src/tree.ts";
import { ALR_DISCLOSURE_SCHEMA } from "../src/schemas/alr.ts";

// An ALR derived_from body shape (every union field present; nulls allowed).
const alrBody = {
  profile: "gdpr.art13.transparency",
  artifact_hash: "sha256:" + "a".repeat(64),
  event_at: "2026-05-17T00:00:00Z",
  qts_attestation_hash: null,
  event_type: "derived_from",
  parents: [{ artifact_hash: "sha256:" + "b".repeat(64), parent_apr_id: null, parent_alr_id: null, uri: null }],
  successor: null,
  transform_claim: { summary: "joined two tables", uri: null },
  disclosure: null,
  field_root: "sha256:" + "f".repeat(64), // present at verify time; not a declared leaf
};

test("ALR schema declares the four always-present scalar leaves", () => {
  assert.deepEqual(ALR_DISCLOSURE_SCHEMA.leaves.map((l) => l.path), [
    "/profile",
    "/artifact_hash",
    "/event_at",
    "/event_type",
  ]);
  assert.equal(ALR_DISCLOSURE_SCHEMA.leaves.every((l) => !l.array), true);
});

test("ALR schema resolves cleanly against a derived_from body (4 leaves, declared order)", () => {
  const layout = resolveLayout(alrBody, ALR_DISCLOSURE_SCHEMA);
  assert.deepEqual(layout.map((l) => l.path), ["/profile", "/artifact_hash", "/event_at", "/event_type"]);
  assert.deepEqual(layout.map((l) => l.value), [
    "gdpr.art13.transparency",
    "sha256:" + "a".repeat(64),
    "2026-05-17T00:00:00Z",
    "derived_from",
  ]);
});

test("ALR schema resolves on a disclosed body (all scalar leaves still present)", () => {
  const disclosed = {
    ...alrBody,
    event_type: "disclosed",
    parents: [],
    transform_claim: null,
    disclosure: { recipient: "r", recipient_role: "processor", scope_hash: "sha256:" + "c".repeat(64), basis: "gdpr.art6.1.f" },
  };
  const layout = resolveLayout(disclosed, ALR_DISCLOSURE_SCHEMA);
  assert.deepEqual(layout.map((l) => l.value), [
    "gdpr.art13.transparency",
    "sha256:" + "a".repeat(64),
    "2026-05-17T00:00:00Z",
    "disclosed",
  ]);
});
