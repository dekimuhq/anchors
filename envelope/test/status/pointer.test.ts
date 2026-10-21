/**
 * Tests for validateCredentialStatusPointer.
 *
 * Phase D Task 15 — @dekimuhq/anchors-envelope 0.2.0
 *
 * Covers every rejection branch in the implementation plus the happy path.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { validateCredentialStatusPointer } from "../../src/status/pointer.ts";

// ── Happy path ───────────────────────────────────────────────────────────────

test("valid pointer parses", () => {
  const p = {
    id: "https://verify.dekimu.com/acr/v1/status/2026/04#7",
    type: "StatusList2021Entry" as const,
    statusPurpose: "revocation" as const,
    statusListIndex: "7",
    statusListCredential: "https://verify.dekimu.com/acr/v1/status/2026/04",
  };
  const r = validateCredentialStatusPointer(p);
  assert.equal(r.ok, true);
});

// ── Top-level shape rejections ───────────────────────────────────────────────

test("null rejects with schema_invalid:credentialStatus", () => {
  const r = validateCredentialStatusPointer(null);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "schema_invalid:credentialStatus");
});

test("non-object (string) rejects with schema_invalid:credentialStatus", () => {
  const r = validateCredentialStatusPointer("not an object");
  assert.equal(r.ok, false);
  assert.equal(r.reason, "schema_invalid:credentialStatus");
});

// ── Field-level rejections ───────────────────────────────────────────────────

test("wrong type rejects with unsupported_status_type", () => {
  const r = validateCredentialStatusPointer({
    id: "https://x",
    type: "BitstringStatusListEntry",
    statusPurpose: "revocation",
    statusListIndex: "7",
    statusListCredential: "https://x",
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "unsupported_status_type");
});

test("wrong statusPurpose rejects with unsupported_status_purpose", () => {
  const r = validateCredentialStatusPointer({
    id: "https://x",
    type: "StatusList2021Entry",
    statusPurpose: "suspension",
    statusListIndex: "7",
    statusListCredential: "https://x",
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "unsupported_status_purpose");
});

test("statusListIndex must be numeric string", () => {
  const r = validateCredentialStatusPointer({
    id: "https://x",
    type: "StatusList2021Entry",
    statusPurpose: "revocation",
    statusListIndex: "not-a-number",
    statusListCredential: "https://x",
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "invalid_status_list_index");
});

test("empty statusListIndex rejects with invalid_status_list_index", () => {
  const r = validateCredentialStatusPointer({
    id: "https://x",
    type: "StatusList2021Entry",
    statusPurpose: "revocation",
    statusListIndex: "",
    statusListCredential: "https://x",
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "invalid_status_list_index");
});

test("non-https statusListCredential rejects with invalid_status_list_credential", () => {
  const r = validateCredentialStatusPointer({
    id: "https://x",
    type: "StatusList2021Entry",
    statusPurpose: "revocation",
    statusListIndex: "7",
    statusListCredential: "http://insecure.example/p",
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "invalid_status_list_credential");
});

test("missing statusListCredential rejects with invalid_status_list_credential", () => {
  const r = validateCredentialStatusPointer({
    id: "https://x",
    type: "StatusList2021Entry",
    statusPurpose: "revocation",
    statusListIndex: "7",
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "invalid_status_list_credential");
});

test("missing id rejects with missing_status_id", () => {
  const r = validateCredentialStatusPointer({
    type: "StatusList2021Entry",
    statusPurpose: "revocation",
    statusListIndex: "7",
    statusListCredential: "https://x",
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "missing_status_id");
});
