/**
 * Tests for validateSuspensionStatusPointer — Wave 3.
 *
 * Mirrors pointer.test.ts structure but validates statusPurpose: "suspension".
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { validateSuspensionStatusPointer } from "../../src/status/suspension-pointer.ts";

test("valid suspension pointer parses", () => {
  const p = {
    id: "https://verify.dekimu.com/acr/v1/suspension/2026/05#7",
    type: "StatusList2021Entry" as const,
    statusPurpose: "suspension" as const,
    statusListIndex: "7",
    statusListCredential: "https://verify.dekimu.com/acr/v1/suspension/2026/05",
  };
  const r = validateSuspensionStatusPointer(p);
  assert.equal(r.ok, true);
});

test("null rejects with schema_invalid:suspensionStatus", () => {
  const r = validateSuspensionStatusPointer(null);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "schema_invalid:suspensionStatus");
});

test("non-object (string) rejects with schema_invalid:suspensionStatus", () => {
  const r = validateSuspensionStatusPointer("not an object");
  assert.equal(r.ok, false);
  assert.equal(r.reason, "schema_invalid:suspensionStatus");
});

test("wrong type rejects with unsupported_status_type", () => {
  const r = validateSuspensionStatusPointer({
    id: "https://x",
    type: "BitstringStatusListEntry",
    statusPurpose: "suspension",
    statusListIndex: "7",
    statusListCredential: "https://x",
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "unsupported_status_type");
});

test("statusPurpose revocation rejects with unsupported_suspension_purpose", () => {
  const r = validateSuspensionStatusPointer({
    id: "https://x",
    type: "StatusList2021Entry",
    statusPurpose: "revocation",
    statusListIndex: "7",
    statusListCredential: "https://x",
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "unsupported_suspension_purpose");
});

test("statusListIndex must be numeric string", () => {
  const r = validateSuspensionStatusPointer({
    id: "https://x",
    type: "StatusList2021Entry",
    statusPurpose: "suspension",
    statusListIndex: "not-a-number",
    statusListCredential: "https://x",
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "invalid_status_list_index");
});

test("empty statusListIndex rejects", () => {
  const r = validateSuspensionStatusPointer({
    id: "https://x",
    type: "StatusList2021Entry",
    statusPurpose: "suspension",
    statusListIndex: "",
    statusListCredential: "https://x",
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "invalid_status_list_index");
});

test("non-https statusListCredential rejects", () => {
  const r = validateSuspensionStatusPointer({
    id: "https://x",
    type: "StatusList2021Entry",
    statusPurpose: "suspension",
    statusListIndex: "7",
    statusListCredential: "http://insecure.example/p",
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "invalid_status_list_credential");
});

test("missing statusListCredential rejects", () => {
  const r = validateSuspensionStatusPointer({
    id: "https://x",
    type: "StatusList2021Entry",
    statusPurpose: "suspension",
    statusListIndex: "7",
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "invalid_status_list_credential");
});

test("missing id rejects with missing_status_id", () => {
  const r = validateSuspensionStatusPointer({
    type: "StatusList2021Entry",
    statusPurpose: "suspension",
    statusListIndex: "7",
    statusListCredential: "https://x",
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "missing_status_id");
});
