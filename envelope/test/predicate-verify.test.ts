/**
 * Phase D tests — composable verifier checks for v1.2 additions.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/envelope §7
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import {
  checkIatMs,
  checkPredicate,
  CLAIM_TYPES,
  rejectUnknownFields,
} from "../src/index.ts";
import type { Envelope } from "../src/index.ts";
import type { JsonLogicAst } from "../src/jsonlogic-types.ts";

// ── envelope fixture builder ─────────────────────────────────────────────────

function envelope(over: Partial<Envelope> = {}): Envelope {
  const iat = "2026-05-17T00:00:00Z";
  return {
    v: 2,
    id: "01HZ0000000000000000000099",
    iat,
    iat_ms: Date.parse(iat),
    claim_type: CLAIM_TYPES[1]!, // ar.consent.v1 by default — non-forbidden
    iss: "did:key:z6Mk",
    iss_key: "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    subject: "sha256:0000",
    exp: null,
    prev: null,
    policy_uri: null,
    policy_hash: null,
    policy_version: null,
    tsa: null,
    credentialStatus: null,
    anchor: {
      log: "https://verify.dekimu.com/acr/v1",
      leaf_index: 0,
      inclusion_proof: [],
      tree_head_root: "sha256:deadbeef",
      tree_size: 1,
      log_time: "2026-05-17T00:00:00Z",
    },
    sig: "AAAA",
    countersig: null,
    body: { subject_age: 18, purpose: "analytics" },
    ...over,
  };
}

// ── checkIatMs ───────────────────────────────────────────────────────────────

test("checkIatMs: absent iat_ms (v1.1 receipt) is OK — backwards-compatible", () => {
  const e: Envelope = envelope();
  // Strip iat_ms (legacy v1.1 receipt).
  const { iat_ms: _drop, ...rest } = e;
  const r = checkIatMs(rest as Envelope);
  assert.strictEqual(r.ok, true);
});

test("checkIatMs: matching iat_ms is OK", () => {
  const r = checkIatMs(envelope());
  assert.strictEqual(r.ok, true);
});

test("checkIatMs: mismatched iat_ms surfaces iat_ms_mismatch", () => {
  const r = checkIatMs(envelope({ iat_ms: 12345 }));
  assert.strictEqual(r.ok, false);
  if (r.ok) return;
  assert.strictEqual(r.reason, "iat_ms_mismatch");
});

test("checkIatMs: unparseable iat surfaces iat_ms_mismatch with detail", () => {
  const r = checkIatMs(envelope({ iat: "not-a-date", iat_ms: 0 }));
  assert.strictEqual(r.ok, false);
  if (r.ok) return;
  assert.strictEqual(r.reason, "iat_ms_mismatch");
});

// ── checkPredicate — forbidden-type rule ─────────────────────────────────────

test("checkPredicate: no predicate on a non-forbidden type is OK", () => {
  const r = checkPredicate(envelope({ predicate: null }));
  assert.strictEqual(r.ok, true);
});

test("checkPredicate: undefined predicate on a non-forbidden type is OK", () => {
  const e = envelope();
  delete (e as { predicate?: unknown }).predicate;
  const r = checkPredicate(e);
  assert.strictEqual(r.ok, true);
});

test("checkPredicate: predicate forbidden on ar.provenance.v1", () => {
  const pred: JsonLogicAst = { "===": [1, 1] };
  const r = checkPredicate(envelope({ claim_type: "ar.provenance.v1", predicate: pred }));
  assert.strictEqual(r.ok, false);
  if (r.ok) return;
  assert.strictEqual(r.reason, "predicate_forbidden_on_claim_type");
});

test("checkPredicate: predicate forbidden on ar.batch.v1", () => {
  const pred: JsonLogicAst = { "===": [1, 1] };
  const r = checkPredicate(envelope({ claim_type: "ar.batch.v1", predicate: pred }));
  assert.strictEqual(r.ok, false);
  if (r.ok) return;
  assert.strictEqual(r.reason, "predicate_forbidden_on_claim_type");
});

test("checkPredicate: null predicate on a forbidden type is still OK", () => {
  const r = checkPredicate(envelope({ claim_type: "ar.provenance.v1", predicate: null }));
  assert.strictEqual(r.ok, true);
});

// ── checkPredicate — AST validation surface ─────────────────────────────────

test("checkPredicate: disallowed operator surfaces predicate_operator_not_allowed", () => {
  const pred = { map: [[], { var: "" }] } as unknown as JsonLogicAst;
  const r = checkPredicate(envelope({ predicate: pred }));
  assert.strictEqual(r.ok, false);
  if (r.ok) return;
  assert.strictEqual(r.reason, "predicate_operator_not_allowed");
});

test("checkPredicate: __proto__ var path surfaces predicate_var_path_invalid", () => {
  const pred = { "===": [{ var: "__proto__" }, "x"] } as unknown as JsonLogicAst;
  const r = checkPredicate(envelope({ predicate: pred }));
  assert.strictEqual(r.ok, false);
  if (r.ok) return;
  assert.strictEqual(r.reason, "predicate_var_path_invalid");
});

test("checkPredicate: malformed AST surfaces predicate_malformed_ast", () => {
  const pred = { "===": [1, 1], extra: 1 } as unknown as JsonLogicAst;
  const r = checkPredicate(envelope({ predicate: pred }));
  assert.strictEqual(r.ok, false);
  if (r.ok) return;
  assert.strictEqual(r.reason, "predicate_malformed_ast");
});

// ── checkPredicate — evaluation outcomes ─────────────────────────────────────

test("checkPredicate: predicate evaluating to true is OK (spec §5.5 ex.1)", () => {
  const pred: JsonLogicAst = {
    and: [
      { ">=": [{ var: "body.subject_age" }, 16] },
      { in: [{ var: "body.purpose" }, ["analytics", "fraud"]] },
    ],
  };
  const r = checkPredicate(envelope({ predicate: pred }));
  assert.strictEqual(r.ok, true);
});

test("checkPredicate: predicate evaluating to false surfaces predicate_evaluation_false", () => {
  // 17 < 18 — false; subject_age is 18.
  const pred: JsonLogicAst = {
    ">": [{ var: "body.subject_age" }, 50],
  };
  const r = checkPredicate(envelope({ predicate: pred }));
  assert.strictEqual(r.ok, false);
  if (r.ok) return;
  assert.strictEqual(r.reason, "predicate_evaluation_false");
});

test("checkPredicate: predicate evaluating to non-boolean truthy surfaces predicate_evaluation_false", () => {
  // 'and' returns the last truthy operand, not boolean true.
  const pred: JsonLogicAst = {
    and: [{ "===": [1, 1] }, "string-truthy"],
  };
  const r = checkPredicate(envelope({ predicate: pred }));
  assert.strictEqual(r.ok, false); // strict `true` required
  if (r.ok) return;
  assert.strictEqual(r.reason, "predicate_evaluation_false");
});

test("checkPredicate: division by zero surfaces predicate_division_by_zero", () => {
  const pred: JsonLogicAst = {
    "===": [{ "/": [10, 0] }, 1],
  };
  const r = checkPredicate(envelope({ predicate: pred }));
  assert.strictEqual(r.ok, false);
  if (r.ok) return;
  assert.strictEqual(r.reason, "predicate_division_by_zero");
});

test("checkPredicate: modulo by zero surfaces predicate_modulo_by_zero", () => {
  const pred: JsonLogicAst = {
    "===": [{ "%": [10, 0] }, 1],
  };
  const r = checkPredicate(envelope({ predicate: pred }));
  assert.strictEqual(r.ok, false);
  if (r.ok) return;
  assert.strictEqual(r.reason, "predicate_modulo_by_zero");
});

// ── checkPredicate — root context = canonicalised envelope ───────────────────

test("checkPredicate: predicate can read top-level envelope fields (iat_ms, kind, cause)", () => {
  const pred: JsonLogicAst = {
    and: [
      { "===": [{ var: "kind" }, "decision"] },
      { "===": [{ var: "cause" }, "manual"] },
      { ">": [{ var: "iat_ms" }, 0] },
    ],
  };
  const r = checkPredicate(envelope({ kind: "decision", cause: "manual", predicate: pred }));
  assert.strictEqual(r.ok, true);
});

// ── ALLOWED_TOP_LEVEL — new v1.2 fields are not rejected as 'unknown' ────────

test("rejectUnknownFields accepts the 4 new v1.2 fields", () => {
  const e = envelope({
    kind: "decision",
    cause: "regulatory_request",
    predicate: { "===": [1, 1] } as JsonLogicAst,
  }) as unknown as Record<string, unknown>;
  const r = rejectUnknownFields(e);
  assert.strictEqual(r, null);
});

test("rejectUnknownFields still rejects an unrecognised field", () => {
  const e = { ...envelope(), surprise: "field" } as unknown as Record<string, unknown>;
  const r = rejectUnknownFields(e);
  assert.strictEqual(r, "unknown_field:surprise");
});
