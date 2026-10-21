/**
 * End-to-end ARR Tier A disclosure: holder builds an ar.disclosure.v1
 * presentation revealing a subset of leaves; relying party verifies it against
 * the issuer-signed field_commit. Covers both the single and batch schemas.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import type { AnchorProof } from "@dekimuhq/anchors-envelope";
import type { ArrStateSnapshot } from "../src/index.ts";
import {
  buildPresentation,
  verifyPresentation,
  seedSaltSource,
  ARR_SINGLE_DISCLOSURE_SCHEMA,
  ARR_BATCH_DISCLOSURE_SCHEMA,
} from "@dekimuhq/anchors-disclosure";
import {
  mintArrV2SingleDisclosable,
  mintArrV2BatchDisclosable,
  type MintArrV2SingleInput,
  type MintArrV2BatchInput,
  type BatchTarget,
} from "../src/issue/index.ts";

function makeSigningKey(): { kid: string; privateKey: Uint8Array } {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const seed = (privateKey.export({ format: "der", type: "pkcs8" }) as Buffer).subarray(-32);
  return { kid: "k-" + Math.random().toString(36).slice(2), privateKey: new Uint8Array(seed) };
}

const anchor: AnchorProof = {
  log: "https://verify.dekimu.com/arr/v1",
  leaf_index: 0,
  inclusion_proof: [],
  tree_head_root: "sha256:" + "0".repeat(64),
  tree_size: 1,
  log_time: "2026-05-17T00:00:00Z",
};

const snapshot: ArrStateSnapshot = {
  retention_status: "erased",
  current_policy_hash: "sha256:" + "a".repeat(64),
  hold_active: false,
  hold_reason_commit: null,
  anonymized: false,
  archived: false,
};

function singleInput(): MintArrV2SingleInput {
  return {
    issuer: "did:web:invoiceup.app",
    signingKey: makeSigningKey(),
    kind: "ar.erasure.v1",
    subject: "sha256:" + "b".repeat(64),
    profile: "gdpr.art17",
    target_kind: "subject",
    target_commit: "sha256:" + "c".repeat(64),
    salt_epoch: "2026-01",
    policy_hash: "sha256:" + "d".repeat(64),
    policy_uri: "https://example.com/policy.pdf",
    policy_version: "1.0.0",
    trigger: "operator",
    trigger_receipt: null,
    event_at: "2026-05-17T10:00:00Z",
    granted_at: "2026-05-17T10:00:01Z",
    state_snapshot: snapshot,
    anchor,
  };
}

function batchInput(): MintArrV2BatchInput {
  const targets: BatchTarget[] = [
    { target_commit: "sha256:" + "e".repeat(64), state_snapshot: snapshot },
    { target_commit: "sha256:" + "f".repeat(64), state_snapshot: { ...snapshot, retention_status: "archived" } },
  ];
  return {
    issuer: "did:web:invoiceup.app",
    signingKey: makeSigningKey(),
    subject: "sha256:" + "0".repeat(64),
    profile: "gdpr.art17",
    batch_event_kind: "ar.erasure.v1",
    target_kind: "subject",
    salt_epoch: "2026-01",
    policy_hash: "sha256:" + "d".repeat(64),
    policy_uri: "https://example.com/policy.pdf",
    policy_version: "1.0.0",
    trigger: "scheduled",
    trigger_receipt: null,
    event_at: "2026-05-17T10:00:00Z",
    granted_at: "2026-05-17T10:00:01Z",
    targets,
    anchor,
  };
}

function bodyNoRoot(receipt: { body: unknown }) {
  const { field_root: _r, ...rest } = receipt.body as Record<string, unknown>;
  return rest;
}

test("ARR single disclosable: reveal only /profile + /trigger, hide the rest", async () => {
  const { receipt, fieldCommit, seed } = await mintArrV2SingleDisclosable(singleInput());
  const p = buildPresentation({
    body: bodyNoRoot(receipt),
    schema: ARR_SINGLE_DISCLOSURE_SCHEMA,
    salts: seedSaltSource(seed),
    fieldCommit,
    reveal: ["/profile", "/trigger"],
  });
  const r = verifyPresentation(p, { schema: ARR_SINGLE_DISCLOSURE_SCHEMA });
  assert.equal(r.valid, true);
  assert.deepEqual(r.revealed, { "/profile": "gdpr.art17", "/trigger": "operator" });
  assert.equal(r.issuer, receipt.iss_key);
  assert.equal(p.revealed.length, 2);
});

test("ARR batch disclosable: reveal only /batch_event_kind + /target_kind", async () => {
  const { receipt, fieldCommit, seed } = await mintArrV2BatchDisclosable(batchInput());
  const p = buildPresentation({
    body: bodyNoRoot(receipt),
    schema: ARR_BATCH_DISCLOSURE_SCHEMA,
    salts: seedSaltSource(seed),
    fieldCommit,
    reveal: ["/batch_event_kind", "/target_kind"],
  });
  const r = verifyPresentation(p, { schema: ARR_BATCH_DISCLOSURE_SCHEMA });
  assert.equal(r.valid, true);
  assert.deepEqual(r.revealed, { "/batch_event_kind": "ar.erasure.v1", "/target_kind": "subject" });
  assert.equal(p.revealed.length, 2);
});

test("ARR single disclosable: tampering a revealed value is rejected", async () => {
  const { receipt, fieldCommit, seed } = await mintArrV2SingleDisclosable(singleInput());
  const p = buildPresentation({
    body: bodyNoRoot(receipt), schema: ARR_SINGLE_DISCLOSURE_SCHEMA, salts: seedSaltSource(seed), fieldCommit, reveal: ["/profile"],
  });
  p.revealed[0]!.value = "hipaa.retention";
  assert.equal(verifyPresentation(p).valid, false);
});

test("ARR single disclosable: an untrusted issuer is rejected", async () => {
  const { receipt, fieldCommit, seed } = await mintArrV2SingleDisclosable(singleInput());
  const p = buildPresentation({
    body: bodyNoRoot(receipt), schema: ARR_SINGLE_DISCLOSURE_SCHEMA, salts: seedSaltSource(seed), fieldCommit, reveal: ["/profile"],
  });
  const r = verifyPresentation(p, { trustIssuer: () => false });
  assert.equal(r.valid, false);
  assert.ok(r.reasons.includes("issuer_untrusted"));
});
