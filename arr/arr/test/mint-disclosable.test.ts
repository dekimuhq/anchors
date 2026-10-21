/**
 * Tests for ARR Tier A disclosable mints — `mintArrV2SingleDisclosable` +
 * `mintArrV2BatchDisclosable`. ARR is special (subset-hash field_root, two entry
 * points), so both wrappers are exercised.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { verifyFieldCommit, base64UrlDecode } from "@dekimuhq/anchors-envelope";
import type { AnchorProof } from "@dekimuhq/anchors-envelope";
import { verifyReceipt } from "../src/index.ts";
import type { ArrStateSnapshot } from "../src/index.ts";
import {
  mintArrV2Single,
  mintArrV2Batch,
  mintArrV2SingleDisclosable,
  mintArrV2BatchDisclosable,
  type MintArrV2SingleInput,
  type MintArrV2BatchInput,
  type BatchTarget,
} from "../src/issue/index.ts";

const ED25519_SPKI_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

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

function makeResolveKey() {
  return async (envelope: unknown): Promise<Uint8Array> => {
    const issKey = (envelope as { iss_key: string }).iss_key;
    const raw = base64UrlDecode(issKey.replace("ed25519:", ""));
    return new Uint8Array(Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]));
  };
}

test("mintArrV2SingleDisclosable returns receipt + signed field_commit + 32-byte seed", async () => {
  const { receipt, fieldCommit, seed } = await mintArrV2SingleDisclosable(singleInput());
  assert.equal(receipt.v, 2);
  assert.equal(receipt.claim_type, "ar.erasure.v1");
  assert.equal(seed.length, 32);
  assert.equal(fieldCommit.family, "arr");
  assert.equal(fieldCommit.id, receipt.id);
  assert.equal(fieldCommit.field_root, (receipt.body as { field_root: string }).field_root);
  assert.equal(fieldCommit.leaf_count, 4); // four declared ARR single leaves
  assert.equal(verifyFieldCommit(fieldCommit).valid, true);
});

test("mintArrV2BatchDisclosable returns receipt + signed field_commit + 32-byte seed", async () => {
  const { receipt, fieldCommit, seed } = await mintArrV2BatchDisclosable(batchInput());
  assert.equal(receipt.v, 2);
  assert.equal(receipt.claim_type, "ar.batch.v1");
  assert.equal(seed.length, 32);
  assert.equal(fieldCommit.family, "arr");
  assert.equal(fieldCommit.leaf_count, 4); // four declared ARR batch leaves
  assert.equal(verifyFieldCommit(fieldCommit).valid, true);
});

test("disclosable field_root differs from the flat subset-hash field_root (single + batch)", async () => {
  const flatS = await mintArrV2Single(singleInput());
  const { receipt: discS } = await mintArrV2SingleDisclosable(singleInput());
  assert.notEqual((flatS.body as { field_root: string }).field_root, (discS.body as { field_root: string }).field_root);

  const flatB = await mintArrV2Batch(batchInput());
  const { receipt: discB } = await mintArrV2BatchDisclosable(batchInput());
  assert.notEqual((flatB.body as { field_root: string }).field_root, (discB.body as { field_root: string }).field_root);
});

test("disclosable receipts still pass arr-verifier (single + batch, signature intact)", async () => {
  const resolveKey = makeResolveKey();
  const { receipt: s } = await mintArrV2SingleDisclosable(singleInput());
  const rs = await verifyReceipt(s, { resolveKey });
  assert.equal(rs.signature_valid, true, rs.reason ?? "single ok");

  const { receipt: b } = await mintArrV2BatchDisclosable(batchInput());
  const rb = await verifyReceipt(b, { resolveKey });
  assert.equal(rb.signature_valid, true, rb.reason ?? "batch ok");
});

test("both ARR disclosable mints reject TSA in v0", async () => {
  await assert.rejects(
    () => mintArrV2SingleDisclosable({ ...singleInput(), tsa: {} as never, tsaFetcher: (async () => ({})) as never }),
    /TSA \+ disclosable/,
  );
  await assert.rejects(
    () => mintArrV2BatchDisclosable({ ...batchInput(), tsa: {} as never, tsaFetcher: (async () => ({})) as never }),
    /TSA \+ disclosable/,
  );
});

test("mintArrV2Single/Batch (non-disclosable) unchanged: bare Envelope, flat field_root", async () => {
  const s = await mintArrV2Single(singleInput());
  assert.equal("fieldCommit" in (s as object), false);
  assert.match((s.body as { field_root: string }).field_root, /^sha256:[0-9a-f]{64}$/);
});
