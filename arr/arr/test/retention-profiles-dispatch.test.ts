/**
 * Mint → verify dispatch for the six regulated retention profiles registered in
 * arrFamily.profiles{} (2026-05-30). Each mints a v=2 ARR receipt carrying
 * `profile_attributes`, dispatches with `opts.profile`, and asserts the profile
 * validator runs against the v=2 body.
 *
 * Invariants exercised:
 *   - profile present + valid attributes → profile_state.ok = true.
 *   - missing required attribute → profile_state.ok = false, but
 *     signature_valid stays true (profile validation is advisory).
 *   - omitting profile_attributes entirely → graceful ok = false (the wire
 *     field is additive-optional).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";

import { mintArrV2Single } from "../src/issue/index.ts";
import type { MintArrV2SingleInput } from "../src/issue/index.ts";
import { verifyReceipt } from "../src/index.ts";
import { base64UrlDecode } from "@dekimuhq/anchors-envelope";
import type { AnchorProof, FamilyVerifyResult } from "@dekimuhq/anchors-envelope";
import type { ArrStateSnapshot, ArrProfileAttributes } from "../src/index.ts";

const ED25519_SPKI_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

function makeSigningKey(): MintArrV2SingleInput["signingKey"] {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const seed = (privateKey.export({ format: "der", type: "pkcs8" }) as Buffer).subarray(-32);
  return { kid: "k-" + Math.random().toString(36).slice(2), privateKey: new Uint8Array(seed) };
}

function makeResolveKey() {
  return async (envelope: unknown): Promise<Uint8Array> => {
    const issKey = (envelope as { iss_key: string }).iss_key;
    const raw = base64UrlDecode(issKey.replace("ed25519:", ""));
    return new Uint8Array(Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]));
  };
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
  retention_status: "expired",
  current_policy_hash: "sha256:" + "a".repeat(64),
  hold_active: false,
  hold_reason_commit: null,
  anonymized: false,
  archived: false,
};

const H = (c: string): string => "sha256:" + c.repeat(64);

function mint(attrs: ArrProfileAttributes | undefined, signingKey: MintArrV2SingleInput["signingKey"]) {
  const input: MintArrV2SingleInput = {
    issuer: "did:web:invoiceup.app",
    signingKey,
    kind: "ar.expiry.v1",
    subject: H("b"),
    profile: "gdpr.art17",
    target_kind: "subject",
    target_commit: H("c"),
    salt_epoch: "2026-01",
    policy_hash: H("d"),
    policy_uri: "https://example.com/policy.pdf",
    policy_version: "1.0.0",
    trigger: "operator",
    trigger_receipt: null,
    event_at: "2026-05-17T10:00:00Z",
    granted_at: "2026-05-17T10:00:01Z",
    state_snapshot: snapshot,
    anchor,
    ...(attrs !== undefined ? { profile_attributes: attrs } : {}),
  };
  return mintArrV2Single(input);
}

// ── Per-profile valid attribute sets (timestamps satisfy each min-period rule) ─

const VALID: Record<string, { profile: string; attrs: ArrProfileAttributes }> = {
  art5e: {
    profile: "arr.gdpr.art5e",
    attrs: { retention_basis_commit: H("1"), original_collection_at: "2017-01-01T00:00:00Z" },
  },
  hipaa: {
    profile: "arr.hipaa.retention",
    attrs: { covered_entity_commit: H("2"), phi_categories: ["demographics"], record_origin_at: "2017-01-01T00:00:00Z" },
  },
  kyc: {
    profile: "arr.kyc.retention",
    attrs: { customer_commit: H("3"), relationship_end_at: "2017-01-01T00:00:00Z", risk_profile_hash: H("4") },
  },
  sox: {
    profile: "arr.sox.retention",
    attrs: { audit_record_commit: H("5"), fiscal_period: "FY2017", record_origin_at: "2017-01-01T00:00:00Z" },
  },
  mifid2: {
    profile: "arr.mifid2.retention",
    attrs: { trade_commit: H("6"), instrument_commit: H("7"), venue_commit: H("8"), mifid_class: "equity", record_origin_at: "2017-01-01T00:00:00Z" },
  },
  aiact: {
    profile: "arr.aiact.art10",
    attrs: { model_commit: H("9"), dataset_commit: H("a"), conformity_assessment_at: "2010-01-01T00:00:00Z" },
  },
};

for (const [name, { profile, attrs }] of Object.entries(VALID)) {
  test(`retention dispatch: ${profile} with valid attributes → profile_state.ok true`, async () => {
    const signingKey = makeSigningKey();
    const env = await mint(attrs, signingKey);
    const r = await verifyReceipt(env, { resolveKey: makeResolveKey(), profile }) as FamilyVerifyResult;
    assert.equal(r.signature_valid, true, "reason" in r ? String(r.reason) : "ok");
    const entry = r.profile_state?.[0];
    assert.ok(entry, `${name}: profile_state must be set`);
    assert.equal(entry?.profile_id, profile);
    assert.equal(entry?.ok, true, `${name}: ${entry?.reason ?? ""}`);
  });
}

// ── Advisory: missing required attribute fails the profile but not the signature ─

test("retention dispatch: hipaa missing covered_entity_commit → profile ok:false, signature_valid:true", async () => {
  const signingKey = makeSigningKey();
  const env = await mint(
    { phi_categories: ["demographics"], record_origin_at: "2017-01-01T00:00:00Z" },
    signingKey,
  );
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey(), profile: "arr.hipaa.retention" }) as FamilyVerifyResult;
  assert.equal(r.signature_valid, true, "profile failure must not poison signature_valid");
  assert.equal(r.profile_state?.[0]?.ok, false);
  assert.match(String(r.profile_state?.[0]?.reason), /covered_entity_commit/);
});

// ── Graceful: omitting profile_attributes entirely → ok:false, signature valid ─

test("retention dispatch: sox with no profile_attributes → profile ok:false (additive field), signature_valid:true", async () => {
  const signingKey = makeSigningKey();
  const env = await mint(undefined, signingKey);
  assert.equal((env.body as { profile_attributes?: unknown }).profile_attributes, undefined);
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey(), profile: "arr.sox.retention" }) as FamilyVerifyResult;
  assert.equal(r.signature_valid, true);
  assert.equal(r.profile_state?.[0]?.ok, false);
});
