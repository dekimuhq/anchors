/**
 * v1.3 R3 Phase 2 — issuer PQC-migration enforcement reaches ALR's PUBLIC
 * `verifyReceipt` (the legacy-verifier "backport" slice).
 *
 * ALR (the `defineFamily()` canary) exposes `verifyReceipt` (src/index.ts) that
 * spreads `Partial<FamilyVerifyOptions>` into `alrFamily.verifyReceipt` — the
 * SHARED `family-verify-pipeline.ts` whose Step 5.6 already carries the PQC seam
 * (commit 800f5c1c). So `verifyIssuerPqc` flows through with no source change;
 * these tests guard that. ALR has no static v=2 fixture, so the receipt is minted
 * via `mintAlrV2` (mirrors mint-v2.test.ts). The pure policy + makeVerifyIssuerPqc
 * factory e2e live in @dekimuhq/anchors-trusted-issuers' own suite (it does not
 * resolve from a family, so the seam is driven with stubs here). Mirrors shared §18.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/envelope
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { base64UrlDecode } from "@dekimuhq/anchors-envelope";
import type {
  AnchorProof,
  VerifyIssuerTrust,
  IssuerTrustResult,
  TrustedIssuerRecord,
  VerifyIssuerPqc,
  VerifyIssuerPqcInput,
  FamilyVerifyResult,
} from "@dekimuhq/anchors-envelope";
import { mintAlrV2, type MintAlrV2Input } from "../src/issue/index.ts";
import { verifyReceipt } from "../src/index.ts";

const ED25519_SPKI_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);
const H = (b: string) => `sha256:${b.repeat(64)}`;

const anchor: AnchorProof = {
  log: "https://verify.dekimu.com/alr/v1",
  leaf_index: 0,
  inclusion_proof: [],
  tree_head_root: "sha256:" + "0".repeat(64),
  tree_size: 1,
  log_time: "2026-05-17T00:00:00Z",
};

function resolveKey(envelope: unknown): Promise<Uint8Array> {
  const issKey = (envelope as { iss_key: string }).iss_key;
  const raw = base64UrlDecode(issKey.replace("ed25519:", ""));
  return Promise.resolve(new Uint8Array(Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)])));
}

// Mint a real, valid v=2 ALR receipt once for all tests.
const { privateKey } = crypto.generateKeyPairSync("ed25519");
const seed = (privateKey.export({ format: "der", type: "pkcs8" }) as Buffer).subarray(-32);
const input: MintAlrV2Input = {
  issuer: "did:web:processor.example",
  signingKey: { kid: "test-kid-pqc", privateKey: new Uint8Array(seed) },
  profile: "aiact.art13.transparency",
  artifact_hash: H("c"),
  event_at: "2026-05-16T14:23:00Z",
  policy_uri: "https://processor.example/lineage-policy",
  policy_hash: "sha256:" + "e".repeat(64),
  policy_version: "1.0.0",
  anchor,
  event_type: "derived_from",
  parents: [
    { artifact_hash: H("b"), parent_apr_id: null, parent_alr_id: null, uri: null },
    { artifact_hash: H("a"), parent_apr_id: null, parent_alr_id: null, uri: null },
  ],
  transform_claim: { summary: "fine-tune", uri: null },
};
const envelope = await mintAlrV2(input);
const spki = await resolveKey(envelope);

function makeRecord(): TrustedIssuerRecord {
  return {
    iss: "did:web:processor.example",
    added_at: "2025-01-01T00:00:00Z",
    revoked_at: null,
    families: ["lineage"],
    profiles_pinned: null,
    notes: null,
  };
}

function makeTrust(
  outcome: "valid_trusted" | "valid_untrusted",
  record: TrustedIssuerRecord | null,
): VerifyIssuerTrust {
  return async () =>
    ({
      outcome,
      iss: "did:web:processor.example",
      iss_key: "ed25519:dummy",
      spki,
      matched_record: record,
      reason: outcome,
    }) satisfies IssuerTrustResult;
}

test("ALR public verifyReceipt: verifyIssuerPqc receives the matched record + verified ed25519 alg", async () => {
  let seen: VerifyIssuerPqcInput | undefined;
  const record = makeRecord();
  const verifyIssuerPqc: VerifyIssuerPqc = (i) => {
    seen = i;
    return { ok: true };
  };
  const r = (await verifyReceipt(envelope, {
    resolveKey,
    verifyIssuerTrust: makeTrust("valid_trusted", record),
    verifyIssuerPqc,
  })) as FamilyVerifyResult;

  assert.equal(r.signature_valid, true);
  assert.ok(seen, "callback threaded through the family wrapper");
  assert.equal(seen.receiptSigAlg, "ed25519");
  assert.deepEqual(seen.record, record);
});

test("ALR public verifyReceipt: ok:false → HARD FAIL, reason surfaced verbatim", async () => {
  const verifyIssuerPqc: VerifyIssuerPqc = () => ({
    ok: false,
    reason: "issuer_pqc_mandatory:ml-dsa-65",
  });
  const r = (await verifyReceipt(envelope, {
    resolveKey,
    verifyIssuerTrust: makeTrust("valid_trusted", makeRecord()),
    verifyIssuerPqc,
  })) as FamilyVerifyResult;

  assert.equal(r.signature_valid, false);
  assert.equal(r.reason, "issuer_pqc_mandatory:ml-dsa-65");
  assert.equal(r.trust_outcome, "valid_trusted");
});

test("ALR public verifyReceipt: async ok:false verdict is awaited", async () => {
  const verifyIssuerPqc: VerifyIssuerPqc = async () => ({
    ok: false,
    reason: "issuer_pqc_unsatisfiable:future-alg",
  });
  const r = (await verifyReceipt(envelope, {
    resolveKey,
    verifyIssuerTrust: makeTrust("valid_trusted", makeRecord()),
    verifyIssuerPqc,
  })) as FamilyVerifyResult;

  assert.equal(r.signature_valid, false);
  assert.equal(r.reason, "issuer_pqc_unsatisfiable:future-alg");
});

test("ALR public verifyReceipt: verifyIssuerPqc omitted → inert (valid)", async () => {
  const r = (await verifyReceipt(envelope, {
    resolveKey,
    verifyIssuerTrust: makeTrust("valid_trusted", makeRecord()),
  })) as FamilyVerifyResult;

  assert.equal(r.signature_valid, true);
});

test("ALR public verifyReceipt: verifyIssuerPqc set but no verifyIssuerTrust → fail-closed misconfig guard", async () => {
  // Envelope §18.7 (fail-closed since anchors-envelope 585293eb): supplying the
  // PQC hook WITHOUT a trust dispatch would silently enforce nothing, so the
  // pipeline rejects with issuer_pqc_requires_trust_dispatch before the hook runs.
  let called = false;
  const verifyIssuerPqc: VerifyIssuerPqc = () => {
    called = true;
    return { ok: true };
  };
  const r = (await verifyReceipt(envelope, { resolveKey, verifyIssuerPqc })) as FamilyVerifyResult;

  assert.equal(r.signature_valid, false);
  assert.equal(r.reason, "issuer_pqc_requires_trust_dispatch");
  assert.equal(called, false, "guard fires before the hook — no record source to enforce against");
});
