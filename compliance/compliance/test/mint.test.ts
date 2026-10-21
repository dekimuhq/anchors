import { test } from "node:test";
import assert from "node:assert/strict";
import { mintComplianceV1 } from "../src/issue/mint-v1.ts";
import { generateComplianceKeypair } from "../src/issue/keys.ts";
import { verifyReceipt } from "../src/index.ts";

const SHA = "sha256:" + "a".repeat(64);
const anchor = { log: "test", leaf_index: 0, inclusion_proof: [], tree_head_root: "r", tree_size: 1, log_time: "2026-06-20T10:00:00Z" } as never;

function body() {
  return {
    profile: "compliance.bundle", workspaceId: "ws_1",
    controller: { entityName: "Acme SL", registeredAddress: null, contactEmail: null },
    regulation: { manifestId: "gdpr", manifestVersion: "1.2.0", manifestHash: SHA },
    coverage: { applicable: 8, satisfied: 8, ratio: 1 },
    constituents: {
      ropa: { ref: "ropa:" + "b".repeat(64), contentHash: SHA, satisfiedObligations: ["gdpr.records"] },
      dpia: { status: "not_applicable", reason: "no high-risk processing", basis: "engine" },
      obligations: { ref: "report", contentHash: SHA, satisfiedObligations: [] },
    },
    generated_at: "2026-06-20T10:00:00Z",
  } as never;
}

test("mint → verifyReceipt signature valid; subject null", async () => {
  const { signingKey, publicKeyDer } = generateComplianceKeypair("kid-1");
  const env = await mintComplianceV1({ issuer: "did:web:test", signingKey, anchor, body: body() });
  assert.equal(env.claim_type, "ar.compliance.v1");
  assert.equal(env.subject, null);
  const r = await verifyReceipt(env, { resolveKey: () => publicKeyDer });
  assert.equal((r as { signature_valid?: boolean }).signature_valid, true, JSON.stringify(r));
});

test("mint rejects invalid body", async () => {
  const { signingKey } = generateComplianceKeypair("kid-1");
  const bad = body() as Record<string, unknown>; (bad as { coverage: { ratio: number } }).coverage.ratio = 9;
  await assert.rejects(() => mintComplianceV1({ issuer: "did:web:test", signingKey, anchor, body: bad as never }));
});
