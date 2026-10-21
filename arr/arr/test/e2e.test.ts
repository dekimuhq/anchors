import { test } from "node:test";
import assert from "node:assert/strict";
import {
  generateIssuerKey,
  encodePublicKey,
  mintErasure,
  mintBatch,
} from "../src/issue/index.ts";
import {
  verifySingleReceipt,
  verifyBatchReceipt,
  resolveTriggerReceipt,
  verify30DayWindow,
} from "../src/index.ts";
import { validateGdprArt17, validateGdprArt5e } from "@dekimuhq/arr-profiles";

const KP = generateIssuerKey();
const ISS = "did:web:bank.example";

test("GDPR Art 17 end-to-end: mint -> verify -> cross-resolve -> 30-day window", async () => {
  const acrWithdrawalGrantedAt = "2026-04-01T12:00:00Z";
  const acrHash = "sha256:" + "ee".repeat(32);

  const erasure = mintErasure({
    iss: ISS,
    iss_key: encodePublicKey(KP.publicKey),
    privateKey: KP.privateKey,
    profile: "gdpr.art17",
    target_kind: "subject",
    target_commit: "sha256:" + "ab".repeat(32),
    salt_epoch: "2026Q2",
    policy_hash: "sha256:" + "cd".repeat(32),
    policy_uri: "https://bank.example/p/v3",
    policy_version: "3.1.0",
    trigger: "subject_request",
    trigger_receipt: acrHash,
    event_at: "2026-04-13T09:00:00Z",
    granted_at: "2026-04-13T09:01:00Z",
    prev: null,
    extraFields: {
      subject_data_categories: ["sha256:" + "11".repeat(32)],
      controller_contact_hash: "sha256:" + "22".repeat(32),
    },
    state_snapshot: {
      retention_status: "erased",
      current_policy_hash: "sha256:" + "cd".repeat(32),
      hold_active: false,
      hold_reason_commit: null,
      anonymized: false,
      archived: false,
    },
  });

  assert.deepEqual(validateGdprArt17(erasure).errors, []);

  const verifyOut = verifySingleReceipt(erasure, {
    anchorInclusionTime: "2026-04-13T09:02:00Z",
  });
  assert.equal(verifyOut.valid, true);

  const trigger = await resolveTriggerReceipt({
    triggerReceiptHash: acrHash,
    expectedIssuer: ISS,
    expectedKinds: ["ar.withdrawal.v1"],
    resolver: async () => ({
      kind: "ar.withdrawal.v1",
      iss: ISS,
      granted_at: acrWithdrawalGrantedAt,
    }),
  });
  assert.equal(trigger.valid, true);

  const window = verify30DayWindow({
    erasureEventAt: erasure.event_at,
    acrWithdrawalGrantedAt,
  });
  assert.equal(window.valid, true);
  assert.equal(window.daysElapsed, 11); // floor of 11.875 days between 2026-04-01T12:00Z and 2026-04-13T09:00Z
});

test("GDPR Art 5(e) batch e2e: mint -> verify -> profile passes", () => {
  const targets = new Array(8).fill(0).map((_, i) => ({
    target_commit: "sha256:" + i.toString(16).padStart(64, "0"),
    state_snapshot: {
      retention_status: "expired" as const,
      current_policy_hash: "sha256:" + "cd".repeat(32),
      hold_active: false,
      hold_reason_commit: null,
      anonymized: false,
      archived: false,
    },
  }));

  const batch = mintBatch({
    iss: ISS,
    iss_key: encodePublicKey(KP.publicKey),
    privateKey: KP.privateKey,
    profile: "gdpr.art5e",
    batch_event_kind: "ar.expiry.v1",
    target_kind: "subject",
    salt_epoch: "2026Q2",
    policy_hash: "sha256:" + "cd".repeat(32),
    policy_uri: "https://bank.example/p/v3",
    policy_version: "3.1.0",
    trigger: "scheduled",
    trigger_receipt: null,
    event_at: "2026-05-16T03:00:00Z",
    granted_at: "2026-05-16T03:01:00Z",
    targets,
    extraFields: {
      retention_basis_commit: "sha256:" + "11".repeat(32),
      original_collection_at: "2020-01-01T00:00:00Z",
    },
  });

  const verifyOut = verifyBatchReceipt(batch, {
    anchorInclusionTime: "2026-05-16T03:02:00Z",
    disclosedTargets: targets.map((t) => t.target_commit),
  });
  assert.equal(verifyOut.valid, true);

  const profileOut = validateGdprArt5e(batch);
  assert.deepEqual(profileOut.errors, []);
});
