import { test } from "node:test";
import assert from "node:assert/strict";
import { generateIssuerKey, encodePublicKey } from "../src/issue/index.ts";
import {
  mintErasure,
  mintExpiry,
  mintHoldExtension,
  mintHoldRelease,
  mintAnonymization,
  mintPseudonymization,
  mintArchive,
} from "../src/issue/index.ts";

const KP = generateIssuerKey();
const ISS = "did:web:bank.example";
const ISS_KEY = encodePublicKey(KP.publicKey);

const baseInput = {
  iss: ISS,
  iss_key: ISS_KEY,
  privateKey: KP.privateKey,
  profile: "gdpr.art17" as const,
  target_kind: "subject" as const,
  target_commit: "sha256:" + "ab".repeat(32),
  salt_epoch: "2026Q2",
  policy_hash: "sha256:" + "cd".repeat(32),
  policy_uri: "https://bank.example/p/v3",
  policy_version: "3.1.0",
  trigger: "subject_request" as const,
  trigger_receipt: "sha256:" + "ef".repeat(32),
  event_at: "2026-05-16T09:12:00Z",
  granted_at: "2026-05-16T09:14:00Z",
  prev: null,
};

test("mintErasure produces a signed ar.erasure.v1 with state_snapshot.retention_status=erased", () => {
  const r = mintErasure({
    ...baseInput,
    state_snapshot: {
      retention_status: "erased",
      current_policy_hash: baseInput.policy_hash,
      hold_active: false,
      hold_reason_commit: null,
      anonymized: false,
      archived: false,
    },
  });
  assert.equal(r.kind, "ar.erasure.v1");
  assert.equal(r.anchor, null);
  assert.match(r.sig!, /^ed25519:/);
});

test("mintExpiry sets kind correctly", () => {
  const r = mintExpiry({
    ...baseInput,
    profile: "gdpr.art5e",
    trigger: "scheduled",
    trigger_receipt: null,
    state_snapshot: {
      retention_status: "expired",
      current_policy_hash: baseInput.policy_hash,
      hold_active: false,
      hold_reason_commit: null,
      anonymized: false,
      archived: false,
    },
  });
  assert.equal(r.kind, "ar.expiry.v1");
});

test("mintHoldExtension requires effective_until", () => {
  assert.throws(
    () =>
      mintHoldExtension({
        ...baseInput,
        effective_until: null as unknown as string,
        state_snapshot: {
          retention_status: "active",
          current_policy_hash: baseInput.policy_hash,
          hold_active: true,
          hold_reason_commit: "sha256:" + "11".repeat(32),
          anonymized: false,
          archived: false,
        },
      }),
    /effective_until.required/,
  );
});

test("mintArchive requires effective_until", () => {
  assert.throws(
    () =>
      mintArchive({
        ...baseInput,
        effective_until: null as unknown as string,
        state_snapshot: {
          retention_status: "archived",
          current_policy_hash: baseInput.policy_hash,
          hold_active: false,
          hold_reason_commit: null,
          anonymized: false,
          archived: true,
        },
      }),
    /effective_until.required/,
  );
});

test("mintHoldRelease yields kind=arr.hold_release.v1", () => {
  const r = mintHoldRelease({
    ...baseInput,
    state_snapshot: {
      retention_status: "active",
      current_policy_hash: baseInput.policy_hash,
      hold_active: false,
      hold_reason_commit: null,
      anonymized: false,
      archived: false,
    },
  });
  assert.equal(r.kind, "arr.hold_release.v1");
});

test("mintAnonymization sets state_snapshot.anonymized=true", () => {
  const r = mintAnonymization({
    ...baseInput,
    state_snapshot: {
      retention_status: "anonymized",
      current_policy_hash: baseInput.policy_hash,
      hold_active: false,
      hold_reason_commit: null,
      anonymized: true,
      archived: false,
    },
  });
  assert.equal(r.kind, "ar.anonymization.v1");
  assert.equal(r.state_snapshot.anonymized, true);
});

test("mintPseudonymization yields retention_status=pseudonymized", () => {
  const r = mintPseudonymization({
    ...baseInput,
    state_snapshot: {
      retention_status: "pseudonymized",
      current_policy_hash: baseInput.policy_hash,
      hold_active: false,
      hold_reason_commit: null,
      anonymized: false,
      archived: false,
    },
  });
  assert.equal(r.kind, "arr.pseudonymization.v1");
});

test("subject_request without trigger_receipt -> throws at mint time", () => {
  assert.throws(
    () =>
      mintErasure({
        ...baseInput,
        trigger_receipt: null,
        state_snapshot: {
          retention_status: "erased",
          current_policy_hash: baseInput.policy_hash,
          hold_active: false,
          hold_reason_commit: null,
          anonymized: false,
          archived: false,
        },
      }),
    /trigger_receipt.required/,
  );
});
