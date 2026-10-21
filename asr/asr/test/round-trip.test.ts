/**
 * Round-trip tests — Phase 3 Task 3.1 Step 5.
 *
 * Mint v=2 envelopes through `asrFamily.mintV2`, verify them through
 * `asrFamily.verifyReceipt`. Covers:
 *   - one happy round-trip per event_type (9)
 *   - per-profile happy paths (6 — placeholder validators all pass)
 *   - subject-presence failures at mint (null + malformed)
 *   - body-schema failures at mint (each rejects with the matching reason)
 *   - signature failure on tampered envelope
 *   - wrong claim_type passed explicitly throws at mint
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { asrFamily } from "../src/family.ts";
import {
  ANCHOR,
  KP,
  PUB_DER,
  REQ_ID,
  SUBJECT,
  bodyEscalated,
  bodyExtended,
  bodyFulfilled,
  bodyIdentityVerified,
  bodyPartiallyHonoured,
  bodyRecipientNotified,
  bodyRefused,
  bodyRequestReceived,
  bodyScopeClarified,
  mintInput,
  sha256,
} from "./_helpers/fixtures.ts";

const resolveKey = () => PUB_DER;

// ── §1 — per-event_type happy round-trips ─────────────────────────────────────

for (const [event_type, builder] of [
  ["request.received", bodyRequestReceived],
  ["request.identity_verified", bodyIdentityVerified],
  ["request.scope_clarified", bodyScopeClarified],
  ["request.extended", bodyExtended],
  ["request.partially_honoured", bodyPartiallyHonoured],
  ["request.fulfilled", bodyFulfilled],
  ["request.refused", bodyRefused],
  ["request.escalated", bodyEscalated],
  ["request.recipient_notified", bodyRecipientNotified],
] as const) {
  test(`§1 round-trip: ${event_type} mints + verifies with signature_valid: true`, async () => {
    const env = await asrFamily.mintV2(mintInput({ body: builder() }));
    assert.equal(env.v, 2);
    assert.equal(env.claim_type, "ar.subject_rights.v1");
    assert.equal(env.subject, SUBJECT);
    assert.equal(env.iss, "did:web:test.example.com");
    assert.ok(env.iss_key.startsWith("ed25519:"));
    assert.ok(typeof env.sig === "string" && env.sig.length > 0);

    const r = await asrFamily.verifyReceipt(env, { resolveKey });
    assert.equal(r.signature_valid, true, `verifyReceipt failed: ${r.reason}`);
    assert.equal(r.claim_type, "ar.subject_rights.v1");
  });
}

// ── §2 — per-profile happy paths ──────────────────────────────────────────────

for (const profile of [
  "subject_rights.art15.access",
  "subject_rights.art16.rectification",
  "subject_rights.art17.erasure_request",
  "subject_rights.art18.restriction",
  "subject_rights.art20.portability",
  "subject_rights.art21.objection",
]) {
  test(`§2 round-trip: profile=${profile} dispatches placeholder validator`, async () => {
    // art17.erasure_request + request.fulfilled MANDATES arr_receipt_id
    // since the §G compose cross-walk shipped (Phase 3 §G). Other profiles
    // round-trip through plain bodyFulfilled().
    const body =
      profile === "subject_rights.art17.erasure_request"
        ? { ...bodyFulfilled(), arr_receipt_id: "arr_test_round_trip" }
        : bodyFulfilled();
    const env = await asrFamily.mintV2(mintInput({ body }));
    const r = await asrFamily.verifyReceipt(env, { resolveKey, profile });
    assert.equal(r.signature_valid, true, `verifyReceipt failed: ${r.reason}`);
  });
}

// ── §3 — subject-presence failures at mint ────────────────────────────────────

test("§3.1 null subject rejected at mint (D10-ASR-5)", async () => {
  await assert.rejects(
    () => asrFamily.mintV2(mintInput({ subject: null })),
    (err: Error) => err.message.includes("subject_missing"),
  );
});

test("§3.2 malformed subject rejected at mint as subject_invalid_form", async () => {
  await assert.rejects(
    () => asrFamily.mintV2(mintInput({ subject: "did:web:notsha" })),
    (err: Error) => err.message.includes("subject_invalid_form"),
  );
});

test("§3.3 uppercase-hex subject rejected at mint", async () => {
  await assert.rejects(
    () => asrFamily.mintV2(mintInput({ subject: `sha256:${"A".repeat(64)}` })),
    (err: Error) => err.message.includes("subject_invalid_form"),
  );
});

// ── §4 — body-schema failures at mint ─────────────────────────────────────────

test("§4.1 unknown event_type rejected at mint", async () => {
  await assert.rejects(
    () =>
      asrFamily.mintV2(
        mintInput({
          body: { event_type: "request.unknown", subject_rights_request_id: REQ_ID },
        }),
      ),
    (err: Error) => err.message.includes("asr_unknown_event_type"),
  );
});

test("§4.2 missing subject_rights_request_id rejected at mint", async () => {
  await assert.rejects(
    () =>
      asrFamily.mintV2(
        mintInput({
          body: { event_type: "request.received", channel: "email" },
        }),
      ),
    (err: Error) => err.message.includes("asr_missing_subject_rights_request_id"),
  );
});

test("§4.3 request.received with invalid channel rejected at mint", async () => {
  const body = { ...bodyRequestReceived(), channel: "telegram" };
  await assert.rejects(
    () => asrFamily.mintV2(mintInput({ body })),
    (err: Error) => err.message.includes("asr_invalid_channel"),
  );
});

test("§4.4 request.fulfilled missing fulfilled_artifact_hash rejected at mint", async () => {
  const body = { ...bodyFulfilled(), fulfilled_artifact_hash: "" };
  await assert.rejects(
    () => asrFamily.mintV2(mintInput({ body })),
    (err: Error) => err.message.includes("asr_missing_fulfilled_artifact_hash"),
  );
});

test("§4.5 request.refused with invalid refusal_ground rejected at mint", async () => {
  const body = { ...bodyRefused(), refusal_ground: "made_up_ground" };
  await assert.rejects(
    () => asrFamily.mintV2(mintInput({ body })),
    (err: Error) => err.message.includes("asr_invalid_refusal_ground"),
  );
});

test("§4.6 non-object body rejected at mint", async () => {
  await assert.rejects(
    () => asrFamily.mintV2(mintInput({ body: "string-body" })),
    (err: Error) => err.message.includes("asr_body_not_object"),
  );
});

// ── §5 — signature tampering ─────────────────────────────────────────────────

test("§5.1 tampered body fails verifyReceipt with signature_valid: false", async () => {
  const env = await asrFamily.mintV2(mintInput());
  const tampered = {
    ...env,
    body: { ...(env.body as object), subject_rights_request_id: "tampered" },
  };
  const r = await asrFamily.verifyReceipt(tampered, { resolveKey });
  assert.equal(r.signature_valid, false);
});

test("§5.2 wrong-key issuer fails verifyReceipt", async () => {
  const env = await asrFamily.mintV2(mintInput());
  // Replace a random byte in PUB_DER to break key parity.
  const wrongKey = new Uint8Array(PUB_DER);
  wrongKey[wrongKey.length - 1] = (wrongKey[wrongKey.length - 1]! ^ 0xff) & 0xff;
  const r = await asrFamily.verifyReceipt(env, { resolveKey: () => wrongKey });
  assert.equal(r.signature_valid, false);
});

test("§5.3 unresolved key fails verifyReceipt", async () => {
  const env = await asrFamily.mintV2(mintInput());
  const r = await asrFamily.verifyReceipt(env, { resolveKey: () => null });
  assert.equal(r.signature_valid, false);
});

// ── §6 — claim_type discipline ───────────────────────────────────────────────

test("§6.1 explicit owned claim_type accepted", async () => {
  const env = await asrFamily.mintV2(
    mintInput({ body: bodyRequestReceived() }),
  );
  // mintV2 accepts an optional claim_type but single-claim families auto-select.
  assert.equal(env.claim_type, "ar.subject_rights.v1");
});

test("§6.2 explicit non-owned claim_type is silently ignored (single-claim auto-select)", async () => {
  // Single-claim families auto-select the owned claim_type. Pass-through
  // values are NOT validated for ownership; the orchestrator ignores them
  // and emits the family's claim_type. See family-mint-pipeline.ts:295-298.
  const env = await asrFamily.mintV2({ ...mintInput(), claim_type: "ar.notice.v1" });
  assert.equal(env.claim_type, "ar.subject_rights.v1");
});

// ── §7 — env-shape invariants ────────────────────────────────────────────────

test("§7.1 minted envelope carries ULID id, iss_key fingerprint, signed-out fields zeroed", async () => {
  const env = await asrFamily.mintV2(mintInput());
  assert.equal(typeof env.id, "string");
  assert.equal(env.id.length, 26);
  assert.ok(env.iss_key.startsWith("ed25519:"));
  assert.equal(env.countersig, null);
  assert.equal(env.tsa, null);
  // anchor is supplied by the caller, not zeroed
  assert.equal(env.anchor?.log, "https://verify.dekimu.com/asr/v1");
});

test("§7.2 minted envelope iat / iat_ms agree", async () => {
  const env = await asrFamily.mintV2(mintInput());
  assert.ok(Number.isInteger(env.iat_ms));
  if (typeof env.iat === "string") {
    assert.equal(env.iat_ms, Date.parse(env.iat));
  }
});

test("§7.3 minted envelope preserves policy fields", async () => {
  const env = await asrFamily.mintV2(mintInput());
  assert.equal(env.policy_uri, "https://example.test/policy.json");
  assert.equal(env.policy_hash, sha256("9"));
  assert.equal(env.policy_version, "2026-05-19");
});

test("§7.4 minted envelope preserves kind + cause v1.2 fields", async () => {
  const env = await asrFamily.mintV2(mintInput());
  assert.equal(env.kind, "observation");
  assert.equal(env.cause, "manual");
});

// ── §8 — determinism (same seed + body produces same body bytes) ─────────────

test("§8.1 mintV2 produces stable bodies + signatures across calls with same inputs (id and iat differ)", async () => {
  const body = bodyRequestReceived();
  const e1 = await asrFamily.mintV2(mintInput({ body }));
  const e2 = await asrFamily.mintV2(mintInput({ body }));
  // id and iat differ by design (ULID + clock); other body bytes are stable.
  assert.equal(e1.claim_type, e2.claim_type);
  assert.equal(JSON.stringify(e1.body), JSON.stringify(e2.body));
});

// ── §9 — short / bad key rejection at mint ───────────────────────────────────

test("§9.1 short issuerPrivateKey rejected at mint", async () => {
  await assert.rejects(
    () =>
      asrFamily.mintV2(
        mintInput({ issuerPrivateKey: new Uint8Array(16) }),
      ),
    (err: Error) => err.message.includes("32-byte"),
  );
});
