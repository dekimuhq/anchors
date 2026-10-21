/**
 * Gap-fill tests for `mintAsrV2` — beyond the 3 smoke tests in `mint.test.ts`.
 *
 * Drives asr-issuer-kit above the ≥99 per-package test floor (Phase 3
 * Step 9.5). asr-issuer-kit is a thin re-export of `asrFamily.mintV2`
 * (greenfield factory-from-day-1 — no hand-rolled mint-v2.ts, no
 * field_root) so these tests exercise the factory contract through the
 * re-export point rather than per-event body builders.
 *
 * Groups:
 *   E*   envelope passthrough invariants (v / id ULID / iat ISO + iat_ms
 *        parity / iss / iss_key / exp / prev / policy_uri / policy_hash /
 *        policy_version / kind / cause / predicate / countersig / anchor /
 *        claim_type / iss_key stability across mints)
 *   B*   body construction per event_type — each of the 9 ASR events
 *        round-trips with discriminator + subject_rights_request_id +
 *        event-specific fields verbatim
 *   D*   body bytes determinism + per-event + per-input differentiation;
 *        orchestrator does not mutate body keys (no field_root for ASR)
 *   SD*  subject discipline (D10-ASR-5 sha256:<hex> form)
 *   BS*  body-schema rejections per event_type, surfaced through mintAsrV2
 *   P*   profile dispatch via verifyReceipt:
 *          art15 / art16 cross-family forbids,
 *          art17 mandatory arr_receipt_id,
 *          art18 restriction_reason_code × 4 closed enum,
 *          art20 portability_format × 7 closed enum + other-detail,
 *          art21 objection_scope × 3 + balancing_test_hash when general LI
 *   S*   credentialStatus attach round-trip (omitted / attached / shape /
 *        verify round-trip / non-https throw / index-out-of-range throw)
 *   X*   misc — explicit claim_type, signature tampering, short key,
 *        wrong-issuer-key, resolveKey returning null, unknown profile_id,
 *        decision-kind passthrough, predicate passthrough
 *
 * regression check: grep -cE 'test\("(E|B|D|SD|BS|P|S|X)[0-9]+:' asr/asr/test/mint-v2-extra.test.ts
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mintAsrV2, asrFamily } from "../src/issue/index.ts";
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
  resolveKey,
  sha256,
} from "./_helpers/common.ts";

const ULID_RE = /^[0-9A-HJKMNP-TV-Z]{26}$/;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;
const ED25519_KEY_RE = /^ed25519:[A-Za-z0-9_-]+$/;

// ── E — envelope passthrough ─────────────────────────────────────────────────

test("E1: envelope.v is 2", async () => {
  const env = await mintAsrV2(mintInput());
  assert.equal(env.v, 2);
});

test("E2: id is a 26-character Crockford ULID", async () => {
  const env = await mintAsrV2(mintInput());
  assert.equal(env.id.length, 26);
  assert.match(env.id, ULID_RE);
});

test("E3: iat is ISO-8601 UTC and iat_ms matches Date.parse(iat) exactly", async () => {
  const env = await mintAsrV2(mintInput());
  assert.match(env.iat, ISO_RE);
  assert.equal(env.iat_ms, Date.parse(env.iat));
});

test("E4: iss is the supplied issuer DID verbatim", async () => {
  const env = await mintAsrV2(mintInput());
  assert.equal(env.iss, "did:web:test.example.com");
});

test("E5: iss_key has shape ed25519:<base64url>", async () => {
  const env = await mintAsrV2(mintInput());
  assert.match(env.iss_key, ED25519_KEY_RE);
});

test("E6: exp defaults to null when omitted", async () => {
  const env = await mintAsrV2(mintInput());
  assert.equal(env.exp, null);
});

test("E7: exp passthrough preserved when supplied", async () => {
  const env = await mintAsrV2(mintInput({ exp: "2027-01-01T00:00:00Z" }));
  assert.equal(env.exp, "2027-01-01T00:00:00Z");
});

test("E8: prev defaults to null when omitted", async () => {
  const env = await mintAsrV2(mintInput());
  assert.equal(env.prev, null);
});

test("E9: prev passthrough preserved when supplied", async () => {
  const prev = "01H8YE1ZQ0000000000000ASR0";
  const env = await mintAsrV2(mintInput({ prev }));
  assert.equal(env.prev, prev);
});

test("E10: policy_uri passes through verbatim", async () => {
  const env = await mintAsrV2(
    mintInput({ policy_uri: "https://controller.example/policy/v2" }),
  );
  assert.equal(env.policy_uri, "https://controller.example/policy/v2");
});

test("E11: policy_hash passes through verbatim", async () => {
  const env = await mintAsrV2(
    mintInput({ policy_hash: "sha256:" + "f".repeat(64) }),
  );
  assert.equal(env.policy_hash, "sha256:" + "f".repeat(64));
});

test("E12: policy_version passes through verbatim", async () => {
  const env = await mintAsrV2(mintInput({ policy_version: "2.1.3" }));
  assert.equal(env.policy_version, "2.1.3");
});

test("E13: kind 'observation' passes through verbatim", async () => {
  const env = await mintAsrV2(mintInput({ kind: "observation" }));
  assert.equal(env.kind, "observation");
});

test("E14: kind 'decision' passes through verbatim", async () => {
  const env = await mintAsrV2(mintInput({ kind: "decision" }));
  assert.equal(env.kind, "decision");
});

test("E15: cause 'manual' passes through verbatim", async () => {
  const env = await mintAsrV2(mintInput({ cause: "manual" }));
  assert.equal(env.cause, "manual");
});

test("E16: cause 'erasure_request' passes through verbatim", async () => {
  const env = await mintAsrV2(mintInput({ cause: "erasure_request" }));
  assert.equal(env.cause, "erasure_request");
});

test("E17: cause 'objection' passes through verbatim", async () => {
  const env = await mintAsrV2(mintInput({ cause: "objection" }));
  assert.equal(env.cause, "objection");
});

test("E18: predicate is absent or null when omitted", async () => {
  const env = await mintAsrV2(mintInput());
  assert.ok(env.predicate === null || env.predicate === undefined);
});

test("E19: predicate passes through verbatim when supplied", async () => {
  const pred = { "==": [{ var: "claim_type" }, "ar.subject_rights.v1"] };
  const env = await mintAsrV2(mintInput({ predicate: pred }));
  assert.deepEqual(env.predicate, pred);
});

test("E20: countersig is null at mint time", async () => {
  const env = await mintAsrV2(mintInput());
  assert.equal(env.countersig, null);
});

test("E21: anchor passes through verbatim across all fields", async () => {
  const env = await mintAsrV2(mintInput());
  assert.equal(env.anchor.log, ANCHOR.log);
  assert.equal(env.anchor.leaf_index, ANCHOR.leaf_index);
  assert.equal(env.anchor.tree_head_root, ANCHOR.tree_head_root);
  assert.equal(env.anchor.tree_size, ANCHOR.tree_size);
  assert.equal(env.anchor.log_time, ANCHOR.log_time);
  assert.deepEqual(env.anchor.inclusion_proof, ANCHOR.inclusion_proof);
});

test("E22: claim_type is ar.subject_rights.v1 (single-claim auto-select)", async () => {
  const env = await mintAsrV2(mintInput());
  assert.equal(env.claim_type, "ar.subject_rights.v1");
});

test("E23: iss_key fingerprint is stable across mints with the same key", async () => {
  const e1 = await mintAsrV2(mintInput());
  const e2 = await mintAsrV2(mintInput({ body: bodyFulfilled() }));
  assert.equal(e1.iss_key, e2.iss_key);
});

test("E24: tsa is null when omitted", async () => {
  const env = await mintAsrV2(mintInput());
  assert.equal(env.tsa, null);
});

test("E25: sig is a non-empty base64url string", async () => {
  const env = await mintAsrV2(mintInput());
  assert.ok(typeof env.sig === "string" && env.sig.length > 0);
  assert.match(env.sig, /^[A-Za-z0-9_-]+$/);
});

// ── B — body construction per event_type ─────────────────────────────────────

test("B1: request.received body preserves channel + received_at + deadline_at", async () => {
  const env = await mintAsrV2(mintInput({ body: bodyRequestReceived() }));
  const b = env.body as ReturnType<typeof bodyRequestReceived>;
  assert.equal(b.event_type, "request.received");
  assert.equal(b.subject_rights_request_id, REQ_ID);
  assert.equal(b.channel, "email");
  assert.equal(b.received_at, "2026-05-19T08:00:00Z");
  assert.equal(b.deadline_at, "2026-06-18T08:00:00Z");
});

test("B2: request.identity_verified body preserves verification_method_hash", async () => {
  const env = await mintAsrV2(mintInput({ body: bodyIdentityVerified() }));
  const b = env.body as ReturnType<typeof bodyIdentityVerified>;
  assert.equal(b.event_type, "request.identity_verified");
  assert.equal(b.verification_method_hash, sha256("1"));
});

test("B3: request.scope_clarified body preserves scope_clarification_hash", async () => {
  const env = await mintAsrV2(mintInput({ body: bodyScopeClarified() }));
  const b = env.body as ReturnType<typeof bodyScopeClarified>;
  assert.equal(b.event_type, "request.scope_clarified");
  assert.equal(b.scope_clarification_hash, sha256("2"));
});

test("B4: request.extended body preserves extension_reason_hash + extended_until_at", async () => {
  const env = await mintAsrV2(mintInput({ body: bodyExtended() }));
  const b = env.body as ReturnType<typeof bodyExtended>;
  assert.equal(b.event_type, "request.extended");
  assert.equal(b.extension_reason_hash, sha256("3"));
  assert.equal(b.extended_until_at, "2026-07-18T08:00:00Z");
});

test("B5: request.partially_honoured body preserves all 5 mandatory fields", async () => {
  const env = await mintAsrV2(mintInput({ body: bodyPartiallyHonoured() }));
  const b = env.body as ReturnType<typeof bodyPartiallyHonoured>;
  assert.equal(b.event_type, "request.partially_honoured");
  assert.deepEqual(b.fulfilled_partial_scope, ["art15"]);
  assert.equal(b.fulfilled_artifact_hash, sha256("4"));
  assert.equal(b.fulfilment_uri, "https://example.test/artifact");
  assert.equal(b.refusal_ground, "art17_3_b_legal_obligation");
  assert.equal(b.refusal_justification_hash, sha256("5"));
});

test("B6: request.fulfilled body preserves fulfilled_artifact_hash + fulfilment_uri", async () => {
  const env = await mintAsrV2(mintInput({ body: bodyFulfilled() }));
  const b = env.body as ReturnType<typeof bodyFulfilled>;
  assert.equal(b.event_type, "request.fulfilled");
  assert.equal(b.fulfilled_artifact_hash, sha256("6"));
  assert.equal(b.fulfilment_uri, "https://example.test/artifact");
});

test("B7: request.refused body preserves refusal_ground + refusal_justification_hash", async () => {
  const env = await mintAsrV2(mintInput({ body: bodyRefused() }));
  const b = env.body as ReturnType<typeof bodyRefused>;
  assert.equal(b.event_type, "request.refused");
  assert.equal(b.refusal_ground, "art12_5_a_unfounded");
  assert.equal(b.refusal_justification_hash, sha256("7"));
});

test("B8: request.escalated body preserves event_type + optional escalation_dpa_reference", async () => {
  const env = await mintAsrV2(mintInput({ body: bodyEscalated() }));
  const b = env.body as ReturnType<typeof bodyEscalated>;
  assert.equal(b.event_type, "request.escalated");
  assert.equal(b.escalation_dpa_reference, null);
});

test("B9: request.recipient_notified body preserves recipient_set_alr_ids + uri + hash", async () => {
  const env = await mintAsrV2(mintInput({ body: bodyRecipientNotified() }));
  const b = env.body as ReturnType<typeof bodyRecipientNotified>;
  assert.equal(b.event_type, "request.recipient_notified");
  assert.deepEqual(b.recipient_set_alr_ids, ["alr_01HK0000000000000000000001"]);
  assert.equal(b.recipient_notification_uri, "https://example.test/art19-notify");
  assert.equal(b.recipient_notification_hash, sha256("8"));
});

// ── D — body bytes determinism + cross-event + cross-input differentiation ───

test("D1: identical body inputs produce byte-equal env.body across mints", async () => {
  const body = bodyRequestReceived();
  const e1 = await mintAsrV2(mintInput({ body }));
  const e2 = await mintAsrV2(mintInput({ body }));
  assert.equal(JSON.stringify(e1.body), JSON.stringify(e2.body));
});

test("D2: different event_type produces different body bytes", async () => {
  const e1 = await mintAsrV2(mintInput({ body: bodyRequestReceived() }));
  const e2 = await mintAsrV2(mintInput({ body: bodyFulfilled() }));
  assert.notEqual(JSON.stringify(e1.body), JSON.stringify(e2.body));
});

test("D3: changing one body field produces different body bytes", async () => {
  const e1 = await mintAsrV2(
    mintInput({ body: bodyRequestReceived({ channel: "email" }) }),
  );
  const e2 = await mintAsrV2(
    mintInput({ body: bodyRequestReceived({ channel: "web_form" }) }),
  );
  assert.notEqual(JSON.stringify(e1.body), JSON.stringify(e2.body));
});

test("D4: subject_rights_request_id is verbatim in env.body", async () => {
  const customId = "01HK-CUSTOM-REQUEST-ID-FOR-D4";
  const env = await mintAsrV2(
    mintInput({
      body: bodyRequestReceived({ subject_rights_request_id: customId }),
    }),
  );
  assert.equal(
    (env.body as { subject_rights_request_id: string })
      .subject_rights_request_id,
    customId,
  );
});

test("D5: orchestrator does NOT add field_root to ASR body (greenfield factory)", async () => {
  const env = await mintAsrV2(mintInput({ body: bodyRequestReceived() }));
  assert.equal(
    Object.prototype.hasOwnProperty.call(env.body, "field_root"),
    false,
  );
});

test("D6: env.body keys match the input body keys (no orchestrator additions)", async () => {
  const body = bodyFulfilled();
  const env = await mintAsrV2(mintInput({ body }));
  const inKeys = Object.keys(body).sort();
  const outKeys = Object.keys(env.body as object).sort();
  assert.deepEqual(outKeys, inKeys);
});

test("D7: identical subject_rights_request_id across two minted receipts pins lifecycle parity", async () => {
  const id = "01HK-LIFECYCLE-PARITY-PIN";
  const e1 = await mintAsrV2(
    mintInput({
      body: bodyRequestReceived({ subject_rights_request_id: id }),
    }),
  );
  const e2 = await mintAsrV2(
    mintInput({
      body: bodyFulfilled({ subject_rights_request_id: id }),
    }),
  );
  const b1 = e1.body as { subject_rights_request_id: string };
  const b2 = e2.body as { subject_rights_request_id: string };
  assert.equal(b1.subject_rights_request_id, b2.subject_rights_request_id);
});

// ── SD — subject discipline (D10-ASR-5 sha256:<hex> form) ────────────────────

test("SD1: null subject rejected at mint with subject_missing", async () => {
  await assert.rejects(
    () => mintAsrV2(mintInput({ subject: null })),
    (e: Error) => e.message.includes("subject_missing"),
  );
});

test("SD2: empty subject rejected at mint with subject_missing", async () => {
  await assert.rejects(
    () => mintAsrV2(mintInput({ subject: "" })),
    (e: Error) => e.message.includes("subject_missing"),
  );
});

test("SD3: did:web subject rejected as subject_invalid_form", async () => {
  await assert.rejects(
    () => mintAsrV2(mintInput({ subject: "did:web:notsha" })),
    (e: Error) => e.message.includes("subject_invalid_form"),
  );
});

test("SD4: uppercase-hex subject rejected as subject_invalid_form", async () => {
  await assert.rejects(
    () => mintAsrV2(mintInput({ subject: `sha256:${"A".repeat(64)}` })),
    (e: Error) => e.message.includes("subject_invalid_form"),
  );
});

test("SD5: short hex (63 chars) rejected as subject_invalid_form", async () => {
  await assert.rejects(
    () => mintAsrV2(mintInput({ subject: `sha256:${"a".repeat(63)}` })),
    (e: Error) => e.message.includes("subject_invalid_form"),
  );
});

test("SD6: valid sha256:<64-lowercase-hex> subject accepted and verbatim", async () => {
  const subj = sha256("d");
  const env = await mintAsrV2(mintInput({ subject: subj }));
  assert.equal(env.subject, subj);
});

// ── BS — body-schema rejections surfaced through mintAsrV2 ───────────────────

test("BS1: request.received missing channel rejects as asr_invalid_channel", async () => {
  const body = { ...bodyRequestReceived() } as Record<string, unknown>;
  delete body.channel;
  await assert.rejects(
    () => mintAsrV2(mintInput({ body })),
    (e: Error) => e.message.includes("asr_invalid_channel"),
  );
});

test("BS2: request.received invalid channel rejects as asr_invalid_channel", async () => {
  const body = { ...bodyRequestReceived(), channel: "carrier_pigeon" };
  await assert.rejects(
    () => mintAsrV2(mintInput({ body })),
    (e: Error) => e.message.includes("asr_invalid_channel"),
  );
});

test("BS3: request.received missing received_at rejects as asr_invalid_received_at", async () => {
  const body = { ...bodyRequestReceived() } as Record<string, unknown>;
  delete body.received_at;
  await assert.rejects(
    () => mintAsrV2(mintInput({ body })),
    (e: Error) => e.message.includes("asr_invalid_received_at"),
  );
});

test("BS4: request.received missing deadline_at rejects as asr_invalid_deadline_at", async () => {
  const body = { ...bodyRequestReceived() } as Record<string, unknown>;
  delete body.deadline_at;
  await assert.rejects(
    () => mintAsrV2(mintInput({ body })),
    (e: Error) => e.message.includes("asr_invalid_deadline_at"),
  );
});

test("BS5: request.identity_verified missing verification_method_hash rejects", async () => {
  const body = { ...bodyIdentityVerified() } as Record<string, unknown>;
  delete body.verification_method_hash;
  await assert.rejects(
    () => mintAsrV2(mintInput({ body })),
    (e: Error) => e.message.includes("asr_missing_verification_method_hash"),
  );
});

test("BS6: request.scope_clarified missing scope_clarification_hash rejects", async () => {
  const body = { ...bodyScopeClarified() } as Record<string, unknown>;
  delete body.scope_clarification_hash;
  await assert.rejects(
    () => mintAsrV2(mintInput({ body })),
    (e: Error) => e.message.includes("asr_missing_scope_clarification_hash"),
  );
});

test("BS7: request.extended missing extension_reason_hash rejects", async () => {
  const body = { ...bodyExtended() } as Record<string, unknown>;
  delete body.extension_reason_hash;
  await assert.rejects(
    () => mintAsrV2(mintInput({ body })),
    (e: Error) => e.message.includes("asr_missing_extension_reason_hash"),
  );
});

test("BS8: request.extended missing extended_until_at rejects", async () => {
  const body = { ...bodyExtended() } as Record<string, unknown>;
  delete body.extended_until_at;
  await assert.rejects(
    () => mintAsrV2(mintInput({ body })),
    (e: Error) => e.message.includes("asr_invalid_extended_until_at"),
  );
});

test("BS9: request.partially_honoured missing fulfilled_partial_scope rejects", async () => {
  const body = { ...bodyPartiallyHonoured() } as Record<string, unknown>;
  delete body.fulfilled_partial_scope;
  await assert.rejects(
    () => mintAsrV2(mintInput({ body })),
    (e: Error) => e.message.includes("asr_invalid_fulfilled_partial_scope"),
  );
});

test("BS10: request.partially_honoured missing fulfilled_artifact_hash rejects", async () => {
  const body = { ...bodyPartiallyHonoured() } as Record<string, unknown>;
  delete body.fulfilled_artifact_hash;
  await assert.rejects(
    () => mintAsrV2(mintInput({ body })),
    (e: Error) => e.message.includes("asr_missing_fulfilled_artifact_hash"),
  );
});

test("BS11: request.partially_honoured missing fulfilment_uri rejects", async () => {
  const body = { ...bodyPartiallyHonoured() } as Record<string, unknown>;
  delete body.fulfilment_uri;
  await assert.rejects(
    () => mintAsrV2(mintInput({ body })),
    (e: Error) => e.message.includes("asr_missing_fulfilment_uri"),
  );
});

test("BS12: request.partially_honoured invalid refusal_ground rejects", async () => {
  const body = { ...bodyPartiallyHonoured(), refusal_ground: "made_up" };
  await assert.rejects(
    () => mintAsrV2(mintInput({ body })),
    (e: Error) => e.message.includes("asr_invalid_refusal_ground"),
  );
});

test("BS13: request.fulfilled missing fulfilled_artifact_hash rejects", async () => {
  const body = { ...bodyFulfilled() } as Record<string, unknown>;
  delete body.fulfilled_artifact_hash;
  await assert.rejects(
    () => mintAsrV2(mintInput({ body })),
    (e: Error) => e.message.includes("asr_missing_fulfilled_artifact_hash"),
  );
});

test("BS14: request.fulfilled missing fulfilment_uri rejects", async () => {
  const body = { ...bodyFulfilled() } as Record<string, unknown>;
  delete body.fulfilment_uri;
  await assert.rejects(
    () => mintAsrV2(mintInput({ body })),
    (e: Error) => e.message.includes("asr_missing_fulfilment_uri"),
  );
});

test("BS15: request.refused invalid refusal_ground rejects", async () => {
  const body = { ...bodyRefused(), refusal_ground: "fake_ground" };
  await assert.rejects(
    () => mintAsrV2(mintInput({ body })),
    (e: Error) => e.message.includes("asr_invalid_refusal_ground"),
  );
});

test("BS16: request.refused missing refusal_justification_hash rejects", async () => {
  const body = { ...bodyRefused() } as Record<string, unknown>;
  delete body.refusal_justification_hash;
  await assert.rejects(
    () => mintAsrV2(mintInput({ body })),
    (e: Error) => e.message.includes("asr_missing_refusal_justification_hash"),
  );
});

test("BS17: request.recipient_notified missing recipient_set_alr_ids rejects", async () => {
  const body = { ...bodyRecipientNotified() } as Record<string, unknown>;
  delete body.recipient_set_alr_ids;
  await assert.rejects(
    () => mintAsrV2(mintInput({ body })),
    (e: Error) => e.message.includes("asr_invalid_recipient_set_alr_ids"),
  );
});

test("BS18: request.recipient_notified empty recipient_set_alr_ids rejects", async () => {
  const body = {
    ...bodyRecipientNotified(),
    recipient_set_alr_ids: [] as readonly string[],
  };
  await assert.rejects(
    () => mintAsrV2(mintInput({ body })),
    (e: Error) => e.message.includes("asr_invalid_recipient_set_alr_ids"),
  );
});

test("BS19: unknown event_type rejects as asr_unknown_event_type", async () => {
  await assert.rejects(
    () =>
      mintAsrV2(
        mintInput({
          body: { event_type: "request.bogus", subject_rights_request_id: REQ_ID },
        }),
      ),
    (e: Error) => e.message.includes("asr_unknown_event_type"),
  );
});

test("BS20: missing subject_rights_request_id rejects", async () => {
  await assert.rejects(
    () =>
      mintAsrV2(
        mintInput({ body: { event_type: "request.received", channel: "email" } }),
      ),
    (e: Error) => e.message.includes("asr_missing_subject_rights_request_id"),
  );
});

// ── P — profile dispatch via verifyReceipt ───────────────────────────────────

const expectProfileOk = async (
  env: Awaited<ReturnType<typeof mintAsrV2>>,
  profile: string,
) => {
  const r = await asrFamily.verifyReceipt(env, { resolveKey, profile });
  assert.equal(
    r.signature_valid,
    true,
    `signature_valid expected true: ${r.reason ?? ""}`,
  );
  const entry = r.profile_state?.[0];
  assert.ok(entry, `profile_state[0] missing for ${profile}`);
  assert.equal(
    entry.ok,
    true,
    `profile ${profile} expected ok=true, got reason=${entry.reason ?? ""}`,
  );
};

const expectProfileFailWith = async (
  env: Awaited<ReturnType<typeof mintAsrV2>>,
  profile: string,
  reasonSubstring: string,
) => {
  const r = await asrFamily.verifyReceipt(env, { resolveKey, profile });
  assert.equal(r.signature_valid, true);
  const entry = r.profile_state?.[0];
  assert.ok(entry);
  assert.equal(entry.ok, false);
  assert.ok(
    entry.reason !== undefined && entry.reason.includes(reasonSubstring),
    `expected profile reason to include "${reasonSubstring}", got "${entry.reason}"`,
  );
};

test("P1: art15.access happy path on request.fulfilled", async () => {
  const env = await mintAsrV2(mintInput({ body: bodyFulfilled() }));
  await expectProfileOk(env, "subject_rights.art15.access");
});

test("P2: art15.access rejects arr_receipt_id on fulfilled (cross-family-forbid)", async () => {
  const body = bodyFulfilled({ arr_receipt_id: "ARR-1234" });
  const env = await mintAsrV2(mintInput({ body }));
  await expectProfileFailWith(
    env,
    "subject_rights.art15.access",
    "arr_receipt_id.forbidden",
  );
});

test("P3: art16.rectification happy path on request.fulfilled", async () => {
  const env = await mintAsrV2(mintInput({ body: bodyFulfilled() }));
  await expectProfileOk(env, "subject_rights.art16.rectification");
});

test("P4: art16.rectification rejects portability_format on fulfilled", async () => {
  const body = bodyFulfilled({ portability_format: "json" });
  const env = await mintAsrV2(mintInput({ body }));
  await expectProfileFailWith(
    env,
    "subject_rights.art16.rectification",
    "portability_format.forbidden",
  );
});

test("P5: art17.erasure_request missing arr_receipt_id on fulfilled HARD-fails (§G compose)", async () => {
  // Phase 3 §G upgraded the MANDATORY arr_receipt_id check from advisory
  // (profile validator returns ok:false) to HARD-invalid (compose returns
  // ok:false → signature_valid flips). The profile validator still
  // surfaces an advisory entry under profile_state[0] as a "first failure"
  // signal, but the canonical rejection is now signature_valid: false +
  // reason: "art17_arr_link_missing".
  const env = await mintAsrV2(mintInput({ body: bodyFulfilled() }));
  const r = await asrFamily.verifyReceipt(env, {
    resolveKey,
    profile: "subject_rights.art17.erasure_request",
  });
  assert.equal(r.signature_valid, false);
  assert.equal(r.reason, "art17_arr_link_missing");
});

test("P6: art17.erasure_request with arr_receipt_id on fulfilled passes", async () => {
  const body = bodyFulfilled({ arr_receipt_id: "ARR-2026-0007" });
  const env = await mintAsrV2(mintInput({ body }));
  await expectProfileOk(env, "subject_rights.art17.erasure_request");
});

test("P7: art18.restriction with art18_1_a_accuracy_contested passes", async () => {
  const body = bodyFulfilled({
    restriction_reason_code: "art18_1_a_accuracy_contested",
  } as Record<string, unknown> as never);
  const env = await mintAsrV2(mintInput({ body }));
  await expectProfileOk(env, "subject_rights.art18.restriction");
});

test("P8: art18.restriction with art18_1_b_unlawful_processing passes", async () => {
  const body = bodyFulfilled({
    restriction_reason_code: "art18_1_b_unlawful_processing",
  } as Record<string, unknown> as never);
  const env = await mintAsrV2(mintInput({ body }));
  await expectProfileOk(env, "subject_rights.art18.restriction");
});

test("P9: art18.restriction with art18_1_c_controller_no_longer_needs passes", async () => {
  const body = bodyFulfilled({
    restriction_reason_code: "art18_1_c_controller_no_longer_needs",
  } as Record<string, unknown> as never);
  const env = await mintAsrV2(mintInput({ body }));
  await expectProfileOk(env, "subject_rights.art18.restriction");
});

test("P10: art18.restriction with art18_1_d_objection_pending passes", async () => {
  const body = bodyFulfilled({
    restriction_reason_code: "art18_1_d_objection_pending",
  } as Record<string, unknown> as never);
  const env = await mintAsrV2(mintInput({ body }));
  await expectProfileOk(env, "subject_rights.art18.restriction");
});

test("P11: art18.restriction missing restriction_reason_code fails", async () => {
  const env = await mintAsrV2(mintInput({ body: bodyFulfilled() }));
  await expectProfileFailWith(
    env,
    "subject_rights.art18.restriction",
    "restriction_reason_code.invalid",
  );
});

test("P12: art20.portability with portability_format=json passes", async () => {
  const body = bodyFulfilled({ portability_format: "json" });
  const env = await mintAsrV2(mintInput({ body }));
  await expectProfileOk(env, "subject_rights.art20.portability");
});

test("P13: art20.portability with portability_format=csv passes", async () => {
  const body = bodyFulfilled({ portability_format: "csv" });
  const env = await mintAsrV2(mintInput({ body }));
  await expectProfileOk(env, "subject_rights.art20.portability");
});

test("P14: art20.portability with portability_format=xml passes", async () => {
  const body = bodyFulfilled({ portability_format: "xml" });
  const env = await mintAsrV2(mintInput({ body }));
  await expectProfileOk(env, "subject_rights.art20.portability");
});

test("P15: art20.portability with portability_format=fhir passes", async () => {
  const body = bodyFulfilled({ portability_format: "fhir" });
  const env = await mintAsrV2(mintInput({ body }));
  await expectProfileOk(env, "subject_rights.art20.portability");
});

test("P16: art20.portability with portability_format=dkim_signed_jwt_bundle passes", async () => {
  const body = bodyFulfilled({ portability_format: "dkim_signed_jwt_bundle" });
  const env = await mintAsrV2(mintInput({ body }));
  await expectProfileOk(env, "subject_rights.art20.portability");
});

test("P17: art20.portability with portability_format=parquet passes", async () => {
  const body = bodyFulfilled({ portability_format: "parquet" });
  const env = await mintAsrV2(mintInput({ body }));
  await expectProfileOk(env, "subject_rights.art20.portability");
});

test("P18: art20.portability with portability_format=other + detail passes", async () => {
  const body = bodyFulfilled({
    portability_format: "other",
    portability_format_detail: "vendor-specific-flat-file",
  } as Record<string, unknown> as never);
  const env = await mintAsrV2(mintInput({ body }));
  await expectProfileOk(env, "subject_rights.art20.portability");
});

test("P19: art20.portability with portability_format=other but missing detail fails", async () => {
  const body = bodyFulfilled({ portability_format: "other" });
  const env = await mintAsrV2(mintInput({ body }));
  await expectProfileFailWith(
    env,
    "subject_rights.art20.portability",
    "portability_format_detail.required",
  );
});

test("P20: art20.portability missing portability_format fails", async () => {
  const env = await mintAsrV2(mintInput({ body: bodyFulfilled() }));
  await expectProfileFailWith(
    env,
    "subject_rights.art20.portability",
    "portability_format.invalid",
  );
});

test("P21: art21.objection with art21_1_direct_marketing passes (no balancing required)", async () => {
  const body = bodyFulfilled({
    objection_scope: "art21_1_direct_marketing",
  } as Record<string, unknown> as never);
  const env = await mintAsrV2(mintInput({ body }));
  await expectProfileOk(env, "subject_rights.art21.objection");
});

test("P22: art21.objection with art21_6_research passes", async () => {
  const body = bodyFulfilled({
    objection_scope: "art21_6_research",
  } as Record<string, unknown> as never);
  const env = await mintAsrV2(mintInput({ body }));
  await expectProfileOk(env, "subject_rights.art21.objection");
});

test("P23: art21.objection with general_legitimate_interest + balancing_test_hash passes", async () => {
  const body = bodyFulfilled({
    objection_scope: "art21_1_general_legitimate_interest",
    balancing_test_hash: sha256("e"),
  } as Record<string, unknown> as never);
  const env = await mintAsrV2(mintInput({ body }));
  await expectProfileOk(env, "subject_rights.art21.objection");
});

test("P24: art21.objection with general_legitimate_interest but no balancing_test_hash fails", async () => {
  const body = bodyFulfilled({
    objection_scope: "art21_1_general_legitimate_interest",
  } as Record<string, unknown> as never);
  const env = await mintAsrV2(mintInput({ body }));
  await expectProfileFailWith(
    env,
    "subject_rights.art21.objection",
    "balancing_test_hash.required",
  );
});

test("P25: art21.objection invalid scope fails", async () => {
  const body = bodyFulfilled({
    objection_scope: "art21_made_up",
  } as Record<string, unknown> as never);
  const env = await mintAsrV2(mintInput({ body }));
  await expectProfileFailWith(
    env,
    "subject_rights.art21.objection",
    "objection_scope.invalid",
  );
});

// ── S — credentialStatus attach round-trip ───────────────────────────────────

test("S1: credentialStatus is null when statusList is omitted", async () => {
  const env = await mintAsrV2(mintInput());
  assert.equal(env.credentialStatus, null);
});

test("S2: credentialStatus carries the 5-field StatusList2021Entry shape when attached", async () => {
  const env = await mintAsrV2(
    mintInput({
      statusList: {
        baseUrl: "https://verify.dekimu.com/asr/status",
        getNextStatusIndex: async () => 17,
        now: () => new Date("2026-07-04T00:00:00Z"),
      },
    }),
  );
  const cs = env.credentialStatus!;
  assert.equal(cs.type, "StatusList2021Entry");
  assert.equal(cs.statusPurpose, "revocation");
  assert.equal(cs.statusListIndex, "17");
  assert.equal(
    cs.statusListCredential,
    "https://verify.dekimu.com/asr/status/2026/07",
  );
  assert.equal(cs.id, "https://verify.dekimu.com/asr/status/2026/07#17");
});

test("S3: credentialStatus bucket honours UTC year/month from cfg.now", async () => {
  const env = await mintAsrV2(
    mintInput({
      statusList: {
        baseUrl: "https://verify.dekimu.com/asr/status",
        getNextStatusIndex: async () => 0,
        now: () => new Date("2026-01-15T12:34:56Z"),
      },
    }),
  );
  assert.equal(
    env.credentialStatus!.statusListCredential,
    "https://verify.dekimu.com/asr/status/2026/01",
  );
});

test("S4: verifyReceipt round-trips a credentialStatus-bearing envelope with signature_valid: true", async () => {
  const env = await mintAsrV2(
    mintInput({
      statusList: {
        baseUrl: "https://verify.dekimu.com/asr/status",
        getNextStatusIndex: async () => 42,
        now: () => new Date("2026-05-19T00:00:00Z"),
      },
    }),
  );
  const r = await asrFamily.verifyReceipt(env, { resolveKey });
  assert.equal(r.signature_valid, true, `verify failed: ${r.reason ?? ""}`);
  assert.ok(env.credentialStatus !== null);
});

test("S5: non-https baseUrl throws at attach", async () => {
  await assert.rejects(
    () =>
      mintAsrV2(
        mintInput({
          statusList: {
            baseUrl: "http://insecure.example/status",
            getNextStatusIndex: async () => 0,
          },
        }),
      ),
    (e: Error) => e.message.includes("baseUrl must start with https://"),
  );
});

test("S6: status index out of range (negative) throws at attach", async () => {
  await assert.rejects(
    () =>
      mintAsrV2(
        mintInput({
          statusList: {
            baseUrl: "https://verify.dekimu.com/asr/status",
            getNextStatusIndex: async () => -1,
          },
        }),
      ),
    (e: Error) => e.message.includes("out of range"),
  );
});

test("S7: status index out of range (above MAX) throws at attach", async () => {
  await assert.rejects(
    () =>
      mintAsrV2(
        mintInput({
          statusList: {
            baseUrl: "https://verify.dekimu.com/asr/status",
            getNextStatusIndex: async () => 131_072,
          },
        }),
      ),
    (e: Error) => e.message.includes("out of range"),
  );
});

test("S8: subject pinning preserved across credentialStatus attach (D10-ASR-5)", async () => {
  const subj = sha256("f");
  const env = await mintAsrV2(
    mintInput({
      subject: subj,
      statusList: {
        baseUrl: "https://verify.dekimu.com/asr/status",
        getNextStatusIndex: async () => 1,
        now: () => new Date("2026-05-19T00:00:00Z"),
      },
    }),
  );
  assert.equal(env.subject, subj);
});

// ── X — misc throws + positive paths ─────────────────────────────────────────

test("X1: explicit owned claim_type accepted", async () => {
  const env = await mintAsrV2(
    mintInput({ claim_type: "ar.subject_rights.v1" }),
  );
  assert.equal(env.claim_type, "ar.subject_rights.v1");
});

test("X2: explicit non-owned claim_type is silently ignored (single-claim auto-select)", async () => {
  const env = await mintAsrV2(
    mintInput({ claim_type: "ar.notice.v1" }),
  );
  assert.equal(env.claim_type, "ar.subject_rights.v1");
});

test("X3: tampered body fails verifyReceipt with signature_valid: false", async () => {
  const env = await mintAsrV2(mintInput());
  const tampered = {
    ...env,
    body: { ...(env.body as object), subject_rights_request_id: "tampered" },
  };
  const r = await asrFamily.verifyReceipt(tampered, { resolveKey });
  assert.equal(r.signature_valid, false);
});

test("X4: short issuerPrivateKey (16 bytes) rejected at mint", async () => {
  await assert.rejects(
    () => mintAsrV2(mintInput({ issuerPrivateKey: new Uint8Array(16) })),
    (e: Error) => e.message.includes("32-byte"),
  );
});

test("X5: resolveKey returning null fails verifyReceipt", async () => {
  const env = await mintAsrV2(mintInput());
  const r = await asrFamily.verifyReceipt(env, {
    resolveKey: async () => null,
  });
  assert.equal(r.signature_valid, false);
});

test("X6: wrong-issuer-key fails verifyReceipt", async () => {
  const env = await mintAsrV2(mintInput());
  const wrong = new Uint8Array(PUB_DER);
  wrong[wrong.length - 1] = (wrong[wrong.length - 1]! ^ 0xff) & 0xff;
  const r = await asrFamily.verifyReceipt(env, {
    resolveKey: async () => wrong,
  });
  assert.equal(r.signature_valid, false);
});

test("X7: unknown profile_id fails verifyReceipt with reason=unknown_profile", async () => {
  const env = await mintAsrV2(mintInput());
  const r = await asrFamily.verifyReceipt(env, {
    resolveKey,
    profile: "subject_rights.bogus",
  });
  assert.equal(r.signature_valid, false);
  assert.equal(r.reason, "unknown_profile");
});

test("X8: kind 'decision' round-trips through verifyReceipt", async () => {
  const env = await mintAsrV2(mintInput({ kind: "decision" }));
  const r = await asrFamily.verifyReceipt(env, { resolveKey });
  assert.equal(r.signature_valid, true);
  assert.equal(env.kind, "decision");
});

test("X9: JSONLogic predicate passthrough round-trips through verifyReceipt", async () => {
  const pred = { "==": [{ var: "iss" }, "did:web:test.example.com"] };
  const env = await mintAsrV2(mintInput({ predicate: pred }));
  const r = await asrFamily.verifyReceipt(env, { resolveKey });
  assert.equal(r.signature_valid, true);
  assert.deepEqual(env.predicate, pred);
});

test("X10: KP-public-key keypair has 32-byte privateKey + 32-byte publicKey", () => {
  assert.equal(KP.privateKey.length, 32);
  assert.equal(KP.publicKey.length, 32);
});

test("X11: SUBJECT and ANCHOR helpers expose stable values for downstream consumers", () => {
  assert.equal(SUBJECT, "sha256:" + "a".repeat(64));
  assert.equal(ANCHOR.log, "https://verify.dekimu.com/asr/v1");
});

test("X_QTS: non-null qts_attestation_hash round-trips through verifier", async () => {
  const QTS = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
  const env = await mintAsrV2(mintInput({
    body: { ...bodyRequestReceived(), qts_attestation_hash: QTS },
  }));
  const body = env.body as Record<string, unknown>;
  assert.equal(body.qts_attestation_hash, QTS);
  const r = await asrFamily.verifyReceipt(env, { resolveKey });
  assert.equal(r.signature_valid, true);
});
