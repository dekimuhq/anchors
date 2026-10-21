/**
 * Validation tests for mint-v2.ts — exercises every documented throw.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mintAnrV2 } from "../src/issue/mint-v2.ts";
import { verifyReceipt } from "../src/index.ts";
import { baseCommon, H, makeResolveKey, makeSigningKey } from "./_helpers/common.ts";

test("V1: throws when issuer missing", async () => {
  await assert.rejects(
    () =>
      mintAnrV2({
        ...baseCommon,
        issuer: "",
        signingKey: makeSigningKey(),
        event_type: "notice.presented",
        jurisdiction: "EU",
        delivery_channel: "web",
        render_uri: "https://example.test/n/v1",
        rights_surface: ["art15"],
      }),
    /issuer required/,
  );
});

test("V2: throws when signingKey.kid missing", async () => {
  await assert.rejects(
    () =>
      mintAnrV2({
        ...baseCommon,
        signingKey: { kid: "", privateKey: new Uint8Array(32) },
        event_type: "notice.presented",
        jurisdiction: "EU",
        delivery_channel: "web",
        render_uri: "https://example.test/n/v1",
        rights_surface: ["art15"],
      }),
    /signingKey\.kid required/,
  );
});

test("V3: throws when private key seed is wrong length", async () => {
  await assert.rejects(
    () =>
      mintAnrV2({
        ...baseCommon,
        signingKey: { kid: "k", privateKey: new Uint8Array(16) },
        event_type: "notice.presented",
        jurisdiction: "EU",
        delivery_channel: "web",
        render_uri: "https://example.test/n/v1",
        rights_surface: ["art15"],
      }),
    /must be 32 bytes/,
  );
});

test("V4: throws when lang_tag empty (D10-ANR-2)", async () => {
  await assert.rejects(
    () =>
      mintAnrV2({
        ...baseCommon,
        lang_tag: "",
        signingKey: makeSigningKey(),
        event_type: "notice.presented",
        jurisdiction: "EU",
        delivery_channel: "web",
        render_uri: "https://example.test/n/v1",
        rights_surface: ["art15"],
      }),
    /lang_tag required/,
  );
});

test("V5: throws on notice.presented with empty rights_surface", async () => {
  await assert.rejects(
    () =>
      mintAnrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "notice.presented",
        jurisdiction: "EU",
        delivery_channel: "web",
        render_uri: "https://example.test/n/v1",
        rights_surface: [],
      }),
    /non-empty rights_surface/,
  );
});

test("V6: throws on layered_transparency profile without layer_uris", async () => {
  await assert.rejects(
    () =>
      mintAnrV2({
        ...baseCommon,
        profile: "notice.layered_transparency",
        signingKey: makeSigningKey(),
        event_type: "notice.presented",
        jurisdiction: "EU",
        delivery_channel: "web",
        render_uri: "https://example.test/n/v1",
        rights_surface: ["art15"],
      }),
    /requires layer_uris/,
  );
});

test("V7: throws on aiact.art50 profile without ai_system_kind", async () => {
  await assert.rejects(
    () =>
      mintAnrV2({
        ...baseCommon,
        profile: "notice.aiact.art50_transparency",
        signingKey: makeSigningKey(),
        event_type: "notice.presented",
        jurisdiction: "EU",
        delivery_channel: "web",
        render_uri: "https://example.test/n/v1",
        rights_surface: ["art15"],
      }),
    /ai_system_kind/,
  );
});

test("V8: throws on notice.re_presented without supersedes_anr_id", async () => {
  await assert.rejects(
    () =>
      mintAnrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "notice.re_presented",
        jurisdiction: "EU",
        delivery_channel: "web",
        render_uri: "https://example.test/n/v2",
        rights_surface: ["art15"],
      } as never),
    /supersedes_anr_id/,
  );
});

test("V9: throws on notice.acknowledged without sha256 subject", async () => {
  await assert.rejects(
    () =>
      mintAnrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "notice.acknowledged",
        subject: "raw-subject-id",
        jurisdiction: "EU",
        ack_method: "checkbox",
      }),
    /sha256:<64-hex>/,
  );
});

test("V10: throws on notice.withdrawn with both supersedes_anr_id and cessation_reason", async () => {
  await assert.rejects(
    () =>
      mintAnrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "notice.withdrawn",
        jurisdiction: "EU",
        supersedes_anr_id: "01HABC0000000000000000",
        cessation_reason: "ceased",
      }),
    /exactly one of supersedes_anr_id/,
  );
});

test("V11: throws on notice.withdrawn with neither supersedes nor cessation", async () => {
  await assert.rejects(
    () =>
      mintAnrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "notice.withdrawn",
        jurisdiction: "EU",
      }),
    /exactly one of supersedes_anr_id/,
  );
});

test("V12: throws on notice.translated without base_anr_id", async () => {
  await assert.rejects(
    () =>
      mintAnrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "notice.translated",
        base_anr_id: "",
      }),
    /base_anr_id/,
  );
});

test("V13: throws on notice.joint_controller_essence with empty controllers", async () => {
  await assert.rejects(
    () =>
      mintAnrV2({
        ...baseCommon,
        profile: "notice.art26.joint_controller_essence",
        signingKey: makeSigningKey(),
        event_type: "notice.joint_controller_essence",
        jurisdiction: "EU",
        joint_controllers: [],
      }),
    /non-empty joint_controllers/,
  );
});

test("V14: throws on non-ack event with non-sha256 raw-string subject", async () => {
  await assert.rejects(
    () =>
      mintAnrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "notice.presented",
        subject: "raw-not-hashed",
        jurisdiction: "EU",
        delivery_channel: "web",
        render_uri: "https://example.test/n/v1",
        rights_surface: ["art15"],
      }),
    /or null on non-ack/,
  );
});

test("V15: throws when tsa config is set without tsaFetcher", async () => {
  await assert.rejects(
    () =>
      mintAnrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "notice.presented",
        jurisdiction: "EU",
        delivery_channel: "web",
        render_uri: "https://example.test/n/v1",
        rights_surface: ["art15"],
        tsa: { provider: "freetsa", hash_alg: "sha256" } as never,
      }),
    /tsaFetcher is required/,
  );
});

test("V16: non-ack event with null subject succeeds (subject pinned null in envelope)", async () => {
  const env = await mintAnrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "notice.presented",
    jurisdiction: "EU",
    delivery_channel: "web",
    render_uri: "https://example.test/n/v1",
    rights_surface: ["art15"],
    // subject omitted — defaults null.
  });
  assert.equal(env.subject, null);
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("V17: non-ack event with sha256 subject is preserved", async () => {
  const env = await mintAnrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "notice.presented",
    subject: H("b"),
    jurisdiction: "EU",
    delivery_channel: "web",
    render_uri: "https://example.test/n/v1",
    rights_surface: ["art15"],
  });
  assert.equal(env.subject, H("b"));
});

test("V18: minted body carries field_root commitment", async () => {
  const env = await mintAnrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "notice.presented",
    jurisdiction: "EU",
    delivery_channel: "web",
    render_uri: "https://example.test/n/v1",
    rights_surface: ["art15"],
  });
  const body = env.body as { field_root: string };
  assert.match(body.field_root, /^sha256:[0-9a-f]{64}$/);
});

test("V19: claim_type is ar.notice.v1", async () => {
  const env = await mintAnrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "notice.presented",
    jurisdiction: "EU",
    delivery_channel: "web",
    render_uri: "https://example.test/n/v1",
    rights_surface: ["art15"],
  });
  assert.equal(env.claim_type, "ar.notice.v1");
});

test("V20: envelope_kind defaults to 'decision' and can be opt-out via null", async () => {
  const defaulted = await mintAnrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "notice.presented",
    jurisdiction: "EU",
    delivery_channel: "web",
    render_uri: "https://example.test/n/v1",
    rights_surface: ["art15"],
  });
  assert.equal(defaulted.kind, "decision");
  const optedOut = await mintAnrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "notice.presented",
    envelope_kind: null,
    jurisdiction: "EU",
    delivery_channel: "web",
    render_uri: "https://example.test/n/v1",
    rights_surface: ["art15"],
  });
  assert.equal(optedOut.kind, null);
});

test("V_QTS: non-null qts_attestation_hash round-trips through verifier", async () => {
  const QTS = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
  const env = await mintAnrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "notice.presented",
    jurisdiction: "EU",
    delivery_channel: "web",
    render_uri: "https://example.test/n/v1",
    rights_surface: ["art15"],
    qts_attestation_hash: QTS,
  });
  const body = env.body as Record<string, unknown>;
  assert.equal(body.qts_attestation_hash, QTS);
  const result = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(result.signature_valid, true, result.reason ?? "ok");
});
