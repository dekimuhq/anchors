/**
 * Tests for the six per-event-type convenience wrappers in mint-single.ts.
 * Each wrapper produces a receipt the verifier accepts and carries the
 * correct `event_type` discriminator in the body.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  mintPresented,
  mintRePresented,
  mintAcknowledged,
  mintWithdrawn,
  mintTranslated,
  mintJointControllerEssence,
} from "../src/issue/index.ts";
import { verifyReceipt } from "../src/index.ts";
import { anchor, baseCommon, H, makeResolveKey, makeSigningKey } from "./_helpers/common.ts";

test("mintPresented round-trips", async () => {
  const env = await mintPresented({
    ...baseCommon,
    signingKey: makeSigningKey(),
    jurisdiction: "EU",
    delivery_channel: "web",
    render_uri: "https://example.test/notice/v1",
    rights_surface: ["art15", "art17"],
  });
  assert.equal((env.body as { event_type: string }).event_type, "notice.presented");
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("mintRePresented round-trips", async () => {
  const env = await mintRePresented({
    ...baseCommon,
    signingKey: makeSigningKey(),
    jurisdiction: "EU",
    delivery_channel: "web",
    render_uri: "https://example.test/notice/v2",
    rights_surface: ["art15"],
    supersedes_anr_id: "01HABCDEF0000000000000",
  });
  assert.equal((env.body as { event_type: string }).event_type, "notice.re_presented");
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("mintAcknowledged round-trips with sha256 subject", async () => {
  const env = await mintAcknowledged({
    ...baseCommon,
    signingKey: makeSigningKey(),
    subject: H("a"),
    jurisdiction: "EU",
    ack_method: "checkbox",
    prev: "01HABCPRESENTED00000000",
  });
  assert.equal((env.body as { event_type: string }).event_type, "notice.acknowledged");
  assert.equal(env.subject, H("a"));
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("mintWithdrawn round-trips (cessation branch)", async () => {
  const env = await mintWithdrawn({
    ...baseCommon,
    signingKey: makeSigningKey(),
    jurisdiction: "EU",
    cessation_reason: "processing halted",
  });
  assert.equal((env.body as { event_type: string }).event_type, "notice.withdrawn");
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("mintTranslated round-trips and forces prev to null (D10-ANR-5)", async () => {
  const env = await mintTranslated({
    ...baseCommon,
    signingKey: makeSigningKey(),
    base_anr_id: "01HBASE000000000000000",
    lang_tag: "es-ES",
    // Even if caller passes prev, it should be forced to null on translation.
    prev: "01HSHOULDBEDROPPED0000",
  });
  assert.equal((env.body as { event_type: string }).event_type, "notice.translated");
  assert.equal(env.prev, null);
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("mintJointControllerEssence round-trips with art26 profile", async () => {
  const env = await mintJointControllerEssence({
    ...baseCommon,
    profile: "notice.art26.joint_controller_essence",
    signingKey: makeSigningKey(),
    jurisdiction: "EU",
    joint_controllers: [
      {
        did: "did:web:partner.example",
        role: "marketing",
        contact_point_uri: "https://partner.example/dpo",
        adr_id: null,
      },
    ],
  });
  assert.equal(
    (env.body as { event_type: string }).event_type,
    "notice.joint_controller_essence",
  );
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("mintPresented uses anchor and policy fields from baseCommon", async () => {
  const env = await mintPresented({
    ...baseCommon,
    signingKey: makeSigningKey(),
    jurisdiction: "EU",
    delivery_channel: "web",
    render_uri: "https://example.test/notice/v1",
    rights_surface: ["art15"],
  });
  assert.equal(env.anchor, anchor);
  assert.equal(env.policy_uri, baseCommon.policy_uri);
});
