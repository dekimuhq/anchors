/**
 * Tests for the profile-validator dispatch helper.
 *
 * Phase E Task E.2.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  dispatchProfiles,
  type ProfileValidator,
  type ProfileValidatorCtx,
} from "../../src/profile/index.ts";
import type { Envelope } from "../../src/envelope-types.ts";

/** A minimal Envelope-shaped object that satisfies the type for test purposes. */
const STUB_ENVELOPE = {
  v: 2,
  id: "01HXX0000000000000000DISPATCH",
  iat: "2026-05-17T00:00:00Z",
  claim_type: "ar.consent.v1",
  iss: "did:web:test.example",
  iss_key: "ed25519:AAAA",
  subject: "sha256:" + "a".repeat(64),
  exp: null,
  prev: null,
  policy_uri: null,
  policy_hash: null,
  policy_version: null,
  tsa: null,
  credentialStatus: null,
  anchor: null,
  sig: "",
  countersig: null,
  body: { test: true },
} as unknown as Envelope;

const STUB_CTX: ProfileValidatorCtx = {
  tsa_state: "tsa_verified",
  tsa_listed: true,
};

// ── empty validators ─────────────────────────────────────────────────────────

test("dispatchProfiles returns an empty array when validators list is empty", () => {
  const out = dispatchProfiles(STUB_ENVELOPE, STUB_ENVELOPE.body, STUB_CTX, []);
  assert.deepEqual(out, []);
});

// ── single OK passthrough ────────────────────────────────────────────────────

test("dispatchProfiles passes through a single ok=true entry", () => {
  const v: ProfileValidator = () => ({ profile_id: "p.ok", ok: true });
  const out = dispatchProfiles(STUB_ENVELOPE, STUB_ENVELOPE.body, STUB_CTX, [v]);
  assert.equal(out.length, 1);
  assert.deepEqual(out[0], { profile_id: "p.ok", ok: true });
});

// ── single failure with reason ───────────────────────────────────────────────

test("dispatchProfiles preserves ok=false + reason from validator", () => {
  const v: ProfileValidator = () => ({
    profile_id: "p.fail",
    ok: false,
    reason: "tsa_required_by_profile",
  });
  const out = dispatchProfiles(STUB_ENVELOPE, STUB_ENVELOPE.body, STUB_CTX, [v]);
  assert.equal(out.length, 1);
  assert.equal(out[0]!.ok, false);
  assert.equal(out[0]!.reason, "tsa_required_by_profile");
  assert.equal(out[0]!.profile_id, "p.fail");
});

// ── throwing validator ───────────────────────────────────────────────────────

test("dispatchProfiles catches a throwing validator and surfaces profile_validator_threw:<msg>", () => {
  const v: ProfileValidator = () => {
    throw new Error("boom");
  };
  const out = dispatchProfiles(STUB_ENVELOPE, STUB_ENVELOPE.body, STUB_CTX, [v]);
  assert.equal(out.length, 1);
  assert.equal(out[0]!.ok, false);
  assert.equal(out[0]!.profile_id, "unknown");
  assert.equal(out[0]!.reason, "profile_validator_threw:boom");
});

// ── multiple validators in caller order ──────────────────────────────────────

test("dispatchProfiles preserves caller order across multiple validators", () => {
  const v1: ProfileValidator = () => ({ profile_id: "p.first", ok: true });
  const v2: ProfileValidator = () => ({ profile_id: "p.second", ok: false, reason: "nope" });
  const v3: ProfileValidator = () => ({ profile_id: "p.third", ok: true });
  const out = dispatchProfiles(STUB_ENVELOPE, STUB_ENVELOPE.body, STUB_CTX, [v1, v2, v3]);
  assert.equal(out.length, 3);
  assert.equal(out[0]!.profile_id, "p.first");
  assert.equal(out[1]!.profile_id, "p.second");
  assert.equal(out[2]!.profile_id, "p.third");
});

// ── ctx forwarded correctly ──────────────────────────────────────────────────

test("dispatchProfiles forwards ctx to the validator (validator reflects ctx.tsa_state)", () => {
  const v: ProfileValidator = (_env, _body, c) => ({
    profile_id: "p.ctx",
    ok: false,
    reason: `seen:${c.tsa_state ?? "<undef>"}|listed=${c.tsa_listed ?? false}`,
  });
  const ctx: ProfileValidatorCtx = {
    tsa_state: "tsa_drift_exceeded",
    tsa_listed: false,
    tsa_policy_oid: "1.2.3",
  };
  const out = dispatchProfiles(STUB_ENVELOPE, STUB_ENVELOPE.body, ctx, [v]);
  assert.equal(out.length, 1);
  assert.equal(out[0]!.reason, "seen:tsa_drift_exceeded|listed=false");
});
