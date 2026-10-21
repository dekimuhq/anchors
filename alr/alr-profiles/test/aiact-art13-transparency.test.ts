/**
 * Tests for the aiact.art13.transparency profile validator (ALR §5.2).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { AlrBody } from "@dekimuhq/alr-profiles/body-types";
import {
  validateAiactArt13Transparency,
  validateAiactArt13TransparencyProfile,
  AIACT_ART13_TRANSPARENCY_PROFILE_ID,
} from "../src/aiact-art13-transparency.ts";

const H = (b: string) => `sha256:${b.repeat(64)}`;

function derivedFrom(
  summary: string,
  profile: string = AIACT_ART13_TRANSPARENCY_PROFILE_ID,
): AlrBody {
  return {
    profile: profile as AlrBody["profile"],
    event_type: "derived_from",
    artifact_hash: H("c"),
    event_at: "2026-05-16T14:23:00Z",
    qts_attestation_hash: null,
    parents: [
      { artifact_hash: H("a"), parent_apr_id: null, parent_alr_id: null, uri: null },
    ],
    successor: null,
    transform_claim: { summary, uri: null },
    disclosure: null,
  };
}

test("aiact.art13.transparency: derived_from with 'fine-tune' summary passes", () => {
  const out = validateAiactArt13Transparency(derivedFrom("fine-tune from base"));
  assert.deepEqual(out.errors, []);
});

test("aiact.art13.transparency: 'pretrain' / 'pretraining' both match", () => {
  for (const s of ["pretrain", "pretraining", "Initial pretraining run"]) {
    const out = validateAiactArt13Transparency(derivedFrom(s));
    assert.deepEqual(out.errors, [], `should pass: ${s}`);
  }
});

test("aiact.art13.transparency: 'distillation', 'merge', 'quantize' all match", () => {
  for (const s of ["distillation", "merge of forks", "Quantization to int8"]) {
    const out = validateAiactArt13Transparency(derivedFrom(s));
    assert.deepEqual(out.errors, [], `should pass: ${s}`);
  }
});

test("aiact.art13.transparency: summary without a training-method class is rejected", () => {
  const out = validateAiactArt13Transparency(derivedFrom("custom reshape pass"));
  assert.ok(
    out.errors.includes("aiact.art13.transparency.transform_claim.method_missing"),
  );
});

test("aiact.art13.transparency: forked_from skips method check (rule applies to derived_from only)", () => {
  const body: AlrBody = {
    profile: AIACT_ART13_TRANSPARENCY_PROFILE_ID,
    event_type: "forked_from",
    artifact_hash: H("c"),
    event_at: "2026-05-16T14:23:00Z",
    qts_attestation_hash: null,
    parents: [
      { artifact_hash: H("a"), parent_apr_id: null, parent_alr_id: null, uri: null },
    ],
    successor: null,
    transform_claim: { summary: "branched", uri: null },
    disclosure: null,
  };
  const out = validateAiactArt13Transparency(body);
  assert.deepEqual(out.errors, []);
});

test("aiact.art13.transparency: disclosed event_type is rejected (not in §5.2 allowlist)", () => {
  const body: AlrBody = {
    profile: AIACT_ART13_TRANSPARENCY_PROFILE_ID,
    event_type: "disclosed",
    artifact_hash: H("c"),
    event_at: "2026-05-16T14:23:00Z",
    qts_attestation_hash: null,
    parents: [],
    successor: null,
    transform_claim: null,
    disclosure: {
      recipient: "did:web:x",
      recipient_role: "controller",
      scope_hash: H("d"),
      basis: "gdpr.art6.1.f",
    },
  };
  const out = validateAiactArt13Transparency(body);
  assert.ok(
    out.errors.includes("aiact.art13.transparency.event_type.disallowed"),
  );
});

test("aiact.art13.transparency: profile mismatch short-circuits", () => {
  const out = validateAiactArt13Transparency(
    derivedFrom("pretrain", "gdpr.art13.transparency"),
  );
  assert.deepEqual(out.errors, ["aiact.art13.transparency.profile.mismatch"]);
});

// ── Adapter ──────────────────────────────────────────────────────────────────

test("aiact.art13.transparency adapter: ok=true on valid", () => {
  const out = validateAiactArt13TransparencyProfile(
    {} as never,
    derivedFrom("fine-tune"),
    {},
  );
  assert.equal(out.profile_id, AIACT_ART13_TRANSPARENCY_PROFILE_ID);
  assert.equal(out.ok, true);
});

test("aiact.art13.transparency adapter: surfaces method_missing reason", () => {
  const out = validateAiactArt13TransparencyProfile(
    {} as never,
    derivedFrom("ad-hoc transform"),
    {},
  );
  assert.equal(out.ok, false);
  assert.equal(
    out.reason,
    "aiact.art13.transparency.transform_claim.method_missing",
  );
});
