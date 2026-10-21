/**
 * Tests for the aiact.art53.gpai-training profile validator (ALR §5.3).
 *
 * Covers:
 *   - event_type restricted to derived_from
 *   - parents[*].uri non-null requirement (resolver to dataset descriptor)
 *   - internal TSA-mandate upgrade: tsa_absent → reason 'tsa.required'
 *     (lives in alr-profiles per FAMILY-CONSISTENCY §2 + 10-spec batch plan)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { AlrBody, AlrParentRef } from "@dekimuhq/alr-profiles/body-types";
import {
  validateAiactArt53GpaiTraining,
  validateAiactArt53GpaiTrainingProfile,
  AIACT_ART53_GPAI_TRAINING_PROFILE_ID,
} from "../src/aiact-art53-gpai-training.ts";

const H = (b: string) => `sha256:${b.repeat(64)}`;

function parent(uri: string | null): AlrParentRef {
  return { artifact_hash: H("a"), parent_apr_id: null, parent_alr_id: null, uri };
}

function derived(parents: AlrParentRef[], profile?: string): AlrBody {
  return {
    profile: (profile ?? AIACT_ART53_GPAI_TRAINING_PROFILE_ID) as AlrBody["profile"],
    event_type: "derived_from",
    artifact_hash: H("c"),
    event_at: "2026-05-16T14:23:00Z",
    qts_attestation_hash: null,
    parents,
    successor: null,
    transform_claim: { summary: "pretrain", uri: null },
    disclosure: null,
  };
}

test("aiact.art53.gpai-training: derived_from + parent uris + tsa_verified passes", () => {
  const out = validateAiactArt53GpaiTraining(
    derived([parent("https://datasets.example/d1"), parent("https://datasets.example/d2")]),
    { tsa_state: "tsa_verified" },
  );
  assert.deepEqual(out.errors, []);
});

test("aiact.art53.gpai-training: missing parent uri rejected at the right index", () => {
  const out = validateAiactArt53GpaiTraining(
    derived([parent("https://datasets.example/d1"), parent(null)]),
    { tsa_state: "tsa_verified" },
  );
  assert.ok(
    out.errors.includes("aiact.art53.gpai-training.parents.1.uri.required"),
  );
  assert.ok(
    !out.errors.includes("aiact.art53.gpai-training.parents.0.uri.required"),
  );
});

test("aiact.art53.gpai-training: empty-string parent uri also rejected", () => {
  const out = validateAiactArt53GpaiTraining(
    derived([parent("")]),
    { tsa_state: "tsa_verified" },
  );
  assert.ok(
    out.errors.includes("aiact.art53.gpai-training.parents.0.uri.required"),
  );
});

test("aiact.art53.gpai-training: TSA upgrade — tsa_absent rejected", () => {
  const out = validateAiactArt53GpaiTraining(
    derived([parent("https://datasets.example/d1")]),
    { tsa_state: "tsa_absent" },
  );
  assert.ok(out.errors.includes("aiact.art53.gpai-training.tsa.required"));
});

test("aiact.art53.gpai-training: TSA upgrade — ctx.tsa_state undefined also rejected", () => {
  const out = validateAiactArt53GpaiTraining(
    derived([parent("https://datasets.example/d1")]),
    {},
  );
  assert.ok(out.errors.includes("aiact.art53.gpai-training.tsa.required"));
});

test("aiact.art53.gpai-training: forked_from rejected (event_type allowlist)", () => {
  const body: AlrBody = {
    profile: AIACT_ART53_GPAI_TRAINING_PROFILE_ID,
    event_type: "forked_from",
    artifact_hash: H("c"),
    event_at: "2026-05-16T14:23:00Z",
    qts_attestation_hash: null,
    parents: [parent("https://datasets.example/d1")],
    successor: null,
    transform_claim: { summary: "fork", uri: null },
    disclosure: null,
  };
  const out = validateAiactArt53GpaiTraining(body, { tsa_state: "tsa_verified" });
  assert.deepEqual(out.errors, ["aiact.art53.gpai-training.event_type.disallowed"]);
});

test("aiact.art53.gpai-training: profile mismatch short-circuits", () => {
  const out = validateAiactArt53GpaiTraining(
    derived([parent("https://x")], "c2pa.non-media"),
    { tsa_state: "tsa_verified" },
  );
  assert.deepEqual(out.errors, ["aiact.art53.gpai-training.profile.mismatch"]);
});

// ── Adapter ──────────────────────────────────────────────────────────────────

test("aiact.art53.gpai-training adapter: ok=true with verified TSA + uris", () => {
  const out = validateAiactArt53GpaiTrainingProfile(
    {} as never,
    derived([parent("https://x")]),
    { tsa_state: "tsa_verified" },
  );
  assert.equal(out.profile_id, AIACT_ART53_GPAI_TRAINING_PROFILE_ID);
  assert.equal(out.ok, true);
});

test("aiact.art53.gpai-training adapter: surfaces tsa.required reason on tsa_absent", () => {
  const out = validateAiactArt53GpaiTrainingProfile(
    {} as never,
    derived([parent("https://x")]),
    { tsa_state: "tsa_absent" },
  );
  assert.equal(out.ok, false);
  assert.equal(out.reason, "aiact.art53.gpai-training.tsa.required");
});
