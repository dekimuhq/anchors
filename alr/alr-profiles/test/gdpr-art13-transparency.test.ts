/**
 * Tests for the gdpr.art13.transparency profile validator (ALR §5.1).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { AlrBody } from "@dekimuhq/alr-profiles/body-types";
import {
  validateGdprArt13Transparency,
  validateGdprArt13TransparencyProfile,
  GDPR_ART13_TRANSPARENCY_PROFILE_ID,
} from "../src/gdpr-art13-transparency.ts";

const H = (b: string) => `sha256:${b.repeat(64)}`;

function derivedFrom(profile: string = GDPR_ART13_TRANSPARENCY_PROFILE_ID): AlrBody {
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
    transform_claim: { summary: "fine-tune", uri: null },
    disclosure: null,
  };
}

test("gdpr.art13.transparency: derived_from with matching profile passes", () => {
  const out = validateGdprArt13Transparency(derivedFrom());
  assert.deepEqual(out.errors, []);
});

test("gdpr.art13.transparency: disclosed event_type passes", () => {
  const body: AlrBody = {
    profile: GDPR_ART13_TRANSPARENCY_PROFILE_ID,
    event_type: "disclosed",
    artifact_hash: H("c"),
    event_at: "2026-05-16T14:23:00Z",
    qts_attestation_hash: null,
    parents: [],
    successor: null,
    transform_claim: null,
    disclosure: {
      recipient: "did:web:auditor.example",
      recipient_role: "auditor",
      scope_hash: H("d"),
      basis: "gdpr.art6.1.c",
    },
  };
  const out = validateGdprArt13Transparency(body);
  assert.deepEqual(out.errors, []);
});

test("gdpr.art13.transparency: superseded_by is rejected (not in §5.1 allowlist)", () => {
  const body: AlrBody = {
    profile: GDPR_ART13_TRANSPARENCY_PROFILE_ID,
    event_type: "superseded_by",
    artifact_hash: H("c"),
    event_at: "2026-05-16T14:23:00Z",
    qts_attestation_hash: null,
    parents: [],
    successor: { artifact_hash: H("b"), parent_apr_id: null, parent_alr_id: null, uri: null },
    transform_claim: { summary: "supersede", uri: null },
    disclosure: null,
  };
  const out = validateGdprArt13Transparency(body);
  assert.ok(out.errors.includes("gdpr.art13.transparency.event_type.disallowed"));
});

test("gdpr.art13.transparency: profile mismatch short-circuits", () => {
  const out = validateGdprArt13Transparency(
    derivedFrom("aiact.art13.transparency"),
  );
  assert.deepEqual(out.errors, ["gdpr.art13.transparency.profile.mismatch"]);
});

// ── Adapter ──────────────────────────────────────────────────────────────────

test("gdpr.art13.transparency adapter: returns profile_id and ok=true on valid", () => {
  const out = validateGdprArt13TransparencyProfile(
    {} as never,
    derivedFrom(),
    {},
  );
  assert.equal(out.profile_id, GDPR_ART13_TRANSPARENCY_PROFILE_ID);
  assert.equal(out.ok, true);
  assert.equal(out.reason, undefined);
});

test("gdpr.art13.transparency adapter: surfaces first error on reject", () => {
  const body = derivedFrom();
  body.event_type = "superseded_by";
  (body as AlrBody).successor = {
    artifact_hash: H("b"),
    parent_apr_id: null,
    parent_alr_id: null,
    uri: null,
  };
  (body as AlrBody).parents = [];
  const out = validateGdprArt13TransparencyProfile(
    {} as never,
    body,
    {},
  );
  assert.equal(out.ok, false);
  assert.equal(out.reason, "gdpr.art13.transparency.event_type.disallowed");
});
