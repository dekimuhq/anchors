/**
 * Tests for the c2pa.non-media profile validator (ALR §5.4).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { AlrBody, AlrEventType } from "@dekimuhq/alr-profiles/body-types";
import {
  validateC2paNonMedia,
  validateC2paNonMediaProfile,
  C2PA_NON_MEDIA_PROFILE_ID,
} from "../src/c2pa-non-media.ts";

const H = (b: string) => `sha256:${b.repeat(64)}`;

function bodyOf(event_type: AlrEventType, profile?: string): AlrBody {
  const base = {
    profile: (profile ?? C2PA_NON_MEDIA_PROFILE_ID) as AlrBody["profile"],
    artifact_hash: H("c"),
    event_at: "2026-05-16T14:23:00Z",
    qts_attestation_hash: null,
  };
  switch (event_type) {
    case "derived_from":
      return {
        ...base,
        event_type,
        parents: [
          { artifact_hash: H("a"), parent_apr_id: null, parent_alr_id: null, uri: null },
        ],
        successor: null,
        transform_claim: { summary: "transcode", uri: null },
        disclosure: null,
      };
    case "forked_from":
      return {
        ...base,
        event_type,
        parents: [
          { artifact_hash: H("a"), parent_apr_id: null, parent_alr_id: null, uri: null },
        ],
        successor: null,
        transform_claim: { summary: "fork", uri: null },
        disclosure: null,
      };
    case "superseded_by":
      return {
        ...base,
        event_type,
        parents: [],
        successor: {
          artifact_hash: H("b"),
          parent_apr_id: null,
          parent_alr_id: null,
          uri: null,
        },
        transform_claim: { summary: "supersede", uri: null },
        disclosure: null,
      };
    case "disclosed":
      return {
        ...base,
        event_type,
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
  }
}

const ALL_EVENT_TYPES: AlrEventType[] = [
  "derived_from",
  "forked_from",
  "superseded_by",
  "disclosed",
];

for (const et of ALL_EVENT_TYPES) {
  test(`c2pa.non-media: ${et} passes (all four event_types allowed)`, () => {
    const out = validateC2paNonMedia(bodyOf(et));
    assert.deepEqual(out.errors, []);
  });
}

test("c2pa.non-media: profile mismatch is rejected", () => {
  const out = validateC2paNonMedia(bodyOf("derived_from", "gdpr.art13.transparency"));
  assert.deepEqual(out.errors, ["c2pa.non-media.profile.mismatch"]);
});

test("c2pa.non-media adapter: ok=true on valid body", () => {
  const out = validateC2paNonMediaProfile({} as never, bodyOf("disclosed"), {});
  assert.equal(out.profile_id, C2PA_NON_MEDIA_PROFILE_ID);
  assert.equal(out.ok, true);
});

test("c2pa.non-media adapter: surfaces mismatch reason on wrong profile id", () => {
  const out = validateC2paNonMediaProfile(
    {} as never,
    bodyOf("derived_from", "c2pa.media"),
    {},
  );
  assert.equal(out.ok, false);
  assert.equal(out.reason, "c2pa.non-media.profile.mismatch");
});
