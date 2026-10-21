/**
 * Tests for the per-event-type ANR body verifier (spec §3.1 + §4).
 *
 * Coverage: one happy path per event_type plus the rejection cases named
 * explicitly in §4.1–§4.6. Cross-event pinning is tested by flipping one
 * field to a non-null value and asserting the corresponding
 * `<field>.must_be_null` error fires.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyAnrBody } from "../src/index.ts";

// ── Shared body templates ─────────────────────────────────────────────────────

const BASE_FIELDS = {
  profile: "notice.art13.collected_direct",
  lang_tag: "en-GB",
  lang_inferred: null,
};

/** Field skeleton with every cross-event-pinned field set to null. */
const ALL_PINS_NULL = {
  subject_age_band: null,
  data_source: null,
  collection_horizon: null,
  data_acquired_at: null,
  layer_uris: null,
  ai_system_kind: null,
  ai_system_provider_did: null,
  aer_id: null,
  supersedes_anr_id: null,
  base_anr_id: null,
  ack_method: null,
  joint_controllers: null,
  cessation_reason: null,
  translation_provenance_alr_id: null,
};

function presented(over: Record<string, unknown> = {}) {
  return {
    ...BASE_FIELDS,
    ...ALL_PINS_NULL,
    event_type: "notice.presented",
    jurisdiction: "EU",
    delivery_channel: "web",
    render_uri: "https://example.test/notice/v1",
    rights_surface: ["art15", "art16", "art17", "art18", "art20", "art21"],
    ...over,
  };
}

function rePresented(over: Record<string, unknown> = {}) {
  return {
    ...BASE_FIELDS,
    ...ALL_PINS_NULL,
    event_type: "notice.re_presented",
    jurisdiction: "EU",
    delivery_channel: "web",
    render_uri: "https://example.test/notice/v2",
    rights_surface: ["art15", "art16", "art17", "art18", "art20", "art21"],
    supersedes_anr_id: "01H0PRIOR",
    ...over,
  };
}

function acknowledged(over: Record<string, unknown> = {}) {
  return {
    ...BASE_FIELDS,
    ...ALL_PINS_NULL,
    event_type: "notice.acknowledged",
    jurisdiction: "EU",
    ack_method: "checkbox",
    delivery_channel: null,
    render_uri: null,
    rights_surface: null,
    ...over,
  };
}

function withdrawn(over: Record<string, unknown> = {}) {
  return {
    ...BASE_FIELDS,
    ...ALL_PINS_NULL,
    event_type: "notice.withdrawn",
    jurisdiction: "EU",
    delivery_channel: null,
    render_uri: null,
    rights_surface: null,
    cessation_reason: "service shutdown",
    ...over,
  };
}

function translated(over: Record<string, unknown> = {}) {
  return {
    ...BASE_FIELDS,
    lang_tag: "de-DE",
    lang_inferred: null,
    ...ALL_PINS_NULL,
    event_type: "notice.translated",
    jurisdiction: null,
    base_anr_id: "01HBASE",
    delivery_channel: null,
    render_uri: null,
    rights_surface: null,
    ...over,
  };
}

function jointControllerEssence(over: Record<string, unknown> = {}) {
  return {
    ...BASE_FIELDS,
    profile: "notice.art26.joint_controller_essence",
    ...ALL_PINS_NULL,
    event_type: "notice.joint_controller_essence",
    jurisdiction: "EU",
    delivery_channel: null,
    render_uri: null,
    rights_surface: null,
    joint_controllers: [
      {
        did: "did:web:partner.example",
        role: "joint_controller",
        contact_point_uri: "https://partner.example/contact",
        adr_id: null,
      },
    ],
    ...over,
  };
}

// ── notice.presented ──────────────────────────────────────────────────────────

test("presented: minimal valid body -> valid", () => {
  const out = verifyAnrBody(presented());
  assert.equal(out.valid, true, out.errors.join("|"));
  assert.equal(out.body?.event_type, "notice.presented");
});

test("presented: missing jurisdiction -> jurisdiction.required", () => {
  const out = verifyAnrBody(presented({ jurisdiction: "" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("jurisdiction.required"));
});

test("presented: invalid delivery_channel -> delivery_channel.invalid", () => {
  const out = verifyAnrBody(presented({ delivery_channel: "smoke_signal" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("delivery_channel.invalid"));
});

test("presented: empty render_uri -> render_uri.required", () => {
  const out = verifyAnrBody(presented({ render_uri: "" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("render_uri.required"));
});

test("presented: non-array rights_surface -> rights_surface.invalid", () => {
  const out = verifyAnrBody(presented({ rights_surface: "art15,art17" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("rights_surface.invalid"));
});

test("presented: supersedes_anr_id non-null -> supersedes_anr_id.must_be_null", () => {
  const out = verifyAnrBody(presented({ supersedes_anr_id: "01HOOPS" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("supersedes_anr_id.must_be_null"));
});

test("presented: ack_method leaked in -> ack_method.must_be_null", () => {
  const out = verifyAnrBody(presented({ ack_method: "checkbox" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("ack_method.must_be_null"));
});

test("presented: invalid subject_age_band -> subject_age_band.invalid", () => {
  const out = verifyAnrBody(presented({ subject_age_band: "geriatric" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("subject_age_band.invalid"));
});

test("presented: layered profile carries layer_uris -> valid", () => {
  const out = verifyAnrBody(
    presented({
      profile: "notice.layered_transparency",
      layer_uris: [
        { layer: "summary", uri: "https://x/s", hash: "sha256:" + "a".repeat(64) },
        { layer: "full", uri: "https://x/f", hash: "sha256:" + "b".repeat(64) },
      ],
    }),
  );
  assert.equal(out.valid, true, out.errors.join("|"));
});

test("presented: malformed layer_uris entry -> layer_uris.invalid", () => {
  const out = verifyAnrBody(
    presented({
      profile: "notice.layered_transparency",
      layer_uris: [{ layer: "tertiary", uri: "x", hash: "y" }],
    }),
  );
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("layer_uris.invalid"));
});

// ── notice.re_presented ───────────────────────────────────────────────────────

test("re_presented: minimal valid body -> valid", () => {
  const out = verifyAnrBody(rePresented());
  assert.equal(out.valid, true, out.errors.join("|"));
  assert.equal(out.body?.event_type, "notice.re_presented");
});

test("re_presented: missing supersedes_anr_id -> supersedes_anr_id.required", () => {
  const out = verifyAnrBody(rePresented({ supersedes_anr_id: null }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("supersedes_anr_id.required"));
});

test("re_presented: base_anr_id leak -> base_anr_id.must_be_null", () => {
  const out = verifyAnrBody(rePresented({ base_anr_id: "01HBASE" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("base_anr_id.must_be_null"));
});

// ── notice.acknowledged ───────────────────────────────────────────────────────

test("acknowledged: minimal valid body -> valid", () => {
  const out = verifyAnrBody(acknowledged());
  assert.equal(out.valid, true, out.errors.join("|"));
  assert.equal(out.body?.event_type, "notice.acknowledged");
});

test("acknowledged: invalid ack_method -> ack_method.invalid", () => {
  const out = verifyAnrBody(acknowledged({ ack_method: "shouted" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("ack_method.invalid"));
});

test("acknowledged: render_uri leak -> render_uri.must_be_null", () => {
  const out = verifyAnrBody(acknowledged({ render_uri: "https://x" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("render_uri.must_be_null"));
});

test("acknowledged: missing jurisdiction -> jurisdiction.required", () => {
  const out = verifyAnrBody(acknowledged({ jurisdiction: "" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("jurisdiction.required"));
});

// ── notice.withdrawn ──────────────────────────────────────────────────────────

test("withdrawn: cessation form -> valid", () => {
  const out = verifyAnrBody(withdrawn());
  assert.equal(out.valid, true, out.errors.join("|"));
  assert.equal(out.body?.event_type, "notice.withdrawn");
});

test("withdrawn: supersession form -> valid", () => {
  const out = verifyAnrBody(
    withdrawn({ cessation_reason: null, supersedes_anr_id: "01HSUCCESSOR" }),
  );
  assert.equal(out.valid, true, out.errors.join("|"));
});

test("withdrawn: both set -> withdrawn.both_set", () => {
  const out = verifyAnrBody(
    withdrawn({ supersedes_anr_id: "01HX", cessation_reason: "shutdown" }),
  );
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("withdrawn.both_set"));
});

test("withdrawn: neither set -> withdrawn.neither_set", () => {
  const out = verifyAnrBody(withdrawn({ supersedes_anr_id: null, cessation_reason: null }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("withdrawn.neither_set"));
});

test("withdrawn: ack_method leak -> ack_method.must_be_null", () => {
  const out = verifyAnrBody(withdrawn({ ack_method: "checkbox" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("ack_method.must_be_null"));
});

// ── notice.translated ─────────────────────────────────────────────────────────

test("translated: minimal valid body -> valid", () => {
  const out = verifyAnrBody(translated());
  assert.equal(out.valid, true, out.errors.join("|"));
  assert.equal(out.body?.event_type, "notice.translated");
});

test("translated: missing base_anr_id -> base_anr_id.required", () => {
  const out = verifyAnrBody(translated({ base_anr_id: null }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("base_anr_id.required"));
});

test("translated: jurisdiction non-null -> jurisdiction.must_be_null", () => {
  const out = verifyAnrBody(translated({ jurisdiction: "EU" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("jurisdiction.must_be_null"));
});

test("translated: with optional translation_provenance_alr_id -> valid", () => {
  const out = verifyAnrBody(
    translated({ translation_provenance_alr_id: "01HALRPROV" }),
  );
  assert.equal(out.valid, true, out.errors.join("|"));
});

test("translated: ack_method leak -> ack_method.must_be_null", () => {
  const out = verifyAnrBody(translated({ ack_method: "checkbox" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("ack_method.must_be_null"));
});

// ── notice.joint_controller_essence ───────────────────────────────────────────

test("joint_controller_essence: minimal valid body -> valid", () => {
  const out = verifyAnrBody(jointControllerEssence());
  assert.equal(out.valid, true, out.errors.join("|"));
  assert.equal(out.body?.event_type, "notice.joint_controller_essence");
});

test("joint_controller_essence: empty array -> joint_controllers.empty", () => {
  const out = verifyAnrBody(jointControllerEssence({ joint_controllers: [] }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("joint_controllers.empty"));
});

test("joint_controller_essence: malformed entry -> joint_controllers[0].invalid", () => {
  const out = verifyAnrBody(
    jointControllerEssence({
      joint_controllers: [{ did: "", role: "x", contact_point_uri: "y", adr_id: null }],
    }),
  );
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("joint_controllers[0].invalid"));
});

test("joint_controller_essence: non-array -> joint_controllers.not_array", () => {
  const out = verifyAnrBody(jointControllerEssence({ joint_controllers: "x" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("joint_controllers.not_array"));
});

test("joint_controller_essence: missing jurisdiction -> jurisdiction.required", () => {
  const out = verifyAnrBody(jointControllerEssence({ jurisdiction: "" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("jurisdiction.required"));
});

test("joint_controller_essence: adr_id set, valid", () => {
  const out = verifyAnrBody(
    jointControllerEssence({
      joint_controllers: [
        {
          did: "did:web:a.example",
          role: "joint_controller",
          contact_point_uri: "https://a.example/c",
          adr_id: "01HADR",
        },
      ],
    }),
  );
  assert.equal(out.valid, true, out.errors.join("|"));
});

// ── Base-shape rejections (D10-ANR-1, D10-ANR-2) ──────────────────────────────

test("non-object body -> body.not_object", () => {
  assert.equal(verifyAnrBody(null).errors[0], "body.not_object");
  assert.equal(verifyAnrBody(42).errors[0], "body.not_object");
  assert.equal(verifyAnrBody("body").errors[0], "body.not_object");
});

test("unregistered profile -> profile.unregistered", () => {
  const out = verifyAnrBody(presented({ profile: "made.up.profile" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("profile.unregistered"));
});

test("missing lang_tag -> lang_tag.invalid", () => {
  const out = verifyAnrBody(presented({ lang_tag: "" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("lang_tag.invalid"));
});

test("lang_inferred non-string non-null -> lang_inferred.invalid", () => {
  const out = verifyAnrBody(presented({ lang_inferred: 42 }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("lang_inferred.invalid"));
});

test("unknown event_type -> event_type.unknown", () => {
  const out = verifyAnrBody({
    ...BASE_FIELDS,
    ...ALL_PINS_NULL,
    event_type: "notice.republished",
    jurisdiction: "EU",
    delivery_channel: "web",
    render_uri: "x",
    rights_surface: [],
  });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("event_type.unknown"));
});
