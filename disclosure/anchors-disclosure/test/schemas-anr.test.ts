import { test } from "node:test";
import assert from "node:assert/strict";
import { resolveLayout } from "../src/tree.ts";
import { ANR_DISCLOSURE_SCHEMA } from "../src/schemas/anr.ts";

// An ANR notice.presented body shape (every union field present; nulls allowed).
const anrBody = {
  profile: "notice.art13.collected_direct",
  lang_tag: "en-GB",
  lang_inferred: null,
  qts_attestation_hash: null,
  event_type: "notice.presented",
  jurisdiction: "EU",
  delivery_channel: "web",
  render_uri: "https://x/notice",
  rights_surface: ["art15"],
  field_root: "sha256:" + "a".repeat(64), // present at verify time; not a declared leaf
};

test("ANR schema declares the four always-present scalar leaves", () => {
  assert.deepEqual(ANR_DISCLOSURE_SCHEMA.leaves.map((l) => l.path), [
    "/profile",
    "/lang_tag",
    "/event_type",
    "/jurisdiction",
  ]);
  assert.equal(ANR_DISCLOSURE_SCHEMA.leaves.every((l) => !l.array), true);
});

test("ANR schema resolves cleanly against a presented body (4 leaves, declared order)", () => {
  const layout = resolveLayout(anrBody, ANR_DISCLOSURE_SCHEMA);
  assert.deepEqual(layout.map((l) => l.path), ["/profile", "/lang_tag", "/event_type", "/jurisdiction"]);
  assert.deepEqual(layout.map((l) => l.value), ["notice.art13.collected_direct", "en-GB", "notice.presented", "EU"]);
});

test("ANR schema resolves on a translated body where jurisdiction is null", () => {
  const translated = { ...anrBody, event_type: "notice.translated", jurisdiction: null };
  const layout = resolveLayout(translated, ANR_DISCLOSURE_SCHEMA);
  assert.deepEqual(layout.map((l) => l.value), ["notice.art13.collected_direct", "en-GB", "notice.translated", null]);
});
