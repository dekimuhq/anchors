import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { parseIssuerManifest } from "../src/schema.ts";
import { makeSignedManifest, defaultMembership, defaultOperator, defaultTrustAnchors } from "./fixtures.ts";

describe("parseIssuerManifest", () => {
  // --- Happy path ---

  it("parses a valid manifest", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest(doc);
    assert.equal(r.ok, true);
    if (r.ok) {
      assert.equal(r.doc.kind, "ar.issuer_manifest.v1");
      assert.equal(r.doc.version, 1);
    }
  });

  it("preserves all fields on valid doc", () => {
    const { doc } = makeSignedManifest({
      iss: "did:web:example.com",
      version: 2,
    });
    const r = parseIssuerManifest(doc);
    assert.equal(r.ok, true);
    if (r.ok) {
      assert.equal(r.doc.iss, "did:web:example.com");
      assert.equal(r.doc.version, 2);
      assert.equal(r.doc.memberships.length, 1);
    }
  });

  it("accepts multiple memberships", () => {
    const { doc } = makeSignedManifest({
      memberships: [
        defaultMembership({ family: "apr" }),
        defaultMembership({ family: "acr", claim_types: ["ar.consent.v1"] }),
      ],
    });
    const r = parseIssuerManifest(doc);
    assert.equal(r.ok, true);
    if (r.ok) assert.equal(r.doc.memberships.length, 2);
  });

  it("accepts profiles in membership", () => {
    const { doc } = makeSignedManifest({
      memberships: [
        defaultMembership({
          family: "acr",
          claim_types: ["ar.consent.v1"],
          profiles: ["acr.gdpr.art7", "acr.eprivacy.cookie"],
        }),
      ],
    });
    const r = parseIssuerManifest(doc);
    assert.equal(r.ok, true);
    if (r.ok) assert.deepEqual(r.doc.memberships[0]!.profiles, ["acr.gdpr.art7", "acr.eprivacy.cookie"]);
  });

  it("accepts endorsed_by array", () => {
    const { doc } = makeSignedManifest({
      trust_anchors: defaultTrustAnchors({ endorsed_by: ["did:web:partner.example"] }),
    });
    const r = parseIssuerManifest(doc);
    assert.equal(r.ok, true);
    if (r.ok) assert.deepEqual(r.doc.trust_anchors.endorsed_by, ["did:web:partner.example"]);
  });

  // --- Top-level field rejections ---

  it("rejects non-object", () => {
    assert.equal(parseIssuerManifest(null).ok, false);
    assert.equal(parseIssuerManifest("string").ok, false);
    assert.equal(parseIssuerManifest(42).ok, false);
    assert.equal(parseIssuerManifest([]).ok, false);
  });

  it("rejects wrong kind", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest({ ...doc, kind: "ar.wrong.v1" });
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, /kind/);
  });

  it("rejects missing kind", () => {
    const { doc } = makeSignedManifest();
    const { kind: _, ...rest } = doc;
    const r = parseIssuerManifest(rest);
    assert.equal(r.ok, false);
  });

  it("rejects non-integer version", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest({ ...doc, version: 1.5 });
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, /version/);
  });

  it("rejects zero version", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest({ ...doc, version: 0 });
    assert.equal(r.ok, false);
  });

  it("rejects negative version", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest({ ...doc, version: -1 });
    assert.equal(r.ok, false);
  });

  // --- Date validations ---

  it("rejects non-ISO issued_at", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest({ ...doc, issued_at: "not-a-date" });
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, /issued_at/);
  });

  it("rejects non-ISO valid_until", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest({ ...doc, valid_until: "2026" });
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, /valid_until/);
  });

  it("rejects issued_at >= valid_until", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest({
      ...doc,
      issued_at: "2026-06-01T00:00:00Z",
      valid_until: "2026-06-01T00:00:00Z",
    });
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, /issued_at.*must be.*valid_until/);
  });

  it("rejects issued_at after valid_until", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest({
      ...doc,
      issued_at: "2026-07-01T00:00:00Z",
      valid_until: "2026-06-01T00:00:00Z",
    });
    assert.equal(r.ok, false);
  });

  it("rejects valid_until > 90 days from issued_at", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest({
      ...doc,
      issued_at: "2026-06-01T00:00:00Z",
      valid_until: "2026-10-01T00:00:00Z",
    });
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, /90 days/);
  });

  it("accepts exactly 90 days", () => {
    const { doc } = makeSignedManifest({
      issued_at: "2026-06-01T00:00:00Z",
      valid_until: "2026-08-30T00:00:00Z",
    });
    const r = parseIssuerManifest(doc);
    assert.equal(r.ok, true);
  });

  // --- iss ---

  it("rejects non-did:web iss", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest({ ...doc, iss: "https://example.com" });
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, /iss/);
  });

  it("rejects missing iss", () => {
    const { doc } = makeSignedManifest();
    const { iss: _, ...rest } = doc;
    const r = parseIssuerManifest(rest);
    assert.equal(r.ok, false);
  });

  // --- Operator ---

  it("rejects missing operator", () => {
    const { doc } = makeSignedManifest();
    const { operator: _, ...rest } = doc;
    const r = parseIssuerManifest(rest);
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, /operator/);
  });

  it("rejects operator with empty name", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest({
      ...doc,
      operator: { ...doc.operator, name: "" },
    });
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, /operator\.name/);
  });

  it("rejects operator with empty jurisdiction", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest({
      ...doc,
      operator: { ...doc.operator, jurisdiction: "" },
    });
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, /operator\.jurisdiction/);
  });

  it("rejects operator with empty contact_uri", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest({
      ...doc,
      operator: { ...doc.operator, contact_uri: "" },
    });
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, /operator\.contact_uri/);
  });

  it("rejects non-object operator", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest({ ...doc, operator: "string" });
    assert.equal(r.ok, false);
  });

  // --- key_doc_uri ---

  it("rejects empty key_doc_uri", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest({ ...doc, key_doc_uri: "" });
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, /key_doc_uri/);
  });

  it("rejects invalid URL key_doc_uri", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest({ ...doc, key_doc_uri: "not a url" });
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, /key_doc_uri/);
  });

  // --- Memberships ---

  it("rejects empty memberships array", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest({ ...doc, memberships: [] });
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, /memberships/);
  });

  it("rejects non-array memberships", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest({ ...doc, memberships: "not array" });
    assert.equal(r.ok, false);
  });

  it("rejects unknown family slug", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest({
      ...doc,
      memberships: [{ ...doc.memberships[0], family: "xyz" }],
    });
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, /14-member taxonomy/);
  });

  it("rejects non-ar.* claim_types", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest({
      ...doc,
      memberships: [{ ...doc.memberships[0], claim_types: ["bad_type"] }],
    });
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, /claim_types/);
  });

  it("accepts all 14 family slugs", () => {
    const slugs = [
      "apr", "acr", "arr", "alr", "atr", "apur",
      "aer", "aar", "adr", "anr", "asr", "abr",
      "air", "atokr",
    ];
    for (const slug of slugs) {
      const { doc } = makeSignedManifest({
        memberships: [defaultMembership({ family: slug, claim_types: [`ar.test.v1`] })],
      });
      const r = parseIssuerManifest(doc);
      assert.equal(r.ok, true, `family slug ${slug} should be accepted`);
    }
  });

  it("rejects non-object membership entry", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest({ ...doc, memberships: ["not-an-object"] });
    assert.equal(r.ok, false);
  });

  it("rejects membership with non-string family", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest({
      ...doc,
      memberships: [{ ...doc.memberships[0], family: 42 }],
    });
    assert.equal(r.ok, false);
  });

  it("rejects membership with non-array claim_types", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest({
      ...doc,
      memberships: [{ ...doc.memberships[0], claim_types: "not-array" }],
    });
    assert.equal(r.ok, false);
  });

  it("rejects membership with non-string claim_type entry", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest({
      ...doc,
      memberships: [{ ...doc.memberships[0], claim_types: [42] }],
    });
    assert.equal(r.ok, false);
  });

  it("rejects membership with non-array profiles", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest({
      ...doc,
      memberships: [{ ...doc.memberships[0], profiles: "not-array" }],
    });
    assert.equal(r.ok, false);
  });

  it("rejects membership with non-string profile entry", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest({
      ...doc,
      memberships: [{ ...doc.memberships[0], profiles: [42] }],
    });
    assert.equal(r.ok, false);
  });

  it("rejects membership with non-array spec_versions", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest({
      ...doc,
      memberships: [{ ...doc.memberships[0], spec_versions: "not-array" }],
    });
    assert.equal(r.ok, false);
  });

  it("rejects membership with non-string spec_version entry", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest({
      ...doc,
      memberships: [{ ...doc.memberships[0], spec_versions: [1] }],
    });
    assert.equal(r.ok, false);
  });

  // --- Trust anchors ---

  it("rejects missing trust_anchors", () => {
    const { doc } = makeSignedManifest();
    const { trust_anchors: _, ...rest } = doc;
    const r = parseIssuerManifest(rest);
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, /trust_anchors/);
  });

  it("rejects non-array endorses", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest({
      ...doc,
      trust_anchors: { ...doc.trust_anchors, endorses: "not-array" },
    });
    assert.equal(r.ok, false);
  });

  it("rejects non-did:web in endorses", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest({
      ...doc,
      trust_anchors: { ...doc.trust_anchors, endorses: ["not-a-did"] },
    });
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, /endorses/);
  });

  it("rejects non-array endorsed_by", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest({
      ...doc,
      trust_anchors: { ...doc.trust_anchors, endorsed_by: "not-array" },
    });
    assert.equal(r.ok, false);
  });

  it("rejects non-did:web in endorsed_by", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest({
      ...doc,
      trust_anchors: { ...doc.trust_anchors, endorsed_by: ["http://example.com"] },
    });
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, /endorsed_by/);
  });

  it("accepts empty endorses and endorsed_by", () => {
    const { doc } = makeSignedManifest({
      trust_anchors: { endorses: [], endorsed_by: [] },
    });
    const r = parseIssuerManifest(doc);
    assert.equal(r.ok, true);
  });

  // --- sig ---

  it("rejects empty sig", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest({ ...doc, sig: "" });
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, /sig/);
  });

  it("rejects non-string sig", () => {
    const { doc } = makeSignedManifest();
    const r = parseIssuerManifest({ ...doc, sig: 42 });
    assert.equal(r.ok, false);
  });

  // --- claim_type format ---

  it("accepts ar.provenance.v1 format", () => {
    const { doc } = makeSignedManifest({
      memberships: [defaultMembership({ claim_types: ["ar.provenance.v1"] })],
    });
    assert.equal(parseIssuerManifest(doc).ok, true);
  });

  it("accepts ar.consent.v1 format", () => {
    const { doc } = makeSignedManifest({
      memberships: [defaultMembership({ family: "acr", claim_types: ["ar.consent.v1", "ar.withdrawal.v1"] })],
    });
    assert.equal(parseIssuerManifest(doc).ok, true);
  });

  it("rejects claim_type without version", () => {
    const { doc } = makeSignedManifest({
      memberships: [defaultMembership({ claim_types: ["ar.provenance"] })],
    });
    assert.equal(parseIssuerManifest(doc).ok, false);
  });

  it("rejects claim_type with uppercase", () => {
    const { doc } = makeSignedManifest({
      memberships: [defaultMembership({ claim_types: ["ar.Provenance.v1"] })],
    });
    assert.equal(parseIssuerManifest(doc).ok, false);
  });
});
