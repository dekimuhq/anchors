import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { TrustedIssuersSourceFromList } from "../src/source.ts";
import { makeSignedDoc, defaultIssuerRecord } from "./fixtures.ts";

const NOW = new Date("2026-06-01T00:00:00Z");

describe("TrustedIssuersSourceFromList — empty + single-record", () => {
  it("S1 empty issuers list — all lookups return null", () => {
    const { doc } = makeSignedDoc({ issuers: [] });
    const src = TrustedIssuersSourceFromList(doc);
    assert.equal(src.lookup("did:web:anyone.example", NOW), null);
    assert.equal(src.lookup("did:web:other.example", NOW), null);
  });

  it("S2 single active issuer — lookup returns record; unknown returns null", () => {
    const rec = defaultIssuerRecord({ iss: "did:web:active.example" });
    const { doc } = makeSignedDoc({ issuers: [rec] });
    const src = TrustedIssuersSourceFromList(doc);
    assert.deepEqual(src.lookup("did:web:active.example", NOW), rec);
    assert.equal(src.lookup("did:web:unknown.example", NOW), null);
  });

  it("S3 single revoked issuer — lookup returns record with revoked_at set", () => {
    const rec = defaultIssuerRecord({
      iss: "did:web:gone.example",
      revoked_at: "2026-05-15T00:00:00Z",
    });
    const { doc } = makeSignedDoc({ issuers: [rec] });
    const src = TrustedIssuersSourceFromList(doc);
    const got = src.lookup("did:web:gone.example", NOW);
    assert.ok(got, "expected non-null record");
    assert.equal(got.revoked_at, "2026-05-15T00:00:00Z");
  });
});

describe("TrustedIssuersSourceFromList — multi-issuer + ordering", () => {
  it("S4 two issuers (active + revoked) — both lookups return the right record", () => {
    const active = defaultIssuerRecord({ iss: "did:web:a.example" });
    const revoked = defaultIssuerRecord({
      iss: "did:web:b.example",
      revoked_at: "2026-05-10T00:00:00Z",
    });
    const { doc } = makeSignedDoc({ issuers: [active, revoked] });
    const src = TrustedIssuersSourceFromList(doc);
    assert.deepEqual(src.lookup("did:web:a.example", NOW), active);
    assert.deepEqual(src.lookup("did:web:b.example", NOW), revoked);
  });

  it("S5 duplicate iss in list — last-wins via Map (documented governance bug)", () => {
    const first = defaultIssuerRecord({
      iss: "did:web:dup.example",
      added_at: "2026-05-01T00:00:00Z",
      notes: "first entry",
    });
    const second = defaultIssuerRecord({
      iss: "did:web:dup.example",
      added_at: "2026-05-10T00:00:00Z",
      notes: "second entry — last-wins",
    });
    const { doc } = makeSignedDoc({ issuers: [first, second] });
    const src = TrustedIssuersSourceFromList(doc);
    const got = src.lookup("did:web:dup.example", NOW);
    assert.ok(got);
    assert.equal(got.notes, "second entry — last-wins");
  });

  it("S6 case-sensitivity — did:web:Foo.com ≠ did:web:foo.com", () => {
    const rec = defaultIssuerRecord({ iss: "did:web:Foo.com" });
    const { doc } = makeSignedDoc({ issuers: [rec] });
    const src = TrustedIssuersSourceFromList(doc);
    assert.deepEqual(src.lookup("did:web:Foo.com", NOW), rec);
    assert.equal(src.lookup("did:web:foo.com", NOW), null);
  });
});

describe("TrustedIssuersSourceFromList — invocation semantics", () => {
  it("S7 lookup ignores now() — passing any Date does not throw", () => {
    const rec = defaultIssuerRecord({ iss: "did:web:a.example" });
    const { doc } = makeSignedDoc({ issuers: [rec] });
    const src = TrustedIssuersSourceFromList(doc);
    assert.doesNotThrow(() => src.lookup("did:web:a.example", new Date(0)));
    assert.doesNotThrow(() =>
      src.lookup("did:web:a.example", new Date("3000-01-01T00:00:00Z")),
    );
  });

  it("S8 Map identity preserved across multiple lookup calls", () => {
    const rec = defaultIssuerRecord({ iss: "did:web:stable.example" });
    const { doc } = makeSignedDoc({ issuers: [rec] });
    const src = TrustedIssuersSourceFromList(doc);
    const first = src.lookup("did:web:stable.example", NOW);
    const second = src.lookup("did:web:stable.example", NOW);
    assert.equal(first, second, "expected referential equality (same Map entry)");
  });

  it("S9 profile-pinned issuer round-trips profiles_pinned correctly", () => {
    const rec = defaultIssuerRecord({
      iss: "did:web:pinned.example",
      profiles_pinned: { "ar.consent.v1": ["dekimu-acr-eu-1.0"] },
    });
    const { doc } = makeSignedDoc({ issuers: [rec] });
    const src = TrustedIssuersSourceFromList(doc);
    const got = src.lookup("did:web:pinned.example", NOW);
    assert.ok(got);
    assert.deepEqual(got.profiles_pinned, {
      "ar.consent.v1": ["dekimu-acr-eu-1.0"],
    });
  });

  it("S10 records with notes round-trip notes through", () => {
    const rec = defaultIssuerRecord({
      iss: "did:web:noted.example",
      notes: "added via key ceremony — see decision 2026-0X-XX",
    });
    const { doc } = makeSignedDoc({ issuers: [rec] });
    const src = TrustedIssuersSourceFromList(doc);
    const got = src.lookup("did:web:noted.example", NOW);
    assert.ok(got);
    assert.equal(
      got.notes,
      "added via key ceremony — see decision 2026-0X-XX",
    );
  });
});
