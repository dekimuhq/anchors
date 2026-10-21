/**
 * Integration tests wiring `verifyIssuerKey` from `@dekimuhq/did-web-resolver`
 * against `TrustedIssuersSourceFromList`. Uses fake `fetcher` + a verified
 * fixture list — no real network, no real did:web resolution.
 *
 * Plan §B2 Step 3 — ≥10 cases covering all 5 `IssuerTrustOutcome` values
 * plus boundary cases.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  verifyIssuerKey,
  type KeyDocV1,
} from "@dekimuhq/did-web-resolver";
import { generateKeypair, base64UrlEncode } from "@dekimuhq/anchors-envelope";
import { TrustedIssuersSourceFromList } from "../src/source.ts";
import { makeSignedDoc, defaultIssuerRecord, rawToSpkiDer } from "./fixtures.ts";

const ISS = "did:web:competitor.example";
// Real ed25519 key so the served SPKI matches the `iss_key` fingerprint under
// the did-web-resolver ≥0.4.0 binding (`checkKeyFingerprint`, commit 6315fb9a).
// A placeholder iss_key + zero-key SPKI fails that bind → invalid_key_doc.
const ISS_KP = generateKeypair("competitor-issuer");
const ISS_KEY = `ed25519:${base64UrlEncode(ISS_KP.publicKey)}`;
const SPKI_DER_B64 = Buffer.from(rawToSpkiDer(ISS_KP.publicKey)).toString("base64");
const NOW = () => new Date("2026-06-01T00:00:00Z");

function makeKeyDoc(
  entries: Partial<KeyDocV1["keys"][number]>[],
): KeyDocV1 {
  return {
    version: 1,
    keys: entries.map((e) => ({
      iss_key: e.iss_key ?? ISS_KEY,
      public_key_der_base64: e.public_key_der_base64 ?? SPKI_DER_B64,
      valid_from: e.valid_from ?? "2026-05-17T00:00:00Z",
      valid_until: e.valid_until ?? null,
    })),
  };
}

function fetcherFor(doc: unknown, status = 200): typeof fetch {
  return async () =>
    new Response(JSON.stringify(doc), {
      status,
      headers: { "content-type": "application/json" },
    });
}

describe("integration — verifyIssuerKey × TrustedIssuersSourceFromList — 5 outcomes", () => {
  it("I1 valid_trusted — issuer on list (active), key resolves, signature valid", async () => {
    const { doc } = makeSignedDoc({
      issuers: [defaultIssuerRecord({ iss: ISS })],
    });
    const trustedIssuers = TrustedIssuersSourceFromList(doc);
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeKeyDoc([{}])),
      now: NOW,
      trustedIssuers,
    });
    assert.equal(result.outcome, "valid_trusted");
    if (result.outcome === "valid_trusted") {
      assert.ok(result.matched_record);
      assert.equal(result.matched_record.iss, ISS);
      assert.equal(result.matched_record.revoked_at, null);
      assert.match(result.reason, /^trusted_since:2026-05-01/);
    }
  });

  it("I2 valid_untrusted — issuer NOT on list, key resolves, signature valid", async () => {
    const { doc } = makeSignedDoc({
      issuers: [defaultIssuerRecord({ iss: "did:web:somebody-else.example" })],
    });
    const trustedIssuers = TrustedIssuersSourceFromList(doc);
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeKeyDoc([{}])),
      now: NOW,
      trustedIssuers,
    });
    assert.equal(result.outcome, "valid_untrusted");
    if (result.outcome === "valid_untrusted") {
      assert.equal(result.matched_record, null);
      assert.equal(result.reason, "issuer_not_on_allowlist");
    }
  });

  it("I3 valid_revoked — issuer on list with revoked_at set, now > revoked_at", async () => {
    const { doc } = makeSignedDoc({
      issuers: [
        defaultIssuerRecord({
          iss: ISS,
          revoked_at: "2026-05-28T00:00:00Z",
        }),
      ],
    });
    const trustedIssuers = TrustedIssuersSourceFromList(doc);
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeKeyDoc([{}])),
      now: NOW,
      trustedIssuers,
    });
    assert.equal(result.outcome, "valid_revoked");
    if (result.outcome === "valid_revoked") {
      assert.ok(result.matched_record);
      assert.equal(result.matched_record.revoked_at, "2026-05-28T00:00:00Z");
      assert.match(result.reason, /^revoked_at:2026-05-28/);
    }
  });

  it("I4 invalid_key_doc — resolver throws DidWebResolveError (404)", async () => {
    const { doc } = makeSignedDoc({
      issuers: [defaultIssuerRecord({ iss: ISS })],
    });
    const trustedIssuers = TrustedIssuersSourceFromList(doc);
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor({}, 404),
      now: NOW,
      trustedIssuers,
    });
    assert.equal(result.outcome, "invalid_key_doc");
    if (result.outcome === "invalid_key_doc") {
      assert.equal(result.reason, "non_200");
      assert.equal(result.spki, null);
      assert.equal(result.matched_record, null);
    }
  });

  it("I5 invalid_signature — key resolves but iss_key not in key-doc", async () => {
    const { doc } = makeSignedDoc({
      issuers: [defaultIssuerRecord({ iss: ISS })],
    });
    const trustedIssuers = TrustedIssuersSourceFromList(doc);
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: "ed25519:NOTPRESENT",
      fetcher: fetcherFor(makeKeyDoc([{}])),
      now: NOW,
      trustedIssuers,
    });
    assert.equal(result.outcome, "invalid_signature");
    if (result.outcome === "invalid_signature") {
      assert.equal(result.reason, "no_matching_key");
    }
  });
});

describe("integration — verifyIssuerKey × TrustedIssuersSourceFromList — boundary cases", () => {
  it("I6 revoked but now() < revoked_at → valid_trusted (revocation not yet in effect)", async () => {
    const { doc } = makeSignedDoc({
      issuers: [
        defaultIssuerRecord({
          iss: ISS,
          revoked_at: "2026-07-01T00:00:00Z",
        }),
      ],
    });
    const trustedIssuers = TrustedIssuersSourceFromList(doc);
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeKeyDoc([{}])),
      now: NOW,
      trustedIssuers,
    });
    assert.equal(result.outcome, "valid_trusted");
    if (result.outcome === "valid_trusted") {
      assert.ok(result.matched_record);
      assert.equal(result.matched_record.revoked_at, "2026-07-01T00:00:00Z");
    }
  });

  it("I7 profile-pinned issuer — outcome is valid_trusted; pin survives the round-trip", async () => {
    const { doc } = makeSignedDoc({
      issuers: [
        defaultIssuerRecord({
          iss: ISS,
          profiles_pinned: { "ar.consent.v1": ["dekimu-acr-eu-1.0"] },
        }),
      ],
    });
    const trustedIssuers = TrustedIssuersSourceFromList(doc);
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeKeyDoc([{}])),
      now: NOW,
      trustedIssuers,
    });
    assert.equal(result.outcome, "valid_trusted");
    if (result.outcome === "valid_trusted") {
      assert.ok(result.matched_record);
      assert.deepEqual(result.matched_record.profiles_pinned, {
        "ar.consent.v1": ["dekimu-acr-eu-1.0"],
      });
    }
  });

  it("I8 empty iss_key — resolver returns no_matching_key → invalid_signature", async () => {
    const { doc } = makeSignedDoc({
      issuers: [defaultIssuerRecord({ iss: ISS })],
    });
    const trustedIssuers = TrustedIssuersSourceFromList(doc);
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: "",
      fetcher: fetcherFor(makeKeyDoc([{}])),
      now: NOW,
      trustedIssuers,
    });
    assert.equal(result.outcome, "invalid_signature");
    if (result.outcome === "invalid_signature") {
      assert.equal(result.reason, "no_matching_key");
      assert.equal(result.matched_record, null);
    }
  });

  it("I9 non-did:web issuer scheme — invalid_key_doc/iss_scheme_unsupported (does not consult source)", async () => {
    const { doc } = makeSignedDoc({
      issuers: [defaultIssuerRecord({ iss: ISS })],
    });
    const trustedIssuers = TrustedIssuersSourceFromList(doc);
    const result = await verifyIssuerKey({
      iss: "did:key:z6MkpTHR8VNsBxYAAAAAAA",
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeKeyDoc([{}])),
      now: NOW,
      trustedIssuers,
    });
    assert.equal(result.outcome, "invalid_key_doc");
    if (result.outcome === "invalid_key_doc") {
      assert.equal(result.reason, "iss_scheme_unsupported");
      assert.equal(result.matched_record, null);
    }
  });

  it("I10 multi-issuer list — only the matching iss receives valid_trusted; others are valid_untrusted", async () => {
    const { doc } = makeSignedDoc({
      issuers: [
        defaultIssuerRecord({ iss: ISS }),
        defaultIssuerRecord({ iss: "did:web:another.example" }),
      ],
    });
    const trustedIssuers = TrustedIssuersSourceFromList(doc);

    const matched = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeKeyDoc([{}])),
      now: NOW,
      trustedIssuers,
    });
    assert.equal(matched.outcome, "valid_trusted");

    const stranger = await verifyIssuerKey({
      iss: "did:web:stranger.example",
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeKeyDoc([{}])),
      now: NOW,
      trustedIssuers,
    });
    assert.equal(stranger.outcome, "valid_untrusted");
    if (stranger.outcome === "valid_untrusted") {
      assert.equal(stranger.reason, "issuer_not_on_allowlist");
    }
  });

  it("I11 verifyIssuerKey forwards now() to the source unchanged (source ignores it; outcome unaffected)", async () => {
    const { doc } = makeSignedDoc({
      issuers: [defaultIssuerRecord({ iss: ISS })],
    });
    const trustedIssuers = TrustedIssuersSourceFromList(doc);
    const result = await verifyIssuerKey({
      iss: ISS,
      iss_key: ISS_KEY,
      fetcher: fetcherFor(makeKeyDoc([{}])),
      now: () => new Date("3000-01-01T00:00:00Z"),
      trustedIssuers,
    });
    assert.equal(result.outcome, "valid_trusted");
  });
});
