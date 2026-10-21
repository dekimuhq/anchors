import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { verifyIssuerManifest } from "../src/verify.ts";
import {
  makeSignedManifest,
  makeKeyDoc,
  dualFetcher,
  issuerKeyFingerprint,
  rawToSpkiDer,
  toUrlStr,
} from "./fixtures.ts";
import { generateKeypair, signCanonical, base64UrlEncode } from "@dekimuhq/anchors-envelope";

describe("verifyIssuerManifest", () => {
  // --- Happy path with iss_key ---

  it("verifies a valid manifest with explicit iss_key", async () => {
    const { doc, keypair } = makeSignedManifest();
    const keyDoc = makeKeyDoc(keypair);
    const iss_key = issuerKeyFingerprint(keypair.publicKey);
    const fetcher = dualFetcher(doc, keyDoc);

    const r = await verifyIssuerManifest({ doc, fetcher, iss_key });
    assert.equal(r.ok, true);
    if (r.ok) {
      assert.equal(r.outcome, "valid");
      assert.equal(r.warnings.length, 0);
    }
  });

  // --- Happy path without iss_key (first-match) ---

  it("verifies a valid manifest without iss_key (first-match)", async () => {
    const { doc, keypair } = makeSignedManifest();
    const keyDoc = makeKeyDoc(keypair);
    const fetcher = dualFetcher(doc, keyDoc);

    const r = await verifyIssuerManifest({ doc, fetcher });
    assert.equal(r.ok, true);
    if (r.ok) assert.equal(r.outcome, "valid");
  });

  // --- Staleness ---

  it("returns valid_stale when past valid_until", async () => {
    const { doc, keypair } = makeSignedManifest({
      issued_at: "2025-01-01T00:00:00Z",
      valid_until: "2025-03-01T00:00:00Z",
    });
    const keyDoc = makeKeyDoc(keypair);
    const fetcher = dualFetcher(doc, keyDoc);

    const r = await verifyIssuerManifest({
      doc,
      fetcher,
      now: () => new Date("2026-01-01T00:00:00Z"),
    });
    assert.equal(r.ok, true);
    if (r.ok) {
      assert.equal(r.outcome, "valid_stale");
      assert.equal(r.warnings.length, 1);
      assert.match(r.warnings[0]!, /issuer_manifest_stale/);
    }
  });

  it("returns valid when within valid_until", async () => {
    const { doc, keypair } = makeSignedManifest({
      issued_at: "2026-06-01T00:00:00Z",
      valid_until: "2026-08-01T00:00:00Z",
    });
    const keyDoc = makeKeyDoc(keypair);
    const fetcher = dualFetcher(doc, keyDoc);

    const r = await verifyIssuerManifest({
      doc,
      fetcher,
      now: () => new Date("2026-07-01T00:00:00Z"),
    });
    assert.equal(r.ok, true);
    if (r.ok) assert.equal(r.outcome, "valid");
  });

  // --- Signature failures ---

  it("rejects tampered doc (first-match path)", async () => {
    const { doc, keypair } = makeSignedManifest();
    const keyDoc = makeKeyDoc(keypair);
    const fetcher = dualFetcher(doc, keyDoc);

    // Tamper with the doc after signing — signature won't match any key
    const tampered = { ...doc, version: 999 };
    const r = await verifyIssuerManifest({ doc: tampered, fetcher });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.outcome, "signature_invalid");
  });

  it("rejects tampered doc (iss_key path)", async () => {
    const { doc, keypair } = makeSignedManifest();
    const keyDoc = makeKeyDoc(keypair);
    const iss_key = issuerKeyFingerprint(keypair.publicKey);
    const fetcher = dualFetcher(doc, keyDoc);

    const tampered = { ...doc, version: 999 };
    const r = await verifyIssuerManifest({ doc: tampered, fetcher, iss_key });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.outcome, "signature_invalid");
  });

  it("rejects doc signed by wrong key (first-match path)", async () => {
    const { doc } = makeSignedManifest();
    const otherKeypair = generateKeypair("other-kid");
    const keyDoc = makeKeyDoc(otherKeypair); // key doc has different key than the signer
    const fetcher = dualFetcher(doc, keyDoc);

    const r = await verifyIssuerManifest({ doc, fetcher });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.outcome, "signature_invalid");
  });

  it("rejects doc signed by wrong key (iss_key path resolves wrong key)", async () => {
    const { doc } = makeSignedManifest();
    const otherKeypair = generateKeypair("other-kid");
    const keyDoc = makeKeyDoc(otherKeypair);
    const iss_key = issuerKeyFingerprint(otherKeypair.publicKey);
    const fetcher = dualFetcher(doc, keyDoc);

    // iss_key resolves the wrong key — sig will fail
    const r = await verifyIssuerManifest({ doc, fetcher, iss_key });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.outcome, "signature_invalid");
  });

  it("rejects malformed sig (not base64url) via first-match", async () => {
    const { doc, keypair } = makeSignedManifest();
    const keyDoc = makeKeyDoc(keypair);
    const fetcher = dualFetcher(doc, keyDoc);

    const badDoc = { ...doc, sig: "!!!not-base64!!!" };
    const r = await verifyIssuerManifest({ doc: badDoc, fetcher });
    assert.equal(r.ok, false);
    // base64url decode throws → signature_invalid from first-match path
    if (!r.ok) assert.equal(r.outcome, "signature_invalid");
  });

  // --- Key resolution failures ---

  it("rejects when key doc fetch fails (with iss_key)", async () => {
    const { doc } = makeSignedManifest();
    const iss_key = "ed25519:fake-key";
    const fetcher = async () => new Response("Not found", { status: 404 });

    const r = await verifyIssuerManifest({ doc, fetcher, iss_key });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.outcome, "key_resolution_failed");
  });

  it("rejects when key doc fetch fails (first-match path)", async () => {
    const { doc } = makeSignedManifest();
    const fetcher = async () => new Response("Not found", { status: 404 });

    const r = await verifyIssuerManifest({ doc, fetcher });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.outcome, "key_resolution_failed");
  });

  it("rejects when key doc is malformed JSON", async () => {
    const { doc } = makeSignedManifest();
    const fetcher = async (url: string | URL | Request) => {
      if (toUrlStr(url).includes("dekimu-keys")) {
        return new Response("not-json", { status: 200 });
      }
      return new Response(JSON.stringify(doc), { status: 200 });
    };

    const r = await verifyIssuerManifest({ doc, fetcher });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.outcome, "key_resolution_failed");
  });

  it("rejects when key doc has invalid structure", async () => {
    const { doc } = makeSignedManifest();
    const fetcher = async (url: string | URL | Request) => {
      if (toUrlStr(url).includes("dekimu-keys")) {
        return new Response(JSON.stringify({ version: 1, keys: "not-array" }), { status: 200 });
      }
      return new Response(JSON.stringify(doc), { status: 200 });
    };

    const r = await verifyIssuerManifest({ doc, fetcher });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.outcome, "key_resolution_failed");
  });

  // --- iss consistency ---

  it("rejects iss that does not start with did:web:", async () => {
    const keypair = generateKeypair("test");
    const unsigned = {
      kind: "ar.issuer_manifest.v1" as const,
      version: 1,
      issued_at: "2026-06-01T00:00:00Z",
      valid_until: "2026-08-01T00:00:00Z",
      iss: "did:key:z6Mk...",
      operator: { name: "Test", jurisdiction: "NL", contact_uri: "mailto:x@y.com" },
      key_doc_uri: "https://test.example/.well-known/dekimu-keys.json",
      memberships: [{ family: "apr", claim_types: ["ar.provenance.v1"], profiles: [], spec_versions: ["v1"] }],
      trust_anchors: { endorses: [], endorsed_by: [] },
      sig: null,
    };
    const sig = base64UrlEncode(signCanonical(unsigned, keypair.privateKey));
    const doc = { ...unsigned, sig };

    // Force it past schema validation (schema accepts did:web only, so this should fail at schema)
    const r = await verifyIssuerManifest({ doc: doc as any });
    assert.equal(r.ok, false);
  });

  // --- Schema re-check ---

  it("rejects schema-invalid doc passed directly", async () => {
    const r = await verifyIssuerManifest({ doc: { kind: "wrong" } as any });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.outcome, "schema_invalid");
  });

  // --- Key doc origin mismatch (first-match path) ---

  it("rejects when key_doc_uri origin does not match iss", async () => {
    const { doc, keypair } = makeSignedManifest({
      iss: "did:web:test-issuer.example",
      key_doc_uri: "https://evil.example/.well-known/dekimu-keys.json",
    });
    const keyDoc = makeKeyDoc(keypair);
    // Serve key doc from wrong origin
    const fetcher = async (url: string | URL | Request) => {
      if (toUrlStr(url).includes("evil.example")) {
        return new Response(JSON.stringify(keyDoc), { status: 200 });
      }
      return new Response("Not found", { status: 404 });
    };

    const r = await verifyIssuerManifest({ doc, fetcher });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.outcome, "iss_consistency_failed");
  });

  // --- Multiple keys in key doc ---

  it("finds the correct key among multiple", async () => {
    const correctKeypair = generateKeypair("correct");
    const wrongKeypair = generateKeypair("wrong");

    const { doc } = makeSignedManifest({ keypair: correctKeypair });
    const keyDoc = {
      version: 1,
      keys: [
        {
          iss_key: issuerKeyFingerprint(wrongKeypair.publicKey),
          public_key_der_base64: Buffer.from(rawToSpkiDer(wrongKeypair.publicKey)).toString("base64"),
          valid_from: "2026-01-01T00:00:00Z",
          valid_until: null,
        },
        {
          iss_key: issuerKeyFingerprint(correctKeypair.publicKey),
          public_key_der_base64: Buffer.from(rawToSpkiDer(correctKeypair.publicKey)).toString("base64"),
          valid_from: "2026-01-01T00:00:00Z",
          valid_until: null,
        },
      ],
    };
    const fetcher = dualFetcher(doc, keyDoc);

    const r = await verifyIssuerManifest({ doc, fetcher });
    assert.equal(r.ok, true);
  });

  it("fails when no key matches among multiple", async () => {
    const correctKeypair = generateKeypair("correct");
    const wrongKeypair1 = generateKeypair("wrong1");
    const wrongKeypair2 = generateKeypair("wrong2");

    const { doc } = makeSignedManifest({ keypair: correctKeypair });
    const keyDoc = {
      version: 1,
      keys: [
        {
          iss_key: issuerKeyFingerprint(wrongKeypair1.publicKey),
          public_key_der_base64: Buffer.from(rawToSpkiDer(wrongKeypair1.publicKey)).toString("base64"),
          valid_from: "2026-01-01T00:00:00Z",
          valid_until: null,
        },
        {
          iss_key: issuerKeyFingerprint(wrongKeypair2.publicKey),
          public_key_der_base64: Buffer.from(rawToSpkiDer(wrongKeypair2.publicKey)).toString("base64"),
          valid_from: "2026-01-01T00:00:00Z",
          valid_until: null,
        },
      ],
    };
    const fetcher = dualFetcher(doc, keyDoc);

    const r = await verifyIssuerManifest({ doc, fetcher });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.outcome, "signature_invalid");
  });

  // --- Empty key doc ---

  it("fails when key doc has no keys", async () => {
    const { doc } = makeSignedManifest();
    const keyDoc = { version: 1, keys: [] };
    const fetcher = dualFetcher(doc, keyDoc);

    const r = await verifyIssuerManifest({ doc, fetcher });
    assert.equal(r.ok, false);
  });

  // --- Doc fields preserved on success ---

  it("returns the parsed doc on success", async () => {
    const { doc, keypair } = makeSignedManifest({
      iss: "did:web:test-issuer.example",
      memberships: [
        { family: "apr", claim_types: ["ar.provenance.v1"], profiles: [], spec_versions: ["v1"] },
        { family: "acr", claim_types: ["ar.consent.v1"], profiles: ["acr.gdpr.art7"], spec_versions: ["v1"] },
      ],
    });
    const keyDoc = makeKeyDoc(keypair);
    const fetcher = dualFetcher(doc, keyDoc);

    const r = await verifyIssuerManifest({ doc, fetcher });
    assert.equal(r.ok, true);
    if (r.ok) {
      assert.equal(r.doc.memberships.length, 2);
      assert.equal(r.doc.operator.name, "Test Issuer BV");
    }
  });
});
