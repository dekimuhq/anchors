import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { verifyTrustedIssuersList } from "../src/index.ts";
import {
  makeSignedDoc,
  makeMlDsaSignedDoc,
  publisherKeyFingerprint,
  rawToSpkiDer,
} from "./fixtures.ts";
import { generateKeypair, MLDSA65_PUBKEY_BYTES } from "@dekimuhq/anchors-envelope";

const IN_WINDOW = () => new Date("2026-05-20T00:00:00Z");

describe("verifyTrustedIssuersList — happy paths", () => {
  it("verifies via bootstrap pin only (no resolver)", async () => {
    const { doc, spki_der } = makeSignedDoc();
    const res = await verifyTrustedIssuersList({
      doc,
      bootstrap: { publisher_key: doc.publisher_key, spki_der },
      now: IN_WINDOW,
    });
    assert.equal(res.ok, true);
    if (res.ok) assert.equal(res.outcome, "valid");
  });

  it("verifies via resolver only (no bootstrap)", async () => {
    const { doc, spki_der } = makeSignedDoc();
    const res = await verifyTrustedIssuersList({
      doc,
      resolver: async () => spki_der,
      now: IN_WINDOW,
    });
    assert.equal(res.ok, true);
  });

  it("bootstrap wins when both present and match", async () => {
    const { doc, spki_der } = makeSignedDoc();
    let resolverCalled = false;
    const res = await verifyTrustedIssuersList({
      doc,
      bootstrap: { publisher_key: doc.publisher_key, spki_der },
      resolver: async () => {
        resolverCalled = true;
        return new Uint8Array(0);
      },
      now: IN_WINDOW,
    });
    assert.equal(res.ok, true);
    assert.equal(resolverCalled, false);
  });

  it("verifies when previous_sha256 is set to a hex string", async () => {
    const { doc, spki_der } = makeSignedDoc({
      previous_sha256: "sha256:" + "b".repeat(64),
    });
    const res = await verifyTrustedIssuersList({
      doc,
      bootstrap: { publisher_key: doc.publisher_key, spki_der },
      now: IN_WINDOW,
    });
    assert.equal(res.ok, true);
  });
});

describe("verifyTrustedIssuersList — resolver/bootstrap failure paths", () => {
  it("resolver throws → resolver_failed", async () => {
    const { doc } = makeSignedDoc();
    const res = await verifyTrustedIssuersList({
      doc,
      resolver: async () => {
        throw new Error("did:web doc not found");
      },
      now: IN_WINDOW,
    });
    assert.equal(res.ok, false);
    if (!res.ok) assert.equal(res.outcome, "resolver_failed");
  });

  it("no resolver, no bootstrap → bootstrap_required_but_absent", async () => {
    const { doc } = makeSignedDoc();
    const res = await verifyTrustedIssuersList({
      doc,
      now: IN_WINDOW,
    });
    assert.equal(res.ok, false);
    if (!res.ok) assert.equal(res.outcome, "bootstrap_required_but_absent");
  });

  it("bootstrap key mismatch + no resolver → publisher_key_mismatch", async () => {
    const { doc } = makeSignedDoc();
    const wrongKp = generateKeypair("other-kid");
    const wrongFingerprint = publisherKeyFingerprint(wrongKp.publicKey);
    const wrongSpki = rawToSpkiDer(wrongKp.publicKey);
    const res = await verifyTrustedIssuersList({
      doc,
      bootstrap: { publisher_key: wrongFingerprint, spki_der: wrongSpki },
      now: IN_WINDOW,
    });
    assert.equal(res.ok, false);
    if (!res.ok) assert.equal(res.outcome, "publisher_key_mismatch");
  });

  it("bootstrap key mismatch + resolver throws → publisher_key_mismatch", async () => {
    const { doc } = makeSignedDoc();
    const wrongKp = generateKeypair("other-kid");
    const res = await verifyTrustedIssuersList({
      doc,
      bootstrap: {
        publisher_key: publisherKeyFingerprint(wrongKp.publicKey),
        spki_der: rawToSpkiDer(wrongKp.publicKey),
      },
      resolver: async () => {
        throw new Error("not found");
      },
      now: IN_WINDOW,
    });
    assert.equal(res.ok, false);
    if (!res.ok) assert.equal(res.outcome, "publisher_key_mismatch");
  });
});

describe("verifyTrustedIssuersList — window check", () => {
  it("rejects when now < issued_at", async () => {
    const { doc, spki_der } = makeSignedDoc();
    const res = await verifyTrustedIssuersList({
      doc,
      bootstrap: { publisher_key: doc.publisher_key, spki_der },
      now: () => new Date("2026-04-01T00:00:00Z"),
    });
    assert.equal(res.ok, false);
    if (!res.ok) assert.equal(res.outcome, "window_invalid");
  });

  it("rejects when now > valid_until", async () => {
    const { doc, spki_der } = makeSignedDoc();
    const res = await verifyTrustedIssuersList({
      doc,
      bootstrap: { publisher_key: doc.publisher_key, spki_der },
      now: () => new Date("2026-07-01T00:00:00Z"),
    });
    assert.equal(res.ok, false);
    if (!res.ok) assert.equal(res.outcome, "window_invalid");
  });
});

describe("verifyTrustedIssuersList — signature tampering", () => {
  it("detects flipped byte in sig", async () => {
    const { doc, spki_der } = makeSignedDoc();
    const decoded = Buffer.from(doc.sig, "base64url");
    decoded[0] = (decoded[0] ?? 0) ^ 0x01;
    const tampered = { ...doc, sig: decoded.toString("base64url") };
    const res = await verifyTrustedIssuersList({
      doc: tampered,
      bootstrap: { publisher_key: doc.publisher_key, spki_der },
      now: IN_WINDOW,
    });
    assert.equal(res.ok, false);
    if (!res.ok) assert.equal(res.outcome, "signature_invalid");
  });

  it("detects tampered issuers[0].iss after signing", async () => {
    const { doc, spki_der } = makeSignedDoc();
    const first = doc.issuers[0];
    if (!first) throw new Error("fixture missing issuer");
    const tampered = {
      ...doc,
      issuers: [{ ...first, iss: "did:web:attacker.example" }],
    };
    const res = await verifyTrustedIssuersList({
      doc: tampered,
      bootstrap: { publisher_key: doc.publisher_key, spki_der },
      now: IN_WINDOW,
    });
    assert.equal(res.ok, false);
    if (!res.ok) assert.equal(res.outcome, "signature_invalid");
  });

  it("rejects sig that is not base64url", async () => {
    const { doc, spki_der } = makeSignedDoc();
    const res = await verifyTrustedIssuersList({
      doc: { ...doc, sig: "AAAA====" }, // base64 with padding, invalid for base64url-decoder
      bootstrap: { publisher_key: doc.publisher_key, spki_der },
      now: IN_WINDOW,
    });
    assert.equal(res.ok, false);
    if (!res.ok) {
      assert.ok(
        res.outcome === "signature_invalid" || res.outcome === "schema_invalid",
        `expected signature_invalid or schema_invalid, got ${res.outcome}`,
      );
    }
  });
});

describe("verifyTrustedIssuersList — defensive schema check", () => {
  it("rejects malformed doc at verify entry → schema_invalid", async () => {
    const { doc, spki_der } = makeSignedDoc();
    const bad = { ...doc, kind: "ar.wrong.v1" } as unknown as typeof doc;
    const res = await verifyTrustedIssuersList({
      doc: bad,
      bootstrap: { publisher_key: doc.publisher_key, spki_der },
      now: IN_WINDOW,
    });
    assert.equal(res.ok, false);
    if (!res.ok) assert.equal(res.outcome, "schema_invalid");
  });
});

describe("verifyTrustedIssuersList — round-trip", () => {
  it("sign with fresh keypair, verify with both bootstrap and resolver", async () => {
    const kp = generateKeypair("rt-kid");
    const { doc, spki_der } = makeSignedDoc({ keypair: kp });

    const viaBootstrap = await verifyTrustedIssuersList({
      doc,
      bootstrap: { publisher_key: doc.publisher_key, spki_der },
      now: IN_WINDOW,
    });
    assert.equal(viaBootstrap.ok, true);

    const viaResolver = await verifyTrustedIssuersList({
      doc,
      resolver: async () => spki_der,
      now: IN_WINDOW,
    });
    assert.equal(viaResolver.ok, true);
  });
});

describe("verifyTrustedIssuersList — publisher-key algorithm fail-closed (v1.3 §L6)", () => {
  it("rejects an UNREGISTERED publisher_key alg at the schema layer (schema_invalid)", async () => {
    // After rollout R2, SUPPORTED_LIST_SIG_ALGS (what Step 4 can verify) equals
    // the registered SIG_ALGS that PUBLISHER_KEY_RE accepts (ed25519 + ml-dsa-65),
    // so the Step-1.5 capability gate is unreachable for a schema-valid doc — an
    // unregistered alg (here slh-dsa-sha2-128s) is rejected one layer earlier, at
    // the schema. The capability gate is retained as forward-safety: if envelope
    // registers a 3rd SIG_ALG before Step 4 grows a verify branch for it, the
    // schema would accept it but the gate would still fail closed
    // (unsupported_publisher_key_alg) rather than mis-verify it.
    const { doc, spki_der } = makeSignedDoc();
    const pqDoc = { ...doc, publisher_key: "slh-dsa-sha2-128s:AAAABBBBCCCCDDDD" };
    const res = await verifyTrustedIssuersList({
      doc: pqDoc,
      bootstrap: { publisher_key: pqDoc.publisher_key, spki_der },
      now: IN_WINDOW,
    });
    assert.equal(res.ok, false);
    if (!res.ok) assert.equal(res.outcome, "schema_invalid");
  });

  it("still verifies an ed25519 publisher_key (no regression)", async () => {
    const { doc, spki_der } = makeSignedDoc();
    const res = await verifyTrustedIssuersList({
      doc,
      bootstrap: { publisher_key: doc.publisher_key, spki_der },
      now: IN_WINDOW,
    });
    assert.equal(res.ok, true);
    if (res.ok) assert.equal(res.outcome, "valid");
  });
});

describe("verifyTrustedIssuersList — ml-dsa-65 list signature (v1.3 rollout R2)", () => {
  it("verifies an ml-dsa-65-signed list via bootstrap pin (raw 1952-byte key)", async () => {
    const { doc, raw_pub } = makeMlDsaSignedDoc();
    assert.equal(raw_pub.length, MLDSA65_PUBKEY_BYTES);
    const res = await verifyTrustedIssuersList({
      doc,
      bootstrap: { publisher_key: doc.publisher_key, spki_der: raw_pub },
      now: IN_WINDOW,
    });
    assert.equal(res.ok, true);
    if (res.ok) assert.equal(res.outcome, "valid");
  });

  it("verifies an ml-dsa-65-signed list via resolver (raw 1952-byte key)", async () => {
    const { doc, raw_pub } = makeMlDsaSignedDoc();
    const res = await verifyTrustedIssuersList({
      doc,
      resolver: async () => raw_pub,
      now: IN_WINDOW,
    });
    assert.equal(res.ok, true);
  });

  it("detects a flipped byte in an ml-dsa-65 list sig → signature_invalid", async () => {
    const { doc, raw_pub } = makeMlDsaSignedDoc();
    const decoded = Buffer.from(doc.sig, "base64url");
    decoded[0] = (decoded[0] ?? 0) ^ 0x01;
    const tampered = { ...doc, sig: decoded.toString("base64url") };
    const res = await verifyTrustedIssuersList({
      doc: tampered,
      bootstrap: { publisher_key: doc.publisher_key, spki_der: raw_pub },
      now: IN_WINDOW,
    });
    assert.equal(res.ok, false);
    if (!res.ok) assert.equal(res.outcome, "signature_invalid");
  });

  it("detects a tampered issuer record in an ml-dsa-65 list → signature_invalid", async () => {
    const { doc, raw_pub } = makeMlDsaSignedDoc();
    const first = doc.issuers[0];
    if (!first) throw new Error("fixture missing issuer");
    const tampered = { ...doc, issuers: [{ ...first, iss: "did:web:attacker.example" }] };
    const res = await verifyTrustedIssuersList({
      doc: tampered,
      bootstrap: { publisher_key: doc.publisher_key, spki_der: raw_pub },
      now: IN_WINDOW,
    });
    assert.equal(res.ok, false);
    if (!res.ok) assert.equal(res.outcome, "signature_invalid");
  });

  it("rejects an ml-dsa-65 key of the wrong length → signature_invalid (not a false pass)", async () => {
    const { doc } = makeMlDsaSignedDoc();
    const res = await verifyTrustedIssuersList({
      doc,
      bootstrap: { publisher_key: doc.publisher_key, spki_der: new Uint8Array(1951) },
      now: IN_WINDOW,
    });
    assert.equal(res.ok, false);
    if (!res.ok) {
      assert.equal(res.outcome, "signature_invalid");
      assert.match(res.reason, /ml-dsa-65 key is 1951 bytes/);
    }
  });

  it("does NOT verify an ml-dsa-65 list against an ed25519 key (cross-alg confusion)", async () => {
    // Resolve a 32-byte ed25519-shaped key for an ml-dsa-65 publisher_key. The
    // length gate rejects it before any verify — a wrong-scheme key can never
    // accidentally satisfy the ml-dsa branch.
    const { doc } = makeMlDsaSignedDoc();
    const ed = generateKeypair("cross-alg");
    const res = await verifyTrustedIssuersList({
      doc,
      bootstrap: { publisher_key: doc.publisher_key, spki_der: rawToSpkiDer(ed.publicKey) },
      now: IN_WINDOW,
    });
    assert.equal(res.ok, false);
    if (!res.ok) assert.equal(res.outcome, "signature_invalid");
  });
});
