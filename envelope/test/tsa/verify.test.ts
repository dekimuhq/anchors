/**
 * Tests for envelope/src/tsa/verify.ts — Phase B Task 10.
 *
 * Uses the bundled FreeTSA fixture (freetsa-sample.tsr + freetsa-sample.imprint).
 * The fixture genTime is 2026-05-17T09:06:45Z — tests that need a valid
 * reference time use the self-calibrating pattern: parse genTime from the
 * fixture, use it as referenceTime with a short tolerance.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { parseTimeStampResp } from "../../src/tsa/response.ts";
import { loadTrustAnchors, defaultTrustAnchorPath } from "../../src/tsa/anchors.ts";
import type { TrustAnchor } from "../../src/tsa/anchors.ts";
import { verifyTsa } from "../../src/tsa/verify.ts";

// ── Fixture setup ─────────────────────────────────────────────────────────────

const tsr = new Uint8Array(readFileSync("test/tsa/fixtures/freetsa-sample.tsr"));
const imprint = new Uint8Array(readFileSync("test/tsa/fixtures/freetsa-sample.imprint"));
const anchors = loadTrustAnchors([defaultTrustAnchorPath()]);

// Self-calibrate: derive referenceTime from the fixture's genTime
const parsed = parseTimeStampResp(tsr);
if (!parsed.granted) throw new Error("fixture setup: status not granted");
const refTime = new Date(parsed.tstInfo.genTime);

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("verifyTsa", () => {
  it("accepts the bundled FreeTSA response against the bundled trust anchor", () => {
    const r = verifyTsa(tsr, imprint, {
      anchors,
      driftToleranceSec: 300,
      referenceTime: refTime,
    });
    assert.equal(r.verified, true, `expected verified=true, got reason=${r.reason}`);
    assert.equal(r.reason, "tsa_verified");
    assert.equal(typeof r.anchorName, "string");
    assert.equal(typeof r.genTime, "string");
    assert.equal(r.listed, false); // FreeTSA is not EUTL-listed
    // I1 — policy_oid populated on happy path. FreeTSA fixture uses 1.2.3.4.1.
    assert.equal(r.policy_oid, "1.2.3.4.1");
  });

  it("populates policy_oid on failure paths past granted (e.g. tsa_imprint_mismatch)", () => {
    const wrongImprint = new Uint8Array(32).fill(0xab);
    const r = verifyTsa(tsr, wrongImprint, {
      anchors,
      driftToleranceSec: 300,
      referenceTime: refTime,
    });
    assert.equal(r.verified, false);
    assert.equal(r.reason, "tsa_imprint_mismatch");
    // I1 — even on failure (imprint mismatch) we surface the parsed policy OID.
    assert.equal(r.policy_oid, "1.2.3.4.1");
  });

  it("rejects when imprint does not match", () => {
    const wrongImprint = new Uint8Array(32).fill(0xab);
    const r = verifyTsa(tsr, wrongImprint, {
      anchors,
      driftToleranceSec: 300,
      referenceTime: refTime,
    });
    assert.equal(r.verified, false);
    assert.equal(r.reason, "tsa_imprint_mismatch");
  });

  it("rejects when drift exceeds tolerance", () => {
    // Use refTime + 1 hour offset so drift = 3600s, tolerance = 60s.
    // The anchor is still valid at this referenceTime (valid_until 2041).
    const slightlyOffTime = new Date(refTime.getTime() + 3600 * 1000);
    const r = verifyTsa(tsr, imprint, {
      anchors,
      driftToleranceSec: 60,
      referenceTime: slightlyOffTime,
    });
    assert.equal(r.verified, false);
    assert.equal(r.reason, "tsa_drift_exceeded");
    assert.equal(typeof r.genTime, "string");
  });

  it("rejects when no matching trust anchor is provided", () => {
    const r = verifyTsa(tsr, imprint, {
      anchors: [],
      driftToleranceSec: 300,
      referenceTime: refTime,
    });
    assert.equal(r.verified, false);
    assert.equal(r.reason, "tsa_unrecognised_anchor");
  });

  it("rejects when anchor is expired relative to referenceTime", () => {
    // Clone the anchor with a valid_until in the past
    const expiredAnchor = { ...anchors[0]!, valid_until: "2000-01-01T00:00:00Z" };
    const r = verifyTsa(tsr, imprint, {
      anchors: [expiredAnchor],
      driftToleranceSec: 365 * 86400, // wide drift so only expiry fires
      referenceTime: refTime,
    });
    assert.equal(r.verified, false);
    assert.equal(r.reason, "tsa_anchor_expired");
  });

  it("rejects anchor missing timeStamping key_usage", () => {
    const wrongUsageAnchor: TrustAnchor = { ...anchors[0]!, key_usage: ["emailProtection"] };
    const r = verifyTsa(tsr, imprint, {
      anchors: [wrongUsageAnchor],
      driftToleranceSec: 300,
      referenceTime: refTime,
    });
    assert.equal(r.verified, false);
    assert.equal(r.reason, "tsa_anchor_not_timestamping");
  });
});

// ── CMS SignerInfo signature (RFC 5652 §5.4/§5.6) ────────────────────────────
//
// These tests mutate a COPY of the fixture through the subarray views the
// parser returns (they share the copy's underlying buffer), then re-verify
// the mutated bytes end-to-end through verifyTsa.

/** Parse a fresh copy of the fixture; returns the copy + parsed views into it. */
function parseFixtureCopy() {
  const copy = tsr.slice();
  const p = parseTimeStampResp(copy);
  if (!p.granted) throw new Error("fixture copy: status not granted");
  return { copy, parsed: p };
}

const verifyOpts = { anchors, driftToleranceSec: 300, referenceTime: refTime };

describe("verifyTsa — CMS SignerInfo signature", () => {
  it("exposes signedAttrs + sid + signatureAlg on the parsed fixture", () => {
    const { parsed: p } = parseFixtureCopy();
    assert.ok(p.signerInfo.signedAttrsDer instanceof Uint8Array);
    assert.equal(p.signerInfo.signedAttrsDer![0], 0xa0); // IMPLICIT [0] tag preserved
    assert.equal(p.signerInfo.sid.kind, "issuerAndSerialNumber");
    assert.equal(typeof p.signerInfo.signatureAlg, "string");
    assert.ok(p.tstInfoDer.length > 0);
  });

  it("rejects a tampered TSTInfo eContent with tsa_signed_attrs_invalid", () => {
    const { copy, parsed: p } = parseFixtureCopy();
    // Flip the LAST byte of the TSTInfo eContent — structurally still valid
    // DER (it sits inside the trailing tsa Name), messageImprint untouched,
    // so only the message-digest signed attribute can catch it.
    p.tstInfoDer[p.tstInfoDer.length - 1]! ^= 0x01;
    const r = verifyTsa(copy, imprint, verifyOpts);
    assert.equal(r.verified, false);
    assert.equal(r.reason, "tsa_signed_attrs_invalid");
  });

  it("rejects a tampered signed attribute with tsa_signed_attrs_invalid", () => {
    const { copy, parsed: p } = parseFixtureCopy();
    // Flip the LAST byte of signedAttrs — inside the message-digest attribute
    // value for the FreeTSA fixture (it is the final signed attribute).
    const sa = p.signerInfo.signedAttrsDer!;
    sa[sa.length - 1]! ^= 0x01;
    const r = verifyTsa(copy, imprint, verifyOpts);
    assert.equal(r.verified, false);
    assert.equal(r.reason, "tsa_signed_attrs_invalid");
  });

  it("rejects a corrupted signature with tsa_cms_signature_invalid", () => {
    const { copy, parsed: p } = parseFixtureCopy();
    // Flip a byte INSIDE an ECDSA INTEGER (offset 5 is r's content), keeping
    // the DER shape of the signature intact.
    p.signerInfo.signature[5]! ^= 0xff;
    const r = verifyTsa(copy, imprint, verifyOpts);
    assert.equal(r.verified, false);
    assert.equal(r.reason, "tsa_cms_signature_invalid");
  });

  it("rejects a well-formed wrong-key signature with tsa_cms_signature_invalid", () => {
    const { copy, parsed: p } = parseFixtureCopy();
    const sigLen = p.signerInfo.signature.length;

    // Reconstruct the exact signed bytes (RFC 5652 §5.4: signedAttrs DER with
    // the [0] IMPLICIT tag replaced by EXPLICIT SET OF 0x31) and sign them
    // with a FRESH P-384 key — same curve + hash as the fixture signer.
    const signedBytes = Uint8Array.from(p.signerInfo.signedAttrsDer!);
    signedBytes[0] = 0x31;

    // ECDSA DER signatures vary in length with r/s leading bytes; re-sign
    // until we get one that fits the fixture's OCTET STRING exactly.
    let wrongSig: Uint8Array | null = null;
    for (let attempt = 0; attempt < 200 && wrongSig === null; attempt++) {
      const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-384" });
      const candidate = cryptoSign("sha512", signedBytes, privateKey);
      if (candidate.length === sigLen) wrongSig = new Uint8Array(candidate);
    }
    assert.ok(wrongSig, "could not produce a same-length wrong-key signature in 200 tries");

    p.signerInfo.signature.set(wrongSig!);
    const r = verifyTsa(copy, imprint, verifyOpts);
    assert.equal(r.verified, false);
    assert.equal(r.reason, "tsa_cms_signature_invalid");
  });

  it("still verifies the untouched fixture after the tamper tests (no shared-state bleed)", () => {
    const r = verifyTsa(tsr, imprint, verifyOpts);
    assert.equal(r.verified, true);
    assert.equal(r.reason, "tsa_verified");
  });
});
