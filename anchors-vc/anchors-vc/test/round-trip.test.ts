/**
 * Carrier round-trip + field-lift tests (design doc §"Acceptance round-trip").
 *
 * These exercise the pure carrier logic (no crypto, no envelope runtime import —
 * the Envelope type is erased by --experimental-strip-types). The crypto-level
 * acceptance test — "the existing family verifier still returns valid on
 * extractEnvelope(vc)" — is added once the workspace is installed (Node ≥24.6 +
 * authed registry); see the handoff item.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { Envelope } from "@dekimuhq/anchors-envelope";
import {
  toVerifiableCredential,
  extractEnvelope,
  isAnchoredReceiptCredential,
  isSubjectless,
  AnchorsVcError,
} from "../src/index.ts";

function dataSubjectEnvelope(): Envelope {
  return {
    v: 2,
    id: "01J0000000000000000000000A",
    iat: "2026-06-30T12:00:00Z",
    iat_ms: Date.parse("2026-06-30T12:00:00Z"),
    claim_type: "ar.consent.v1",
    iss: "did:web:issuer.example",
    iss_key: "ed25519:AAAA",
    subject: "did:web:subject.example",
    exp: "2027-06-30T12:00:00Z",
    prev: null,
    policy_uri: null,
    policy_hash: null,
    policy_version: null,
    tsa: null,
    credentialStatus: {
      id: "https://verify.dekimu.com/status/acr/v1#7",
      type: "StatusList2021Entry",
      statusPurpose: "revocation",
      statusListIndex: "7",
      statusListCredential: "https://verify.dekimu.com/status/acr/v1",
    },
    anchor: {
      log: "https://verify.dekimu.com/acr/v1",
      leaf_index: 3,
      inclusion_proof: ["sha256:deadbeef"],
      tree_head_root: "sha256:cafef00d",
      tree_size: 8,
      log_time: "2026-06-30T12:00:01Z",
    },
    sig: "ZmFrZXNpZw",
    countersig: null,
    body: { purpose: "marketing" },
  } as Envelope;
}

function subjectlessActEnvelope(): Envelope {
  const e = dataSubjectEnvelope();
  // On the wire, null-subject families carry literal `subject: null` (verified
  // vs FAMILY-CONSISTENCY §3 + checkActionSubjectPresence). The Envelope TS type
  // says `string`, so cast through unknown.
  return {
    ...e,
    claim_type: "ar.action.v1",
    subject: null,
    exp: null,
  } as unknown as Envelope;
}

test("carrier round-trip is byte-equal (data-subject)", () => {
  const e = dataSubjectEnvelope();
  const vc = toVerifiableCredential(e);
  assert.deepEqual(extractEnvelope(vc), e);
});

test("carrier round-trip is byte-equal (subjectless act)", () => {
  const e = subjectlessActEnvelope();
  const vc = toVerifiableCredential(e);
  assert.deepEqual(extractEnvelope(vc), e);
});

test("lifts issuer / validFrom / validUntil from the envelope", () => {
  const e = dataSubjectEnvelope();
  const vc = toVerifiableCredential(e);
  assert.equal(vc.issuer, e.iss);
  assert.equal(vc.validFrom, e.iat);
  assert.equal(vc.validUntil, e.exp);
  assert.equal(vc.type[0], "VerifiableCredential");
});

test("lifts credentialStatus 1:1 (Q4 parity)", () => {
  const e = dataSubjectEnvelope();
  const vc = toVerifiableCredential(e);
  assert.deepEqual(vc.credentialStatus, e.credentialStatus);
});

test("data-subject framing uses credentialSubject.id", () => {
  const vc = toVerifiableCredential(dataSubjectEnvelope());
  assert.equal(
    (vc.credentialSubject as { id: string }).id,
    "did:web:subject.example",
  );
});

test("subjectless framing drops id, names the act (Q4)", () => {
  const e = subjectlessActEnvelope();
  const vc = toVerifiableCredential(e);
  assert.ok(!("id" in vc.credentialSubject));
  assert.equal((vc.credentialSubject as { receipt: string }).receipt, e.id);
  assert.equal((vc.credentialSubject as { claimType: string }).claimType, "ar.action.v1");
});

test("perpetual receipt (exp null) omits validUntil", () => {
  const vc = toVerifiableCredential(subjectlessActEnvelope());
  assert.ok(!("validUntil" in vc));
});

test("anchor descriptor surfaced for legibility, not as proof (Q3)", () => {
  const vc = toVerifiableCredential(dataSubjectEnvelope());
  assert.equal(vc.evidence[0].anchorLog, "https://verify.dekimu.com/acr/v1");
  assert.equal(vc.evidence[0].treeHeadRoot, "sha256:cafef00d");
  assert.ok(!("proof" in vc)); // no wrapper proof unless explicitly attached
});

test("isSubjectless is true iff envelope subject is null (Q4)", () => {
  assert.equal(isSubjectless(null), true);
  assert.equal(isSubjectless("did:web:subject.example"), false);
  // an empty string is a (degenerate) subject, NOT null — not subjectless
  assert.equal(isSubjectless(""), false);
});

test("isAnchoredReceiptCredential type-guards the carrier", () => {
  const vc = toVerifiableCredential(dataSubjectEnvelope());
  assert.equal(isAnchoredReceiptCredential(vc), true);
  assert.equal(isAnchoredReceiptCredential({ type: ["VerifiableCredential"] }), false);
  assert.equal(isAnchoredReceiptCredential(null), false);
});

test("extractEnvelope throws on a malformed carrier", () => {
  const bad = { type: ["VerifiableCredential", "AnchoredReceiptCredential"], evidence: [{ type: ["AnchoredReceipt"] }] };
  assert.throws(() => extractEnvelope(bad as never), AnchorsVcError);
});
