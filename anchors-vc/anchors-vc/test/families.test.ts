/**
 * Coverage matrix across every active claim_type + status/hybrid/tamper/edge.
 *
 * The carrier is subject-agnostic BY DESIGN: it frames on `subject === null`
 * and never enforces FAMILY-CONSISTENCY §3 (that is the family verifier's job).
 * So the honest per-family coverage is a CONTRACT matrix — for each discriminator,
 * a null-subject envelope frames subjectless and a subject-bearing one frames by
 * id, both byte-equal through the carrier. Driven from the envelope's own
 * CLAIM_TYPES so it can never drift from the registered set.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import type { Envelope } from "@dekimuhq/anchors-envelope";
import { CLAIM_TYPES, encodeRaw } from "@dekimuhq/anchors-envelope";
import {
  toVerifiableCredential,
  extractEnvelope,
  attachWrapperProof,
  verifyWrapperProof,
  publicKeyFromIssKey,
  isAnchoredReceiptCredential,
  AnchorsVcError,
} from "../src/index.ts";

type ClaimType = (typeof CLAIM_TYPES)[number];

function baseEnvelope(claim_type: ClaimType, subject: string | null): Envelope {
  return {
    v: 2,
    id: "01J0000000000000000000000A",
    iat: "2026-06-30T12:00:00Z",
    iat_ms: Date.parse("2026-06-30T12:00:00Z"),
    claim_type,
    iss: "did:web:issuer.example",
    iss_key: "ed25519:AAAA",
    subject,
    exp: null,
    prev: null,
    policy_uri: null,
    policy_hash: null,
    policy_version: null,
    tsa: null,
    credentialStatus: null,
    anchor: {
      log: "https://verify.dekimu.com/x/v1",
      leaf_index: 0,
      inclusion_proof: [],
      tree_head_root: "sha256:00",
      tree_size: 1,
      log_time: "2026-06-30T12:00:01Z",
    },
    sig: "ZmFrZQ",
    countersig: null,
    body: { k: "v" },
  } as unknown as Envelope;
}

// ── Per-claim-type contract matrix (2 assertions × every discriminator) ──────────
for (const ct of CLAIM_TYPES) {
  test(`${ct}: null-subject envelope frames subjectless + round-trips byte-equal`, () => {
    const e = baseEnvelope(ct, null);
    const vc = toVerifiableCredential(e);
    assert.ok(!("id" in vc.credentialSubject));
    assert.equal((vc.credentialSubject as { claimType: string }).claimType, ct);
    assert.deepEqual(extractEnvelope(vc), e);
  });

  test(`${ct}: subject-bearing envelope frames by id + round-trips byte-equal`, () => {
    const subject = `sha256:${"a".repeat(64)}`;
    const e = baseEnvelope(ct, subject);
    const vc = toVerifiableCredential(e);
    assert.equal((vc.credentialSubject as { id: string }).id, subject);
    assert.deepEqual(extractEnvelope(vc), e);
  });
}

// ── credentialStatus matrix (Q4 parity) ──────────────────────────────────────────
const REVOCATION = {
  id: "https://verify.dekimu.com/status/x/v1#1",
  type: "StatusList2021Entry" as const,
  statusPurpose: "revocation" as const,
  statusListIndex: "1",
  statusListCredential: "https://verify.dekimu.com/status/x/v1",
};
const SUSPENSION = {
  id: "https://verify.dekimu.com/status/x/v1#2",
  type: "StatusList2021Entry" as const,
  statusPurpose: "suspension" as const,
  statusListIndex: "2",
  statusListCredential: "https://verify.dekimu.com/status/x/v1",
};

test("status: revocation-only lifts a single credentialStatus", () => {
  const e = { ...baseEnvelope("ar.consent.v1", "sha256:x"), credentialStatus: REVOCATION } as Envelope;
  assert.deepEqual(toVerifiableCredential(e).credentialStatus, REVOCATION);
});

test("status: suspension-only lifts a single credentialStatus", () => {
  const e = { ...baseEnvelope("ar.consent.v1", "sha256:x"), suspensionStatus: SUSPENSION } as unknown as Envelope;
  assert.deepEqual(toVerifiableCredential(e).credentialStatus, SUSPENSION);
});

test("status: both revocation + suspension lift as an array (rev first)", () => {
  const e = {
    ...baseEnvelope("ar.consent.v1", "sha256:x"),
    credentialStatus: REVOCATION,
    suspensionStatus: SUSPENSION,
  } as unknown as Envelope;
  assert.deepEqual(toVerifiableCredential(e).credentialStatus, [REVOCATION, SUSPENSION]);
});

test("status: a non-consumer (no status) never invents a credentialStatus", () => {
  const e = baseEnvelope("ar.action.v1", null); // null-subject, status-list non-consumer
  assert.ok(!("credentialStatus" in toVerifiableCredential(e)));
});

// ── Hybrid / PQC field carriage (no ml-dsa runtime needed — carriage only) ───────
test("hybrid: sig2/sig2_alg/sig2_key/sig_min_alg survive the carrier byte-equal", () => {
  const e = {
    ...baseEnvelope("ar.consent.v1", "sha256:x"),
    sig_alg: "ed25519",
    sig2: "cGtjc2ln",
    sig2_alg: "ml-dsa-65",
    sig2_key: "ml-dsa-65:AAAB",
    sig_min_alg: "ml-dsa-65",
  } as unknown as Envelope;
  assert.deepEqual(extractEnvelope(toVerifiableCredential(e)), e);
});

test("carriage: an incl (transparency) block survives byte-equal", () => {
  const e = {
    ...baseEnvelope("ar.consent.v1", "sha256:x"),
    incl: { log_id: "log", leaf: "sha256:aa", promise: { timestamp: "2026-06-30T12:00:02Z", sig: "cw" } },
  } as unknown as Envelope;
  assert.deepEqual(extractEnvelope(toVerifiableCredential(e)), e);
});

// ── Wrapper-proof tamper matrix (each lifted field) ──────────────────────────────
function realKeyEnvelope() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const raw = new Uint8Array((publicKey.export({ format: "der", type: "spki" }) as Buffer).subarray(-32));
  const seed = new Uint8Array((privateKey.export({ format: "der", type: "pkcs8" }) as Buffer).subarray(-32));
  const e = { ...baseEnvelope("ar.consent.v1", "did:web:subject.example"), iss_key: `ed25519:${encodeRaw(raw)}`, exp: "2027-01-01T00:00:00Z" } as Envelope;
  return { key: { kid: "k", privateKey: seed, publicKey: raw }, e };
}

for (const mut of [
  { name: "issuer", patch: { issuer: "did:web:evil.example" } },
  { name: "validFrom", patch: { validFrom: "2000-01-01T00:00:00Z" } },
  { name: "validUntil", patch: { validUntil: "2099-01-01T00:00:00Z" } },
  { name: "credentialSubject", patch: { credentialSubject: { id: "did:web:evil.example" } } },
]) {
  test(`wrapper tamper: mutating ${mut.name} fails verification`, () => {
    const { key, e } = realKeyEnvelope();
    const signed = attachWrapperProof(toVerifiableCredential(e), key, { verificationMethod: "did:web:issuer.example#k" });
    const tampered = { ...signed, ...mut.patch } as typeof signed;
    assert.equal(verifyWrapperProof(tampered, key.publicKey).ok, false);
  });
}

test("wrapper: an untampered signed credential verifies", () => {
  const { key, e } = realKeyEnvelope();
  const signed = attachWrapperProof(toVerifiableCredential(e), key, { verificationMethod: "did:web:issuer.example#k" });
  assert.deepEqual(verifyWrapperProof(signed, key.publicKey), { ok: true });
});

// ── Edge / guard cases ───────────────────────────────────────────────────────────
test("edge: extra contexts are appended after the base + anchors contexts", () => {
  const e = baseEnvelope("ar.consent.v1", "sha256:x");
  const vc = toVerifiableCredential(e, { contexts: ["https://example.com/ns/extra"] });
  assert.equal(vc["@context"][0], "https://www.w3.org/ns/credentials/v2");
  assert.equal(vc["@context"].at(-1), "https://example.com/ns/extra");
});

test("edge: validUntil present iff envelope exp is non-null", () => {
  const withExp = { ...baseEnvelope("ar.consent.v1", "sha256:x"), exp: "2030-01-01T00:00:00Z" } as Envelope;
  assert.equal(toVerifiableCredential(withExp).validUntil, "2030-01-01T00:00:00Z");
  assert.ok(!("validUntil" in toVerifiableCredential(baseEnvelope("ar.consent.v1", "sha256:x"))));
});

test("edge: opts.subjectless forces act framing on a subject-bearing envelope", () => {
  const e = baseEnvelope("ar.consent.v1", "did:web:subject.example");
  const vc = toVerifiableCredential(e, { subjectless: true });
  assert.ok(!("id" in vc.credentialSubject));
});

test("edge: type array is exactly [VerifiableCredential, AnchoredReceiptCredential]", () => {
  const vc = toVerifiableCredential(baseEnvelope("ar.provenance.v1", "sha256:x"));
  assert.deepEqual(vc.type, ["VerifiableCredential", "AnchoredReceiptCredential"]);
});

test("edge: evidence[0] carries the envelope verbatim + anchor descriptor", () => {
  const e = baseEnvelope("ar.provenance.v1", "sha256:x");
  const vc = toVerifiableCredential(e);
  assert.deepEqual(vc.evidence[0].envelope, e);
  assert.equal(vc.evidence[0].anchorLog, e.anchor.log);
  assert.equal(vc.evidence[0].treeHeadRoot, e.anchor.tree_head_root);
});

test("edge: verifyWrapperProof rejects a wrong-length public key", () => {
  const { key, e } = realKeyEnvelope();
  const signed = attachWrapperProof(toVerifiableCredential(e), key, { verificationMethod: "did:web:issuer.example#k" });
  assert.deepEqual(verifyWrapperProof(signed, new Uint8Array(16)), { ok: false, reason: "bad_signature" });
});

test("edge: publicKeyFromIssKey decodes an ml-dsa-65 ref", () => {
  const r = publicKeyFromIssKey("ml-dsa-65:AAAB");
  assert.equal(r.alg, "ml-dsa-65");
  assert.ok(r.key.length > 0);
});

test("edge: isAnchoredReceiptCredential rejects a wrong-typed or evidence-less doc", () => {
  assert.equal(isAnchoredReceiptCredential({ type: ["VerifiableCredential", "AnchoredReceiptCredential"], evidence: [] }), false);
  assert.equal(isAnchoredReceiptCredential({ type: ["VerifiableCredential"], evidence: [{ envelope: {} }] }), false);
  assert.equal(isAnchoredReceiptCredential(42), false);
});

test("edge: extractEnvelope throws when evidence[0] has no envelope", () => {
  const bad = { type: ["VerifiableCredential", "AnchoredReceiptCredential"], evidence: [{ type: ["AnchoredReceipt"] }] };
  assert.throws(() => extractEnvelope(bad as never), AnchorsVcError);
});
