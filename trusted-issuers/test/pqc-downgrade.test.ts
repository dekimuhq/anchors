/**
 * PQC downgrade via self-certified sig2 key (security audit finding F2).
 *
 * Threat: an adversary who can forge the issuer's CLASSICAL signature (the
 * CRQC case the `pqc_mandatory` posture exists for) mints a "hybrid" receipt
 * whose `sig2` is an ML-DSA signature by the ATTACKER's own key, embedded in
 * the receipt as `sig2_key`. With no `resolveSig2Key` the pipeline used to
 * self-certify that key, so the mandate was satisfied by an attacker key.
 * Fix: under a mandate, a PQC signature only counts when its key was bound by
 * the verifier (`resolveSig2Key`), i.e. came from issuer-published material.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  generateKeypair,
  generateMlDsaKeypair,
  toMlDsaSecret,
  buildMintV2,
  buildVerifyReceipt,
  defineFamily,
  keyBytesFromKeyRef,
  type FamilyVerifyOptions,
} from "@dekimuhq/anchors-envelope";
import { makeVerifyIssuerPqc } from "../src/index.ts";
import { defaultIssuerRecord } from "./fixtures.ts";

const ISS = "did:web:issuer.example";
const fam = defineFamily({
  acronym: "APR", name: "x", claim_types: ["ar.provenance.v1"], spec_path: "x", chip: 1,
  status_list_slot: null, subject_presence: "must-be-present", tsa_upgrade_path: "free",
  body_schema: { validate: (b: unknown) => ({ ok: true, value: b }) },
} as never);
const ANCHOR = {
  log: "https://verify.dekimu.com/apr/v1", leaf_index: 0, inclusion_proof: ["sha256:aa"],
  tree_head_root: "sha256:bb", tree_size: 1, log_time: "2026-05-19T00:00:00Z",
};
const mint = buildMintV2({
  meta: fam.meta,
  validateBody: (b: unknown) => fam.validateBody(b),
  checkSubjectPresence: (s: never, b: never) => fam.checkSubjectPresence(s, b),
  isOwnedClaimType: (c: string) => fam.isOwnedClaimType(c),
} as never);
const verify = buildVerifyReceipt({
  meta: fam.meta,
  validateBody: (b: unknown) => fam.validateBody(b),
  isOwnedClaimType: (c: string) => fam.isOwnedClaimType(c),
  checkSubjectPresence: (s: never, b: never) => fam.checkSubjectPresence(s, b),
  tsaMandateLevel: (p: string) => fam.tsaMandateLevel(p),
  profileValidators: fam.profileValidators,
  profileIds: fam.profileIds,
  hasProfile: (p: string) => fam.hasProfile(p),
} as never);

const issuerEd = generateKeypair("issuer-ed");
const issuerMl = generateMlDsaKeypair("issuer-ml"); // issuer-PUBLISHED PQC key
const attackerMl = generateMlDsaKeypair("attacker-ml"); // never published by the issuer
const body = { kind: "ar.provenance.v1", events: ["forged"] };

async function receiptSignedWith(ml: typeof issuerMl) {
  return (mint as (a: unknown) => Promise<never>)({
    body,
    issuerPrivateKey: issuerEd.privateKey,
    issuerDid: ISS,
    subject: "sha256:aa",
    anchor: ANCHOR,
    sig2: { mlDsa: toMlDsaSecret(ml) },
    sigMinAlg: "ml-dsa-65",
  });
}

function opts(over: {
  mandate: boolean;
  boundSig2?: Uint8Array | null;
}): FamilyVerifyOptions {
  const record = defaultIssuerRecord({
    iss: ISS,
    ...(over.mandate
      ? { pqc_mandatory: { min_sig_alg: "ml-dsa-65", mandatory_from: "2026-01-01T00:00:00Z" } }
      : {}),
  });
  const o: FamilyVerifyOptions = {
    resolveKey: (e: unknown) => keyBytesFromKeyRef((e as { iss_key: string }).iss_key),
    verifyIssuerTrust: async () =>
      ({
        outcome: "valid_trusted", iss: ISS, iss_key: "ed25519:x", spki: new Uint8Array(),
        matched_record: record, reason: "allowlisted",
      }) as never,
    verifyIssuerPqc: makeVerifyIssuerPqc({ now: () => new Date("2026-11-22T00:00:00Z") }),
  };
  if (over.boundSig2 !== undefined) o.resolveSig2Key = () => over.boundSig2;
  return o;
}

describe("F2 — PQC mandate vs self-certified sig2 key", () => {
  it("ATTACK: forged classical + attacker's own ML-DSA sig2, no resolveSig2Key → rejected (issuer_pqc_mandatory)", async () => {
    const forged = await receiptSignedWith(attackerMl);
    const r = await verify(forged, opts({ mandate: true }));
    assert.equal(r.signature_valid, false);
    assert.equal(r.reason, "issuer_pqc_mandatory:ml-dsa-65");
  });

  it("ATTACK: resolveSig2Key bound to issuer's published key, receipt signed by attacker key → rejected", async () => {
    const forged = await receiptSignedWith(attackerMl);
    const r = await verify(forged, opts({ mandate: true, boundSig2: issuerMl.publicKeyRaw }));
    assert.equal(r.signature_valid, false);
  });

  it("ATTACK: resolveSig2Key returns nothing under a mandate → fail closed", async () => {
    const forged = await receiptSignedWith(attackerMl);
    const r = await verify(forged, opts({ mandate: true, boundSig2: null }));
    assert.equal(r.signature_valid, false);
  });

  it("LEGIT: sig2 by issuer's published key, bound via resolveSig2Key → accepted under the mandate", async () => {
    const genuine = await receiptSignedWith(issuerMl);
    const r = await verify(genuine, opts({ mandate: true, boundSig2: issuerMl.publicKeyRaw }));
    assert.equal(r.signature_valid, true, r.reason);
  });

  it("NO REGRESSION: without a mandate, self-certified hybrid receipts verify exactly as before", async () => {
    const forgedLooking = await receiptSignedWith(attackerMl);
    const r = await verify(forgedLooking, opts({ mandate: false }));
    assert.equal(r.signature_valid, true, r.reason);
  });

  it("NO REGRESSION: classical-only receipt without a mandate still verifies", async () => {
    const classical = await (mint as (a: unknown) => Promise<never>)({
      body, issuerPrivateKey: issuerEd.privateKey, issuerDid: ISS, subject: "sha256:aa", anchor: ANCHOR,
    });
    const r = await verify(classical, opts({ mandate: false }));
    assert.equal(r.signature_valid, true, r.reason);
  });
});
