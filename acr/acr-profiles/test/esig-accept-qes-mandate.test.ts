import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import * as crypto from "node:crypto";
import {
  validateEsigAcceptQes,
  ESIG_ACCEPT_QES_DESCRIPTOR,
} from "../src/esig-accept.ts";
import type { EsigAcceptQesReceipt, EsigAcceptQesCtx } from "../src/esig-accept.ts";
import { signEnvelope, base64UrlEncode } from "@dekimuhq/anchors-envelope";
import type { Envelope, FamilyVerifyResult } from "@dekimuhq/anchors-envelope";
import { loadTrustAnchors } from "@dekimuhq/anchors-envelope/tsa";
import { verifyReceipt } from "@dekimuhq/acr";

const VALID_POLICY_OID = ESIG_ACCEPT_QES_DESCRIPTOR.requires_tsa_policy_oid!;

/** Minimal TsaBlock stub sufficient for the receipt shape check. */
const TSA_STUB = {
  v: 1 as const,
  tsr: "base64url",
  alg: "sha-256" as const,
  tsa_url: "https://tsa.example",
  tsa_cert_chain_sha256: ["sha256:" + "a".repeat(64)],
  issued_at: "2026-05-17T12:00:00Z",
};

const RECEIPT_WITH_TSA: EsigAcceptQesReceipt = { tsa: TSA_STUB };
const RECEIPT_NO_TSA: EsigAcceptQesReceipt = { tsa: null };

const CTX_VERIFIED_LISTED: EsigAcceptQesCtx = {
  tsa_state: "tsa_verified",
  tsa_listed: true,
  tsa_policy_oid: VALID_POLICY_OID,
};

// ── tsa absent ────────────────────────────────────────────────────────────────

test("esig.accept@qes rejects a receipt missing tsa", () => {
  const r = validateEsigAcceptQes(RECEIPT_NO_TSA, CTX_VERIFIED_LISTED);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "tsa_required_by_profile");
});

// ── tsa present but not verified ─────────────────────────────────────────────

test("esig.accept@qes rejects tsa_state=tsa_unrecognised_anchor", () => {
  const ctx: EsigAcceptQesCtx = {
    tsa_state: "tsa_unrecognised_anchor",
    tsa_listed: true,
    tsa_policy_oid: VALID_POLICY_OID,
  };
  const r = validateEsigAcceptQes(RECEIPT_WITH_TSA, ctx);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "tsa_failed:tsa_unrecognised_anchor");
});

test("esig.accept@qes rejects tsa_state=tsa_imprint_mismatch", () => {
  const ctx: EsigAcceptQesCtx = {
    tsa_state: "tsa_imprint_mismatch",
    tsa_listed: true,
    tsa_policy_oid: VALID_POLICY_OID,
  };
  const r = validateEsigAcceptQes(RECEIPT_WITH_TSA, ctx);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "tsa_failed:tsa_imprint_mismatch");
});

test("esig.accept@qes rejects tsa_state=tsa_drift_exceeded", () => {
  const ctx: EsigAcceptQesCtx = {
    tsa_state: "tsa_drift_exceeded",
    tsa_listed: false,
    tsa_policy_oid: VALID_POLICY_OID,
  };
  const r = validateEsigAcceptQes(RECEIPT_WITH_TSA, ctx);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "tsa_failed:tsa_drift_exceeded");
});

// ── tsa verified but not EUTL-listed ─────────────────────────────────────────

test("esig.accept@qes rejects a tsa from a non-EUTL anchor (FreeTSA)", () => {
  const ctx: EsigAcceptQesCtx = {
    tsa_state: "tsa_verified",
    tsa_listed: false,
    tsa_policy_oid: VALID_POLICY_OID,
  };
  const r = validateEsigAcceptQes(RECEIPT_WITH_TSA, ctx);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "tsa_listed_required_by_profile");
});

// ── tsa verified, EUTL-listed, wrong policy OID ───────────────────────────────

test("esig.accept@qes rejects a mismatched policy OID", () => {
  const ctx: EsigAcceptQesCtx = {
    tsa_state: "tsa_verified",
    tsa_listed: true,
    tsa_policy_oid: "0.4.0.99999.1.1", // wrong OID
  };
  const r = validateEsigAcceptQes(RECEIPT_WITH_TSA, ctx);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "tsa_policy_oid_mismatch");
});

test("esig.accept@qes rejects when policy OID is absent", () => {
  // ctx.tsa_policy_oid is undefined — must not match the required OID
  const ctx: EsigAcceptQesCtx = {
    tsa_state: "tsa_verified",
    tsa_listed: true,
  };
  const r = validateEsigAcceptQes(RECEIPT_WITH_TSA, ctx);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "tsa_policy_oid_mismatch");
});

// ── happy path ────────────────────────────────────────────────────────────────

test("esig.accept@qes passes with a verified EUTL-listed TSA at the QTS OID", () => {
  const r = validateEsigAcceptQes(RECEIPT_WITH_TSA, CTX_VERIFIED_LISTED);
  assert.equal(r.ok, true);
  assert.equal(r.reason, undefined);
});

// ── I1 e2e: full verifier → validator plumbing ────────────────────────────────
//
// Proves the tsa_policy_oid surfaces end-to-end: mint a v=2 ACR envelope,
// inject the bundled FreeTSA TSR, verify via @dekimuhq/acr-verifier, then feed
// the verifier's EnvelopeVerifyResult straight into validateEsigAcceptQes.
//
// The FreeTSA fixture's TST has policy OID `1.2.3.4.1` (test/development
// fixture, NOT the eIDAS QTS OID). The receipt is also imprint-mismatched
// because the fixture imprint is fixed and our envelope content differs — so
// the verifier returns `tsa_state: "tsa_imprint_mismatch"`. The validator
// therefore rejects with `tsa_failed:tsa_imprint_mismatch` (state check fires
// before policy check). Either way the policy_oid must flow through to the
// EnvelopeVerifyResult — which is the wiring this test proves.

const __dirname = dirname(fileURLToPath(import.meta.url));
const tsrPath = resolve(__dirname, "../../../envelope/test/tsa/fixtures/freetsa-sample.tsr");
const anchorPath = resolve(__dirname, "../../../data/freetsa-trust-anchor.json");

test("esig.accept@qes e2e: verifier output flows tsa_policy_oid into validateEsigAcceptQes", async () => {
  // 1. Build a signed v=2 ACR envelope (tsa null at signing time).
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const pkRaw = pkDer.subarray(-32);
  const issKey = `ed25519:${base64UrlEncode(new Uint8Array(pkRaw))}` as const;

  const unsigned: Envelope = {
    v: 2,
    id: "01HXX0000000000000000QES_E2E",
    claim_type: "ar.consent.v1",
    iss: "did:web:bank.example",
    iss_key: issKey,
    subject: "sha256:" + "a".repeat(64),
    iat: "2026-05-17T12:00:00Z",
    exp: null,
    prev: null,
    policy_uri: "https://bank.example/policy",
    policy_hash: "sha256:" + "b".repeat(64),
    policy_version: "1.0.0",
    tsa: null,
    credentialStatus: null,
    anchor: null as unknown as Envelope["anchor"],
    sig: "",
    countersig: null,
    body: { lawful_basis: "6(1)(a)", purposes: ["test"] },
  };
  const signed = await signEnvelope(unsigned, privateKey);

  // 2. Inject the FreeTSA TSR. We need genTime as referenceTime to clear drift.
  const tsrBytes = new Uint8Array(readFileSync(tsrPath));
  const sampleTsrB64 = base64UrlEncode(tsrBytes);
  const { parseTimeStampResp } = await import("@dekimuhq/anchors-envelope/tsa");
  const parsedTsr = parseTimeStampResp(tsrBytes);
  assert.ok(parsedTsr.granted, "fixture setup: tsr must be granted");
  const refTime = new Date(parsedTsr.tstInfo.genTime);

  const injected = {
    ...signed,
    tsa: {
      v: 1 as const,
      tsr: sampleTsrB64,
      alg: "sha-256" as const,
      tsa_url: "https://freetsa.org/tsr",
      tsa_cert_chain_sha256: [],
      issued_at: "2026-05-17T09:06:45Z",
    },
  };

  // 3. Verify via acr-verifier (real plumbing — not a mock).
  const anchors = loadTrustAnchors([anchorPath]);
  const result = await verifyReceipt(injected as never, {
    resolveKey: async () => new Uint8Array(pkDer),
    tsaAnchors: anchors,
    tsaDriftToleranceSec: 300,
    tsaReferenceTime: refTime,
  }) as FamilyVerifyResult;

  // 4. Verifier surfaces tsa_policy_oid past the imprint-mismatch error.
  assert.equal(result.signature_valid, true);
  assert.equal(result.tsa_state, "tsa_imprint_mismatch");
  assert.equal(result.tsa_policy_oid, "1.2.3.4.1", "verifier must populate tsa_policy_oid from parsed TSTInfo");

  // 5. Feed the verifier result into the profile validator. Build the ctx
  //    using ONLY fields supplied by the verifier (no fabrication).
  const ctx: EsigAcceptQesCtx = {
    tsa_state: result.tsa_state as EsigAcceptQesCtx["tsa_state"],
    tsa_listed: result.tsa_listed ?? false,
    ...(result.tsa_policy_oid !== undefined ? { tsa_policy_oid: result.tsa_policy_oid } : {}),
  };
  const receipt: EsigAcceptQesReceipt = { tsa: injected.tsa };
  const validation = validateEsigAcceptQes(receipt, ctx);

  // Imprint mismatch trips the tsa_state guard before the policy OID guard.
  // That is the correct end-to-end behaviour and still proves the wiring:
  // the validator received a ctx assembled exclusively from verifier output.
  assert.equal(validation.ok, false);
  assert.equal(validation.reason, "tsa_failed:tsa_imprint_mismatch");
});

test("esig.accept@qes e2e: validator pinpoints policy_oid mismatch when state is forced verified", async () => {
  // Companion to the above. The verifier's tsa_policy_oid is flowed through
  // unchanged; we only synthesise a `tsa_verified` state to hit the OID-
  // mismatch branch specifically. Confirms the verifier-supplied OID
  // (FreeTSA `1.2.3.4.1`) ≠ the QES descriptor OID `0.4.0.2023.1.1`.
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const pkRaw = pkDer.subarray(-32);
  const issKey = `ed25519:${base64UrlEncode(new Uint8Array(pkRaw))}` as const;

  const unsigned: Envelope = {
    v: 2,
    id: "01HXX0000000000000000QES_OID",
    claim_type: "ar.consent.v1",
    iss: "did:web:bank.example",
    iss_key: issKey,
    subject: "sha256:" + "a".repeat(64),
    iat: "2026-05-17T12:00:00Z",
    exp: null,
    prev: null,
    policy_uri: "https://bank.example/policy",
    policy_hash: "sha256:" + "b".repeat(64),
    policy_version: "1.0.0",
    tsa: null,
    credentialStatus: null,
    anchor: null as unknown as Envelope["anchor"],
    sig: "",
    countersig: null,
    body: { lawful_basis: "6(1)(a)", purposes: ["test"] },
  };
  const signed = await signEnvelope(unsigned, privateKey);

  const tsrBytes = new Uint8Array(readFileSync(tsrPath));
  const sampleTsrB64 = base64UrlEncode(tsrBytes);
  const { parseTimeStampResp } = await import("@dekimuhq/anchors-envelope/tsa");
  const parsedTsr = parseTimeStampResp(tsrBytes);
  assert.ok(parsedTsr.granted, "fixture setup: tsr must be granted");
  const refTime = new Date(parsedTsr.tstInfo.genTime);

  const injected = {
    ...signed,
    tsa: {
      v: 1 as const,
      tsr: sampleTsrB64,
      alg: "sha-256" as const,
      tsa_url: "https://freetsa.org/tsr",
      tsa_cert_chain_sha256: [],
      issued_at: "2026-05-17T09:06:45Z",
    },
  };
  const anchors = loadTrustAnchors([anchorPath]);
  const result = await verifyReceipt(injected as never, {
    resolveKey: async () => new Uint8Array(pkDer),
    tsaAnchors: anchors,
    tsaDriftToleranceSec: 300,
    tsaReferenceTime: refTime,
  }) as FamilyVerifyResult;

  // Synthesise just enough of a `tsa_verified` ctx to reach the OID gate,
  // while keeping `tsa_policy_oid` strictly from the verifier output.
  assert.notEqual(result.tsa_policy_oid, undefined);
  const ctx: EsigAcceptQesCtx = {
    tsa_state: "tsa_verified",
    tsa_listed: true,
    tsa_policy_oid: result.tsa_policy_oid!,
  };
  const validation = validateEsigAcceptQes({ tsa: injected.tsa }, ctx);
  assert.equal(validation.ok, false);
  assert.equal(validation.reason, "tsa_policy_oid_mismatch");
});
