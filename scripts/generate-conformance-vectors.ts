/**
 * generate-conformance-vectors.ts — mint reproducible conformance test vectors
 * for APR, ACR, and ARR families.
 *
 * Uses a FIXED Ed25519 seed so output is deterministic across runs.
 * Generates 3 valid vectors + 4 invalid vectors, writes JSON to
 * anchors-spec/conformance/{valid,invalid}/.
 *
 * Run: node --experimental-strip-types scripts/generate-conformance-vectors.ts
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as crypto from "node:crypto";

import {
  signEnvelope,
  base64UrlEncode,
  base64UrlDecode,
  keyObjectFromSeed,
  publicKeyFromSeed,
  generateReceiptId,
} from "@dekimuhq/anchors-envelope";
import type { Envelope } from "@dekimuhq/anchors-envelope";

// ── Fixed seed for reproducibility ──────────────────────────────────────────

const SEED = Buffer.alloc(32, 0xaa);
const { privateKey, issKey } = keyObjectFromSeed(new Uint8Array(SEED));
const publicKeyRaw = publicKeyFromSeed(new Uint8Array(SEED));
const publicKeyB64 = base64UrlEncode(publicKeyRaw);

// ── Output paths ────────────────────────────────────────────────────────────

const SPEC_ROOT = path.resolve(
  import.meta.dirname ?? path.dirname(new URL(import.meta.url).pathname),
  "../../anchors-spec/conformance"
);
const VALID_DIR = path.join(SPEC_ROOT, "valid");
const INVALID_DIR = path.join(SPEC_ROOT, "invalid");

fs.mkdirSync(VALID_DIR, { recursive: true });
fs.mkdirSync(INVALID_DIR, { recursive: true });

// ── Shared envelope fields ──────────────────────────────────────────────────

const FIXED_IAT = "2026-05-25T00:00:00Z";
const FIXED_IAT_MS = Date.parse(FIXED_IAT);

function stubAnchor() {
  return {
    log: "https://verify.dekimu.com/test/v1",
    leaf_index: 0,
    inclusion_proof: [],
    tree_head_root: "sha256:" + "0".repeat(64),
    tree_size: 1,
    log_time: FIXED_IAT,
  };
}

// Use deterministic receipt IDs (ULID-like but fixed for reproducibility).
let idCounter = 0;
function deterministicId(): string {
  idCounter++;
  const base = "01J5CONFORMANCE";
  return (base + idCounter.toString().padStart(26 - base.length, "0")).slice(
    0,
    26
  );
}

// ── 1. APR valid vector ─────────────────────────────────────────────────────

async function makeAprValid() {
  const unsigned: Envelope = {
    v: 2,
    id: deterministicId(),
    iat: FIXED_IAT,
    iat_ms: FIXED_IAT_MS,
    claim_type: "ar.provenance.v1",
    iss: "did:web:example.com",
    iss_key: issKey,
    subject: "urn:example:artifact:001",
    exp: null,
    prev: null,
    policy_uri: null,
    policy_hash: null,
    policy_version: null,
    kind: "observation",
    cause: "api",
    tsa: null,
    credentialStatus: null,
    anchor: stubAnchor(),
    sig: "",
    countersig: null,
    body: {
      artifact: {
        type: "commander.run.output",
        id: "art-001",
        hash: "sha256:" + "b".repeat(64),
        hashAlgorithm: "sha256",
      },
      agent: { kind: "ai", model: "claude-4", provider: "anthropic" },
      authorization: { principalId: "user-001" },
      startedAt: FIXED_IAT_MS / 1000 - 60,
      completedAt: FIXED_IAT_MS / 1000,
      disclosure: "public_full",
      qts_attestation_hash: null,
    },
  };
  const signed = await signEnvelope(unsigned, privateKey);
  return {
    description:
      "Valid APR ar.provenance.v1 receipt — v=2 envelope, Ed25519 signed, observation/api, public_full disclosure",
    receipt: signed,
    issuer_public_key: publicKeyB64,
    expected_result: {
      signature: "valid",
      claim_type: "ar.provenance.v1",
    },
  };
}

// ── 2. ACR valid vector ─────────────────────────────────────────────────────

async function makeAcrValid() {
  const unsigned: Envelope = {
    v: 2,
    id: deterministicId(),
    iat: FIXED_IAT,
    iat_ms: FIXED_IAT_MS,
    claim_type: "ar.consent.v1",
    iss: "did:web:example.com",
    iss_key: issKey,
    subject: "sha256:" + "c".repeat(64),
    exp: null,
    prev: null,
    policy_uri: "https://example.com/privacy-policy",
    policy_hash: "sha256:" + "d".repeat(64),
    policy_version: "1.0.0",
    kind: "decision",
    cause: "manual",
    tsa: null,
    credentialStatus: null,
    anchor: stubAnchor(),
    sig: "",
    countersig: null,
    body: {
      kind: "ar.consent.v1",
      profile: "gdpr.art7",
      iss: "did:web:example.com",
      iss_key: issKey,
      sub_commit: "sha256:" + "c".repeat(64),
      purposes: ["sha256:" + "e".repeat(64)],
      lawful_basis: "6(1)(a)",
      policy_hash: "sha256:" + "d".repeat(64),
      granted_at: FIXED_IAT,
      prev: null,
      field_root: "sha256:" + "f".repeat(64),
      anchor: null,
      sig: "",
      countersig: null,
      qts_attestation_hash: null,
    },
  };
  const signed = await signEnvelope(unsigned, privateKey);
  return {
    description:
      "Valid ACR ar.consent.v1 receipt — v=2 envelope, Ed25519 signed, GDPR Art. 7 profile, decision/manual",
    receipt: signed,
    issuer_public_key: publicKeyB64,
    expected_result: {
      signature: "valid",
      claim_type: "ar.consent.v1",
    },
  };
}

// ── 3. ARR valid vector ─────────────────────────────────────────────────────

async function makeArrValid() {
  const unsigned: Envelope = {
    v: 2,
    id: deterministicId(),
    iat: FIXED_IAT,
    iat_ms: FIXED_IAT_MS,
    claim_type: "ar.erasure.v1",
    iss: "did:web:example.com",
    iss_key: issKey,
    subject: "sha256:" + "a".repeat(64),
    exp: null,
    prev: null,
    policy_uri: "https://example.com/retention-policy",
    policy_hash: "sha256:" + "1".repeat(64),
    policy_version: "2.0.0",
    kind: "decision",
    cause: "erasure_request",
    tsa: null,
    credentialStatus: null,
    anchor: stubAnchor(),
    sig: "",
    countersig: null,
    body: {
      kind: "ar.erasure.v1",
      profile: "gdpr.art17",
      iss: "did:web:example.com",
      iss_key: issKey,
      target_kind: "subject",
      target_commit: "sha256:" + "a".repeat(64),
      salt_epoch: "2026-01-01",
      policy_hash: "sha256:" + "1".repeat(64),
      policy_uri: "https://example.com/retention-policy",
      policy_version: "2.0.0",
      trigger: "subject_request",
      trigger_receipt: null,
      event_at: FIXED_IAT,
      granted_at: FIXED_IAT,
      effective_until: null,
      state_snapshot: {
        retention_status: "erased",
        current_policy_hash: "sha256:" + "1".repeat(64),
        hold_active: false,
        hold_reason_commit: null,
        anonymized: false,
        archived: false,
      },
      prev: null,
      field_root: "sha256:" + "2".repeat(64),
      anchor: null,
      sig: null,
      qts_attestation_hash: null,
    },
  };
  const signed = await signEnvelope(unsigned, privateKey);
  return {
    description:
      "Valid ARR ar.erasure.v1 receipt — v=2 envelope, Ed25519 signed, GDPR Art. 17 erasure, decision/erasure_request",
    receipt: signed,
    issuer_public_key: publicKeyB64,
    expected_result: {
      signature: "valid",
      claim_type: "ar.erasure.v1",
    },
  };
}

// ── 4. Invalid: signature bit-flip ──────────────────────────────────────────

async function makeSigInvalid() {
  const unsigned: Envelope = {
    v: 2,
    id: deterministicId(),
    iat: FIXED_IAT,
    iat_ms: FIXED_IAT_MS,
    claim_type: "ar.provenance.v1",
    iss: "did:web:example.com",
    iss_key: issKey,
    subject: "urn:example:artifact:tampered",
    exp: null,
    prev: null,
    policy_uri: null,
    policy_hash: null,
    policy_version: null,
    kind: "observation",
    cause: "api",
    tsa: null,
    credentialStatus: null,
    anchor: stubAnchor(),
    sig: "",
    countersig: null,
    body: {
      artifact: {
        type: "commander.run.output",
        id: "art-tampered",
        hash: "sha256:" + "b".repeat(64),
        hashAlgorithm: "sha256",
      },
      agent: { kind: "ai", model: "claude-4", provider: "anthropic" },
      authorization: { principalId: "user-001" },
      startedAt: FIXED_IAT_MS / 1000 - 60,
      completedAt: FIXED_IAT_MS / 1000,
      disclosure: "public_full",
      qts_attestation_hash: null,
    },
  };
  const signed = await signEnvelope(unsigned, privateKey);

  // Flip one bit in the signature.
  const sigBytes = base64UrlDecode(signed.sig);
  sigBytes[0] = sigBytes[0]! ^ 0x01;
  const tampered = { ...signed, sig: base64UrlEncode(sigBytes) };

  return {
    description:
      "Invalid: valid APR receipt with one bit flipped in the Ed25519 signature — verifiers MUST reject",
    receipt: tampered,
    issuer_public_key: publicKeyB64,
    expected_error: "sig_invalid",
  };
}

// ── 5. Invalid: unknown claim_type ──────────────────────────────────────────

async function makeClaimTypeUnknown() {
  const unsigned: Envelope = {
    v: 2,
    id: deterministicId(),
    iat: FIXED_IAT,
    iat_ms: FIXED_IAT_MS,
    claim_type: "ar.unknown.v1" as Envelope["claim_type"],
    iss: "did:web:example.com",
    iss_key: issKey,
    subject: "urn:example:unknown",
    exp: null,
    prev: null,
    policy_uri: null,
    policy_hash: null,
    policy_version: null,
    tsa: null,
    credentialStatus: null,
    anchor: stubAnchor(),
    sig: "",
    countersig: null,
    body: {},
  };
  // Sign even with the invalid claim_type — the envelope layer signs anything.
  const signed = await signEnvelope(unsigned, privateKey);
  return {
    description:
      "Invalid: receipt with unregistered claim_type 'ar.unknown.v1' — verifiers MUST reject with schema_invalid:claim_type",
    receipt: signed,
    issuer_public_key: publicKeyB64,
    expected_error: "claim_type_unknown",
  };
}

// ── 6. Invalid: iat_ms mismatch ─────────────────────────────────────────────

async function makeIatMsMismatch() {
  const unsigned: Envelope = {
    v: 2,
    id: deterministicId(),
    iat: FIXED_IAT,
    iat_ms: FIXED_IAT_MS + 1000, // off by 1 second
    claim_type: "ar.consent.v1",
    iss: "did:web:example.com",
    iss_key: issKey,
    subject: "sha256:" + "c".repeat(64),
    exp: null,
    prev: null,
    policy_uri: "https://example.com/privacy-policy",
    policy_hash: "sha256:" + "d".repeat(64),
    policy_version: "1.0.0",
    kind: "decision",
    cause: "manual",
    tsa: null,
    credentialStatus: null,
    anchor: stubAnchor(),
    sig: "",
    countersig: null,
    body: {
      kind: "ar.consent.v1",
      profile: "gdpr.art7",
      iss: "did:web:example.com",
      iss_key: issKey,
      sub_commit: "sha256:" + "c".repeat(64),
      purposes: ["sha256:" + "e".repeat(64)],
      lawful_basis: "6(1)(a)",
      policy_hash: "sha256:" + "d".repeat(64),
      granted_at: FIXED_IAT,
      prev: null,
      field_root: "sha256:" + "f".repeat(64),
      anchor: null,
      sig: "",
      countersig: null,
      qts_attestation_hash: null,
    },
  };
  const signed = await signEnvelope(unsigned, privateKey);
  return {
    description:
      "Invalid: ACR receipt where iat_ms does not match Date.parse(iat) — off by 1000ms, verifiers MUST reject with iat_ms_mismatch",
    receipt: signed,
    issuer_public_key: publicKeyB64,
    expected_error: "iat_ms_mismatch",
  };
}

// ── 7. Invalid: forbidden predicate operator ────────────────────────────────

async function makePredicateOperatorNotAllowed() {
  const unsigned: Envelope = {
    v: 2,
    id: deterministicId(),
    iat: FIXED_IAT,
    iat_ms: FIXED_IAT_MS,
    claim_type: "ar.consent.v1",
    iss: "did:web:example.com",
    iss_key: issKey,
    subject: "sha256:" + "c".repeat(64),
    exp: null,
    prev: null,
    policy_uri: "https://example.com/privacy-policy",
    policy_hash: "sha256:" + "d".repeat(64),
    policy_version: "1.0.0",
    kind: "decision",
    cause: "manual",
    tsa: null,
    credentialStatus: null,
    anchor: stubAnchor(),
    sig: "",
    countersig: null,
    // Inject a forbidden operator (cat, log, map, reduce etc. are NOT in the allowlist).
    predicate: {
      cat: [{ var: "subject" }, "-injected"],
    } as unknown as Envelope["predicate"],
    body: {
      kind: "ar.consent.v1",
      profile: "gdpr.art7",
      iss: "did:web:example.com",
      iss_key: issKey,
      sub_commit: "sha256:" + "c".repeat(64),
      purposes: ["sha256:" + "e".repeat(64)],
      lawful_basis: "6(1)(a)",
      policy_hash: "sha256:" + "d".repeat(64),
      granted_at: FIXED_IAT,
      prev: null,
      field_root: "sha256:" + "f".repeat(64),
      anchor: null,
      sig: "",
      countersig: null,
      qts_attestation_hash: null,
    },
  };
  const signed = await signEnvelope(unsigned, privateKey);
  return {
    description:
      "Invalid: ACR receipt with forbidden predicate operator 'cat' (not in JSON_LOGIC_ALLOWLIST_V1_2) — verifiers MUST reject",
    receipt: signed,
    issuer_public_key: publicKeyB64,
    expected_error: "predicate_operator_not_allowed",
  };
}

// ── Generate all vectors ────────────────────────────────────────────────────

function writeVector(dir: string, filename: string, data: unknown) {
  const p = path.join(dir, filename);
  fs.writeFileSync(p, JSON.stringify(data, null, 2) + "\n", "utf8");
  console.log(`  wrote ${path.relative(process.cwd(), p)}`);
}

async function main() {
  console.log("Generating conformance vectors...\n");

  // Valid vectors
  const aprValid = await makeAprValid();
  writeVector(VALID_DIR, "apr-provenance-v1.json", aprValid);

  const acrValid = await makeAcrValid();
  writeVector(VALID_DIR, "acr-consent-v1.json", acrValid);

  const arrValid = await makeArrValid();
  writeVector(VALID_DIR, "arr-erasure-v1.json", arrValid);

  // Invalid vectors
  const sigInvalid = await makeSigInvalid();
  writeVector(INVALID_DIR, "sig-invalid.json", sigInvalid);

  const claimTypeUnknown = await makeClaimTypeUnknown();
  writeVector(INVALID_DIR, "claim-type-unknown.json", claimTypeUnknown);

  const iatMismatch = await makeIatMsMismatch();
  writeVector(INVALID_DIR, "iat-ms-mismatch.json", iatMismatch);

  const predicateOp = await makePredicateOperatorNotAllowed();
  writeVector(INVALID_DIR, "predicate-operator-not-allowed.json", predicateOp);

  console.log("\nDone. 7 vectors generated.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
