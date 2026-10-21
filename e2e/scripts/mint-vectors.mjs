/**
 * mint-vectors.mjs — deterministic one-shot minter for v1.1 cross-family conformance vectors.
 *
 * Writes 8 JSON vector files to anchors/e2e/test/vectors-v1-1/:
 *   apr-v1.json, apr-v2.json
 *   acr-consent-v1.json, acr-consent-v2.json, acr-withdrawal-v2.json
 *   arr-erasure-v1.json, arr-erasure-v2.json, arr-erasure-v2-tsa.json
 *
 * ── DETERMINISM ──────────────────────────────────────────────────────────────
 * Fixed Ed25519 seed: Buffer.alloc(32, 0x42)  (PUBLIC TEST KEY — never use in production)
 * Fixed ULIDs (string literals — no ulid() call)
 * Fixed iat strings / unix ints
 * Fixed salts for ACR field commits
 *
 * ── IDEMPOTENCY ──────────────────────────────────────────────────────────────
 * Existing files are overwritten deterministically. Running twice produces
 * byte-identical output EXCEPT the TSA vector (arr-erasure-v2-tsa.json) which
 * requires a live FreeTSA network call; subsequent runs skip it if the file
 * already exists and contains a valid tsa block.
 *
 * ── INVOCATION ───────────────────────────────────────────────────────────────
 *   node e2e/scripts/mint-vectors.mjs
 * (from the repository root)
 *
 * @module mint-vectors
 */

import * as crypto from "node:crypto";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

// ── Workspace path resolution ────────────────────────────────────────────────

const __dir = dirname(fileURLToPath(import.meta.url));
// anchors/e2e/scripts/ → anchors/e2e/
const E2E_DIR = resolve(__dir, "..");
// anchors/e2e/scripts/ → anchors/
const WORKSPACE_ROOT = resolve(__dir, "../..");

const VECTORS_DIR = join(E2E_DIR, "test", "vectors-v1-1");

// ── Package imports (resolved via workspace node_modules) ────────────────────
// We import from the workspace-hoisted packages using standard module specifiers.
// The workspaces are symlinked under anchors/node_modules/@dekimuhq/.

const {
  mint: mintAprV1,
  signEnvelope: _signEnvelopeImport,
} = await import("@dekimuhq/apr-issuer-kit");

const {
  signEnvelope,
  base64UrlEncode,
  base64UrlDecode,
} = await import("@dekimuhq/anchors-envelope");

const {
  canonicalize: canonicalizeApr,
  base64UrlEncode: b64encApr,
} = await import("@dekimuhq/apr-verifier");

const {
  canonicalize: canonicalizeAcr,
  commit,
  buildTree,
} = await import("@dekimuhq/acr-verifier");

const {
  computeTsaImprint,
  buildTimeStampReq,
  parseTimeStampResp,
  loadTrustAnchors,
  defaultTrustAnchorPath,
} = await import("@dekimuhq/anchors-envelope/tsa");

// ── Fixed deterministic constants ────────────────────────────────────────────

/**
 * PUBLIC TEST KEY — 32-byte Ed25519 seed all-0x42.
 * NEVER use this in production. It is public by design.
 */
const SEED = Buffer.alloc(32, 0x42);
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

/** Derive a KeyObject from the fixed seed. */
function makePrivateKey() {
  const der = Buffer.concat([PKCS8_PREFIX, SEED]);
  return crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

/** Derive the raw 32-byte public key from the fixed seed. */
function makePublicKeyRaw() {
  const sk = makePrivateKey();
  const pkDer = crypto.createPublicKey(sk).export({ format: "der", type: "spki" });
  return Buffer.from(pkDer).subarray(-32);
}

const PRIVATE_KEY = makePrivateKey();
const PUBLIC_KEY_RAW = makePublicKeyRaw();
const PUBLIC_KEY_B64URL = base64UrlEncode(new Uint8Array(PUBLIC_KEY_RAW));
const ISS_KEY = `ed25519:${PUBLIC_KEY_B64URL}`;

// ── Fixed ULIDs (Crockford base32, 26 chars each) ───────────────────────────

const ULID_APR_V1    = "01HXXAPRV1REGRESSION00001";
const ULID_APR_V2    = "01HXXAPRV2CROSSFAMILY001";
const ULID_ACR_CV1   = "01HXXACRCONSENTV1REGRSS1";
const ULID_ACR_CV2   = "01HXXACRCONSENTV2CROSS001";
const ULID_ACR_WV2   = "01HXXACRWITHDRAWV2CROSS1";
const ULID_ARR_EV1   = "01HXXARRERASV1REGRSSN001";
const ULID_ARR_EV2   = "01HXXARRERASV2CROSS00001";
const ULID_ARR_ETSA  = "01HXXARRERASV2TSA000001";
// ALR vectors (§J)
const ULID_ALR_DERIV   = "01HXXALRDERIVEDV2CROSS001";
const ULID_ALR_FORKED  = "01HXXALRFORKEDV2CROSS0001";
const ULID_ALR_DISCL   = "01HXXALRDISCLOSEDV2CROSS1";
// Cross-issuer (ALR ↔ APR composition)
const ULID_ALR_DERIV_APR    = "01HXXALRDERIVAPRCROSS0001";
const ULID_ALR_DERIV_MIXED  = "01HXXALRDERIVMIXEDCROSS01";
// Cited APR receipt the cross-issuer vectors compose with
const ULID_APR_COMPOSED   = "01HXXAPRCOMPOSEDALR000001";

// Fixed timestamps
const IAT_UNIX   = 1_747_440_000;  // 2026-05-17T00:00:00Z
const IAT_ISO    = "2026-05-17T00:00:00Z";

// Fixed placeholder anchor (post-mint the log worker replaces this)
const ANCHOR = {
  log: "https://verify.dekimu.com/test/v1",
  leaf_index: 0,
  inclusion_proof: [],
  tree_head_root: "sha256:" + "0".repeat(64),
  tree_size: 1,
  log_time: IAT_ISO,
};

// ── APR v1 ───────────────────────────────────────────────────────────────────

function buildAprV1() {
  const result = mintAprV1({
    issuer: "did:web:test-issuer.example",
    subject: "sha256:" + "a".repeat(64),
    body: {
      artifact: {
        type: "miniterms.document",
        id: "art-v1-cross-001",
        hash: "0".repeat(64),
        hashAlgorithm: "sha256",
      },
      agent: { kind: "template" },
      authorization: { principalId: "principal-cross-001" },
      startedAt: IAT_UNIX,
      completedAt: IAT_UNIX + 1,
      disclosure: "public_minimal",
    },
    signingKey: {
      kid: "test-cross-kid-v1",
      privateKey: new Uint8Array(SEED),
    },
    now: () => IAT_UNIX,
    newId: () => ULID_APR_V1,
  });

  return {
    name: "apr-v1",
    family: "apr",
    envelope_version: 1,
    receipt: result,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 1,
      signature_valid: true,
    },
  };
}

// ── APR v2 ───────────────────────────────────────────────────────────────────

async function buildAprV2() {
  const body = {
    artifact: {
      type: "miniterms.document",
      id: "art-v2-cross-001",
      hash: "b".repeat(64),
      hashAlgorithm: "sha256",
    },
    agent: { kind: "template" },
    authorization: { principalId: "principal-cross-002" },
    startedAt: IAT_UNIX,
    completedAt: IAT_UNIX + 2,
    disclosure: "public_minimal",
  };

  const preSign = {
    v: 2,
    id: ULID_APR_V2,
    iat: IAT_ISO,
    claim_type: "ar.provenance.v1",
    iss: "did:web:test-issuer.example",
    iss_key: ISS_KEY,
    subject: "sha256:" + "b".repeat(64),
    exp: null,
    prev: null,
    policy_uri: null,
    policy_hash: null,
    policy_version: null,
    tsa: null,
    credentialStatus: null,
    anchor: ANCHOR,
    sig: "",
    countersig: null,
    body,
  };

  const signed = await signEnvelope(preSign, PRIVATE_KEY);

  return {
    name: "apr-v2",
    family: "apr",
    envelope_version: 2,
    receipt: signed,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: true,
      tsa_state: "tsa_absent",
    },
  };
}

// ── ACR v1 ───────────────────────────────────────────────────────────────────
// Build a v=1 ACR consent receipt directly (same approach as acr-consent-v1.ts)

function buildAcrConsentV1() {
  // Fixed salts (32 bytes each, all-0x43 / 0x44 / 0x45)
  const subSalt = Buffer.alloc(32, 0x43).toString("hex");
  const purSalt = Buffer.alloc(32, 0x44).toString("hex");
  const polSalt = Buffer.alloc(32, 0x45).toString("hex");

  const sub_commit = commit(subSalt, "user@cross-test.example");
  const purposes = [commit(purSalt, "marketing.cross-v1")];
  const policy_hash_val = commit(polSalt, "sha256:" + "c".repeat(64));
  const leaves = [sub_commit, ...purposes, policy_hash_val];
  const { root: field_root } = buildTree(leaves);

  const base = {
    kind: "ar.consent.v1",
    profile: "gdpr.art7",
    iss: "did:web:controller-cross-v1.example",
    iss_key: ISS_KEY,
    sub_commit,
    purposes,
    lawful_basis: "6(1)(a)",
    policy_hash: policy_hash_val,
    granted_at: IAT_ISO,
    prev: null,
    field_root,
    anchor: null,
    sig: null,
    countersig: null,
  };

  const canonicalBytes = new TextEncoder().encode(canonicalizeAcr(base));
  const sigBytes = crypto.sign(null, canonicalBytes, PRIVATE_KEY);
  const sig = `ed25519:${base64UrlEncode(new Uint8Array(sigBytes))}`;

  const receipt = { ...base, sig };

  return {
    name: "acr-consent-v1",
    family: "acr",
    envelope_version: 1,
    receipt,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 1,
      signature_valid: true,
    },
  };
}

// ── ACR v2 consent ───────────────────────────────────────────────────────────

async function buildAcrConsentV2() {
  // Fixed salts for field commits
  const subSalt = Buffer.alloc(32, 0x53).toString("hex");
  const purSalt = Buffer.alloc(32, 0x54).toString("hex");
  const polSalt = Buffer.alloc(32, 0x55).toString("hex");

  const sub_commit = commit(subSalt, "user@cross-test.example");
  const purposes = [commit(purSalt, "marketing.cross-v2")];
  const policy_hash_val = commit(polSalt, "sha256:" + "e".repeat(64));
  const leaves = [sub_commit, ...purposes, policy_hash_val];
  const { root: field_root } = buildTree(leaves);

  const acrBody = {
    profile: "gdpr.art7",
    sub_commit,
    purposes,
    lawful_basis: "6(1)(a)",
    policy_hash: policy_hash_val,
    granted_at: IAT_ISO,
    field_root,
  };

  // ACR consent/withdrawal are POLICY_BOUND — policy_uri/hash/version required.
  const ACR_POLICY_URI = "https://controller-cross-v2.example/privacy/v1";
  const ACR_POLICY_HASH = "sha256:" + "ee".repeat(32);
  const ACR_POLICY_VERSION = "1.0.0";

  const preSign = {
    v: 2,
    id: ULID_ACR_CV2,
    iat: IAT_ISO,
    claim_type: "ar.consent.v1",
    iss: "did:web:controller-cross-v2.example",
    iss_key: ISS_KEY,
    subject: "sha256:" + "e".repeat(64),
    exp: null,
    prev: null,
    policy_uri: ACR_POLICY_URI,
    policy_hash: ACR_POLICY_HASH,
    policy_version: ACR_POLICY_VERSION,
    tsa: null,
    credentialStatus: null,
    anchor: ANCHOR,
    sig: "",
    countersig: null,
    body: acrBody,
  };

  const signed = await signEnvelope(preSign, PRIVATE_KEY);

  return {
    name: "acr-consent-v2",
    family: "acr",
    envelope_version: 2,
    receipt: signed,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: true,
      tsa_state: "tsa_absent",
    },
  };
}

// ── ACR v2 withdrawal (chained on acr-consent-v2) ───────────────────────────

async function buildAcrWithdrawalV2(consentVector) {
  // prev references the consent envelope's id
  const prevId = consentVector.receipt.id;

  const subSalt = Buffer.alloc(32, 0x53).toString("hex");
  const purSalt = Buffer.alloc(32, 0x54).toString("hex");
  const polSalt = Buffer.alloc(32, 0x55).toString("hex");

  // Withdrawal reuses commitments from the prior receipt
  const sub_commit = commit(subSalt, "user@cross-test.example");
  const purposes = [commit(purSalt, "marketing.cross-v2")];
  const policy_hash_val = commit(polSalt, "sha256:" + "e".repeat(64));
  const leaves = [sub_commit, ...purposes, policy_hash_val];
  const { root: field_root } = buildTree(leaves);

  const acrBody = {
    profile: "gdpr.art7",
    sub_commit,
    purposes,
    lawful_basis: "6(1)(a)",
    policy_hash: policy_hash_val,
    granted_at: IAT_ISO,
    field_root,
  };

  // ar.withdrawal.v1 is POLICY_BOUND — must carry policy fields.
  const preSign = {
    v: 2,
    id: ULID_ACR_WV2,
    iat: IAT_ISO,
    claim_type: "ar.withdrawal.v1",
    iss: "did:web:controller-cross-v2.example",
    iss_key: ISS_KEY,
    subject: "sha256:" + "e".repeat(64),
    exp: null,
    prev: prevId,
    policy_uri: "https://controller-cross-v2.example/privacy/v1",
    policy_hash: "sha256:" + "ee".repeat(32),
    policy_version: "1.0.0",
    tsa: null,
    credentialStatus: null,
    anchor: ANCHOR,
    sig: "",
    countersig: null,
    body: acrBody,
  };

  const signed = await signEnvelope(preSign, PRIVATE_KEY);

  return {
    name: "acr-withdrawal-v2",
    family: "acr",
    envelope_version: 2,
    receipt: signed,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: true,
      tsa_state: "tsa_absent",
    },
  };
}

// ── ARR v1 erasure ───────────────────────────────────────────────────────────
// Build a v=1 ARR erasure receipt directly using the same low-level signing
// pattern as arr-erasure-v1.ts

function buildArrErasureV1() {
  const unsigned = {
    kind: "ar.erasure.v1",
    profile: "gdpr.art17",
    iss: "did:web:processor-cross-v1.example",
    iss_key: ISS_KEY,
    target_kind: "subject",
    target_commit: "sha256:" + "ab".repeat(32),
    salt_epoch: "2026Q2",
    policy_hash: "sha256:" + "cd".repeat(32),
    policy_uri: "https://processor-cross-v1.example/p/v1",
    policy_version: "1.0.0",
    trigger: "subject_request",
    trigger_receipt: "sha256:" + "ef".repeat(32),
    event_at: "2026-05-17T08:00:00Z",
    granted_at: "2026-05-17T08:02:00Z",
    effective_until: null,
    state_snapshot: {
      retention_status: "erased",
      current_policy_hash: "sha256:" + "cd".repeat(32),
      hold_active: false,
      hold_reason_commit: null,
      anonymized: false,
      archived: false,
    },
    prev: null,
    field_root: "sha256:" + "11".repeat(32),
    anchor: null,
    sig: null,
  };

  // canonicalize uses APR's canonicalize (same JCS under the hood for ARR v1)
  const msg = new TextEncoder().encode(canonicalizeApr(unsigned));
  const sigBytes = crypto.sign(null, msg, PRIVATE_KEY);
  const sig = `ed25519:${base64UrlEncode(new Uint8Array(sigBytes))}`;

  const receipt = { ...unsigned, sig };

  return {
    name: "arr-erasure-v1",
    family: "arr",
    envelope_version: 1,
    receipt,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 1,
      signature_valid: true,
    },
  };
}

// ── ARR v2 erasure (no TSA) ──────────────────────────────────────────────────

async function buildArrErasureV2() {
  // Compute field_root the same way mintArrV2Single does:
  // SHA-256 of 0x00 || canonical(field inputs)
  const fieldInputs = {
    kind: "ar.erasure.v1",
    profile: "gdpr.art17",
    target_kind: "subject",
    target_commit: "sha256:" + "fa".repeat(32),
    salt_epoch: "2026Q2",
    policy_hash: "sha256:" + "fb".repeat(32),
    policy_uri: "https://processor-cross-v2.example/p/v1",
    policy_version: "1.0.0",
    trigger: "subject_request",
    trigger_receipt: "sha256:" + "fc".repeat(32),
    event_at: "2026-05-17T09:00:00Z",
    granted_at: "2026-05-17T09:02:00Z",
    effective_until: null,
  };

  const fieldBytes = new TextEncoder().encode(canonicalizeApr(fieldInputs));
  const prefixed = Buffer.concat([Buffer.from([0x00]), Buffer.from(fieldBytes)]);
  const field_root = "sha256:" + crypto.createHash("sha256").update(prefixed).digest("hex");

  const body = {
    profile: "gdpr.art17",
    target_kind: "subject",
    target_commit: "sha256:" + "fa".repeat(32),
    salt_epoch: "2026Q2",
    policy_hash: "sha256:" + "fb".repeat(32),
    policy_uri: "https://processor-cross-v2.example/p/v1",
    policy_version: "1.0.0",
    trigger: "subject_request",
    trigger_receipt: "sha256:" + "fc".repeat(32),
    event_at: "2026-05-17T09:00:00Z",
    granted_at: "2026-05-17T09:02:00Z",
    effective_until: null,
    state_snapshot: {
      retention_status: "erased",
      current_policy_hash: "sha256:" + "fb".repeat(32),
      hold_active: false,
      hold_reason_commit: null,
      anonymized: false,
      archived: false,
    },
    field_root,
  };

  const preSign = {
    v: 2,
    id: ULID_ARR_EV2,
    iat: IAT_ISO,
    claim_type: "ar.erasure.v1",
    iss: "did:web:processor-cross-v2.example",
    iss_key: ISS_KEY,
    subject: "sha256:" + "fa".repeat(32),
    exp: null,
    prev: null,
    policy_uri: "https://processor-cross-v2.example/p/v1",
    policy_hash: "sha256:" + "fb".repeat(32),
    policy_version: "1.0.0",
    tsa: null,
    credentialStatus: null,
    anchor: ANCHOR,
    sig: "",
    countersig: null,
    body,
  };

  const signed = await signEnvelope(preSign, PRIVATE_KEY);

  return {
    name: "arr-erasure-v2",
    family: "arr",
    envelope_version: 2,
    receipt: signed,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: true,
      tsa_state: "tsa_absent",
    },
  };
}

// ── ARR v2 erasure with valid FreeTSA TSR ────────────────────────────────────
// Network-dependent. Idempotent: skips mint if the output file exists and
// already contains a tsa block (i.e. a previous run already captured the TSR).

async function buildArrErasureV2Tsa() {
  const outputPath = join(VECTORS_DIR, "arr-erasure-v2-tsa.json");

  // ── Idempotency guard ─────────────────────────────────────────────────────
  if (existsSync(outputPath)) {
    const existing = JSON.parse(readFileSync(outputPath, "utf8"));
    if (existing?.receipt?.tsa?.tsr) {
      console.log("arr-erasure-v2-tsa.json: skipping (already minted)");
      return existing;
    }
  }

  // ── Build envelope (same shape as arr-erasure-v2 but with different IDs) ──
  const fieldInputs = {
    kind: "ar.erasure.v1",
    profile: "gdpr.art17",
    target_kind: "subject",
    target_commit: "sha256:" + "da".repeat(32),
    salt_epoch: "2026Q2",
    policy_hash: "sha256:" + "db".repeat(32),
    policy_uri: "https://processor-cross-tsa.example/p/v1",
    policy_version: "1.0.0",
    trigger: "subject_request",
    trigger_receipt: "sha256:" + "dc".repeat(32),
    event_at: "2026-05-17T10:00:00Z",
    granted_at: "2026-05-17T10:02:00Z",
    effective_until: null,
  };

  const fieldBytes = new TextEncoder().encode(canonicalizeApr(fieldInputs));
  const prefixed = Buffer.concat([Buffer.from([0x00]), Buffer.from(fieldBytes)]);
  const field_root = "sha256:" + crypto.createHash("sha256").update(prefixed).digest("hex");

  const body = {
    profile: "gdpr.art17",
    target_kind: "subject",
    target_commit: "sha256:" + "da".repeat(32),
    salt_epoch: "2026Q2",
    policy_hash: "sha256:" + "db".repeat(32),
    policy_uri: "https://processor-cross-tsa.example/p/v1",
    policy_version: "1.0.0",
    trigger: "subject_request",
    trigger_receipt: "sha256:" + "dc".repeat(32),
    event_at: "2026-05-17T10:00:00Z",
    granted_at: "2026-05-17T10:02:00Z",
    effective_until: null,
    state_snapshot: {
      retention_status: "erased",
      current_policy_hash: "sha256:" + "db".repeat(32),
      hold_active: false,
      hold_reason_commit: null,
      anonymized: false,
      archived: false,
    },
    field_root,
  };

  const preSign = {
    v: 2,
    id: ULID_ARR_ETSA,
    iat: IAT_ISO,
    claim_type: "ar.erasure.v1",
    iss: "did:web:processor-cross-tsa.example",
    iss_key: ISS_KEY,
    subject: "sha256:" + "da".repeat(32),
    exp: null,
    prev: null,
    policy_uri: "https://processor-cross-tsa.example/p/v1",
    policy_hash: "sha256:" + "db".repeat(32),
    policy_version: "1.0.0",
    tsa: null,
    credentialStatus: null,
    anchor: ANCHOR,
    sig: "",
    countersig: null,
    body,
  };

  const signed = await signEnvelope(preSign, PRIVATE_KEY);

  // ── Compute imprint + request TSA timestamp ───────────────────────────────
  console.log("arr-erasure-v2-tsa: requesting FreeTSA timestamp...");
  const imprint = computeTsaImprint(signed);
  const req = buildTimeStampReq(imprint, "sha-256", { certReq: true });

  const res = await fetch("https://freetsa.org/tsr", {
    method: "POST",
    headers: { "Content-Type": "application/timestamp-query" },
    body: req,
  });

  if (!res.ok) {
    throw new Error(`FreeTSA responded with HTTP ${res.status} — cannot mint TSA vector`);
  }

  const tsrBytes = new Uint8Array(await res.arrayBuffer());
  const parsed = parseTimeStampResp(tsrBytes);

  if (!parsed.granted) {
    throw new Error(`FreeTSA PKI status not granted (status=${parsed.status})`);
  }

  // ── Build cert chain SHA-256 pins ─────────────────────────────────────────
  const certChainSha256 = (parsed.signerInfo.certChainDer ?? []).map(
    (certDer) =>
      "sha256:" + crypto.createHash("sha256").update(certDer).digest("hex"),
  );

  // ── Build TsaBlock ────────────────────────────────────────────────────────
  const tsaBlock = {
    v: 1,
    tsr: base64UrlEncode(tsrBytes),
    alg: "sha-256",
    tsa_url: "https://freetsa.org/tsr",
    tsa_cert_chain_sha256: certChainSha256,
    issued_at: parsed.tstInfo.genTime,
  };

  const signedWithTsa = { ...signed, tsa: tsaBlock };

  // ── Verify imprint round-trip (sanity check before writing) ──────────────
  const recomputedImprint = computeTsaImprint(signedWithTsa);
  const tsrImprint = Buffer.from(parsed.tstInfo.hashedMessage);
  if (Buffer.compare(Buffer.from(recomputedImprint), tsrImprint) !== 0) {
    throw new Error("TSA imprint round-trip mismatch — TSA vector would be invalid");
  }

  // ── Load trust anchors to confirm verifiability ───────────────────────────
  const anchors = loadTrustAnchors([defaultTrustAnchorPath()]);
  const { verifyTsa } = await import("@dekimuhq/anchors-envelope/tsa");
  const refTime = new Date(parsed.tstInfo.genTime);
  const tsaResult = verifyTsa(tsrBytes, imprint, {
    anchors,
    driftToleranceSec: 300,
    referenceTime: refTime,
  });

  if (!tsaResult.verified || tsaResult.reason !== "tsa_verified") {
    throw new Error(
      `TSA verify sanity check failed: reason=${tsaResult.reason} — aborting TSA vector`,
    );
  }

  console.log(`arr-erasure-v2-tsa: TSA verified (anchor=${tsaResult.anchorName}, genTime=${tsaResult.genTime})`);

  return {
    name: "arr-erasure-v2-tsa",
    family: "arr",
    envelope_version: 2,
    receipt: signedWithTsa,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: true,
      tsa_state: "tsa_verified",
    },
  };
}

// ── ALR §J vector builders ───────────────────────────────────────────────────
//
// ALR is v=2 only — no v=1 path. Builds envelopes directly (same approach as
// the ACR/ARR v2 builders above) to keep determinism. `subject` is forced to
// `null` per FAMILY-CONSISTENCY §3 (lineage is dataset-level).
//
// Body shape mirrors `@dekimuhq/alr-issuer-kit#buildBody`. `field_root` is the
// SHA-256 over `0x00 || canonicalize(body-without-field_root)`, matching the
// issuer-kit's `computeFieldRoot` helper.

const ALR_ARTIFACT  = "sha256:" + "ca".repeat(32);
const ALR_PARENT_A  = "sha256:" + "cb".repeat(32);
const ALR_PARENT_B  = "sha256:" + "cc".repeat(32);
const ALR_SUCCESSOR = "sha256:" + "cd".repeat(32);
const ALR_POLICY_URI = "https://processor-alr.example/lineage-policy/v1";
const ALR_POLICY_HASH = "sha256:" + "ce".repeat(32);
const ALR_EVENT_AT = "2026-05-17T10:00:00Z";

function alrFieldRoot(body) {
  const bytes = new TextEncoder().encode(canonicalizeApr(body));
  const prefixed = Buffer.concat([Buffer.from([0x00]), Buffer.from(bytes)]);
  return "sha256:" + crypto.createHash("sha256").update(prefixed).digest("hex");
}

// Use Date.parse(IAT_ISO) directly — IAT_UNIX is intentionally left as the
// historical 1747440000 (2025-05-17) for v=1 vectors; v1.2 `iat_ms` requires
// strict parity with `Date.parse(iat)`, so re-derive from IAT_ISO here.
const IAT_MS = Date.parse(IAT_ISO);

async function signAlrEnvelope(id, body) {
  const preSign = {
    v: 2,
    id,
    iat: IAT_ISO,
    iat_ms: IAT_MS,
    claim_type: "ar.lineage.v1",
    iss: "did:web:processor-alr.example",
    iss_key: ISS_KEY,
    // FAMILY-CONSISTENCY §3 — ALR subject MUST be null. The Envelope type
    // declares subject as `string`; the verifier nulls it back out via
    // applyAlrSubjectPresence.
    subject: null,
    exp: null,
    prev: null,
    policy_uri: ALR_POLICY_URI,
    policy_hash: ALR_POLICY_HASH,
    policy_version: "1.0.0",
    kind: "decision",
    cause: null,
    predicate: null,
    tsa: null,
    credentialStatus: null,
    anchor: ANCHOR,
    sig: "",
    countersig: null,
    body,
  };
  return signEnvelope(preSign, PRIVATE_KEY);
}

async function buildAlrDerivedFromV2() {
  // Two APR-uncovered parents (parent_apr_id: null). Cross-issuer composition
  // is exercised by the dedicated vectors below.
  const parents = [
    { artifact_hash: ALR_PARENT_A, parent_apr_id: null, parent_alr_id: null, uri: null },
    { artifact_hash: ALR_PARENT_B, parent_apr_id: null, parent_alr_id: null, uri: null },
  ].sort((a, b) => (a.artifact_hash < b.artifact_hash ? -1 : 1));

  const bodyBase = {
    profile: "gdpr.art13.transparency",
    artifact_hash: ALR_ARTIFACT,
    event_at: ALR_EVENT_AT,
    event_type: "derived_from",
    parents,
    successor: null,
    transform_claim: { summary: "Merged two upstream datasets via row-level join.", uri: null },
    disclosure: null,
  };
  const body = { ...bodyBase, field_root: alrFieldRoot(bodyBase) };
  const signed = await signAlrEnvelope(ULID_ALR_DERIV, body);

  return {
    name: "alr-derived-from-v2",
    family: "alr",
    envelope_version: 2,
    receipt: signed,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: true,
      tsa_state: "tsa_absent",
    },
  };
}

async function buildAlrForkedFromV2() {
  const parents = [
    { artifact_hash: ALR_PARENT_A, parent_apr_id: null, parent_alr_id: null, uri: null },
  ];

  const bodyBase = {
    profile: "aiact.art13.transparency",
    artifact_hash: ALR_ARTIFACT,
    event_at: ALR_EVENT_AT,
    event_type: "forked_from",
    parents,
    successor: null,
    transform_claim: { summary: "Forked for downstream fine-tuning branch.", uri: null },
    disclosure: null,
  };
  const body = { ...bodyBase, field_root: alrFieldRoot(bodyBase) };
  const signed = await signAlrEnvelope(ULID_ALR_FORKED, body);

  return {
    name: "alr-forked-from-v2",
    family: "alr",
    envelope_version: 2,
    receipt: signed,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: true,
      tsa_state: "tsa_absent",
    },
  };
}

async function buildAlrDisclosedV2() {
  const bodyBase = {
    profile: "disclosure.recipients",
    artifact_hash: ALR_ARTIFACT,
    event_at: ALR_EVENT_AT,
    event_type: "disclosed",
    parents: [],
    successor: null,
    transform_claim: null,
    disclosure: {
      recipient: "did:web:dpa-cross-test.example",
      recipient_role: "supervisory_authority",
      scope_hash: "sha256:" + "df".repeat(32),
      basis: "gdpr.art6.1.c",
    },
  };
  const body = { ...bodyBase, field_root: alrFieldRoot(bodyBase) };
  const signed = await signAlrEnvelope(ULID_ALR_DISCL, body);

  return {
    name: "alr-disclosed-v2",
    family: "alr",
    envelope_version: 2,
    receipt: signed,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: true,
      tsa_state: "tsa_absent",
    },
  };
}

// ── ALR cross-issuer (composition with APR) ──────────────────────────────────

async function buildAlrDerivedFromV2AprCovered() {
  // One APR-covered parent — `parent_apr_id` cites a sibling APR receipt.
  const parents = [
    {
      artifact_hash: ALR_PARENT_A,
      parent_apr_id: ULID_APR_COMPOSED,
      parent_alr_id: null,
      uri: null,
    },
  ];

  const bodyBase = {
    profile: "aiact.art53.gpai-training",
    artifact_hash: ALR_ARTIFACT,
    event_at: ALR_EVENT_AT,
    event_type: "derived_from",
    parents,
    successor: null,
    transform_claim: { summary: "Trained model from APR-anchored corpus.", uri: null },
    disclosure: null,
  };
  const body = { ...bodyBase, field_root: alrFieldRoot(bodyBase) };
  const signed = await signAlrEnvelope(ULID_ALR_DERIV_APR, body);

  return {
    name: "alr-derived-from-v2-apr-covered",
    family: "alr",
    envelope_version: 2,
    receipt: signed,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: true,
      tsa_state: "tsa_absent",
    },
  };
}

async function buildAlrDerivedFromV2MixedParents() {
  // Two parents — one APR-covered, one uncovered. Exercises the composition
  // surface (`extractAprComposition`) which partitions parents on
  // `parent_apr_id`.
  const parents = [
    {
      artifact_hash: ALR_PARENT_A,
      parent_apr_id: ULID_APR_COMPOSED,
      parent_alr_id: null,
      uri: null,
    },
    { artifact_hash: ALR_PARENT_B, parent_apr_id: null, parent_alr_id: null, uri: null },
  ].sort((a, b) => (a.artifact_hash < b.artifact_hash ? -1 : 1));

  const bodyBase = {
    profile: "c2pa.non-media",
    artifact_hash: ALR_ARTIFACT,
    event_at: ALR_EVENT_AT,
    event_type: "derived_from",
    parents,
    successor: null,
    transform_claim: { summary: "Composed APR-anchored asset with external one.", uri: null },
    disclosure: null,
  };
  const body = { ...bodyBase, field_root: alrFieldRoot(bodyBase) };
  const signed = await signAlrEnvelope(ULID_ALR_DERIV_MIXED, body);

  return {
    name: "alr-derived-from-v2-mixed-parents",
    family: "alr",
    envelope_version: 2,
    receipt: signed,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: true,
      tsa_state: "tsa_absent",
    },
  };
}

// ── ALR negative vectors ─────────────────────────────────────────────────────
//
// Each negative starts from a positive ALR receipt and mutates one field to
// trigger a specific verifier failure path. The mutation MUST happen post-sign
// for the tampered-sig vector; for schema/structural negatives we build the
// receipt directly with the bad field so the signature itself remains valid
// over the malformed body.

async function buildAlrNegTamperedSig(positive) {
  // Flip the last byte of the signature. The verifier MUST fail closed on
  // signature mismatch — no body/structure error first.
  const r = positive.receipt;
  const sig = r.sig;
  const last = sig.charAt(sig.length - 1);
  // Replace last char with a different valid base64url char to keep length intact
  const flipped = (last === "A" ? "B" : "A");
  const tamperedSig = sig.slice(0, -1) + flipped;

  return {
    name: "alr-neg-tampered-sig",
    family: "alr",
    envelope_version: 2,
    receipt: { ...r, sig: tamperedSig },
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: false,
    },
  };
}

async function buildAlrNegUnknownProfile() {
  // Profile not in the registered union. The alr-verifier rejects on unknown
  // profile (§5 profile dispatch) before reaching the signature check.
  const bodyBase = {
    profile: "unknown.profile.v0",
    artifact_hash: ALR_ARTIFACT,
    event_at: ALR_EVENT_AT,
    event_type: "derived_from",
    parents: [
      { artifact_hash: ALR_PARENT_A, parent_apr_id: null, parent_alr_id: null, uri: null },
    ],
    successor: null,
    transform_claim: { summary: "Negative — unknown profile.", uri: null },
    disclosure: null,
  };
  const body = { ...bodyBase, field_root: alrFieldRoot(bodyBase) };
  // Sign over the bad body so structural rejection (not sig mismatch) is the
  // proven failure path.
  const signed = await signAlrEnvelope("01HXXALRNEGPROFILE00000001", body);

  return {
    name: "alr-neg-unknown-profile",
    family: "alr",
    envelope_version: 2,
    receipt: signed,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: false,
    },
  };
}

async function buildAlrNegSubjectPresent() {
  // FAMILY-CONSISTENCY §3 — ALR `subject` MUST be null. A non-null subject
  // must be rejected by `applyAlrSubjectPresence` regardless of signature.
  const bodyBase = {
    profile: "gdpr.art13.transparency",
    artifact_hash: ALR_ARTIFACT,
    event_at: ALR_EVENT_AT,
    event_type: "derived_from",
    parents: [
      { artifact_hash: ALR_PARENT_A, parent_apr_id: null, parent_alr_id: null, uri: null },
    ],
    successor: null,
    transform_claim: { summary: "Negative — subject MUST be null.", uri: null },
    disclosure: null,
  };
  const body = { ...bodyBase, field_root: alrFieldRoot(bodyBase) };
  const preSign = {
    v: 2,
    id: "01HXXALRNEGSUBJECT00000001",
    iat: IAT_ISO,
    iat_ms: IAT_MS,
    claim_type: "ar.lineage.v1",
    iss: "did:web:processor-alr.example",
    iss_key: ISS_KEY,
    // Violates FAMILY-CONSISTENCY §3 — verifier MUST fail closed.
    subject: "sha256:" + "ab".repeat(32),
    exp: null,
    prev: null,
    policy_uri: ALR_POLICY_URI,
    policy_hash: ALR_POLICY_HASH,
    policy_version: "1.0.0",
    kind: "decision",
    cause: null,
    predicate: null,
    tsa: null,
    credentialStatus: null,
    anchor: ANCHOR,
    sig: "",
    countersig: null,
    body,
  };
  const signed = await signEnvelope(preSign, PRIVATE_KEY);

  return {
    name: "alr-neg-subject-present",
    family: "alr",
    envelope_version: 2,
    receipt: signed,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: false,
    },
  };
}

// ── ANR §J.1 vector builders ─────────────────────────────────────────────────
//
// ANR is v=2 only (claim_type `ar.notice.v1`). Builds envelopes directly via
// signEnvelope to keep determinism, mirroring the ALR §J pattern above.
//
// Family invariants enforced:
//   - POLICY_BOUND — policy_uri/hash/version required (§B fix).
//   - lang_tag REQUIRED on every body (D10-ANR-2).
//   - `notice.translated` forces envelope `prev: null` (D10-ANR-5).
//   - `notice.acknowledged` subject MUST be `sha256:<hex>` (FAMILY-CONSISTENCY
//     §3); other event_types MAY be `sha256:<hex>` OR `null`.
//   - field_root = `sha256:<hex>` over `0x00 || canonicalize(body)` where the
//     body excludes `field_root` itself (matches `computeFieldRoot` in
//     anr-issuer-kit).
//
// Cross-issuer surfaces exercised:
//   - `notice.translated.translation_provenance_alr_id` cites a sibling ALR
//     `derived_from` receipt (spec §8.3 ALR composition).
//   - `notice.acknowledged` with `prev` pointing at a sibling `notice.presented`
//     (spec §4.3 + §C chain walker).
//
// Negatives:
//   - tampered-sig — flip last byte of sig.
//   - ack-subject-null — `notice.acknowledged` with subject: null
//     (FAMILY-CONSISTENCY §3 violation; caught by applyAnrSubjectPresence).
//   - art50-no-tsa — AI Act `notice.aiact.art50_transparency` profile minted
//     without a TSA block. The §D TSA mandate matrix upgrades `tsa_absent` to
//     `tsa_required` and poisons signature_valid (per FAMILY-CONSISTENCY §2 +
//     spec §5.5). The other negatives (unknown profile, structural body errors)
//     are NOT exercised by verifyReceipt — body validation in ANR is exposed
//     separately as `verifyAnrBody()` and is caller-driven.

const ANR_POLICY_URI = "https://controller-anr.example/notice-policy/v1";
const ANR_POLICY_HASH = "sha256:" + "ba".repeat(32);
const ANR_POLICY_VERSION = "1.0.0";
const ANR_ISS = "did:web:controller-anr.example";
const ANR_RENDER_URI = "https://controller-anr.example/notice/v1/en";
const ANR_RIGHTS_SURFACE = ["art15", "art16", "art17", "art18", "art20", "art21"];
const ANR_ACK_SUBJECT = "sha256:" + "ac".repeat(32);

const ULID_ANR_PRESENTED       = "01HXXANRPRESENTEDV2CROSS01";
const ULID_ANR_JCE             = "01HXXANRJOINTCTRLESSENCE01";
const ULID_ANR_WITHDRAWN       = "01HXXANRWITHDRAWNV2CROSS01";
const ULID_ANR_TRANSLATED      = "01HXXANRTRANSLATEDV2CROSS1";
const ULID_ANR_ACK             = "01HXXANRACKNOWLEDGEDV2CRS1";
const ULID_ANR_NEG_TAMPERED    = "01HXXANRNEGTAMPEREDSIG0001"; // unused (mutated post-sign)
const ULID_ANR_NEG_ACK_NULL    = "01HXXANRNEGACKSUBJNULL0001";
const ULID_ANR_NEG_ART50_NOTSA = "01HXXANRNEGART50NOTSA00001";

function anrFieldRoot(body) {
  // body MUST exclude `field_root` itself — matches computeFieldRoot in
  // @dekimuhq/anr-issuer-kit which canonicalises baseBody before field_root
  // is appended.
  const bytes = new TextEncoder().encode(canonicalizeApr(body));
  const prefixed = Buffer.concat([Buffer.from([0x00]), Buffer.from(bytes)]);
  return "sha256:" + crypto.createHash("sha256").update(prefixed).digest("hex");
}

async function signAnrEnvelope({ id, subject, prev, body }) {
  const preSign = {
    v: 2,
    id,
    iat: IAT_ISO,
    iat_ms: IAT_MS,
    claim_type: "ar.notice.v1",
    iss: ANR_ISS,
    iss_key: ISS_KEY,
    // ANR subject is per-event-split (FAMILY-CONSISTENCY §3). Envelope type
    // declares string; verifier reconciles via applyAnrSubjectPresence.
    subject,
    exp: null,
    prev,
    policy_uri: ANR_POLICY_URI,
    policy_hash: ANR_POLICY_HASH,
    policy_version: ANR_POLICY_VERSION,
    kind: "decision",
    cause: null,
    predicate: null,
    tsa: null,
    credentialStatus: null,
    anchor: ANCHOR,
    sig: "",
    countersig: null,
    body,
  };
  return signEnvelope(preSign, PRIVATE_KEY);
}

function anrPresentedBodyBase({ profile = "notice.art13.collected_direct", overrides = {} } = {}) {
  return {
    profile,
    lang_tag: "en-GB",
    lang_inferred: null,
    event_type: "notice.presented",
    jurisdiction: "EU",
    delivery_channel: "web",
    render_uri: ANR_RENDER_URI,
    rights_surface: ANR_RIGHTS_SURFACE,
    subject_age_band: "adult",
    data_source: null,
    collection_horizon: null,
    data_acquired_at: null,
    layer_uris: null,
    ai_system_kind: null,
    ai_system_provider_did: null,
    aer_id: null,
    supersedes_anr_id: null,
    base_anr_id: null,
    ack_method: null,
    joint_controllers: null,
    cessation_reason: null,
    translation_provenance_alr_id: null,
    ...overrides,
  };
}

async function buildAnrPresentedV2() {
  const bodyBase = anrPresentedBodyBase();
  const body = { ...bodyBase, field_root: anrFieldRoot(bodyBase) };
  const signed = await signAnrEnvelope({
    id: ULID_ANR_PRESENTED,
    subject: null,
    prev: null,
    body,
  });

  return {
    name: "anr-presented-v2",
    family: "anr",
    envelope_version: 2,
    receipt: signed,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: true,
      tsa_state: "tsa_recommended",
    },
  };
}

async function buildAnrJointControllerEssenceV2() {
  const bodyBase = {
    profile: "notice.art26.joint_controller_essence",
    lang_tag: "en-GB",
    lang_inferred: null,
    event_type: "notice.joint_controller_essence",
    jurisdiction: "EU",
    joint_controllers: [
      {
        did: "did:web:co-controller-a.example",
        role: "marketing analytics",
        contact_point_uri: "https://co-controller-a.example/privacy",
        adr_id: null,
      },
      {
        did: "did:web:co-controller-b.example",
        role: "ad delivery",
        contact_point_uri: "https://co-controller-b.example/privacy",
        adr_id: null,
      },
    ],
    delivery_channel: null,
    render_uri: null,
    rights_surface: null,
    subject_age_band: null,
    data_source: null,
    collection_horizon: null,
    data_acquired_at: null,
    layer_uris: null,
    ai_system_kind: null,
    ai_system_provider_did: null,
    aer_id: null,
    supersedes_anr_id: null,
    base_anr_id: null,
    ack_method: null,
    cessation_reason: null,
    translation_provenance_alr_id: null,
  };
  const body = { ...bodyBase, field_root: anrFieldRoot(bodyBase) };
  const signed = await signAnrEnvelope({
    id: ULID_ANR_JCE,
    subject: null,
    prev: null,
    body,
  });

  return {
    name: "anr-joint-controller-essence-v2",
    family: "anr",
    envelope_version: 2,
    receipt: signed,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: true,
      tsa_state: "tsa_recommended",
    },
  };
}

async function buildAnrWithdrawnV2(presentedVector) {
  // Cessation form — `cessation_reason` set, `supersedes_anr_id` null. The
  // XOR rule is asserted by §C body verifier; the supersession form is
  // exercised by the per-package mint-v2 unit suite.
  const bodyBase = {
    profile: "notice.art13.collected_direct",
    lang_tag: "en-GB",
    lang_inferred: null,
    event_type: "notice.withdrawn",
    jurisdiction: "EU",
    supersedes_anr_id: null,
    cessation_reason: "controller_ceased_processing",
    delivery_channel: null,
    render_uri: null,
    rights_surface: null,
    subject_age_band: null,
    data_source: null,
    collection_horizon: null,
    data_acquired_at: null,
    layer_uris: null,
    ai_system_kind: null,
    ai_system_provider_did: null,
    aer_id: null,
    base_anr_id: null,
    ack_method: null,
    joint_controllers: null,
    translation_provenance_alr_id: null,
  };
  const body = { ...bodyBase, field_root: anrFieldRoot(bodyBase) };
  const signed = await signAnrEnvelope({
    id: ULID_ANR_WITHDRAWN,
    subject: null,
    prev: presentedVector.receipt.id,
    body,
  });

  return {
    name: "anr-withdrawn-v2",
    family: "anr",
    envelope_version: 2,
    receipt: signed,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: true,
      tsa_state: "tsa_recommended",
    },
  };
}

async function buildAnrTranslatedV2WithAlrProv(alrDerivedVector) {
  // Cross-issuer composition surface (spec §8.3): translation_provenance_alr_id
  // cites a sibling ALR `derived_from` receipt. envelope.prev MUST be null
  // (D10-ANR-5).
  const bodyBase = {
    profile: "notice.art13.collected_direct",
    lang_tag: "fr-FR",
    lang_inferred: null,
    event_type: "notice.translated",
    base_anr_id: ULID_ANR_PRESENTED,
    jurisdiction: null,
    translation_provenance_alr_id: alrDerivedVector.receipt.id,
    delivery_channel: null,
    render_uri: null,
    rights_surface: null,
    subject_age_band: null,
    data_source: null,
    collection_horizon: null,
    data_acquired_at: null,
    layer_uris: null,
    ai_system_kind: null,
    ai_system_provider_did: null,
    aer_id: null,
    supersedes_anr_id: null,
    ack_method: null,
    joint_controllers: null,
    cessation_reason: null,
  };
  const body = { ...bodyBase, field_root: anrFieldRoot(bodyBase) };
  const signed = await signAnrEnvelope({
    id: ULID_ANR_TRANSLATED,
    subject: null,
    prev: null,
    body,
  });

  return {
    name: "anr-translated-v2-alr-provenance",
    family: "anr",
    envelope_version: 2,
    receipt: signed,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: true,
      tsa_state: "tsa_recommended",
    },
  };
}

async function buildAnrAcknowledgedV2OnPresented(presentedVector) {
  // Cross-issuer / chain composition surface (spec §4.3 + §C chain walker):
  // `notice.acknowledged` envelope's prev cites the sibling `notice.presented`.
  // Subject MUST be sha256:<hex> per FAMILY-CONSISTENCY §3.
  const bodyBase = {
    profile: "notice.art13.collected_direct",
    lang_tag: "en-GB",
    lang_inferred: null,
    event_type: "notice.acknowledged",
    jurisdiction: "EU",
    ack_method: "checkbox",
    delivery_channel: null,
    render_uri: null,
    rights_surface: null,
    subject_age_band: null,
    data_source: null,
    collection_horizon: null,
    data_acquired_at: null,
    layer_uris: null,
    ai_system_kind: null,
    ai_system_provider_did: null,
    aer_id: null,
    supersedes_anr_id: null,
    base_anr_id: null,
    joint_controllers: null,
    cessation_reason: null,
    translation_provenance_alr_id: null,
  };
  const body = { ...bodyBase, field_root: anrFieldRoot(bodyBase) };
  const signed = await signAnrEnvelope({
    id: ULID_ANR_ACK,
    subject: ANR_ACK_SUBJECT,
    prev: presentedVector.receipt.id,
    body,
  });

  return {
    name: "anr-acknowledged-v2-on-presented",
    family: "anr",
    envelope_version: 2,
    receipt: signed,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: true,
      tsa_state: "tsa_recommended",
    },
  };
}

// ── ANR negative vectors ─────────────────────────────────────────────────────

async function buildAnrNegTamperedSig(positive) {
  const r = positive.receipt;
  const sig = r.sig;
  const last = sig.charAt(sig.length - 1);
  const flipped = last === "A" ? "B" : "A";
  const tamperedSig = sig.slice(0, -1) + flipped;

  return {
    name: "anr-neg-tampered-sig",
    family: "anr",
    envelope_version: 2,
    receipt: { ...r, sig: tamperedSig },
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: false,
    },
  };
}

async function buildAnrNegAckSubjectNull() {
  // FAMILY-CONSISTENCY §3 — `notice.acknowledged` subject MUST be sha256:<hex>.
  // A null subject must be rejected by applyAnrSubjectPresence regardless of
  // signature. Sign over the body so structural rejection is the proven path.
  const bodyBase = {
    profile: "notice.art13.collected_direct",
    lang_tag: "en-GB",
    lang_inferred: null,
    event_type: "notice.acknowledged",
    jurisdiction: "EU",
    ack_method: "checkbox",
    delivery_channel: null,
    render_uri: null,
    rights_surface: null,
    subject_age_band: null,
    data_source: null,
    collection_horizon: null,
    data_acquired_at: null,
    layer_uris: null,
    ai_system_kind: null,
    ai_system_provider_did: null,
    aer_id: null,
    supersedes_anr_id: null,
    base_anr_id: null,
    joint_controllers: null,
    cessation_reason: null,
    translation_provenance_alr_id: null,
  };
  const body = { ...bodyBase, field_root: anrFieldRoot(bodyBase) };
  const signed = await signAnrEnvelope({
    id: ULID_ANR_NEG_ACK_NULL,
    subject: null,
    prev: null,
    body,
  });

  return {
    name: "anr-neg-ack-subject-null",
    family: "anr",
    envelope_version: 2,
    receipt: signed,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: false,
    },
  };
}

async function buildAnrNegArt50NoTsa() {
  // FAMILY-CONSISTENCY §2 + spec §5.5: `notice.aiact.art50_transparency` is
  // the only ANR profile where TSA is MANDATORY. The §D TSA mandate matrix
  // (applyAnrTsaMandate) upgrades `tsa_absent` to `tsa_required` and poisons
  // signature_valid. Mint a valid-otherwise art50 receipt with no TSA block.
  const bodyBase = anrPresentedBodyBase({
    profile: "notice.aiact.art50_transparency",
    overrides: {
      subject_age_band: null,
      ai_system_kind: "interaction",
      ai_system_provider_did: "did:web:ai-provider-anr.example",
    },
  });
  const body = { ...bodyBase, field_root: anrFieldRoot(bodyBase) };
  const signed = await signAnrEnvelope({
    id: ULID_ANR_NEG_ART50_NOTSA,
    subject: null,
    prev: null,
    body,
  });

  return {
    name: "anr-neg-art50-no-tsa",
    family: "anr",
    envelope_version: 2,
    receipt: signed,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: false,
      tsa_state: "tsa_required",
    },
  };
}

// ── ABR §J.2 vector builders ─────────────────────────────────────────────────
//
// ABR is v=2 only (claim_type `ar.breach.v1`). Builds envelopes directly via
// signEnvelope to keep determinism, mirroring the ANR §J.1 pattern above.
//
// Family invariants enforced:
//   - POLICY_BOUND — policy_uri/hash/version required.
//   - incident_correlation_id REQUIRED on every body (D10-ABR-3); identical
//     across all receipts for the same incident.
//   - `breach.subject_notified` subject MUST be `"sha256:<hex>"` and bound to
//     `body.subject_batch_root` (FAMILY-CONSISTENCY §3 + D10-ABR-4); every
//     other event MUST be `null`.
//   - `breach.detected` MANDATORY TSA (D10-ABR-2 / FAMILY-CONSISTENCY §2);
//     absent TSA poisons signature_valid with reason "tsa_required". The
//     §J positive vectors here pick events that are TSA RECOMMENDED so they
//     stay byte-deterministic without a captured TSR; the MANDATORY path is
//     exercised by the §J negative below.
//   - field_root = `sha256:<hex>` over `0x00 || canonicalize(body)` where the
//     body excludes `field_root` itself (matches `computeFieldRoot` in
//     abr-issuer-kit).
//
// Cross-issuer surfaces exercised:
//   - `breach.contained.containment_remediation_arr_ids` cites a sibling ARR
//     `ar.erasure.v1` receipt id (spec §8.3, audit fix C5).
//   - `breach.closed.post_breach_anr_id` cites a sibling ANR
//     `ar.notice.v1` (notice.presented) receipt id (spec §8.5, audit fix C5).
//
// Negatives:
//   - tampered-sig — flip last byte of sig.
//   - detected-no-tsa — `breach.detected` minted without a TSA block. The §D
//     MANDATORY mandate upgrades `tsa_absent` to `tsa_required` and poisons
//     signature_valid (per FAMILY-CONSISTENCY §2 + spec §4.1 + D10-ABR-2).
//   - subject-notified-null — `subject_notified` with subject:null. §E
//     subject-presence flags `subject_missing` and poisons signature_valid.

const ABR_POLICY_URI     = "https://controller-abr.example/breach-policy/v1";
const ABR_POLICY_HASH    = "sha256:" + "bb".repeat(32);
const ABR_POLICY_VERSION = "1.0.0";
const ABR_ISS            = "did:web:controller-abr.example";
const ABR_INCIDENT_ID    = "incident-abr-cross-001";

const ABR_AFFECTED_HASH      = "sha256:" + "ad".repeat(32);
const ABR_ASSESSMENT_HASH    = "sha256:" + "ae".repeat(32);
const ABR_NOTIFICATION_HASH  = "sha256:" + "af".repeat(32);
const ABR_CONTAINMENT_HASH   = "sha256:" + "c0".repeat(32);
const ABR_SUBJECT_BATCH_ROOT = "sha256:" + "ab".repeat(32);

const ULID_ABR_ASSESSED      = "01HXXABRASSESSEDV2CROSS002";
const ULID_ABR_DPA_NOTIFIED  = "01HXXABRDPANOTIFIEDNIS2003";
const ULID_ABR_SUBJ_NOTIFIED = "01HXXABRSUBJECTNOTIFIED004";
const ULID_ABR_CONTAINED_ARR = "01HXXABRCONTAINEDARRCMP005";
const ULID_ABR_CLOSED_ANR    = "01HXXABRCLOSEDV2ANRCMP0006";
const ULID_ABR_NEG_TAMPERED  = "01HXXABRNEGTAMPEREDSIG0001"; // unused (mutated post-sign)
const ULID_ABR_NEG_NO_TSA    = "01HXXABRNEGNOTSADETECT0001";
const ULID_ABR_NEG_SUBJ_NULL = "01HXXABRNEGSUBJECTNULL0001";

function abrFieldRoot(body) {
  const bytes = new TextEncoder().encode(canonicalizeApr(body));
  const prefixed = Buffer.concat([Buffer.from([0x00]), Buffer.from(bytes)]);
  return "sha256:" + crypto.createHash("sha256").update(prefixed).digest("hex");
}

async function signAbrEnvelope({ id, subject, prev, body, tsa = null }) {
  const preSign = {
    v: 2,
    id,
    iat: IAT_ISO,
    iat_ms: IAT_MS,
    claim_type: "ar.breach.v1",
    iss: ABR_ISS,
    iss_key: ISS_KEY,
    // ABR subject is per-event split (FAMILY-CONSISTENCY §3). Envelope type
    // declares string; verifier reconciles via applyAbrSubjectPresence.
    subject,
    exp: null,
    prev,
    policy_uri: ABR_POLICY_URI,
    policy_hash: ABR_POLICY_HASH,
    policy_version: ABR_POLICY_VERSION,
    kind: "decision",
    cause: null,
    predicate: null,
    tsa,
    credentialStatus: null,
    anchor: ANCHOR,
    sig: "",
    countersig: null,
    body,
  };
  return signEnvelope(preSign, PRIVATE_KEY);
}

function abrAssessedBodyBase({ profile = "breach.gdpr.art33", overrides = {} } = {}) {
  return {
    profile,
    incident_correlation_id: ABR_INCIDENT_ID,
    event_type: "breach.assessed",
    severity_class: "high_risk",
    assessment_method_hash: ABR_ASSESSMENT_HASH,
    detected_at: null,
    affected_data_categories: null,
    affected_data_hash: null,
    affected_count: null,
    jurisdiction: null,
    notification_uri: null,
    notification_hash: null,
    dpa_reference_id: null,
    notification_phase: null,
    delay_reason_hash: null,
    delay_until_at: null,
    subject_batch_root: null,
    subject_batch_size: null,
    exemption_ground: null,
    justification_hash: null,
    public_communication_uri: null,
    containment_at: null,
    containment_summary_hash: null,
    containment_attestation: null,
    closed_at: null,
    closure_dpa_reference_id: null,
    affected_aer_ids: null,
    containment_remediation_arr_ids: null,
    transfer_suspension_atr_ids: null,
    post_breach_anr_id: null,
    qes_aar_id: null,
    ...overrides,
  };
}

async function buildAbrAssessedV2() {
  const bodyBase = abrAssessedBodyBase();
  const body = { ...bodyBase, field_root: abrFieldRoot(bodyBase) };
  const signed = await signAbrEnvelope({
    id: ULID_ABR_ASSESSED,
    subject: null,
    prev: null,
    body,
  });

  return {
    name: "abr-assessed-v2",
    family: "abr",
    envelope_version: 2,
    receipt: signed,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: true,
      tsa_state: "tsa_recommended",
    },
  };
}

async function buildAbrDpaNotifiedNis2V2() {
  // NIS2 Art. 23 — notification_phase REQUIRED on this profile only (spec
  // §4.3); qes_aar_id is null here since the QES (Article 21 eIDAS) pilot
  // path is exercised by the AAR family, not this cross-family scenario.
  const bodyBase = {
    profile: "breach.nis2.art23",
    incident_correlation_id: ABR_INCIDENT_ID,
    event_type: "breach.dpa_notified",
    notification_uri: "https://nis2-dpa.example/case/abr-001",
    notification_hash: ABR_NOTIFICATION_HASH,
    dpa_reference_id: "NIS2-2026-0042",
    notification_phase: "full_notification",
    qes_aar_id: null,
    detected_at: null,
    severity_class: null,
    affected_data_categories: null,
    affected_data_hash: null,
    affected_count: null,
    jurisdiction: null,
    assessment_method_hash: null,
    delay_reason_hash: null,
    delay_until_at: null,
    subject_batch_root: null,
    subject_batch_size: null,
    exemption_ground: null,
    justification_hash: null,
    public_communication_uri: null,
    containment_at: null,
    containment_summary_hash: null,
    containment_attestation: null,
    closed_at: null,
    closure_dpa_reference_id: null,
    affected_aer_ids: null,
    containment_remediation_arr_ids: null,
    transfer_suspension_atr_ids: null,
    post_breach_anr_id: null,
  };
  const body = { ...bodyBase, field_root: abrFieldRoot(bodyBase) };
  const signed = await signAbrEnvelope({
    id: ULID_ABR_DPA_NOTIFIED,
    subject: null,
    prev: null,
    body,
  });

  return {
    name: "abr-dpa-notified-v2-nis2",
    family: "abr",
    envelope_version: 2,
    receipt: signed,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: true,
      tsa_state: "tsa_recommended",
    },
  };
}

async function buildAbrSubjectNotifiedV2() {
  const bodyBase = {
    profile: "breach.gdpr.art34",
    incident_correlation_id: ABR_INCIDENT_ID,
    event_type: "breach.subject_notified",
    subject_batch_root: ABR_SUBJECT_BATCH_ROOT,
    subject_batch_size: 1024,
    notification_uri: "https://controller-abr.example/notice/v1/en",
    notification_hash: ABR_NOTIFICATION_HASH,
    detected_at: null,
    severity_class: null,
    affected_data_categories: null,
    affected_data_hash: null,
    affected_count: null,
    jurisdiction: null,
    assessment_method_hash: null,
    dpa_reference_id: null,
    notification_phase: null,
    delay_reason_hash: null,
    delay_until_at: null,
    exemption_ground: null,
    justification_hash: null,
    public_communication_uri: null,
    containment_at: null,
    containment_summary_hash: null,
    containment_attestation: null,
    closed_at: null,
    closure_dpa_reference_id: null,
    affected_aer_ids: null,
    containment_remediation_arr_ids: null,
    transfer_suspension_atr_ids: null,
    post_breach_anr_id: null,
    qes_aar_id: null,
  };
  const body = { ...bodyBase, field_root: abrFieldRoot(bodyBase) };
  const signed = await signAbrEnvelope({
    id: ULID_ABR_SUBJ_NOTIFIED,
    // D10-ABR-4 — envelope subject MUST equal body.subject_batch_root.
    subject: ABR_SUBJECT_BATCH_ROOT,
    prev: null,
    body,
  });

  return {
    name: "abr-subject-notified-v2",
    family: "abr",
    envelope_version: 2,
    receipt: signed,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: true,
      tsa_state: "tsa_recommended",
    },
  };
}

async function buildAbrContainedV2ArrComposed(arrErasureV2Vector) {
  // Cross-family: cite an ARR `ar.erasure.v1` receipt id under
  // containment_remediation_arr_ids (spec §8.3 + audit fix C5). Verifier
  // accepts the id as opaque — composition walk lives in abr-issuer-kit and
  // is not exercised at envelope-verify time.
  const arrReceiptId = arrErasureV2Vector.receipt.id;
  const bodyBase = {
    profile: "breach.gdpr.art33",
    incident_correlation_id: ABR_INCIDENT_ID,
    event_type: "breach.contained",
    containment_at: "2026-05-17T04:00:00Z",
    containment_summary_hash: ABR_CONTAINMENT_HASH,
    containment_attestation: null,
    containment_remediation_arr_ids: [arrReceiptId],
    transfer_suspension_atr_ids: null,
    detected_at: null,
    severity_class: null,
    affected_data_categories: null,
    affected_data_hash: null,
    affected_count: null,
    jurisdiction: null,
    assessment_method_hash: null,
    notification_uri: null,
    notification_hash: null,
    dpa_reference_id: null,
    notification_phase: null,
    delay_reason_hash: null,
    delay_until_at: null,
    subject_batch_root: null,
    subject_batch_size: null,
    exemption_ground: null,
    justification_hash: null,
    public_communication_uri: null,
    closed_at: null,
    closure_dpa_reference_id: null,
    affected_aer_ids: null,
    post_breach_anr_id: null,
    qes_aar_id: null,
  };
  const body = { ...bodyBase, field_root: abrFieldRoot(bodyBase) };
  const signed = await signAbrEnvelope({
    id: ULID_ABR_CONTAINED_ARR,
    subject: null,
    prev: null,
    body,
  });

  return {
    name: "abr-contained-v2-arr-composed",
    family: "abr",
    envelope_version: 2,
    receipt: signed,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: true,
      tsa_state: "tsa_recommended",
    },
  };
}

async function buildAbrClosedV2AnrComposed(anrPresentedVector) {
  // Cross-family: cite an ANR `ar.notice.v1` receipt id under
  // post_breach_anr_id (spec §8.5 + audit fix C5).
  const anrReceiptId = anrPresentedVector.receipt.id;
  const bodyBase = {
    profile: "breach.gdpr.art33",
    incident_correlation_id: ABR_INCIDENT_ID,
    event_type: "breach.closed",
    closed_at: "2026-05-17T12:00:00Z",
    closure_dpa_reference_id: "DPA-2026-0042",
    post_breach_anr_id: anrReceiptId,
    detected_at: null,
    severity_class: null,
    affected_data_categories: null,
    affected_data_hash: null,
    affected_count: null,
    jurisdiction: null,
    assessment_method_hash: null,
    notification_uri: null,
    notification_hash: null,
    dpa_reference_id: null,
    notification_phase: null,
    delay_reason_hash: null,
    delay_until_at: null,
    subject_batch_root: null,
    subject_batch_size: null,
    exemption_ground: null,
    justification_hash: null,
    public_communication_uri: null,
    containment_at: null,
    containment_summary_hash: null,
    containment_attestation: null,
    affected_aer_ids: null,
    containment_remediation_arr_ids: null,
    transfer_suspension_atr_ids: null,
    qes_aar_id: null,
  };
  const body = { ...bodyBase, field_root: abrFieldRoot(bodyBase) };
  const signed = await signAbrEnvelope({
    id: ULID_ABR_CLOSED_ANR,
    subject: null,
    prev: null,
    body,
  });

  return {
    name: "abr-closed-v2-anr-composed",
    family: "abr",
    envelope_version: 2,
    receipt: signed,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: true,
      tsa_state: "tsa_recommended",
    },
  };
}

// ── ABR negative vectors ─────────────────────────────────────────────────────

async function buildAbrNegTamperedSig(positive) {
  const r = positive.receipt;
  const sig = r.sig;
  const last = sig.charAt(sig.length - 1);
  const flipped = last === "A" ? "B" : "A";
  const tamperedSig = sig.slice(0, -1) + flipped;

  return {
    name: "abr-neg-tampered-sig",
    family: "abr",
    envelope_version: 2,
    receipt: { ...r, sig: tamperedSig, id: ULID_ABR_NEG_TAMPERED },
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: false,
    },
  };
}

async function buildAbrNegDetectedNoTsa() {
  // FAMILY-CONSISTENCY §2 + spec §4.1 + D10-ABR-2: `breach.detected` is the
  // ONLY ABR event with MANDATORY TSA — the 72-hour Art. 33 clock starts
  // here. The §D TSA mandate matrix (applyAbrTsaMandate) upgrades
  // `tsa_absent` to `tsa_required` and poisons signature_valid. Mint a
  // valid-otherwise detected receipt with no TSA block.
  const bodyBase = {
    profile: "breach.gdpr.art33",
    incident_correlation_id: ABR_INCIDENT_ID,
    event_type: "breach.detected",
    detected_at: "2026-05-17T00:00:00Z",
    severity_class: "high_risk",
    affected_data_categories: ["contact_info", "auth_credentials"],
    affected_data_hash: ABR_AFFECTED_HASH,
    affected_count: 1024,
    jurisdiction: "EU",
    affected_aer_ids: null,
    assessment_method_hash: null,
    notification_uri: null,
    notification_hash: null,
    dpa_reference_id: null,
    notification_phase: null,
    delay_reason_hash: null,
    delay_until_at: null,
    subject_batch_root: null,
    subject_batch_size: null,
    exemption_ground: null,
    justification_hash: null,
    public_communication_uri: null,
    containment_at: null,
    containment_summary_hash: null,
    containment_attestation: null,
    closed_at: null,
    closure_dpa_reference_id: null,
    containment_remediation_arr_ids: null,
    transfer_suspension_atr_ids: null,
    post_breach_anr_id: null,
    qes_aar_id: null,
  };
  const body = { ...bodyBase, field_root: abrFieldRoot(bodyBase) };
  const signed = await signAbrEnvelope({
    id: ULID_ABR_NEG_NO_TSA,
    subject: null,
    prev: null,
    body,
  });

  return {
    name: "abr-neg-detected-no-tsa",
    family: "abr",
    envelope_version: 2,
    receipt: signed,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: false,
      reason: "tsa_required",
      tsa_state: "tsa_required",
    },
  };
}

async function buildAbrNegSubjectNotifiedNull() {
  // FAMILY-CONSISTENCY §3 + D10-ABR-4 — `breach.subject_notified` subject
  // MUST be `sha256:<hex>` (the batch root). A null subject must be rejected
  // by applyAbrSubjectPresence regardless of signature.
  const bodyBase = {
    profile: "breach.gdpr.art34",
    incident_correlation_id: ABR_INCIDENT_ID,
    event_type: "breach.subject_notified",
    subject_batch_root: ABR_SUBJECT_BATCH_ROOT,
    subject_batch_size: 64,
    notification_uri: "https://controller-abr.example/notice/v1/en",
    notification_hash: ABR_NOTIFICATION_HASH,
    detected_at: null,
    severity_class: null,
    affected_data_categories: null,
    affected_data_hash: null,
    affected_count: null,
    jurisdiction: null,
    assessment_method_hash: null,
    dpa_reference_id: null,
    notification_phase: null,
    delay_reason_hash: null,
    delay_until_at: null,
    exemption_ground: null,
    justification_hash: null,
    public_communication_uri: null,
    containment_at: null,
    containment_summary_hash: null,
    containment_attestation: null,
    closed_at: null,
    closure_dpa_reference_id: null,
    affected_aer_ids: null,
    containment_remediation_arr_ids: null,
    transfer_suspension_atr_ids: null,
    post_breach_anr_id: null,
    qes_aar_id: null,
  };
  const body = { ...bodyBase, field_root: abrFieldRoot(bodyBase) };
  const signed = await signAbrEnvelope({
    id: ULID_ABR_NEG_SUBJ_NULL,
    subject: null,
    prev: null,
    body,
  });

  return {
    name: "abr-neg-subject-notified-null",
    family: "abr",
    envelope_version: 2,
    receipt: signed,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: false,
      reason: "subject_missing",
    },
  };
}

// ── ASR §J.3 vector builders ─────────────────────────────────────────────────
//
// ASR is v=2 only (claim_type `ar.subject_rights.v1`). Builds envelopes
// directly via signEnvelope to keep determinism, mirroring the ABR §J.2
// pattern above.
//
// Family invariants enforced:
//   - POLICY_BOUND — policy_uri/hash/version required.
//   - subject MUST be `"sha256:<hex>"` on EVERY event (D10-ASR-5 uniform
//     subject-presence rule). subject_rights.checkAsrSubjectPresence handles
//     the format check.
//   - body.subject_rights_request_id REQUIRED on every body (D10-ASR-2);
//     identical across all receipts in one request lifecycle.
//   - No TSA mandate in the factory manifest (asrFamily omits `tsa_mandate`);
//     all positive vectors mint with `tsa: null` and surface
//     `tsa_state: "tsa_absent"` at verify time.
//   - Bodies carry no `field_root` (the factory mint pipeline does not add
//     one; the verifier does not check one).
//
// Cross-issuer surface exercised:
//   - art17.erasure_request `request.fulfilled.arr_receipt_id` cites a
//     sibling ARR `ar.erasure.v1` receipt id (D10-ASR-3 MANDATORY link,
//     spec §5.3). The verifier accepts the id as opaque; cross-family
//     composition (stale-link, subject-parity, claim_type) is deferred to
//     Phase 3 §G `compose`.
//
// Negatives:
//   - tampered-sig — flip last byte of sig.
//   - subject-null — subject:null at sign time; checkAsrSubjectPresence
//     flags `subject_missing` (D10-ASR-5).
//   - subject-malformed — subject:"did:web:not-sha256"; checkAsrSubjectPresence
//     flags `subject_invalid_form` (D10-ASR-5 sha256:<hex> format).

const ASR_POLICY_URI     = "https://controller-asr.example/subject-rights-policy/v1";
const ASR_POLICY_HASH    = "sha256:" + "5a".repeat(32);
const ASR_POLICY_VERSION = "1.0.0";
const ASR_ISS            = "did:web:controller-asr.example";

const ASR_SUBJECT          = "sha256:" + "5b".repeat(32);
const ASR_REQ_ID           = "srr-asr-cross-001";
const ASR_DEADLINE         = "2026-06-16T00:00:00Z";
const ASR_VERIF_HASH       = "sha256:" + "5c".repeat(32);
const ASR_SCOPE_HASH       = "sha256:" + "5d".repeat(32);
const ASR_EXT_REASON_HASH  = "sha256:" + "5e".repeat(32);
const ASR_EXT_UNTIL        = "2026-07-16T00:00:00Z";
const ASR_ARTIFACT_HASH    = "sha256:" + "5f".repeat(32);
const ASR_FULFILMENT_URI   = "https://controller-asr.example/fulfilments/0001";
const ASR_REFUSAL_JUST     = "sha256:" + "60".repeat(32);
const ASR_BALANCING_HASH   = "sha256:" + "61".repeat(32);
const ASR_RECIP_NOTIF_URI  = "https://controller-asr.example/recipient-notice/0001";
const ASR_RECIP_NOTIF_HASH = "sha256:" + "62".repeat(32);
const ASR_RECIP_ALR_IDS    = ["01HXXALRRECPSET00000000001"];

async function signAsrEnvelope({ id, subject, prev, body }) {
  const preSign = {
    v: 2,
    id,
    iat: IAT_ISO,
    iat_ms: IAT_MS,
    claim_type: "ar.subject_rights.v1",
    iss: ASR_ISS,
    iss_key: ISS_KEY,
    // ASR subject is uniform `sha256:<hex>` per D10-ASR-5; envelope type
    // declares string. Reconciliation lives in checkAsrSubjectPresence.
    subject,
    exp: null,
    prev,
    policy_uri: ASR_POLICY_URI,
    policy_hash: ASR_POLICY_HASH,
    policy_version: ASR_POLICY_VERSION,
    kind: "decision",
    cause: null,
    predicate: null,
    tsa: null,
    credentialStatus: null,
    anchor: ANCHOR,
    sig: "",
    countersig: null,
    body,
  };
  return signEnvelope(preSign, PRIVATE_KEY);
}

// ── Per-event ASR body factories ─────────────────────────────────────────────
// Each returns a minimal valid AsrBody matching the body-schema MANDATORY
// fields per spec §4. Profile-specific extras (Art. 17 arr_receipt_id,
// Art. 18 restriction_reason_code, Art. 20 portability_format / detail,
// Art. 21 objection_scope / balancing_test_hash) are added via `extras`.

function asrBodyReceived(extras = {}) {
  return {
    event_type: "request.received",
    subject_rights_request_id: ASR_REQ_ID,
    channel: "web_form",
    received_at: IAT_ISO,
    deadline_at: ASR_DEADLINE,
    ...extras,
  };
}

function asrBodyIdentityVerified(extras = {}) {
  return {
    event_type: "request.identity_verified",
    subject_rights_request_id: ASR_REQ_ID,
    verification_method_hash: ASR_VERIF_HASH,
    ...extras,
  };
}

function asrBodyScopeClarified(extras = {}) {
  return {
    event_type: "request.scope_clarified",
    subject_rights_request_id: ASR_REQ_ID,
    scope_clarification_hash: ASR_SCOPE_HASH,
    ...extras,
  };
}

function asrBodyExtended(extras = {}) {
  return {
    event_type: "request.extended",
    subject_rights_request_id: ASR_REQ_ID,
    extension_reason_hash: ASR_EXT_REASON_HASH,
    extended_until_at: ASR_EXT_UNTIL,
    ...extras,
  };
}

function asrBodyPartiallyHonoured(extras = {}) {
  return {
    event_type: "request.partially_honoured",
    subject_rights_request_id: ASR_REQ_ID,
    fulfilled_partial_scope: ["category_a"],
    fulfilled_artifact_hash: ASR_ARTIFACT_HASH,
    fulfilment_uri: ASR_FULFILMENT_URI,
    refusal_ground: "art12_5_b_excessive",
    refusal_justification_hash: ASR_REFUSAL_JUST,
    ...extras,
  };
}

function asrBodyFulfilled(extras = {}) {
  return {
    event_type: "request.fulfilled",
    subject_rights_request_id: ASR_REQ_ID,
    fulfilled_artifact_hash: ASR_ARTIFACT_HASH,
    fulfilment_uri: ASR_FULFILMENT_URI,
    ...extras,
  };
}

function asrBodyRefused(extras = {}) {
  return {
    event_type: "request.refused",
    subject_rights_request_id: ASR_REQ_ID,
    refusal_ground: "art17_3_a_freedom_of_expression",
    refusal_justification_hash: ASR_REFUSAL_JUST,
    ...extras,
  };
}

function asrBodyEscalated(extras = {}) {
  return {
    event_type: "request.escalated",
    subject_rights_request_id: ASR_REQ_ID,
    escalation_dpa_reference: "DPA-ASR-2026-0001",
    ...extras,
  };
}

function asrBodyRecipientNotified(extras = {}) {
  return {
    event_type: "request.recipient_notified",
    subject_rights_request_id: ASR_REQ_ID,
    recipient_set_alr_ids: ASR_RECIP_ALR_IDS,
    recipient_notification_uri: ASR_RECIP_NOTIF_URI,
    recipient_notification_hash: ASR_RECIP_NOTIF_HASH,
    ...extras,
  };
}

async function mkAsrVector({
  name,
  id,
  body,
  profile,
  subject = ASR_SUBJECT,
  prev = null,
  expectedOverrides = {},
}) {
  const signed = await signAsrEnvelope({ id, subject, prev, body });
  const vec = {
    name,
    family: "asr",
    envelope_version: 2,
    receipt: signed,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: true,
      tsa_state: "tsa_absent",
      ...expectedOverrides,
    },
  };
  if (profile) vec.profile = profile;
  return vec;
}

// ── ASR positive vectors — 5 per profile × 6 profiles = 30 ───────────────────

const ASR_PROFILE_ART15 = "subject_rights.art15.access";
const ASR_PROFILE_ART16 = "subject_rights.art16.rectification";
const ASR_PROFILE_ART17 = "subject_rights.art17.erasure_request";
const ASR_PROFILE_ART18 = "subject_rights.art18.restriction";
const ASR_PROFILE_ART20 = "subject_rights.art20.portability";
const ASR_PROFILE_ART21 = "subject_rights.art21.objection";

// art15.access — 5 events touching the access lifecycle. Profile is advisory
// at dispatch; art15 only forbids cross-link fields on fulfilled (no extras).
async function buildAsrA15Vectors() {
  return [
    await mkAsrVector({
      name: "asr-art15-received",
      id: "01HXXASRA15RECVD0000000001",
      body: asrBodyReceived(),
      profile: ASR_PROFILE_ART15,
    }),
    await mkAsrVector({
      name: "asr-art15-identity-verified",
      id: "01HXXASRA15VRFYD0000000001",
      body: asrBodyIdentityVerified(),
      profile: ASR_PROFILE_ART15,
    }),
    await mkAsrVector({
      name: "asr-art15-fulfilled",
      id: "01HXXASRA15FLFLD0000000001",
      body: asrBodyFulfilled(),
      profile: ASR_PROFILE_ART15,
    }),
    await mkAsrVector({
      name: "asr-art15-extended",
      id: "01HXXASRA15EXTND0000000001",
      body: asrBodyExtended(),
      profile: ASR_PROFILE_ART15,
    }),
    await mkAsrVector({
      name: "asr-art15-recipient-notified",
      id: "01HXXASRA15RCPNT0000000001",
      body: asrBodyRecipientNotified(),
      profile: ASR_PROFILE_ART15,
    }),
  ];
}

// art16.rectification — same forbids on fulfilled; before-after hash is
// issuer-side (committed via fulfilled_artifact_hash, not validated here).
async function buildAsrA16Vectors() {
  return [
    await mkAsrVector({
      name: "asr-art16-received",
      id: "01HXXASRA16RECVD0000000001",
      body: asrBodyReceived(),
      profile: ASR_PROFILE_ART16,
    }),
    await mkAsrVector({
      name: "asr-art16-scope-clarified",
      id: "01HXXASRA16SCPCR0000000001",
      body: asrBodyScopeClarified(),
      profile: ASR_PROFILE_ART16,
    }),
    await mkAsrVector({
      name: "asr-art16-fulfilled",
      id: "01HXXASRA16FLFLD0000000001",
      body: asrBodyFulfilled(),
      profile: ASR_PROFILE_ART16,
    }),
    await mkAsrVector({
      name: "asr-art16-partially-honoured",
      id: "01HXXASRA16PRTLY0000000001",
      body: asrBodyPartiallyHonoured(),
      profile: ASR_PROFILE_ART16,
    }),
    await mkAsrVector({
      name: "asr-art16-refused",
      id: "01HXXASRA16REFSD0000000001",
      body: asrBodyRefused(),
      profile: ASR_PROFILE_ART16,
    }),
  ];
}

// art17.erasure_request — fulfilled MUST carry arr_receipt_id (D10-ASR-3).
// One cross-family vector cites the ARR `ar.erasure.v1` receipt id.
async function buildAsrA17Vectors(arrErasureV2Vector) {
  const arrReceiptId = arrErasureV2Vector.receipt.id;
  return [
    await mkAsrVector({
      name: "asr-art17-received",
      id: "01HXXASRA17RECVD0000000001",
      body: asrBodyReceived(),
      profile: ASR_PROFILE_ART17,
    }),
    await mkAsrVector({
      name: "asr-art17-identity-verified",
      id: "01HXXASRA17VRFYD0000000001",
      body: asrBodyIdentityVerified(),
      profile: ASR_PROFILE_ART17,
    }),
    await mkAsrVector({
      name: "asr-art17-fulfilled-arr-composed",
      id: "01HXXASRA17FLFLD0000000001",
      body: asrBodyFulfilled({ arr_receipt_id: arrReceiptId }),
      profile: ASR_PROFILE_ART17,
    }),
    await mkAsrVector({
      name: "asr-art17-extended",
      id: "01HXXASRA17EXTND0000000001",
      body: asrBodyExtended(),
      profile: ASR_PROFILE_ART17,
    }),
    await mkAsrVector({
      name: "asr-art17-escalated",
      id: "01HXXASRA17ESCLT0000000001",
      body: asrBodyEscalated(),
      profile: ASR_PROFILE_ART17,
    }),
  ];
}

// art18.restriction — fulfilled MUST carry restriction_reason_code ∈ Art. 18(1)(a-d).
async function buildAsrA18Vectors() {
  return [
    await mkAsrVector({
      name: "asr-art18-received",
      id: "01HXXASRA18RECVD0000000001",
      body: asrBodyReceived(),
      profile: ASR_PROFILE_ART18,
    }),
    await mkAsrVector({
      name: "asr-art18-scope-clarified",
      id: "01HXXASRA18SCPCR0000000001",
      body: asrBodyScopeClarified(),
      profile: ASR_PROFILE_ART18,
    }),
    await mkAsrVector({
      name: "asr-art18-fulfilled-accuracy-contested",
      id: "01HXXASRA18FLFLA0000000001",
      body: asrBodyFulfilled({
        restriction_reason_code: "art18_1_a_accuracy_contested",
      }),
      profile: ASR_PROFILE_ART18,
    }),
    await mkAsrVector({
      name: "asr-art18-fulfilled-objection-pending",
      id: "01HXXASRA18FLFLD0000000001",
      body: asrBodyFulfilled({
        restriction_reason_code: "art18_1_d_objection_pending",
      }),
      profile: ASR_PROFILE_ART18,
    }),
    await mkAsrVector({
      name: "asr-art18-recipient-notified",
      id: "01HXXASRA18RCPNT0000000001",
      body: asrBodyRecipientNotified(),
      profile: ASR_PROFILE_ART18,
    }),
  ];
}

// art20.portability — fulfilled MUST carry portability_format ∈ closed enum;
// `other` requires portability_format_detail.
async function buildAsrA20Vectors() {
  return [
    await mkAsrVector({
      name: "asr-art20-received",
      id: "01HXXASRA20RECVD0000000001",
      body: asrBodyReceived(),
      profile: ASR_PROFILE_ART20,
    }),
    await mkAsrVector({
      name: "asr-art20-identity-verified",
      id: "01HXXASRA20VRFYD0000000001",
      body: asrBodyIdentityVerified(),
      profile: ASR_PROFILE_ART20,
    }),
    await mkAsrVector({
      name: "asr-art20-fulfilled-json",
      id: "01HXXASRA20FLFLJ0000000001",
      body: asrBodyFulfilled({ portability_format: "json" }),
      profile: ASR_PROFILE_ART20,
    }),
    await mkAsrVector({
      name: "asr-art20-fulfilled-other-with-detail",
      id: "01HXXASRA20FLFLT0000000001",
      body: asrBodyFulfilled({
        portability_format: "other",
        portability_format_detail: "MARC21 bibliographic record (RFC 8226)",
      }),
      profile: ASR_PROFILE_ART20,
    }),
    await mkAsrVector({
      name: "asr-art20-fulfilled-fhir",
      id: "01HXXASRA20FLFLF0000000001",
      body: asrBodyFulfilled({ portability_format: "fhir" }),
      profile: ASR_PROFILE_ART20,
    }),
  ];
}

// art21.objection — fulfilled MUST carry objection_scope ∈ closed enum;
// `art21_1_general_legitimate_interest` requires balancing_test_hash.
async function buildAsrA21Vectors() {
  return [
    await mkAsrVector({
      name: "asr-art21-received",
      id: "01HXXASRA21RECVD0000000001",
      body: asrBodyReceived(),
      profile: ASR_PROFILE_ART21,
    }),
    await mkAsrVector({
      name: "asr-art21-fulfilled-direct-marketing",
      id: "01HXXASRA21DRMKT0000000001",
      body: asrBodyFulfilled({
        objection_scope: "art21_1_direct_marketing",
      }),
      profile: ASR_PROFILE_ART21,
    }),
    await mkAsrVector({
      name: "asr-art21-fulfilled-general-legit-balancing",
      id: "01HXXASRA21GNLGT0000000001",
      body: asrBodyFulfilled({
        objection_scope: "art21_1_general_legitimate_interest",
        balancing_test_hash: ASR_BALANCING_HASH,
      }),
      profile: ASR_PROFILE_ART21,
    }),
    await mkAsrVector({
      name: "asr-art21-fulfilled-research",
      id: "01HXXASRA21RSRCH0000000001",
      body: asrBodyFulfilled({ objection_scope: "art21_6_research" }),
      profile: ASR_PROFILE_ART21,
    }),
    await mkAsrVector({
      name: "asr-art21-refused",
      id: "01HXXASRA21REFSD0000000001",
      body: asrBodyRefused(),
      profile: ASR_PROFILE_ART21,
    }),
  ];
}

// ── ASR negative vectors ─────────────────────────────────────────────────────

async function buildAsrNegTamperedSig(positive) {
  const r = positive.receipt;
  const sig = r.sig;
  const last = sig.charAt(sig.length - 1);
  const flipped = last === "A" ? "B" : "A";
  const tamperedSig = sig.slice(0, -1) + flipped;

  return {
    name: "asr-neg-tampered-sig",
    family: "asr",
    envelope_version: 2,
    receipt: { ...r, sig: tamperedSig, id: "01HXXASRNEGTAMPER000000001" },
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: false,
    },
  };
}

async function buildAsrNegSubjectNull() {
  // D10-ASR-5 — subject MUST be `sha256:<hex>` on every event. A null
  // subject must be rejected by checkAsrSubjectPresence as `subject_missing`.
  const signed = await signAsrEnvelope({
    id: "01HXXASRNEGSUBNULL00000001",
    subject: null,
    prev: null,
    body: asrBodyReceived(),
  });
  return {
    name: "asr-neg-subject-null",
    family: "asr",
    envelope_version: 2,
    receipt: signed,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: false,
      reason: "subject_missing",
    },
  };
}

async function buildAsrNegSubjectMalformed() {
  // D10-ASR-5 — non-sha256-form subject rejected as `subject_invalid_form`.
  const signed = await signAsrEnvelope({
    id: "01HXXASRNEGSUBMLFRM0000001",
    subject: "did:web:not-a-sha256",
    prev: null,
    body: asrBodyReceived(),
  });
  return {
    name: "asr-neg-subject-malformed",
    family: "asr",
    envelope_version: 2,
    receipt: signed,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: false,
      reason: "subject_invalid_form",
    },
  };
}

// ── AIR §J.4 vector builders ─────────────────────────────────────────────────
//
// AIR is v=2 only (claim_type `ar.impact.v1`). Builds envelopes directly via
// signEnvelope to keep determinism, mirroring the ASR §J.3 pattern above.
//
// Family invariants enforced:
//   - POLICY_BOUND — policy_uri/hash/version required.
//   - Subject is per-event-split (FAMILY-CONSISTENCY §3 + spec §4.4 +
//     D10-AIR-6): every event MUST have subject:null EXCEPT
//     `dpia.stakeholders_consulted`, where subject MAY be `sha256:<hex>`
//     AND only when consultation_method ∈ {representative_org, ngo_review}.
//     Reconciliation lives in applyAirSubjectPresence in the verifier.
//   - Three RECOMMENDED-TSA events (`dpia.completed`,
//     `dpia.prior_consultation_initiated`, `dpia.prior_consultation_resolved`)
//     surface `tsa_state: "tsa_recommended"` when minted without a TSA block
//     (per AIR §D matrix). Every other event surfaces `tsa_absent`. AIR has
//     no MANDATORY-TSA event in v1 — positives mint with `tsa: null`.
//   - body.air_receipt_id + body.processing_activity_id REQUIRED on every
//     body (D10-AIR-2 / D10-AIR-3); identical across all receipts in one
//     DPIA chain.
//   - Bodies carry no `field_root` (the hand-rolled v=2 mint kit adds one in
//     the on-package surface, but the verifier ignores extra body fields per
//     mint-v2.ts § "Verifier ignores extra fields today"). Vectors stay
//     minimal to match the verifier's actual contract.
//
// Cross-issuer surface exercised:
//   - `dpia.completed.alr_receipt_ids` cites a sibling ALR `ar.lineage.v1`
//     receipt id (composition §8.3 — data-flows in scope). The verifier
//     accepts the id as opaque; cross-family composition walks are deferred.
//   - `dpia.reviewed.abr_receipt_id` cites a sibling ABR `ar.breach.v1`
//     receipt id (composition §8.5 — breach-triggered review). Same opaque
//     contract.
//   - AER/ATR/APuR cross-links are part of the spec composition surface but
//     intentionally left null in v1 vectors — those families are not yet
//     shipped. Vectors will pick them up when AER/ATR/APuR land.
//
// Negatives:
//   - air-neg-tampered-sig — flip last byte of sig on a positive.
//   - air-neg-subject-present-on-completed — subject:sha256 on dpia.completed;
//     applyAirSubjectPresence flags `subject_present` (FAMILY-CONSISTENCY §3
//     non-stakeholders_consulted MUST be null).
//   - air-neg-stakeholders-method-mismatch — sha256 subject on
//     dpia.stakeholders_consulted but consultation_method = "survey";
//     applyAirSubjectPresence flags `representative_subject_method_mismatch`
//     (D10-AIR-6 method gating).

const AIR_POLICY_URI     = "https://controller-air.example/dpia-methodology/v1";
const AIR_POLICY_HASH    = "sha256:" + "63".repeat(32);
const AIR_POLICY_VERSION = "1.0.0";
const AIR_ISS            = "did:web:controller-air.example";

const AIR_RECEIPT_ID                = "air-dpia-chain-001";
const AIR_PROCESSING_ACTIVITY_ID    = "pa-controller-air-001";
const AIR_PROCESSING_ACT_HASH       = "sha256:" + "64".repeat(32);
const AIR_PROCESSING_START_AT       = "2026-05-17T00:00:00Z";
const AIR_SCOPE_HASH                = "sha256:" + "65".repeat(32);
const AIR_DPO_COMMIT                = "sha256:" + "66".repeat(32);
const AIR_DPO_ADVICE_HASH           = "sha256:" + "67".repeat(32);
const AIR_CONSULTATION_OUTPUT_HASH  = "sha256:" + "68".repeat(32);
const AIR_REP_ORG_SUBJECT           = "sha256:" + "69".repeat(32);
const AIR_DPIA_ARTIFACT_HASH        = "sha256:" + "6a".repeat(32);
const AIR_DPIA_URI                  = "https://controller-air.example/dpia/0001";
const AIR_REVIEW_DUE_AT             = "2027-05-17T00:00:00Z";
const AIR_REVIEW_EVIDENCE_HASH      = "sha256:" + "6b".repeat(32);
const AIR_SUBMISSION_HASH           = "sha256:" + "6c".repeat(32);
const AIR_DPA_JURISDICTION          = "ES";
const AIR_DPA_ADVICE_HASH           = "sha256:" + "6d".repeat(32);
const AIR_CONTROLLER_RESPONSE_HASH  = "sha256:" + "6e".repeat(32);
const AIR_DPA_DID                   = "did:web:dpa-es.example";
const AIR_TERMINATION_REASON_HASH   = "sha256:" + "6f".repeat(32);

async function signAirEnvelope({ id, subject, prev, body, kind = "decision" }) {
  const preSign = {
    v: 2,
    id,
    iat: IAT_ISO,
    iat_ms: Date.parse(IAT_ISO),
    claim_type: "ar.impact.v1",
    iss: AIR_ISS,
    iss_key: ISS_KEY,
    // AIR subject is per-event-split. Reconciliation lives in
    // applyAirSubjectPresence — non-null only on stakeholders_consulted
    // with subject-bearing method.
    subject,
    exp: null,
    prev,
    policy_uri: AIR_POLICY_URI,
    policy_hash: AIR_POLICY_HASH,
    policy_version: AIR_POLICY_VERSION,
    kind,
    cause: null,
    predicate: null,
    tsa: null,
    credentialStatus: null,
    anchor: ANCHOR,
    sig: "",
    countersig: null,
    body,
  };
  return signEnvelope(preSign, PRIVATE_KEY);
}

// ── Per-event AIR body factories ─────────────────────────────────────────────
// Each returns a minimal valid AirBody matching the discriminated union's
// non-applicable-pinned-to-null contract per types.ts. Composition fields
// default to null; cross-issuer variants override via `extras`.

function airBodyThresholdTriggered(extras = {}) {
  return {
    event_type: "dpia.threshold_triggered",
    air_receipt_id: AIR_RECEIPT_ID,
    processing_activity_id: AIR_PROCESSING_ACTIVITY_ID,
    processing_activity_hash: AIR_PROCESSING_ACT_HASH,
    processing_start_at: AIR_PROCESSING_START_AT,
    scope_hash: null,
    dpo_did_or_email_commit: null,
    dpo_advice_hash: null,
    consultation_method: null,
    consultation_output_hash: null,
    dpia_artifact_hash: null,
    dpia_uri: null,
    residual_risk_level: null,
    review_due_at: null,
    review_outcome: null,
    review_evidence_hash: null,
    dpa_jurisdiction: null,
    submission_hash: null,
    dpa_advice_hash: null,
    dpa_did: null,
    controller_response_hash: null,
    terminal_disposition: null,
    termination_reason_hash: null,
    aer_receipt_ids: null,
    atr_receipt_ids: null,
    alr_receipt_ids: null,
    apur_receipt_ids: null,
    abr_receipt_id: null,
    ...extras,
  };
}

function airBodyScopeLocked(extras = {}) {
  return {
    event_type: "dpia.scope_locked",
    air_receipt_id: AIR_RECEIPT_ID,
    processing_activity_id: AIR_PROCESSING_ACTIVITY_ID,
    scope_hash: AIR_SCOPE_HASH,
    processing_activity_hash: null,
    processing_start_at: null,
    dpo_did_or_email_commit: null,
    dpo_advice_hash: null,
    consultation_method: null,
    consultation_output_hash: null,
    dpia_artifact_hash: null,
    dpia_uri: null,
    residual_risk_level: null,
    review_due_at: null,
    review_outcome: null,
    review_evidence_hash: null,
    dpa_jurisdiction: null,
    submission_hash: null,
    dpa_advice_hash: null,
    dpa_did: null,
    controller_response_hash: null,
    terminal_disposition: null,
    termination_reason_hash: null,
    aer_receipt_ids: null,
    atr_receipt_ids: null,
    alr_receipt_ids: null,
    apur_receipt_ids: null,
    abr_receipt_id: null,
    ...extras,
  };
}

function airBodyDpoAdvised(extras = {}) {
  return {
    event_type: "dpia.dpo_advised",
    air_receipt_id: AIR_RECEIPT_ID,
    processing_activity_id: AIR_PROCESSING_ACTIVITY_ID,
    dpo_did_or_email_commit: AIR_DPO_COMMIT,
    dpo_advice_hash: AIR_DPO_ADVICE_HASH,
    processing_activity_hash: null,
    processing_start_at: null,
    scope_hash: null,
    consultation_method: null,
    consultation_output_hash: null,
    dpia_artifact_hash: null,
    dpia_uri: null,
    residual_risk_level: null,
    review_due_at: null,
    review_outcome: null,
    review_evidence_hash: null,
    dpa_jurisdiction: null,
    submission_hash: null,
    dpa_advice_hash: null,
    dpa_did: null,
    controller_response_hash: null,
    terminal_disposition: null,
    termination_reason_hash: null,
    aer_receipt_ids: null,
    atr_receipt_ids: null,
    alr_receipt_ids: null,
    apur_receipt_ids: null,
    abr_receipt_id: null,
    ...extras,
  };
}

function airBodyStakeholdersConsulted(method, extras = {}) {
  return {
    event_type: "dpia.stakeholders_consulted",
    air_receipt_id: AIR_RECEIPT_ID,
    processing_activity_id: AIR_PROCESSING_ACTIVITY_ID,
    consultation_method: method,
    consultation_output_hash: AIR_CONSULTATION_OUTPUT_HASH,
    processing_activity_hash: null,
    processing_start_at: null,
    scope_hash: null,
    dpo_did_or_email_commit: null,
    dpo_advice_hash: null,
    dpia_artifact_hash: null,
    dpia_uri: null,
    residual_risk_level: null,
    review_due_at: null,
    review_outcome: null,
    review_evidence_hash: null,
    dpa_jurisdiction: null,
    submission_hash: null,
    dpa_advice_hash: null,
    dpa_did: null,
    controller_response_hash: null,
    terminal_disposition: null,
    termination_reason_hash: null,
    aer_receipt_ids: null,
    atr_receipt_ids: null,
    alr_receipt_ids: null,
    apur_receipt_ids: null,
    abr_receipt_id: null,
    ...extras,
  };
}

function airBodyCompleted(residualRiskLevel, extras = {}) {
  return {
    event_type: "dpia.completed",
    air_receipt_id: AIR_RECEIPT_ID,
    processing_activity_id: AIR_PROCESSING_ACTIVITY_ID,
    dpia_artifact_hash: AIR_DPIA_ARTIFACT_HASH,
    dpia_uri: AIR_DPIA_URI,
    residual_risk_level: residualRiskLevel,
    review_due_at: AIR_REVIEW_DUE_AT,
    aer_receipt_ids: null,
    atr_receipt_ids: null,
    alr_receipt_ids: null,
    apur_receipt_ids: null,
    processing_activity_hash: null,
    processing_start_at: null,
    scope_hash: null,
    dpo_did_or_email_commit: null,
    dpo_advice_hash: null,
    consultation_method: null,
    consultation_output_hash: null,
    review_outcome: null,
    review_evidence_hash: null,
    dpa_jurisdiction: null,
    submission_hash: null,
    dpa_advice_hash: null,
    dpa_did: null,
    controller_response_hash: null,
    terminal_disposition: null,
    termination_reason_hash: null,
    abr_receipt_id: null,
    ...extras,
  };
}

function airBodyReviewed(reviewOutcome, extras = {}) {
  return {
    event_type: "dpia.reviewed",
    air_receipt_id: AIR_RECEIPT_ID,
    processing_activity_id: AIR_PROCESSING_ACTIVITY_ID,
    review_outcome: reviewOutcome,
    review_evidence_hash: AIR_REVIEW_EVIDENCE_HASH,
    abr_receipt_id: null,
    processing_activity_hash: null,
    processing_start_at: null,
    scope_hash: null,
    dpo_did_or_email_commit: null,
    dpo_advice_hash: null,
    consultation_method: null,
    consultation_output_hash: null,
    dpia_artifact_hash: null,
    dpia_uri: null,
    residual_risk_level: null,
    review_due_at: null,
    dpa_jurisdiction: null,
    submission_hash: null,
    dpa_advice_hash: null,
    dpa_did: null,
    controller_response_hash: null,
    terminal_disposition: null,
    termination_reason_hash: null,
    aer_receipt_ids: null,
    atr_receipt_ids: null,
    alr_receipt_ids: null,
    apur_receipt_ids: null,
    ...extras,
  };
}

function airBodyPriorConsultationInitiated(extras = {}) {
  return {
    event_type: "dpia.prior_consultation_initiated",
    air_receipt_id: AIR_RECEIPT_ID,
    processing_activity_id: AIR_PROCESSING_ACTIVITY_ID,
    dpa_jurisdiction: AIR_DPA_JURISDICTION,
    submission_hash: AIR_SUBMISSION_HASH,
    processing_activity_hash: null,
    processing_start_at: null,
    scope_hash: null,
    dpo_did_or_email_commit: null,
    dpo_advice_hash: null,
    consultation_method: null,
    consultation_output_hash: null,
    dpia_artifact_hash: null,
    dpia_uri: null,
    residual_risk_level: null,
    review_due_at: null,
    review_outcome: null,
    review_evidence_hash: null,
    dpa_advice_hash: null,
    dpa_did: null,
    controller_response_hash: null,
    terminal_disposition: null,
    termination_reason_hash: null,
    aer_receipt_ids: null,
    atr_receipt_ids: null,
    alr_receipt_ids: null,
    apur_receipt_ids: null,
    abr_receipt_id: null,
    ...extras,
  };
}

function airBodyPriorConsultationResolved(extras = {}) {
  return {
    event_type: "dpia.prior_consultation_resolved",
    air_receipt_id: AIR_RECEIPT_ID,
    processing_activity_id: AIR_PROCESSING_ACTIVITY_ID,
    dpa_advice_hash: AIR_DPA_ADVICE_HASH,
    controller_response_hash: AIR_CONTROLLER_RESPONSE_HASH,
    dpa_did: AIR_DPA_DID,
    processing_activity_hash: null,
    processing_start_at: null,
    scope_hash: null,
    dpo_did_or_email_commit: null,
    dpo_advice_hash: null,
    consultation_method: null,
    consultation_output_hash: null,
    dpia_artifact_hash: null,
    dpia_uri: null,
    residual_risk_level: null,
    review_due_at: null,
    review_outcome: null,
    review_evidence_hash: null,
    dpa_jurisdiction: null,
    submission_hash: null,
    terminal_disposition: null,
    termination_reason_hash: null,
    aer_receipt_ids: null,
    atr_receipt_ids: null,
    alr_receipt_ids: null,
    apur_receipt_ids: null,
    abr_receipt_id: null,
    ...extras,
  };
}

function airBodyProcessingAuthorised(extras = {}) {
  return {
    event_type: "dpia.processing_authorised",
    air_receipt_id: AIR_RECEIPT_ID,
    processing_activity_id: AIR_PROCESSING_ACTIVITY_ID,
    terminal_disposition: "authorised",
    processing_activity_hash: null,
    processing_start_at: null,
    scope_hash: null,
    dpo_did_or_email_commit: null,
    dpo_advice_hash: null,
    consultation_method: null,
    consultation_output_hash: null,
    dpia_artifact_hash: null,
    dpia_uri: null,
    residual_risk_level: null,
    review_due_at: null,
    review_outcome: null,
    review_evidence_hash: null,
    dpa_jurisdiction: null,
    submission_hash: null,
    dpa_advice_hash: null,
    dpa_did: null,
    controller_response_hash: null,
    termination_reason_hash: null,
    aer_receipt_ids: null,
    atr_receipt_ids: null,
    alr_receipt_ids: null,
    apur_receipt_ids: null,
    abr_receipt_id: null,
    ...extras,
  };
}

function airBodyProcessingBlocked(extras = {}) {
  return {
    event_type: "dpia.processing_blocked",
    air_receipt_id: AIR_RECEIPT_ID,
    processing_activity_id: AIR_PROCESSING_ACTIVITY_ID,
    terminal_disposition: "blocked",
    processing_activity_hash: null,
    processing_start_at: null,
    scope_hash: null,
    dpo_did_or_email_commit: null,
    dpo_advice_hash: null,
    consultation_method: null,
    consultation_output_hash: null,
    dpia_artifact_hash: null,
    dpia_uri: null,
    residual_risk_level: null,
    review_due_at: null,
    review_outcome: null,
    review_evidence_hash: null,
    dpa_jurisdiction: null,
    submission_hash: null,
    dpa_advice_hash: null,
    dpa_did: null,
    controller_response_hash: null,
    termination_reason_hash: null,
    aer_receipt_ids: null,
    atr_receipt_ids: null,
    alr_receipt_ids: null,
    apur_receipt_ids: null,
    abr_receipt_id: null,
    ...extras,
  };
}

function airBodyTerminated(extras = {}) {
  return {
    event_type: "dpia.terminated",
    air_receipt_id: AIR_RECEIPT_ID,
    processing_activity_id: AIR_PROCESSING_ACTIVITY_ID,
    terminal_disposition: "terminated",
    termination_reason_hash: AIR_TERMINATION_REASON_HASH,
    processing_activity_hash: null,
    processing_start_at: null,
    scope_hash: null,
    dpo_did_or_email_commit: null,
    dpo_advice_hash: null,
    consultation_method: null,
    consultation_output_hash: null,
    dpia_artifact_hash: null,
    dpia_uri: null,
    residual_risk_level: null,
    review_due_at: null,
    review_outcome: null,
    review_evidence_hash: null,
    dpa_jurisdiction: null,
    submission_hash: null,
    dpa_advice_hash: null,
    dpa_did: null,
    controller_response_hash: null,
    aer_receipt_ids: null,
    atr_receipt_ids: null,
    alr_receipt_ids: null,
    apur_receipt_ids: null,
    abr_receipt_id: null,
    ...extras,
  };
}

// Per-event TSA-state defaults per AIR §D matrix. RECOMMENDED on 3 events;
// OPTIONAL on the other 8 (verifier surfaces `tsa_absent` with no upgrade).
const AIR_TSA_RECOMMENDED = new Set([
  "dpia.completed",
  "dpia.prior_consultation_initiated",
  "dpia.prior_consultation_resolved",
]);

async function mkAirVector({
  name,
  id,
  body,
  profile,
  subject = null,
  prev = null,
  kind = "decision",
  expectedOverrides = {},
}) {
  const signed = await signAirEnvelope({ id, subject, prev, body, kind });
  const tsaState = AIR_TSA_RECOMMENDED.has(body.event_type)
    ? "tsa_recommended"
    : "tsa_absent";
  const vec = {
    name,
    family: "air",
    envelope_version: 2,
    receipt: signed,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: true,
      tsa_state: tsaState,
      ...expectedOverrides,
    },
  };
  if (profile) vec.profile = profile;
  return vec;
}

// ── AIR positive vectors — 5 per profile × 5 profiles = 25 ───────────────────
//
// Each profile picks a distinct slice of the 11-event lifecycle so that every
// event_type appears at least once across the 25 vectors:
//   art35_3_a   (5): threshold, scope_locked, dpo_advised,
//                    stakeholders (rep_org + sha256 subject), authorised.
//   art35_3_b   (5): threshold, dpo_advised, completed (high),
//                    reviewed (no_material_change), authorised.
//   art35_3_c   (5): threshold, completed (high), prior_consultation_initiated,
//                    prior_consultation_resolved, authorised.
//   art35_4     (5): threshold, scope_locked, completed (low),
//                    processing_blocked, terminated.
//   voluntary   (5): threshold, dpo_advised,
//                    stakeholders (subject:null, method:survey),
//                    completed (medium), reviewed (material_change).

const AIR_PROFILE_A    = "impact.art35_3_a_automated_decisions";
const AIR_PROFILE_B    = "impact.art35_3_b_large_scale_special_categories";
const AIR_PROFILE_C    = "impact.art35_3_c_public_monitoring";
const AIR_PROFILE_DPA  = "impact.art35_4_dpa_list";
const AIR_PROFILE_VOL  = "impact.voluntary";

async function buildAirA35_3_aVectors() {
  return [
    await mkAirVector({
      name: "air-a-threshold-triggered",
      id: "01HXXAIRA3ATHRTRG000000001",
      body: airBodyThresholdTriggered(),
      profile: AIR_PROFILE_A,
      kind: "decision",
    }),
    await mkAirVector({
      name: "air-a-scope-locked",
      id: "01HXXAIRA3ASCPLCK000000001",
      body: airBodyScopeLocked(),
      profile: AIR_PROFILE_A,
      kind: "decision",
    }),
    await mkAirVector({
      name: "air-a-dpo-advised",
      id: "01HXXAIRA3ADPOADV000000001",
      body: airBodyDpoAdvised(),
      profile: AIR_PROFILE_A,
      kind: "observation",
    }),
    await mkAirVector({
      name: "air-a-stakeholders-rep-org",
      id: "01HXXAIRA3ASTKRPR000000001",
      body: airBodyStakeholdersConsulted("representative_org"),
      profile: AIR_PROFILE_A,
      subject: AIR_REP_ORG_SUBJECT,
      kind: "observation",
    }),
    await mkAirVector({
      name: "air-a-processing-authorised",
      id: "01HXXAIRA3APROAUT000000001",
      body: airBodyProcessingAuthorised(),
      profile: AIR_PROFILE_A,
      kind: "decision",
    }),
  ];
}

async function buildAirA35_3_bVectors() {
  return [
    await mkAirVector({
      name: "air-b-threshold-triggered",
      id: "01HXXAIRA3BTHRTRG000000001",
      body: airBodyThresholdTriggered(),
      profile: AIR_PROFILE_B,
      kind: "decision",
    }),
    await mkAirVector({
      name: "air-b-dpo-advised",
      id: "01HXXAIRA3BDPOADV000000001",
      body: airBodyDpoAdvised(),
      profile: AIR_PROFILE_B,
      kind: "observation",
    }),
    await mkAirVector({
      name: "air-b-completed-high",
      id: "01HXXAIRA3BCMPHGH000000001",
      body: airBodyCompleted("high"),
      profile: AIR_PROFILE_B,
      kind: "decision",
    }),
    await mkAirVector({
      name: "air-b-reviewed-no-material-change",
      id: "01HXXAIRA3BRVWNMC000000001",
      body: airBodyReviewed("no_material_change"),
      profile: AIR_PROFILE_B,
      kind: "decision",
    }),
    await mkAirVector({
      name: "air-b-processing-authorised",
      id: "01HXXAIRA3BPROAUT000000001",
      body: airBodyProcessingAuthorised(),
      profile: AIR_PROFILE_B,
      kind: "decision",
    }),
  ];
}

async function buildAirA35_3_cVectors() {
  return [
    await mkAirVector({
      name: "air-c-threshold-triggered",
      id: "01HXXAIRA3CTHRTRG000000001",
      body: airBodyThresholdTriggered(),
      profile: AIR_PROFILE_C,
      kind: "decision",
    }),
    await mkAirVector({
      name: "air-c-completed-high",
      id: "01HXXAIRA3CCMPHGH000000001",
      body: airBodyCompleted("high"),
      profile: AIR_PROFILE_C,
      kind: "decision",
    }),
    await mkAirVector({
      name: "air-c-prior-consultation-initiated",
      id: "01HXXAIRA3CPCRINI000000001",
      body: airBodyPriorConsultationInitiated(),
      profile: AIR_PROFILE_C,
      kind: "decision",
    }),
    await mkAirVector({
      name: "air-c-prior-consultation-resolved",
      id: "01HXXAIRA3CPCRRSL000000001",
      body: airBodyPriorConsultationResolved(),
      profile: AIR_PROFILE_C,
      kind: "observation",
    }),
    await mkAirVector({
      name: "air-c-processing-authorised",
      id: "01HXXAIRA3CPROAUT000000001",
      body: airBodyProcessingAuthorised(),
      profile: AIR_PROFILE_C,
      kind: "decision",
    }),
  ];
}

async function buildAirA35_4Vectors() {
  return [
    await mkAirVector({
      name: "air-dpa-threshold-triggered",
      id: "01HXXAIRA354THRTRG00000001",
      body: airBodyThresholdTriggered(),
      profile: AIR_PROFILE_DPA,
      kind: "decision",
    }),
    await mkAirVector({
      name: "air-dpa-scope-locked",
      id: "01HXXAIRA354SCPLCK00000001",
      body: airBodyScopeLocked(),
      profile: AIR_PROFILE_DPA,
      kind: "decision",
    }),
    await mkAirVector({
      name: "air-dpa-completed-low",
      id: "01HXXAIRA354CMPLOW00000001",
      body: airBodyCompleted("low"),
      profile: AIR_PROFILE_DPA,
      kind: "decision",
    }),
    await mkAirVector({
      name: "air-dpa-processing-blocked",
      id: "01HXXAIRA354PROBLK00000001",
      body: airBodyProcessingBlocked(),
      profile: AIR_PROFILE_DPA,
      kind: "decision",
    }),
    await mkAirVector({
      name: "air-dpa-terminated",
      id: "01HXXAIRA354TERMIN00000001",
      body: airBodyTerminated(),
      profile: AIR_PROFILE_DPA,
      kind: "decision",
    }),
  ];
}

async function buildAirVoluntaryVectors() {
  return [
    await mkAirVector({
      name: "air-vol-threshold-triggered",
      id: "01HXXAIRVOLTHRTRG00000001",
      body: airBodyThresholdTriggered(),
      profile: AIR_PROFILE_VOL,
      kind: "decision",
    }),
    await mkAirVector({
      name: "air-vol-dpo-advised",
      id: "01HXXAIRVOLDPOADV00000001",
      body: airBodyDpoAdvised(),
      profile: AIR_PROFILE_VOL,
      kind: "observation",
    }),
    await mkAirVector({
      // Survey method → subject MUST be null (D10-AIR-6).
      name: "air-vol-stakeholders-survey",
      id: "01HXXAIRVOLSTKSRV00000001",
      body: airBodyStakeholdersConsulted("survey"),
      profile: AIR_PROFILE_VOL,
      subject: null,
      kind: "observation",
    }),
    await mkAirVector({
      name: "air-vol-completed-medium",
      id: "01HXXAIRVOLCMPMED00000001",
      body: airBodyCompleted("medium"),
      profile: AIR_PROFILE_VOL,
      kind: "decision",
    }),
    await mkAirVector({
      name: "air-vol-reviewed-material-change",
      id: "01HXXAIRVOLRVWMCH00000001",
      body: airBodyReviewed("material_change"),
      profile: AIR_PROFILE_VOL,
      kind: "decision",
    }),
  ];
}

// ── AIR cross-issuer composition vectors (2) ─────────────────────────────────

async function buildAirCompletedAlrComposed(alrVector) {
  const alrReceiptId = alrVector.receipt.id;
  return mkAirVector({
    name: "air-completed-alr-composed",
    id: "01HXXAIRCMPALRCOMP0000001",
    body: airBodyCompleted("medium", { alr_receipt_ids: [alrReceiptId] }),
    profile: AIR_PROFILE_A,
    kind: "decision",
  });
}

async function buildAirReviewedAbrComposed(abrVector) {
  const abrReceiptId = abrVector.receipt.id;
  return mkAirVector({
    name: "air-reviewed-abr-composed",
    id: "01HXXAIRRVWABRCOMP0000001",
    body: airBodyReviewed("material_change", { abr_receipt_id: abrReceiptId }),
    profile: AIR_PROFILE_B,
    kind: "decision",
  });
}

// ── AIR negative vectors ─────────────────────────────────────────────────────

async function buildAirNegTamperedSig(positive) {
  const r = positive.receipt;
  const sig = r.sig;
  const last = sig.charAt(sig.length - 1);
  const flipped = last === "A" ? "B" : "A";
  const tamperedSig = sig.slice(0, -1) + flipped;

  return {
    name: "air-neg-tampered-sig",
    family: "air",
    envelope_version: 2,
    receipt: { ...r, sig: tamperedSig, id: "01HXXAIRNEGTAMPER000000001" },
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: false,
    },
  };
}

async function buildAirNegSubjectPresentOnCompleted() {
  // FAMILY-CONSISTENCY §3 — non-stakeholders_consulted MUST have subject:null.
  // applyAirSubjectPresence flags `subject_present` on dpia.completed when
  // a non-null subject sneaks past the kit (this hand-signed vector models a
  // misbehaving issuer).
  const signed = await signAirEnvelope({
    id: "01HXXAIRNEGSUBJONCMP000001",
    subject: AIR_REP_ORG_SUBJECT,
    prev: null,
    body: airBodyCompleted("low"),
    kind: "decision",
  });
  return {
    name: "air-neg-subject-present-on-completed",
    family: "air",
    envelope_version: 2,
    receipt: signed,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: false,
      reason: "subject_present",
    },
  };
}

async function buildAirNegStakeholdersMethodMismatch() {
  // D10-AIR-6 method gating — sha256 subject on dpia.stakeholders_consulted
  // is only permitted when consultation_method ∈ {representative_org,
  // ngo_review}. method="survey" with a sha256 subject MUST fail with
  // `representative_subject_method_mismatch`.
  const signed = await signAirEnvelope({
    id: "01HXXAIRNEGSTKMTMSM000001",
    subject: AIR_REP_ORG_SUBJECT,
    prev: null,
    body: airBodyStakeholdersConsulted("survey"),
    kind: "observation",
  });
  return {
    name: "air-neg-stakeholders-method-mismatch",
    family: "air",
    envelope_version: 2,
    receipt: signed,
    publicKey_b64url: PUBLIC_KEY_B64URL,
    expected: {
      envelope_version: 2,
      signature_valid: false,
      reason: "representative_subject_method_mismatch",
    },
  };
}

// ── Write helper ─────────────────────────────────────────────────────────────

function write(name, vector) {
  const dest = join(VECTORS_DIR, `${name}.json`);
  writeFileSync(dest, JSON.stringify(vector, null, 2) + "\n");
  console.log(`wrote ${dest}`);
}

// ── Main ─────────────────────────────────────────────────────────────────────

console.log("mint-vectors: building 95 cross-family conformance vectors (8 baseline + 8 ALR §J + 8 ANR §J.1 + 8 ABR §J.2 + 33 ASR §J.3 + 30 AIR §J.4)...\n");

const aprV1 = buildAprV1();
write("apr-v1", aprV1);

const aprV2 = await buildAprV2();
write("apr-v2", aprV2);

const acrConsentV1 = buildAcrConsentV1();
write("acr-consent-v1", acrConsentV1);

const acrConsentV2 = await buildAcrConsentV2();
write("acr-consent-v2", acrConsentV2);

const acrWithdrawalV2 = await buildAcrWithdrawalV2(acrConsentV2);
write("acr-withdrawal-v2", acrWithdrawalV2);

const arrErasureV1 = buildArrErasureV1();
write("arr-erasure-v1", arrErasureV1);

const arrErasureV2 = await buildArrErasureV2();
write("arr-erasure-v2", arrErasureV2);

const arrErasureV2Tsa = await buildArrErasureV2Tsa();
// Only write if freshly minted (TSA skip returns existing object but we still write it back)
// to ensure idempotent file content.
const tsaDest = join(VECTORS_DIR, "arr-erasure-v2-tsa.json");
writeFileSync(tsaDest, JSON.stringify(arrErasureV2Tsa, null, 2) + "\n");
console.log(`wrote ${tsaDest}`);

// ── ALR §J — 3 positive + 2 cross-issuer + 3 negative ────────────────────────

const alrDerived = await buildAlrDerivedFromV2();
write("alr-derived-from-v2", alrDerived);

const alrForked = await buildAlrForkedFromV2();
write("alr-forked-from-v2", alrForked);

const alrDisclosed = await buildAlrDisclosedV2();
write("alr-disclosed-v2", alrDisclosed);

const alrDerivedAprCovered = await buildAlrDerivedFromV2AprCovered();
write("alr-derived-from-v2-apr-covered", alrDerivedAprCovered);

const alrDerivedMixed = await buildAlrDerivedFromV2MixedParents();
write("alr-derived-from-v2-mixed-parents", alrDerivedMixed);

const alrNegSig = await buildAlrNegTamperedSig(alrDerived);
write("alr-neg-tampered-sig", alrNegSig);

const alrNegProfile = await buildAlrNegUnknownProfile();
write("alr-neg-unknown-profile", alrNegProfile);

const alrNegSubject = await buildAlrNegSubjectPresent();
write("alr-neg-subject-present", alrNegSubject);

// ── ANR §J.1 — 3 positive + 2 cross-issuer + 3 negative ──────────────────────

const anrPresented = await buildAnrPresentedV2();
write("anr-presented-v2", anrPresented);

const anrJce = await buildAnrJointControllerEssenceV2();
write("anr-joint-controller-essence-v2", anrJce);

const anrWithdrawn = await buildAnrWithdrawnV2(anrPresented);
write("anr-withdrawn-v2", anrWithdrawn);

const anrTranslated = await buildAnrTranslatedV2WithAlrProv(alrDerived);
write("anr-translated-v2-alr-provenance", anrTranslated);

const anrAck = await buildAnrAcknowledgedV2OnPresented(anrPresented);
write("anr-acknowledged-v2-on-presented", anrAck);

const anrNegSig = await buildAnrNegTamperedSig(anrPresented);
write("anr-neg-tampered-sig", anrNegSig);

const anrNegAckNull = await buildAnrNegAckSubjectNull();
write("anr-neg-ack-subject-null", anrNegAckNull);

const anrNegArt50 = await buildAnrNegArt50NoTsa();
write("anr-neg-art50-no-tsa", anrNegArt50);

// ── ABR §J.2 — 3 positive + 2 cross-issuer + 3 negative ──────────────────────

const abrAssessed = await buildAbrAssessedV2();
write("abr-assessed-v2", abrAssessed);

const abrDpaNotified = await buildAbrDpaNotifiedNis2V2();
write("abr-dpa-notified-v2-nis2", abrDpaNotified);

const abrSubjectNotified = await buildAbrSubjectNotifiedV2();
write("abr-subject-notified-v2", abrSubjectNotified);

const abrContainedArr = await buildAbrContainedV2ArrComposed(arrErasureV2);
write("abr-contained-v2-arr-composed", abrContainedArr);

const abrClosedAnr = await buildAbrClosedV2AnrComposed(anrPresented);
write("abr-closed-v2-anr-composed", abrClosedAnr);

const abrNegSig = await buildAbrNegTamperedSig(abrAssessed);
write("abr-neg-tampered-sig", abrNegSig);

const abrNegNoTsa = await buildAbrNegDetectedNoTsa();
write("abr-neg-detected-no-tsa", abrNegNoTsa);

const abrNegSubjNull = await buildAbrNegSubjectNotifiedNull();
write("abr-neg-subject-notified-null", abrNegSubjNull);

// ── ASR §J.3 — 30 positive (5 × 6 profiles) + 3 negative ─────────────────────

const asrA15 = await buildAsrA15Vectors();
for (const v of asrA15) write(v.name, v);

const asrA16 = await buildAsrA16Vectors();
for (const v of asrA16) write(v.name, v);

const asrA17 = await buildAsrA17Vectors(arrErasureV2);
for (const v of asrA17) write(v.name, v);

const asrA18 = await buildAsrA18Vectors();
for (const v of asrA18) write(v.name, v);

const asrA20 = await buildAsrA20Vectors();
for (const v of asrA20) write(v.name, v);

const asrA21 = await buildAsrA21Vectors();
for (const v of asrA21) write(v.name, v);

// Pick a stable positive for sig-tampering (art15 received — lifecycle root).
const asrNegSig = await buildAsrNegTamperedSig(asrA15[0]);
write("asr-neg-tampered-sig", asrNegSig);

const asrNegSubjNull = await buildAsrNegSubjectNull();
write("asr-neg-subject-null", asrNegSubjNull);

const asrNegSubjMalformed = await buildAsrNegSubjectMalformed();
write("asr-neg-subject-malformed", asrNegSubjMalformed);

// ── AIR §J.4 — 25 positive (5 × 5 profiles) + 2 cross-issuer + 3 negative ────

const airA = await buildAirA35_3_aVectors();
for (const v of airA) write(v.name, v);

const airB = await buildAirA35_3_bVectors();
for (const v of airB) write(v.name, v);

const airC = await buildAirA35_3_cVectors();
for (const v of airC) write(v.name, v);

const airDpa = await buildAirA35_4Vectors();
for (const v of airDpa) write(v.name, v);

const airVol = await buildAirVoluntaryVectors();
for (const v of airVol) write(v.name, v);

// Cross-issuer composition — ALR ← AIR `dpia.completed`; ABR ← AIR `dpia.reviewed`.
const airCompletedAlrComposed = await buildAirCompletedAlrComposed(alrDerived);
write(airCompletedAlrComposed.name, airCompletedAlrComposed);

const airReviewedAbrComposed = await buildAirReviewedAbrComposed(abrAssessed);
write(airReviewedAbrComposed.name, airReviewedAbrComposed);

// Pick a stable positive for sig-tampering (art35_3_a threshold — lifecycle root).
const airNegSig = await buildAirNegTamperedSig(airA[0]);
write("air-neg-tampered-sig", airNegSig);

const airNegSubjOnCmp = await buildAirNegSubjectPresentOnCompleted();
write("air-neg-subject-present-on-completed", airNegSubjOnCmp);

const airNegStkMM = await buildAirNegStakeholdersMethodMismatch();
write("air-neg-stakeholders-method-mismatch", airNegStkMM);

console.log("\nmint-vectors: done.");
